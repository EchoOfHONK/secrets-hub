"""Advanced vault features: controlled sharing, local formats, MFA, exports, backup."""
from __future__ import annotations

import base64
import csv
import io
import json
import secrets
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

import pyotp
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field, ValidationError, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from . import backup
from .auth import (check_credentials, client_ip, rate_limit, require_admin, require_reauth,
                   require_user, session_for, settings_row, token_hash)
from .core import audit, create_secret, serialize_secret
from .crypto import decrypt_json, encrypt_json, get_key, hash_password, set_key, unwrap_key, verify_password
from .db import aware, get_db, utcnow
from .formats import generate_ssh, parse_import, parse_wireguard, qr_data_url, render_wireguard
from .models import (AuditEvent, AuthSession, BackupRecord, Collection, Secret,
                     TemporaryLink, User, uid)
from .permissions import access_secret, collection_access, secret_access
from .schemas import RevealWrite, SecretWrite, StrictModel

router = APIRouter(prefix="/api")
Db = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(require_user)]
VerifiedUser = Annotated[User, Depends(require_reauth)]
AdminUser = Annotated[User, Depends(require_admin)]
WORDLIST = tuple(Path(__file__).with_name("wordlist.txt").read_text().splitlines())


class EmptyWrite(StrictModel):
    pass


def _new_recovery_codes(user: User) -> list[str]:
    codes = [secrets.token_hex(12) for _ in range(10)]
    user.recovery_codes = [token_hash(value) for value in codes]
    return ["-".join(value[index:index + 4] for index in range(0, len(value), 4)) for value in codes]


def _secret(db: Session, secret_id: str) -> Secret:
    secret = db.get(Secret, secret_id)
    if secret is None:
        raise HTTPException(404, "Secret not found")
    return secret


class TemporaryWrite(StrictModel):
    secret_id: str = Field(min_length=1, max_length=36)
    expires_minutes: int = Field(ge=1, le=525600)
    max_views: int = Field(default=1, ge=1, le=100000)
    password: str | None = Field(default=None, min_length=8, max_length=1024)
    allow_copy: bool = False


class TemporaryOpen(StrictModel):
    token: str = Field(min_length=20, max_length=128)
    password: str | None = Field(default=None, max_length=1024)


def link_info(db: Session, link: TemporaryLink) -> dict:
    secret = db.get(Secret, link.secret_id)
    creator = db.get(User, link.creator_id)
    return {"id": link.id, "secret_id": link.secret_id, "name": secret.name if secret else "Deleted secret",
            "created_at": link.created_at, "expires_at": link.expires_at, "max_views": link.max_views,
            "views": link.views, "allow_copy": link.allow_copy, "password_protected": bool(link.password_hash),
            "revoked": link.revoked, "creator": creator.username if creator else "Deleted user",
            "available": not link.revoked and aware(link.expires_at) > utcnow() and link.views < link.max_views}


@router.get("/temporary-links")
def list_temporary(db: Db, user: CurrentUser):
    query = select(TemporaryLink).order_by(TemporaryLink.created_at.desc())
    if user.role != "admin":
        query = query.where(TemporaryLink.creator_id == user.id)
    return [link_info(db, row) for row in db.scalars(query).all()]


@router.post("/temporary-links")
def create_temporary(body: TemporaryWrite, request: Request, db: Db, user: CurrentUser):
    secret = access_secret(db, user, _secret(db, body.secret_id), write=True, copy=True)
    raw = secrets.token_urlsafe(32)
    link = TemporaryLink(id=uid(), secret_id=secret.id, creator_id=user.id, token_hash=token_hash(raw),
                         expires_at=utcnow() + timedelta(minutes=body.expires_minutes), max_views=body.max_views,
                         password_hash=hash_password(body.password) if body.password else None,
                         allow_copy=body.allow_copy)
    db.add(link)
    db.flush()
    audit(db, request, user, "temporary_link_created", secret.name)
    origin = settings_row(db).app_url
    return {**link_info(db, link), "url": origin + "/t#" + raw, "token": raw}


@router.delete("/temporary-links/{link_id}")
def revoke_temporary(link_id: str, request: Request, db: Db, user: CurrentUser):
    link = db.get(TemporaryLink, link_id)
    if link is None or user.role != "admin" and link.creator_id != user.id:
        raise HTTPException(404, "Temporary link not found")
    link.revoked = True
    audit(db, request, user, "temporary_link_revoked", _secret(db, link.secret_id).name)
    return {"revoked": True}


@router.post("/public/temporary")
def open_temporary(body: TemporaryOpen, request: Request, db: Db):
    rate_limit(db, request, "temporary:ip", limit=40)
    rate_limit(db, request, "temporary:" + token_hash(body.token), limit=15)
    now = utcnow()
    unavailable = HTTPException(410, "This secret is no longer available.")
    link = db.scalar(select(TemporaryLink).where(TemporaryLink.token_hash == token_hash(body.token)).with_for_update())
    if link is None or link.revoked or aware(link.expires_at) <= now or link.views >= link.max_views:
        raise unavailable
    if link.password_hash and not verify_password(link.password_hash, body.password or ""):
        raise unavailable
    secret = db.get(Secret, link.secret_id)
    creator = db.get(User, link.creator_id)
    if secret is None or creator is None or creator.disabled:
        raise unavailable
    if secret.expires_at and aware(secret.expires_at) <= now:
        raise unavailable
    read, _, can_copy = secret_access(db, creator, secret)
    if not read or not can_copy:
        raise unavailable
    # Conditional update makes one-time consumption atomic even when two requests race.
    consumed = db.execute(update(TemporaryLink).where(
        TemporaryLink.id == link.id, TemporaryLink.revoked.is_(False),
        TemporaryLink.expires_at > now, TemporaryLink.views < TemporaryLink.max_views,
    ).values(views=TemporaryLink.views + 1).execution_options(synchronize_session=False))
    if consumed.rowcount != 1:
        raise unavailable
    data = decrypt_json(secret.ciphertext, secret.id)
    secret.last_used = now
    db.add(AuditEvent(username="temporary visitor", action="temporary_link_used", target=secret.name,
                      ip=client_ip(request)))
    return {"name": secret.name, "type": secret.type, "data": data,
            "allow_copy": link.allow_copy, "expires_at": link.expires_at}


@router.post("/public/temporary/copy")
def record_temporary_copy(body: TemporaryOpen, request: Request, db: Db):
    rate_limit(db, request, "temporary-copy:ip", limit=40)
    rate_limit(db, request, "temporary-copy:" + token_hash(body.token), limit=15)
    unavailable = HTTPException(410, "This secret is no longer available.")
    link = db.scalar(select(TemporaryLink).where(TemporaryLink.token_hash == token_hash(body.token)).with_for_update())
    # Consumption prevents another reveal. An allowed clipboard action on an already
    # displayed value is audited without returning the value or consuming another view.
    if link is None or link.revoked or not link.allow_copy or aware(link.expires_at) <= utcnow():
        raise unavailable
    if link.password_hash and not verify_password(link.password_hash, body.password or ""):
        raise unavailable
    secret = db.get(Secret, link.secret_id)
    creator = db.get(User, link.creator_id)
    if secret is None or creator is None or creator.disabled or secret.expires_at and aware(secret.expires_at) <= utcnow():
        raise unavailable
    read, _, can_copy = secret_access(db, creator, secret)
    if not read or not can_copy:
        raise unavailable
    db.add(AuditEvent(username="temporary visitor", action="secret_copied", target=secret.name,
                      ip=client_ip(request)))
    return {"recorded": True}


class TotpCode(StrictModel):
    code: str = Field(min_length=6, max_length=100)


class TotpDisable(TotpCode):
    password: str = Field(min_length=1, max_length=1024)


@router.post("/auth/totp/setup")
def totp_setup(request: Request, db: Db, user: VerifiedUser):
    if user.totp_secret:
        raise HTTPException(409, "Two-factor authentication is already enabled")
    seed = pyotp.random_base32()
    user.totp_pending = encrypt_json({"secret": seed, "created_at": utcnow().isoformat()}, "totp-pending:" + user.id)
    uri = pyotp.TOTP(seed).provisioning_uri(user.username, issuer_name=settings_row(db).instance_name)
    audit(db, request, user, "totp_setup_started", user.username)
    return {"secret": seed, "uri": uri, "qr_data_url": qr_data_url(uri)}


@router.post("/auth/totp/enable")
def totp_enable(body: TotpCode, request: Request, db: Db, user: VerifiedUser):
    rate_limit(db, request, "totp-enable:" + user.id)
    user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if not user or not user.totp_pending or user.totp_secret:
        raise HTTPException(409, "Start two-factor setup first")
    pending = decrypt_json(user.totp_pending, "totp-pending:" + user.id)
    from datetime import datetime
    if aware(datetime.fromisoformat(pending["created_at"])) < utcnow() - timedelta(minutes=10):
        user.totp_pending = None
        db.commit()
        raise HTTPException(410, "Two-factor setup has expired")
    step = int(utcnow().timestamp()) // 30
    totp = pyotp.TOTP(pending["secret"])
    code = body.code.replace(" ", "")
    accepted = next((candidate for candidate in (step - 1, step, step + 1)
                     if secrets.compare_digest(totp.at(candidate * 30), code)), None)
    if accepted is None:
        raise HTTPException(400, "Invalid verification code")
    user.totp_secret = encrypt_json({"secret": pending["secret"]}, "totp:" + user.id)
    user.totp_pending, user.totp_last_step = None, accepted
    codes = _new_recovery_codes(user)
    current_session = session_for(db, request)
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id, AuthSession.id != current_session.id))
    audit(db, request, user, "totp_enabled", user.username)
    return {"recovery_codes": codes}


@router.post("/auth/totp/recovery-codes")
def regenerate_recovery_codes(body: EmptyWrite, request: Request, db: Db, user: VerifiedUser):
    user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if not user or not user.totp_secret:
        raise HTTPException(409, "Enable two-factor authentication first")
    codes = _new_recovery_codes(user)
    audit(db, request, user, "recovery_codes_regenerated", user.username)
    return {"recovery_codes": codes}


@router.post("/auth/totp/disable")
def totp_disable(body: TotpDisable, request: Request, db: Db, user: CurrentUser):
    rate_limit(db, request, "totp-disable:" + user.id)
    user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if not check_credentials(db, user, body.password, body.code):
        audit(db, request, user, "failed_totp_disable", user.username)
        db.commit()
        raise HTTPException(401, "Invalid credentials or verification code")
    user.totp_secret, user.totp_pending, user.recovery_codes, user.totp_last_step = None, None, [], -1
    current_session = session_for(db, request)
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id, AuthSession.id != current_session.id))
    current_session.reauth_until = None
    audit(db, request, user, "totp_disabled", user.username)
    return {"disabled": True}


class PasswordChange(StrictModel):
    old_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)
    otp: str | None = Field(default=None, max_length=100)


@router.post("/auth/password")
def change_password(body: PasswordChange, request: Request, db: Db, user: CurrentUser):
    rate_limit(db, request, "password:" + user.id)
    user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if not check_credentials(db, user, body.old_password, body.otp):
        audit(db, request, user, "failed_password_change", user.username)
        db.commit()
        raise HTTPException(401, "Invalid credentials or verification code")
    user.password_hash = hash_password(body.new_password)
    current_session = session_for(db, request)
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id, AuthSession.id != current_session.id))
    current_session.reauth_until = None
    audit(db, request, user, "password_changed", user.username)
    return {"changed": True}


class RecoverWrite(StrictModel):
    username: str = Field(min_length=1, max_length=80)
    recovery_key: str = Field(min_length=20, max_length=128)
    new_password: str = Field(min_length=12, max_length=1024)


@router.post("/auth/recover")
def recover_access(body: RecoverWrite, request: Request, db: Db):
    rate_limit(db, request, "recovery:ip", limit=10, minutes=60)
    settings = settings_row(db)
    user = db.scalar(select(User).where(User.username == body.username).with_for_update())
    try:
        key = unwrap_key(body.recovery_key, settings.recovery_wrap or "", "recovery-key")
        if user is None or user.role != "admin" or user.disabled:
            raise ValueError("Recovery failed")
    except (ValueError, TypeError, InvalidTag):
        audit(db, request, None, "failed_recovery", "Administrator recovery")
        db.commit()
        raise HTTPException(401, "Invalid recovery credentials")
    set_key(key)
    user.password_hash = hash_password(body.new_password)
    user.totp_secret, user.totp_pending, user.recovery_codes, user.totp_last_step = None, None, [], -1
    db.execute(delete(AuthSession))
    audit(db, request, user, "administrator_recovered", user.username)
    return {"recovered": True}


class GeneratorWrite(StrictModel):
    kind: Literal["password", "passphrase", "token"] = "password"
    length: int = Field(default=24, ge=12, le=256)
    uppercase: bool = True
    lowercase: bool = True
    numbers: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = True
    words: int = Field(default=6, ge=6, le=12)


@router.post("/generate")
def generate(body: GeneratorWrite, user: CurrentUser):
    if body.kind == "passphrase":
        return {"value": "-".join(secrets.choice(WORDLIST) for _ in range(body.words))}
    if body.kind == "token":
        # Each character has 6 bits of entropy; URL-safe text suitable for API tokens.
        return {"value": "".join(secrets.choice(string.ascii_letters + string.digits + "-_") for _ in range(body.length))}
    groups = [alphabet for enabled, alphabet in ((body.uppercase, string.ascii_uppercase),
              (body.lowercase, string.ascii_lowercase), (body.numbers, string.digits),
              (body.symbols, "!@#$%^&*()-_=+[]{}:,.?")) if enabled]
    if body.exclude_ambiguous:
        groups = ["".join(char for char in alphabet if char not in "Il1O0o") for alphabet in groups]
    if not groups:
        raise HTTPException(400, "Choose at least one character group")
    alphabet = "".join(groups)
    # Rejection sampling retains a uniform distribution over passwords satisfying selections.
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(body.length))
        if all(any(char in group for char in value) for group in groups):
            return {"value": value}


class ImportWrite(StrictModel):
    format: Literal["json", "csv", "env", "ssh", "wireguard"]
    content: str = Field(min_length=1, max_length=8 * 1024 * 1024)
    name: str | None = Field(default=None, max_length=180)
    collection_id: str | None = Field(default=None, max_length=36)
    passphrase: str | None = Field(default=None, max_length=1024)


@router.post("/import")
def import_secrets(body: ImportWrite, request: Request, db: Db, user: CurrentUser):
    try:
        records = parse_import(body.format, body.content, body.name, body.passphrase)
        validated = [SecretWrite(**record, collection_id=body.collection_id) for record in records]
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, "Invalid import. Check the file format and required fields") from exc
    for record in validated:
        create_secret(db, user, record, request)
    audit(db, request, user, "import", f"{len(validated)} secrets")
    return {"created": len(validated)}


class SshGenerateWrite(StrictModel):
    name: str = Field(min_length=1, max_length=180)
    host: str = Field(default="", max_length=500)
    username: str = Field(default="", max_length=500)
    passphrase: str | None = Field(default=None, max_length=1024)
    collection_id: str | None = Field(default=None, max_length=36)
    tags: list[str] = Field(default_factory=list, max_length=30)
    expires_at: datetime | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    _tags = field_validator("tags")(SecretWrite.valid_tags.__func__)
    _expiration = field_validator("expires_at")(SecretWrite.valid_expiration.__func__)
    _metadata = field_validator("metadata")(SecretWrite.valid_metadata.__func__)

    @field_validator("passphrase")
    @classmethod
    def valid_passphrase(cls, value: str | None) -> str | None:
        if value and len(value.encode("utf-8")) > 1023:
            raise ValueError("SSH passphrase exceeds the OpenSSH byte limit")
        return value


@router.post("/ssh/generate")
def create_ssh(body: SshGenerateWrite, request: Request, db: Db, user: CurrentUser):
    if user.role == "viewer":
        raise HTTPException(403, "Editors or administrators can create secrets")
    data = {**generate_ssh(body.passphrase), "host": body.host, "username": body.username}
    secret = create_secret(db, user, SecretWrite(name=body.name, type="ssh_key", collection_id=body.collection_id,
                           tags=body.tags, expires_at=body.expires_at,
                           metadata={**body.metadata, "hostname": body.host, "username": body.username, "fingerprint": data["fingerprint"]},
                           data=data), request)
    return serialize_secret(db, user, secret)


class ConfigParse(StrictModel):
    content: str = Field(min_length=1, max_length=1024 * 1024)


@router.post("/wireguard/parse")
def wireguard_parse(body: ConfigParse, user: CurrentUser):
    try:
        data = parse_wireguard(body.content)
    except ValueError as exc:
        raise HTTPException(400, "Invalid WireGuard configuration") from exc
    return {"data": data, "metadata": {"hostname": data["endpoint"], "address": data["address"]}}


@router.post("/wireguard/{secret_id}/config")
def wireguard_config(secret_id: str, body: RevealWrite, request: Request, db: Db, user: CurrentUser):
    secret = access_secret(db, user, _secret(db, secret_id), copy=body.action in {"copy", "export"})
    if secret.type != "wireguard":
        raise HTTPException(400, "Secret is not a WireGuard profile")
    if body.action == "export":
        require_reauth(request, user, db)
    try:
        config_text = render_wireguard(decrypt_json(secret.ciphertext, secret.id))
    except ValueError as exc:
        raise HTTPException(400, "WireGuard profile is incomplete or invalid") from exc
    try:
        qr = qr_data_url(config_text)
    except ValueError:
        qr = None
    secret.last_used = utcnow()
    audit(db, request, user, {"view": "secret_viewed", "copy": "secret_copied", "export": "export"}[body.action], secret.name)
    return {"config": config_text, "qr_data_url": qr}


@router.post("/secrets/{secret_id}/duplicate")
def duplicate_secret(secret_id: str, request: Request, db: Db, user: CurrentUser):
    source = access_secret(db, user, _secret(db, secret_id), write=True, copy=True)
    collection_id = source.collection_id
    if collection_id:
        collection = db.get(Collection, collection_id)
        if collection is None or not collection_access(db, user, collection)[1]:
            collection_id = None
    data = decrypt_json(source.ciphertext, source.id)
    secret = create_secret(db, user, SecretWrite(name=source.name[:173] + " (copy)", type=source.type,
                           collection_id=collection_id, tags=source.tags, expires_at=source.expires_at,
                           metadata=source.meta, data=data), request)
    return serialize_secret(db, user, secret)


class ExportWrite(StrictModel):
    format: Literal["json", "csv"]


def _csv_safe(value: str) -> str:
    # Prevent spreadsheet formula injection when users open metadata in Excel/LibreOffice.
    dangerous = value.startswith(("\t", "\r", "\n")) or value.lstrip().startswith(("=", "+", "-", "@"))
    return "'" + value if dangerous else value


@router.post("/export")
def export_secrets(body: ExportWrite, request: Request, db: Db, user: VerifiedUser):
    rows = [row for row in db.scalars(select(Secret).order_by(Secret.name)).all() if secret_access(db, user, row)[0]]
    if body.format == "json":
        rows = [row for row in rows if secret_access(db, user, row)[2]]
        values = [{"name": row.name, "type": row.type, "tags": row.tags, "metadata": row.meta,
                   "expires_at": aware(row.expires_at).isoformat() if row.expires_at else None,
                   "data": decrypt_json(row.ciphertext, row.id)} for row in rows]
        content = json.dumps({"format": "Secrets Hub plaintext export v1", "secrets": values}, ensure_ascii=False)
        media_type, extension = "application/json", "json"
    else:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        fields = ["name", "type", "tags", "username", "hostname", "service", "expires_at"]
        writer.writerow(fields)
        for row in rows:
            values = [row.name, row.type, ",".join(row.tags), row.meta.get("username", ""),
                      row.meta.get("hostname", ""), row.meta.get("service", ""),
                      aware(row.expires_at).isoformat() if row.expires_at else ""]
            writer.writerow([_csv_safe(value) for value in values])
        content, media_type, extension = buffer.getvalue(), "text/csv", "csv"
    audit(db, request, user, "export", f"{len(rows)} secrets ({body.format})")
    return Response(content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="secrets-hub-export.{extension}"',
                             "Cache-Control": "no-store"})


class BackupWrite(StrictModel):
    password: str = Field(min_length=12, max_length=1024)


def backup_info(row: BackupRecord) -> dict:
    return {"id": row.id, "filename": row.filename, "created_at": row.created_at, "scheduled": row.scheduled}


@router.get("/backups")
def list_backups(db: Db, user: AdminUser):
    return [backup_info(row) for row in db.scalars(select(BackupRecord).order_by(BackupRecord.created_at.desc())).all()]


@router.post("/backups")
def new_backup(body: BackupWrite, request: Request, db: Db, user: VerifiedUser):
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required")
    db.commit()
    try:
        record = backup.create_backup(db, body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    audit(db, request, user, "backup_created", "Encrypted backup")
    return backup_info(record)


@router.post("/backups/{backup_id}/download")
def download_backup(backup_id: str, body: EmptyWrite, request: Request, db: Db, user: VerifiedUser):
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required")
    record = db.get(BackupRecord, backup_id)
    if record is None:
        raise HTTPException(404, "Backup not found")
    path = backup.backup_dir() / record.filename
    if path.parent != backup.backup_dir() or not path.is_file():
        raise HTTPException(404, "Backup file is unavailable")
    content = path.read_bytes()
    audit(db, request, user, "backup_downloaded", "Encrypted backup")
    return Response(content, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{record.filename}"', "Cache-Control": "no-store"})


class BackupRestore(StrictModel):
    content_base64: str = Field(min_length=1, max_length=90 * 1024 * 1024)
    password: str | None = Field(default=None, max_length=1024)


@router.post("/backups/restore")
def restore_backup(body: BackupRestore, request: Request, db: Db, user: VerifiedUser):
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required")
    username, user_id = user.username, user.id
    try:
        content = base64.b64decode(body.content_base64, validate=True)
        value = backup.open_backup(content, body.password)
    except ValueError as exc:
        raise HTTPException(400, "Unable to decrypt backup. Check the password and file") from exc
    db.commit()
    try:
        backup.restore_snapshot(value, db)
    except backup.RestoreInterrupted as exc:
        raise HTTPException(503, "Restore was committed. Restart Secrets Hub to finalize the encryption key") from exc
    except Exception as exc:
        raise HTTPException(400, "Restore failed; the existing vault was preserved") from exc
    restored_user = db.get(User, user_id)
    db.add(AuditEvent(user_id=restored_user.id if restored_user else None, username=username,
                      action="backup_restored", target="Encrypted backup", ip=client_ip(request)))
    return {"restored": True}


@router.get("/security")
def security_status(request: Request, db: Db, user: CurrentUser):
    records = [row for row in db.scalars(select(Secret)).all() if secret_access(db, user, row)[0]]
    latest = db.scalar(select(BackupRecord).order_by(BackupRecord.created_at.desc()).limit(1))
    failed = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "failed_login",
                               AuditEvent.created_at >= utcnow() - timedelta(hours=24))) or 0
    try:
        configured = len(get_key()) == 32
    except (FileNotFoundError, RuntimeError):
        configured = False
    settings = settings_row(db)
    return {"encryption": configured, "https": request.url.scheme == "https", "master_key": configured and bool(settings.master_wrap),
            "totp_enabled": bool(user.totp_secret), "last_backup": latest.created_at if latest else None,
            "failed_logins": failed, "weak_passwords": sum(row.weak_password for row in records),
            "expired_secrets": sum(bool(row.expires_at and aware(row.expires_at) <= utcnow()) for row in records)}
