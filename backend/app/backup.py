"""Authenticated encrypted snapshots, retention, and offline backup/restore CLI."""
from __future__ import annotations

import argparse
import base64
import getpass
import gzip
import json
import logging
import os
import secrets
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import DateTime, delete, select, update
from sqlalchemy.orm import Session

from .config import config
from .crypto import derive_key, get_key, key_path, set_key
from .db import Base, SessionLocal, aware, engine, utcnow
from .models import AppSettings, AuditEvent, AuthSession, BackupRecord, RateLimit, TemporaryLink, User, uid

MAX_BACKUP_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
FORMAT = "secrets-hub-backup-v1"
AAD = FORMAT.encode("ascii")
EPHEMERAL = {"sessions", "rate_limits", "backups"}
restore_in_progress = False
operation_lock = threading.RLock()
logger = logging.getLogger("secrets_hub.backup")


class RestoreInterrupted(RuntimeError):
    """Database commit succeeded; key finalization will be recovered on startup."""


def _journal_path() -> Path:
    return key_path().parent / "restore-journal.json"


def _write_journal(value: dict[str, Any]) -> None:
    directory = _journal_path().parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    temporary = directory / ("restore-" + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(value, separators=(",", ":")).encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, _journal_path())
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def recover_interrupted_restore() -> None:
    """Reconcile DB commit and key-file replacement after an interrupted restore."""
    with operation_lock:
        path = _journal_path()
        if not path.exists():
            return
        journal = json.loads(path.read_bytes())
        with SessionLocal() as db:
            settings = db.get(AppSettings, 1)
            marker = settings.master_wrap if settings else None
        if marker == journal["new_marker"]:
            key = base64.b64decode(journal["new_key"], validate=True)
        elif marker == journal["old_marker"]:
            key = base64.b64decode(journal["old_key"], validate=True) if journal["old_key"] else None
        else:
            raise RuntimeError("Restore journal does not match the database")
        if key is not None:
            set_key(key)
        path.unlink()


def backup_dir() -> Path:
    directory = config.data_dir / "backups"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return aware(value).isoformat()
    return value


def snapshot(db: Session | None = None) -> dict[str, Any]:
    """PostgreSQL snapshot is repeatable-read; SQLite uses one read transaction."""
    tables = [table for table in Base.metadata.sorted_tables if table.name not in EPHEMERAL]
    result: dict[str, Any] = {"schema": 1, "created_at": utcnow().isoformat(),
                              "master_key": base64.b64encode(get_key()).decode("ascii"), "tables": {}}
    if db is not None:
        connection = db.connection()
        for table in tables:
            result["tables"][table.name] = [{key: _json_value(value) for key, value in row.items()}
                                            for row in connection.execute(select(table)).mappings()]
    else:
        isolation = "REPEATABLE READ" if engine.dialect.name == "postgresql" else "SERIALIZABLE"
        with engine.connect().execution_options(isolation_level=isolation) as connection:
            with connection.begin():
                for table in tables:
                    result["tables"][table.name] = [{key: _json_value(value) for key, value in row.items()}
                                                    for row in connection.execute(select(table)).mappings()]
    return result


def seal(value: dict[str, Any], password: str | None = None) -> bytes:
    plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(plaintext) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Backup exceeds the 128 MiB snapshot limit")
    compressed = gzip.compress(plaintext, mtime=0)
    nonce = secrets.token_bytes(12)
    if password is not None:
        if len(password) < 12 or len(password) > 1024:
            raise ValueError("Backup password must have 12 to 1024 characters")
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        mode = "password"
    else:
        key, salt, mode = get_key(), b"", "machine"
    encrypted = AESGCM(key).encrypt(nonce, compressed, AAD)
    envelope = {"format": FORMAT, "mode": mode, "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(encrypted).decode("ascii")}
    output = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    if len(output) > MAX_BACKUP_BYTES:
        raise ValueError("Encrypted backup exceeds the 64 MiB limit")
    return output


def open_backup(content: bytes, password: str | None = None) -> dict[str, Any]:
    if len(content) > MAX_BACKUP_BYTES:
        raise ValueError("Backup exceeds the 64 MiB limit")
    try:
        envelope = json.loads(content)
        if not isinstance(envelope, dict) or envelope.get("format") != FORMAT:
            raise ValueError("Unsupported backup format")
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        salt = base64.b64decode(envelope["salt"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(nonce) != 12:
            raise ValueError("Invalid backup nonce")
        if envelope["mode"] == "password":
            if not password or len(salt) != 16 or len(password) > 1024:
                raise ValueError("A backup password is required")
            key = derive_key(password, salt)
        elif envelope["mode"] == "machine":
            if salt:
                raise ValueError("Invalid backup salt")
            key = get_key()
        else:
            raise ValueError("Unsupported backup mode")
        compressed = AESGCM(key).decrypt(nonce, ciphertext, AAD)
        # Bound gzip expansion before deserializing attacker-controlled snapshots.
        import io
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            plaintext = stream.read(MAX_SNAPSHOT_BYTES + 1)
        if len(plaintext) > MAX_SNAPSHOT_BYTES:
            raise ValueError("Snapshot is too large")
        value = json.loads(plaintext)
        validate_snapshot(value)
        return value
    except (KeyError, TypeError, ValueError, InvalidTag, OSError, AttributeError, OverflowError, RecursionError) as exc:
        raise ValueError("Unable to decrypt backup: wrong password, missing machine key, or damaged file") from exc


def validate_snapshot(value: Any) -> None:
    if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("tables"), dict):
        raise ValueError("Unsupported snapshot schema")
    if len(base64.b64decode(value.get("master_key", ""), validate=True)) != 32:
        raise ValueError("Invalid snapshot encryption key")
    expected = {table.name for table in Base.metadata.sorted_tables if table.name not in EPHEMERAL}
    if set(value["tables"]) != expected:
        raise ValueError("Snapshot table set is incompatible")
    for table in Base.metadata.sorted_tables:
        if table.name in EPHEMERAL:
            continue
        rows = value["tables"][table.name]
        if not isinstance(rows, list) or len(rows) > 1_000_000:
            raise ValueError("Invalid snapshot rows")
        columns = {column.name for column in table.columns}
        for row in rows:
            if not isinstance(row, dict) or set(row) != columns:
                raise ValueError("Invalid snapshot columns")
    settings_rows = value["tables"].get("app_settings", [])
    if len(settings_rows) != 1 or settings_rows[0].get("id") != 1 or not settings_rows[0].get("initialized"):
        raise ValueError("Snapshot does not contain an initialized vault")
    for field in ("master_wrap", "recovery_wrap"):
        wrapped = settings_rows[0].get(field)
        if not isinstance(wrapped, str) or len(base64.urlsafe_b64decode(wrapped.encode("ascii"))) != 76:
            raise ValueError("Snapshot recovery envelopes are invalid")
    if not any(user.get("role") == "admin" and not user.get("disabled") for user in value["tables"].get("users", [])):
        raise ValueError("Snapshot needs an active administrator")
    # Verify authenticated ciphertext before changing live state.
    snapshot_key = base64.b64decode(value["master_key"], validate=True)
    for table_name in ("secrets", "secret_versions"):
        for row in value["tables"][table_name]:
            raw = base64.urlsafe_b64decode(row["ciphertext"].encode("ascii"))
            context = row["id"] if table_name == "secrets" else row["secret_id"]
            parsed = json.loads(AESGCM(snapshot_key).decrypt(raw[:12], raw[12:], context.encode()))
            if not isinstance(parsed, dict):
                raise ValueError("Invalid encrypted snapshot record")
    for user in value["tables"]["users"]:
        for field, context in (("totp_secret", "totp:"), ("totp_pending", "totp-pending:")):
            if user[field]:
                raw = base64.urlsafe_b64decode(user[field].encode("ascii"))
                parsed = json.loads(AESGCM(snapshot_key).decrypt(raw[:12], raw[12:], (context + user["id"]).encode()))
                if not isinstance(parsed, dict) or not isinstance(parsed.get("secret"), str):
                    raise ValueError("Invalid encrypted authentication record")


def restore_snapshot(value: dict[str, Any], db: Session | None = None) -> None:
    global restore_in_progress
    validate_snapshot(value)
    replacement_key = base64.b64decode(value["master_key"], validate=True)
    with operation_lock:
        try:
            previous_key: bytes | None = get_key()
        except (FileNotFoundError, RuntimeError):
            previous_key = None
        restore_in_progress = True
        owned_db = db is None
        active_db = db if db is not None else SessionLocal()
        committed = False
        try:
            if active_db is None:
                raise RuntimeError("Database unavailable")
            # Callers must have committed authorization/audit work before restore.
            active_db.rollback()
            with active_db.begin():
                old_settings = active_db.get(AppSettings, 1)
                _write_journal({"old_key": base64.b64encode(previous_key).decode("ascii") if previous_key else None,
                                "new_key": value["master_key"],
                                "old_marker": old_settings.master_wrap if old_settings else None,
                                "new_marker": value["tables"]["app_settings"][0]["master_wrap"]})
                for table in reversed(Base.metadata.sorted_tables):
                    # Local backup files survive restore, so their catalog must survive too.
                    if table.name == "backups":
                        continue
                    active_db.execute(delete(table))
                for table in Base.metadata.sorted_tables:
                    if table.name in EPHEMERAL:
                        continue
                    rows: list[dict[str, Any]] = []
                    for source in value["tables"][table.name]:
                        row = dict(source)
                        for column in table.columns:
                            if isinstance(column.type, DateTime) and row[column.name] is not None:
                                row[column.name] = datetime.fromisoformat(row[column.name])
                        rows.append(row)
                    if rows:
                        active_db.execute(table.insert(), rows)
                # Never resurrect public bearer access or spent one-time recovery codes.
                active_db.execute(update(TemporaryLink).values(revoked=True))
                active_db.execute(update(User).values(recovery_codes=[], totp_pending=None,
                                                      totp_last_step=int(utcnow().timestamp()) // 30 - 1))
            committed = True
            set_key(replacement_key)
            _journal_path().unlink()
            active_db.expire_all()
        except Exception:
            if committed:
                raise RestoreInterrupted("Restart Secrets Hub to finish restoring the encryption key") from None
            _journal_path().unlink(missing_ok=True)
            raise
        finally:
            if owned_db and active_db is not None:
                active_db.close()
            restore_in_progress = False


def create_backup(db: Session, password: str | None = None, scheduled: bool = False) -> BackupRecord:
    with operation_lock:
        record_id = uid()
        filename = f"secrets-hub-{utcnow().strftime('%Y%m%dT%H%M%SZ')}-{record_id[:8]}.shbak"
        content = seal(snapshot(), password)
        destination = backup_dir() / filename
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        record = BackupRecord(id=record_id, filename=filename, created_at=utcnow(), scheduled=scheduled)
        db.add(record)
        db.flush()
        return record


def retain_backups(db: Session, settings: AppSettings) -> None:
    records = db.scalars(select(BackupRecord).where(BackupRecord.scheduled.is_(True)).order_by(BackupRecord.created_at.desc())).all()
    keep: set[str] = set()
    for field, limit in (("daily", settings.retention_daily), ("weekly", settings.retention_weekly), ("monthly", settings.retention_monthly)):
        buckets: set[Any] = set()
        for record in records:
            date = aware(record.created_at)
            bucket: Any = date.date() if field == "daily" else (date.isocalendar()[:2] if field == "weekly" else (date.year, date.month))
            if bucket in buckets:
                continue
            if len(buckets) >= limit:
                break
            buckets.add(bucket)
            keep.add(record.id)
    for record in records:
        if record.id not in keep:
            (backup_dir() / record.filename).unlink(missing_ok=True)
            db.delete(record)


def _scheduler_tick() -> None:
    if _journal_path().exists():
        return
    with SessionLocal() as db:
        settings = db.get(AppSettings, 1)
        now = utcnow()
        db.execute(delete(AuthSession).where(AuthSession.expires_at <= now))
        db.execute(delete(RateLimit).where(
            RateLimit.window_start < now - timedelta(hours=24),
            (RateLimit.blocked_until.is_(None)) | (RateLimit.blocked_until <= now)))
        db.commit()
        if not settings or not settings.initialized:
            return
        db.execute(delete(TemporaryLink).where(TemporaryLink.expires_at <= now))
        db.commit()
        if not settings.backup_enabled or now.hour < settings.backup_hour:
            return
        latest = db.scalar(select(BackupRecord).where(BackupRecord.scheduled.is_(True)).order_by(BackupRecord.created_at.desc()).limit(1))
        if latest and aware(latest.created_at).date() == now.date():
            return
        create_backup(db, scheduled=True)
        db.add(AuditEvent(username="system", action="backup scheduled", target="Encrypted backup", ip="local"))
        retain_backups(db, settings)
        db.commit()


def scheduler_tick() -> None:
    with operation_lock:
        _scheduler_tick()


def scheduler_loop(stop: threading.Event) -> None:
    while not stop.wait(60):
        try:
            scheduler_tick()
        except Exception:
            # No exception details: crypto/parser exceptions can contain supplied material.
            logger.error('{"event":"scheduled_backup_failed"}')


def main() -> None:
    parser = argparse.ArgumentParser(description="Secrets Hub encrypted backup and offline restore")
    subcommands = parser.add_subparsers(dest="command", required=True)
    backup_command = subcommands.add_parser("backup")
    backup_command.add_argument("--output", required=True)
    backup_command.add_argument("--password-file")
    backup_command.add_argument("--machine", action="store_true", help="Use the existing master key instead of a portable password")
    restore_command = subcommands.add_parser("restore")
    restore_command.add_argument("--input", required=True)
    restore_command.add_argument("--password-file")
    restore_command.add_argument("--password-stdin", action="store_true",
                                 help="With --input -, read a password line followed by encrypted backup bytes")
    args = parser.parse_args()
    try:
        recover_interrupted_restore()
        if args.command == "restore" and args.password_stdin and (args.input != "-" or args.password_file):
            raise ValueError("Password stdin requires backup stdin and cannot use a password file")
        password = Path(args.password_file).read_text().rstrip("\r\n") if args.password_file else None
        if args.command == "backup":
            if not args.machine and password is None:
                password = getpass.getpass("Backup password (12+ characters): ")
                if password != getpass.getpass("Repeat backup password: "):
                    raise ValueError("Backup passwords do not match")
            content = seal(snapshot(), None if args.machine else password)
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            with SessionLocal() as db:
                if destination.parent.resolve() == backup_dir().resolve():
                    db.add(BackupRecord(id=uid(), filename=destination.name, created_at=utcnow(), scheduled=False))
                db.add(AuditEvent(username="system", action="backup_created", target="CLI encrypted backup", ip="local"))
                db.commit()
            print("Encrypted backup created")
        else:
            if args.input == "-":
                if not args.password_stdin:
                    raise ValueError("Backup stdin requires --password-stdin")
                password_line = sys.stdin.buffer.readline(4098)
                if not password_line.endswith(b"\n"):
                    raise ValueError("Invalid password input")
                password = password_line.rstrip(b"\r\n").decode("utf-8") or None
                if password and len(password) > 1024:
                    raise ValueError("Backup password is too long")
                content = sys.stdin.buffer.read(MAX_BACKUP_BYTES + 1)
            else:
                with Path(args.input).open("rb") as stream:
                    content = stream.read(MAX_BACKUP_BYTES + 1)
            envelope = json.loads(content)
            if envelope.get("mode") == "password" and password is None and not args.password_stdin:
                password = getpass.getpass("Backup password: ")
            restore_snapshot(open_backup(content, password))
            with SessionLocal() as db:
                db.add(AuditEvent(username="system", action="backup_restored", target="CLI encrypted backup", ip="local"))
                db.commit()
            print("Backup restored. All sessions were revoked")
    except Exception:
        # Do not print traceback, supplied passwords, SQL rows, or decrypted content.
        parser.exit(1, "Backup operation failed. Check password, file, storage, and database availability.\n")


if __name__ == "__main__":
    main()
