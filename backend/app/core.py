from datetime import timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from .auth import client_ip, require_admin, require_reauth, require_user, settings_row, user_info
from .crypto import decrypt_json, encrypt_json, hash_password
from .db import aware, get_db, utcnow
from .models import AppSettings, AuditEvent, AuthSession, Collection, CollectionPermission, Secret, SecretShare, SecretVersion, User, uid
from .permissions import access_collection, access_secret, collection_access, require_collection_owner, require_secret_owner, secret_access
from .schemas import CollectionWrite, GrantWrite, RevealWrite, RestoreVersionWrite, SecretWrite, SettingsWrite, UserUpdate, UserWrite

router = APIRouter(prefix='/api')
Db = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(require_user)]
Admin = Annotated[User, Depends(require_admin)]


def audit(db: Session, request: Request, user: User | None, action: str, target: str = '') -> None:
    db.add(AuditEvent(user_id=user.id if user else None, username=user.username if user else 'anonymous',
                      action=action, target=target[:180], ip=client_ip(request)))


def serialize_secret(db: Session, user: User, secret: Secret) -> dict:
    _, can_edit, can_copy = secret_access(db, user, secret)
    return {'id': secret.id, 'name': secret.name, 'type': secret.type, 'collection_id': secret.collection_id,
            'tags': secret.tags, 'expires_at': secret.expires_at, 'metadata': secret.meta, 'created_at': secret.created_at,
            'updated_at': secret.updated_at, 'owner_id': secret.owner_id, 'version': secret.version,
            'can_edit': can_edit, 'can_copy': can_copy, 'can_share': user.role != 'viewer' and (user.role == 'admin' or secret.owner_id == user.id), 'last_used': secret.last_used}


def snapshot(secret: Secret) -> dict:
    return {'name': secret.name, 'type': secret.type, 'collection_id': secret.collection_id, 'tags': secret.tags,
            'metadata': secret.meta, 'expires_at': aware(secret.expires_at).isoformat() if secret.expires_at else None,
            'weak_password': secret.weak_password}


def weak_password(data: dict[str, str]) -> bool:
    password = data.get('password', '')
    return bool(password and (len(password) < 12 or len(set(password)) < 6))


def add_version(db: Session, secret: Secret, user: User, changed_fields: list[str]) -> None:
    db.add(SecretVersion(secret_id=secret.id, number=secret.version, user_id=user.id, ciphertext=secret.ciphertext,
                         snapshot=snapshot(secret), changed_fields=changed_fields))
    db.flush()


def normalize_secret(body: SecretWrite) -> SecretWrite:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from .formats import parse_env, parse_ssh, parse_wireguard, render_wireguard
    data, metadata, expiration = dict(body.data), dict(body.metadata), body.expires_at
    if body.type == 'note' and not data.get('content') and data.get('text'):
        data['content'] = data.pop('text')
    displayed_metadata = {'login': ('username', 'url'), 'api_key': ('service', 'environment'),
                          'token': ('service',), 'ssh_key': ('username',), 'certificate': ('hostname', 'issuer')}
    for field in displayed_metadata.get(body.type, ()):
        if not data.get(field) and metadata.get(field):
            data[field] = metadata[field]
    if body.type == 'ssh_key' and not data.get('host'):
        data['host'] = metadata.get('hostname', metadata.get('host', ''))
    try:
        if body.type == 'wireguard':
            data = {**data, **parse_wireguard(render_wireguard(data))}
            metadata.update(hostname=data['endpoint'], endpoint=data['endpoint'], address=data['address'])
        elif body.type == 'ssh_key':
            key = data.get('private_key') or data.get('public_key', '')
            parsed = parse_ssh(key, data.get('passphrase') or None)
            data.update(parsed)
            metadata['fingerprint'] = parsed['fingerprint']
        elif body.type == 'environment':
            parse_env(data.get('content', ''))
        elif body.type == 'certificate':
            certificates = x509.load_pem_x509_certificates(data.get('certificate', '').encode())
            if not certificates:
                raise ValueError('Certificate content is required')
            certificate = certificates[0]
            if data.get('private_key'):
                private = serialization.load_pem_private_key(data['private_key'].encode(), password=data.get('passphrase', '').encode() or None)
                encoding, format = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                if private.public_key().public_bytes(encoding, format) != certificate.public_key().public_bytes(encoding, format):
                    raise ValueError('Certificate and private key do not match')
            expiration = min(aware(expiration), certificate.not_valid_after_utc) if expiration else certificate.not_valid_after_utc
            metadata['issuer'] = certificate.issuer.rfc4514_string()[:500]
            data['issuer'] = metadata['issuer']
        elif body.type == 'login' and not data.get('password'):
            raise ValueError('Password is required')
        elif body.type == 'api_key' and not (data.get('key') or data.get('secret')):
            raise ValueError('API key is required')
        elif body.type == 'token' and not data.get('token'):
            raise ValueError('Token is required')
        elif body.type == 'note' and not (data.get('text') or data.get('content')):
            raise ValueError('Secure note is required')
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, 'Invalid secret content. Check the key, configuration, or certificate format') from exc
    return SecretWrite(**{**body.model_dump(), 'data': data, 'metadata': metadata, 'expires_at': expiration})


def create_secret(db: Session, user: User, body: SecretWrite, request: Request) -> Secret:
    body = normalize_secret(body)
    if user.role == 'viewer':
        raise HTTPException(403, 'Editors or administrators can create secrets')
    if body.collection_id:
        access_collection(db, user, body.collection_id, write=True)
    secret_id = uid()
    secret = Secret(id=secret_id, owner_id=user.id, name=body.name, type=body.type, collection_id=body.collection_id,
                    tags=body.tags, meta=body.metadata, expires_at=body.expires_at, ciphertext=encrypt_json(body.data, secret_id),
                    version=1, weak_password=weak_password(body.data))
    db.add(secret)
    db.flush()
    add_version(db, secret, user, sorted(body.data))
    audit(db, request, user, 'secret_created', secret.name)
    return secret


def visible_secrets(db: Session, user: User) -> list[Secret]:
    return [secret for secret in db.scalars(select(Secret).order_by(Secret.updated_at.desc())) if secret_access(db, user, secret)[0]]


@router.get('/secrets')
def list_secrets(db: Db, user: CurrentUser, search: str = '', type: str = '', collection_id: str = ''):
    if len(search) > 300 or len(collection_id) > 36 or len(type) > 30:
        raise HTTPException(400, 'Invalid search')
    term = search.casefold()
    collections = {collection.id: collection.name for collection in db.scalars(select(Collection))}
    result = []
    for secret in visible_secrets(db, user):
        if type and secret.type != type or collection_id and secret.collection_id != collection_id:
            continue
        searchable = ' '.join([secret.name, *secret.tags, *secret.meta.values(), collections.get(secret.collection_id, '')]).casefold()
        if term and term not in searchable:
            continue
        result.append(serialize_secret(db, user, secret))
    return result


@router.get('/secrets/{secret_id}')
def get_secret(secret_id: str, db: Db, user: CurrentUser):
    return serialize_secret(db, user, access_secret(db, user, db.get(Secret, secret_id)))


@router.post('/secrets')
def new_secret(body: SecretWrite, request: Request, db: Db, user: CurrentUser):
    return serialize_secret(db, user, create_secret(db, user, body, request))


@router.put('/secrets/{secret_id}')
def update_secret(secret_id: str, body: SecretWrite, request: Request, db: Db, user: CurrentUser):
    body = normalize_secret(body)
    secret = access_secret(db, user, db.scalar(select(Secret).where(Secret.id == secret_id).with_for_update()), write=True)
    if secret.collection_id != body.collection_id:
        require_secret_owner(user, secret)
        if body.collection_id:
            access_collection(db, user, body.collection_id, write=True)
    old_data = decrypt_json(secret.ciphertext, secret.id)
    changed = ['data.' + field for field in sorted(set(old_data) | set(body.data)) if old_data.get(field) != body.data.get(field)]
    fields = {'name': body.name, 'type': body.type, 'collection_id': body.collection_id, 'tags': body.tags, 'meta': body.metadata, 'expires_at': body.expires_at}
    for key, value in fields.items():
        if getattr(secret, key) != value:
            changed.append('metadata' if key == 'meta' else key)
            setattr(secret, key, value)
    secret.ciphertext = encrypt_json(body.data, secret.id)
    secret.version += 1
    secret.weak_password = weak_password(body.data)
    secret.updated_at = utcnow()
    add_version(db, secret, user, changed)
    audit(db, request, user, 'secret_edited', secret.name)
    return serialize_secret(db, user, secret)


@router.delete('/secrets/{secret_id}')
def remove_secret(secret_id: str, request: Request, db: Db, user: CurrentUser):
    secret = access_secret(db, user, db.get(Secret, secret_id), write=True)
    audit(db, request, user, 'secret_deleted', secret.name)
    db.delete(secret)
    return {'deleted': True}


@router.post('/secrets/{secret_id}/reveal')
def reveal_secret(secret_id: str, body: RevealWrite, request: Request, db: Db, user: CurrentUser):
    secret = access_secret(db, user, db.get(Secret, secret_id), copy=body.action in ('copy', 'export'))
    ciphertext = secret.ciphertext
    if body.action == 'export':
        session = request.state.auth_session
        if not session.reauth_until or aware(session.reauth_until) <= utcnow():
            raise HTTPException(428, 'Please confirm your password again')
    if body.version_id:
        version = db.get(SecretVersion, body.version_id)
        if not version or version.secret_id != secret.id:
            raise HTTPException(404, 'Version not found')
        ciphertext = version.ciphertext
    data = decrypt_json(ciphertext, secret.id)
    secret.last_used = utcnow()
    audit(db, request, user, {'view': 'secret_viewed', 'copy': 'secret_copied', 'export': 'export'}[body.action], secret.name)
    return {'data': data}


@router.get('/secrets/{secret_id}/versions')
def list_versions(secret_id: str, db: Db, user: CurrentUser):
    secret = access_secret(db, user, db.get(Secret, secret_id))
    versions = db.execute(select(SecretVersion, User.username).join(User, SecretVersion.user_id == User.id).where(SecretVersion.secret_id == secret.id).order_by(SecretVersion.number.desc()))
    return [{'id': version.id, 'number': version.number, 'created_at': version.created_at, 'username': username, 'changed_fields': version.changed_fields} for version, username in versions]


@router.post('/secrets/{secret_id}/restore')
def restore_version(secret_id: str, body: RestoreVersionWrite, request: Request, db: Db, user: CurrentUser):
    secret = access_secret(db, user, db.scalar(select(Secret).where(Secret.id == secret_id).with_for_update()), write=True)
    version = db.get(SecretVersion, body.version_id)
    if not version or version.secret_id != secret.id:
        raise HTTPException(404, 'Version not found')
    previous = version.snapshot
    destination = previous.get('collection_id')
    if destination and db.get(Collection, destination) is None:
        destination = None
    if destination != secret.collection_id:
        require_secret_owner(user, secret)
        if destination:
            access_collection(db, user, destination, write=True)
    from datetime import datetime
    for field in ('name', 'type', 'tags'):
        setattr(secret, field, previous[field])
    secret.collection_id = destination
    secret.meta = previous['metadata']
    secret.expires_at = datetime.fromisoformat(previous['expires_at']) if previous.get('expires_at') else None
    secret.weak_password = previous.get('weak_password', False)
    secret.ciphertext = encrypt_json(decrypt_json(version.ciphertext, secret.id), secret.id)
    secret.version += 1
    secret.updated_at = utcnow()
    add_version(db, secret, user, ['restored_from_version_' + str(version.number)])
    audit(db, request, user, 'secret_restored', secret.name)
    return serialize_secret(db, user, secret)


def serialize_collection(db: Session, user: User, collection: Collection) -> dict:
    return {'id': collection.id, 'name': collection.name, 'description': collection.description, 'icon': collection.icon,
            'color': collection.color, 'can_edit': collection_access(db, user, collection)[1], 'can_manage': user.role != 'viewer' and (user.role == 'admin' or collection.owner_id == user.id), 'owner_id': collection.owner_id}


@router.get('/collections')
def list_collections(db: Db, user: CurrentUser):
    return [serialize_collection(db, user, collection) for collection in db.scalars(select(Collection).order_by(Collection.name)) if collection_access(db, user, collection)[0]]


@router.post('/collections')
def new_collection(body: CollectionWrite, request: Request, db: Db, user: CurrentUser):
    if user.role == 'viewer':
        raise HTTPException(403, 'Editors or administrators can create collections')
    collection = Collection(owner_id=user.id, **body.model_dump())
    db.add(collection)
    db.flush()
    audit(db, request, user, 'collection_created', collection.name)
    return serialize_collection(db, user, collection)


@router.put('/collections/{collection_id}')
def update_collection(collection_id: str, body: CollectionWrite, request: Request, db: Db, user: CurrentUser):
    collection = access_collection(db, user, collection_id, write=True)
    for key, value in body.model_dump().items():
        setattr(collection, key, value)
    audit(db, request, user, 'collection_edited', collection.name)
    return serialize_collection(db, user, collection)


@router.delete('/collections/{collection_id}')
def remove_collection(collection_id: str, request: Request, db: Db, user: CurrentUser):
    collection = access_collection(db, user, collection_id, write=True)
    require_collection_owner(user, collection)
    audit(db, request, user, 'collection_deleted', collection.name)
    db.delete(collection)
    return {'deleted': True}


@router.get('/collections/{collection_id}/permissions')
def list_permissions(collection_id: str, db: Db, user: CurrentUser):
    collection = access_collection(db, user, collection_id)
    require_collection_owner(user, collection)
    return [{'user_id': grant.user_id, 'access': grant.access, 'can_copy': grant.can_copy} for grant in db.scalars(select(CollectionPermission).where(CollectionPermission.collection_id == collection_id))]


@router.put('/collections/{collection_id}/permissions')
def update_permissions(collection_id: str, body: list[GrantWrite], request: Request, db: Db, user: CurrentUser):
    collection = access_collection(db, user, collection_id, write=True)
    require_collection_owner(user, collection)
    if len(body) > 1000 or len({grant.user_id for grant in body}) != len(body):
        raise HTTPException(400, 'Invalid permission list')
    if any(db.get(User, grant.user_id) is None for grant in body):
        raise HTTPException(404, 'User not found')
    db.execute(delete(CollectionPermission).where(CollectionPermission.collection_id == collection_id))
    for grant in body:
        db.add(CollectionPermission(collection_id=collection_id, **grant.model_dump()))
    audit(db, request, user, 'permissions_changed', collection.name)
    return [grant.model_dump() for grant in body]


@router.get('/secrets/{secret_id}/shares')
def list_shares(secret_id: str, db: Db, user: CurrentUser):
    secret = access_secret(db, user, db.get(Secret, secret_id))
    require_secret_owner(user, secret)
    return [{'user_id': share.user_id, 'access': share.access, 'can_copy': share.can_copy} for share in db.scalars(select(SecretShare).where(SecretShare.secret_id == secret.id))]


@router.post('/secrets/{secret_id}/shares')
def share_secret(secret_id: str, body: GrantWrite, request: Request, db: Db, user: CurrentUser):
    secret = access_secret(db, user, db.get(Secret, secret_id), write=True)
    require_secret_owner(user, secret)
    if body.access == 'none':
        raise HTTPException(400, 'Shared access must be read or write')
    target = db.get(User, body.user_id)
    if target is None or target.disabled:
        raise HTTPException(404, 'User not found')
    share = db.get(SecretShare, (secret.id, body.user_id))
    if share:
        share.access, share.can_copy = body.access, body.can_copy
    else:
        db.add(SecretShare(secret_id=secret.id, **body.model_dump()))
    audit(db, request, user, 'secret_shared', secret.name)
    return body.model_dump()


@router.delete('/secrets/{secret_id}/shares/{user_id}')
def unshare_secret(secret_id: str, user_id: str, request: Request, db: Db, user: CurrentUser):
    secret = access_secret(db, user, db.get(Secret, secret_id), write=True)
    require_secret_owner(user, secret)
    share = db.get(SecretShare, (secret.id, user_id))
    if share:
        db.delete(share)
    audit(db, request, user, 'permissions_changed', secret.name)
    return {'deleted': True}


@router.get('/shared')
def shared_secrets(db: Db, user: CurrentUser):
    ids = set(db.scalars(select(SecretShare.secret_id).where(SecretShare.user_id == user.id)))
    return [serialize_secret(db, user, secret) for secret in visible_secrets(db, user) if secret.id in ids]


def serialize_audit(event: AuditEvent) -> dict:
    return {'id': event.id, 'created_at': event.created_at, 'username': event.username, 'action': event.action, 'target': event.target, 'ip': event.ip}


@router.get('/audit')
def audit_log(db: Db, user: CurrentUser, limit: int = 200):
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(max(1, min(limit, 1000)))
    if user.role != 'admin':
        query = query.where(AuditEvent.user_id == user.id)
    return [serialize_audit(event) for event in db.scalars(query)]


@router.get('/dashboard')
def dashboard(db: Db, user: CurrentUser):
    visible = visible_secrets(db, user)
    now = utcnow()
    expired = sum(bool(secret.expires_at and aware(secret.expires_at) < now) for secret in visible)
    expiring = sum(bool(secret.expires_at and now <= aware(secret.expires_at) <= now + timedelta(days=30)) for secret in visible)
    count_collections = sum(collection_access(db, user, collection)[0] for collection in db.scalars(select(Collection)))
    shared_ids = set(db.scalars(select(SecretShare.secret_id)))
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(12)
    if user.role != 'admin':
        query = query.where(AuditEvent.user_id == user.id)
    warnings = []
    if not user.totp_secret:
        warnings.append('Enable two-factor authentication')
    if expired:
        warnings.append(f'{expired} secrets have expired')
    if expiring:
        warnings.append(f'{expiring} secrets expire within 30 days')
    return {'counts': {'secrets': len(visible), 'collections': count_collections, 'ssh_keys': sum(secret.type == 'ssh_key' for secret in visible),
                       'wireguard': sum(secret.type == 'wireguard' for secret in visible), 'shared': sum(secret.id in shared_ids for secret in visible),
                       'expiring': expiring, 'expired': expired},
            'recent_activity': [serialize_audit(event) for event in db.scalars(query)], 'warnings': warnings}


@router.get('/users')
def list_users(db: Db, user: CurrentUser):
    query = select(User).order_by(User.username)
    if user.role != 'admin':
        query = query.where(User.disabled.is_(False))
    return [user_info(item) if user.role == 'admin' else {'id': item.id, 'username': item.username, 'role': item.role} for item in db.scalars(query)]


@router.post('/users')
def create_user(body: UserWrite, request: Request, db: Db, user: Admin):
    if db.scalar(select(User.id).where(User.username == body.username)):
        raise HTTPException(409, 'Username already exists')
    created = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(created)
    db.flush()
    audit(db, request, user, 'user_created', created.username)
    return user_info(created)


@router.put('/users/{user_id}')
def update_user(user_id: str, body: UserUpdate, request: Request, db: Db, user: Admin, verified: Annotated[User, Depends(require_reauth)]):
    if user.role != 'admin':
        raise HTTPException(403, 'Administrator access required')
    target = db.scalar(select(User).where(User.id == user_id).with_for_update())
    if target is None:
        raise HTTPException(404, 'User not found')
    demoting = target.role == 'admin' and (body.role and body.role != 'admin' or body.disabled is True)
    if demoting and db.scalar(select(func.count()).select_from(User).where(User.role == 'admin', User.disabled.is_(False))) <= 1:
        raise HTTPException(409, 'At least one active administrator is required')
    if body.role is not None:
        target.role = body.role
    if body.disabled is not None:
        target.disabled = body.disabled
    if body.password:
        target.password_hash = hash_password(body.password)
    db.execute(delete(AuthSession).where(AuthSession.user_id == target.id))
    audit(db, request, user, 'permissions_changed' if body.role else 'user_updated', target.username)
    return user_info(target)


SETTINGS_FIELDS = ('instance_name', 'app_url', 'lock_timeout', 'session_hours', 'backup_enabled', 'backup_hour', 'retention_daily', 'retention_weekly', 'retention_monthly')


@router.get('/settings')
def get_settings(db: Db, user: CurrentUser):
    settings = settings_row(db)
    return {field: getattr(settings, field) for field in SETTINGS_FIELDS}


@router.put('/settings')
def update_settings(body: SettingsWrite, request: Request, db: Db, user: Annotated[User, Depends(require_reauth)]):
    if user.role != 'admin':
        raise HTTPException(403, 'Administrator access required')
    settings = settings_row(db)
    for field, value in body.model_dump().items():
        setattr(settings, field, value)
    audit(db, request, user, 'settings_changed')
    return {field: getattr(settings, field) for field in SETTINGS_FIELDS}
