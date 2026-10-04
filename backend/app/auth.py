import hashlib
import secrets
from datetime import timedelta
from typing import Annotated
import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .config import config
from .crypto import decrypt_json, hash_password, verify_password, initialize_key, wrap_key, password_hasher
from .db import SessionLocal, aware, get_db, utcnow
from .models import AppSettings, AuditEvent, AuthSession, RateLimit, User
from .schemas import Credentials, PasswordProof, SetupWrite, StrictModel

router = APIRouter(prefix='/api')
DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host[:64] if request.client else 'unknown'


def audit_auth(db: Session, request: Request, user: User | None, action: str) -> None:
    db.add(AuditEvent(user_id=user.id if user else None, username=user.username if user else 'anonymous', action=action, target='', ip=client_ip(request)))


def settings_row(db: Session) -> AppSettings:
    row = db.get(AppSettings, 1)
    if row is None:
        raise HTTPException(503, 'Database migrations are required')
    return row


def rate_limit(db: Session, request: Request, key: str, limit: int = 10, minutes: int = 15) -> None:
    # Throttling runs before protected mutations; persist session activity independently.
    db.commit()
    digest = token_hash(client_ip(request) + ':' + key)
    now = utcnow()
    with SessionLocal() as limiter:
        row = limiter.scalar(select(RateLimit).where(RateLimit.key == digest).with_for_update())
        if row is None:
            try:
                with limiter.begin_nested():
                    row = RateLimit(key=digest, window_start=now, attempts=0)
                    limiter.add(row)
                    limiter.flush()
            except IntegrityError:
                row = limiter.scalar(select(RateLimit).where(RateLimit.key == digest).with_for_update())
        if row.blocked_until and aware(row.blocked_until) > now:
            limiter.commit()
            raise HTTPException(429, 'Too many attempts. Try again later', headers={'Retry-After': '900'})
        if aware(row.window_start) < now - timedelta(minutes=minutes):
            row.window_start, row.attempts, row.blocked_until = now, 0, None
        row.attempts += 1
        if row.attempts > limit:
            row.blocked_until = now + timedelta(minutes=minutes)
            limiter.commit()
            raise HTTPException(429, 'Too many attempts. Try again later', headers={'Retry-After': '900'})
        limiter.commit()


def check_credentials(db: Session, user: User | None, password: str, otp: str | None = None) -> bool:
    if user is None or user.disabled:
        verify_password(DUMMY_HASH, password)
        return False
    if not verify_password(user.password_hash, password):
        return False
    if user.totp_secret:
        if not otp:
            return False
        code = otp.strip().replace(' ', '').replace('-', '')
        if len(code) == 6 and code.isdigit():
            protected = decrypt_json(user.totp_secret, 'totp:' + user.id)
            seed = protected['secret']
            totp = pyotp.TOTP(seed)
            step = int(utcnow().timestamp()) // 30
            accepted = next((candidate for candidate in (step - 1, step, step + 1)
                             if candidate > user.totp_last_step and secrets.compare_digest(totp.at(candidate * 30), code)), None)
            if accepted is None:
                return False
            user.totp_last_step = accepted
        else:
            matched = next((item for item in user.recovery_codes if secrets.compare_digest(item, token_hash(code.lower()))), None)
            if matched is None:
                return False
            user.recovery_codes = [item for item in user.recovery_codes if item != matched]
    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    db.flush()
    return True


def lookup_session(db: Session, request: Request) -> AuthSession | None:
    token = request.cookies.get(config.cookie_name, '')
    if not token or len(token) > 200:
        return None
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(token)))
    if session is None or aware(session.expires_at) <= utcnow():
        return None
    return session


def session_for(db: Session, request: Request) -> AuthSession:
    session = lookup_session(db, request)
    if session is None or not session.user_id:
        raise HTTPException(401, 'Authentication required')
    return session


def require_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User:
    session = session_for(db, request)
    user = db.get(User, session.user_id)
    if user is None or user.disabled:
        raise HTTPException(401, 'Authentication required')
    timeout = settings_row(db).lock_timeout
    if timeout and aware(session.last_seen) < utcnow() - timedelta(minutes=timeout):
        session.locked = True
        session.reauth_until = None
        db.commit()
    if session.locked:
        raise HTTPException(423, 'Secrets Hub Locked')
    session.last_seen = utcnow()
    request.state.auth_session = session
    return user


def require_admin(user: Annotated[User, Depends(require_user)]) -> User:
    if user.role != 'admin':
        raise HTTPException(403, 'Administrator access required')
    return user


def require_reauth(request: Request, user: Annotated[User, Depends(require_user)], db: Annotated[Session, Depends(get_db)]) -> User:
    session = session_for(db, request)
    if not session.reauth_until or aware(session.reauth_until) <= utcnow():
        raise HTTPException(428, 'Please confirm your password again')
    return user


def user_info(user: User | None) -> dict | None:
    return {'id': user.id, 'username': user.username, 'role': user.role, 'totp_enabled': bool(user.totp_secret), 'disabled': user.disabled} if user else None


def session_response(db: Session, session: AuthSession) -> dict:
    settings = settings_row(db)
    user = db.get(User, session.user_id) if session.user_id else None
    timeout = settings.lock_timeout
    locked = bool(user and (session.locked or timeout and aware(session.last_seen) < utcnow() - timedelta(minutes=timeout)))
    return {'user': user_info(user if user and not user.disabled else None), 'csrf_token': session.csrf_token,
            'settings': {'instance_name': settings.instance_name, 'app_url': settings.app_url, 'lock_timeout': timeout},
            'setup_required': not settings.initialized, 'locked': locked}


def issue_session(db: Session, response: Response, user: User | None = None) -> AuthSession:
    raw = secrets.token_urlsafe(48)
    lifetime = settings_row(db).session_hours if user else 1
    session = AuthSession(token_hash=token_hash(raw), csrf_token=secrets.token_urlsafe(32),
                          user_id=user.id if user else None, expires_at=utcnow() + timedelta(hours=lifetime), last_seen=utcnow())
    db.add(session)
    db.flush()
    response.set_cookie(config.cookie_name, raw, httponly=True, secure=config.secure_cookies, samesite='strict',
                        max_age=lifetime * 3600, path='/')
    return session


@router.get('/auth/session')
def get_session(request: Request, response: Response, db: Annotated[Session, Depends(get_db)]):
    session = lookup_session(db, request)
    if session is None:
        rate_limit(db, request, 'session:create', limit=100)
        db.execute(delete(AuthSession).where(AuthSession.expires_at <= utcnow()))
        session = issue_session(db, response)
    return session_response(db, session)


@router.post('/setup')
def setup(body: SetupWrite, request: Request, response: Response, db: Annotated[Session, Depends(get_db)]):
    settings = db.scalar(select(AppSettings).where(AppSettings.id == 1).with_for_update())
    if settings is None:
        raise HTTPException(503, 'Database migrations are required')
    if settings.initialized:
        raise HTTPException(409, 'Secrets Hub is already configured')
    initialize_key()
    recovery_key = secrets.token_urlsafe(32)
    settings.master_wrap = wrap_key(body.master_password, 'master-key')
    settings.recovery_wrap = wrap_key(recovery_key, 'recovery-key')
    settings.instance_name, settings.app_url, settings.initialized = body.instance_name, body.app_url, True
    user = User(username=body.username, password_hash=hash_password(body.password), role='admin')
    db.add(user)
    db.flush()
    old = lookup_session(db, request)
    if old:
        db.delete(old)
    session = issue_session(db, response, user)
    audit_auth(db, request, user, 'setup_completed')
    kit = {'format': 'Secrets Hub Recovery Kit v1', 'instance_name': settings.instance_name, 'username': user.username,
           'recovery_key': recovery_key, 'instructions': 'Keep offline. The key resets administrator access and recovers the encryption key using the database. Database backups are also required.'}
    return {**session_response(db, session), 'recovery_key': recovery_key, 'recovery_kit': kit}


@router.post('/auth/login')
def login(body: Credentials, request: Request, response: Response, db: Annotated[Session, Depends(get_db)]):
    if not settings_row(db).initialized:
        raise HTTPException(409, 'Setup required')
    rate_limit(db, request, 'login:ip', limit=40)
    rate_limit(db, request, 'login:' + body.username.lower())
    user = db.scalar(select(User).where(User.username == body.username).with_for_update())
    if not check_credentials(db, user, body.password, body.otp):
        audit_auth(db, request, None, 'failed_login')
        db.commit()
        raise HTTPException(401, 'Invalid credentials or verification code')
    old = lookup_session(db, request)
    if old:
        db.delete(old)
    session = issue_session(db, response, user)
    audit_auth(db, request, user, 'login')
    return session_response(db, session)


class LogoutWrite(StrictModel):
    all_devices: bool = False


@router.post('/auth/logout')
def logout(body: LogoutWrite, request: Request, response: Response, db: Annotated[Session, Depends(get_db)]):
    session = session_for(db, request)
    user = db.get(User, session.user_id)
    if body.all_devices:
        db.execute(delete(AuthSession).where(AuthSession.user_id == session.user_id))
    else:
        db.delete(session)
    audit_auth(db, request, user, 'logout_all_devices' if body.all_devices else 'logout')
    response.delete_cookie(config.cookie_name, path='/', secure=config.secure_cookies, httponly=True, samesite='strict')
    return {'logged_out': True}


@router.post('/auth/lock')
def lock(request: Request, db: Annotated[Session, Depends(get_db)]):
    session = session_for(db, request)
    session.locked = True
    session.reauth_until = None
    return {'locked': True}


@router.post('/auth/unlock')
def unlock(body: PasswordProof, request: Request, db: Annotated[Session, Depends(get_db)]):
    session = session_for(db, request)
    rate_limit(db, request, 'unlock:' + str(session.user_id))
    user = db.scalar(select(User).where(User.id == session.user_id).with_for_update())
    if not check_credentials(db, user, body.password, body.otp):
        audit_auth(db, request, user, 'failed_unlock')
        db.commit()
        raise HTTPException(401, 'Invalid credentials or verification code')
    session.locked, session.last_seen = False, utcnow()
    audit_auth(db, request, user, 'unlocked')
    return session_response(db, session)


@router.post('/auth/reauth')
def reauth(body: PasswordProof, request: Request, db: Annotated[Session, Depends(get_db)], user: Annotated[User, Depends(require_user)]):
    rate_limit(db, request, 'reauth:' + user.id)
    locked_user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if not check_credentials(db, locked_user, body.password, body.otp):
        audit_auth(db, request, user, 'failed_reauth')
        db.commit()
        raise HTTPException(401, 'Invalid credentials or verification code')
    session = session_for(db, request)
    session.reauth_until = utcnow() + timedelta(minutes=5)
    audit_auth(db, request, user, 'reauthenticated')
    return {'verified': True, 'expires_at': session.reauth_until}


class ActivityWrite(StrictModel):
    pass


@router.post('/auth/activity')
def activity(body: ActivityWrite, user: Annotated[User, Depends(require_user)]):
    return {'active': True}
