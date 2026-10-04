import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException
from . import auth, core
from .config import config
from .crypto import decrypt_json, encrypt_json, get_key, key_path
from .db import SessionLocal
from .models import AppSettings

logger = logging.getLogger('secrets_hub')


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    from .backup import recover_interrupted_restore
    recover_interrupted_restore()
    with SessionLocal() as db:
        settings = db.get(AppSettings, 1)
        if settings is None:
            raise RuntimeError('Database migrations are required')
        if settings.initialized:
            try:
                get_key()
            except (FileNotFoundError, RuntimeError):
                logger.error('{"event":"encryption_key_unavailable"}')
    from threading import Event, Thread
    from .backup import scheduler_loop
    stop = Event()
    worker = Thread(target=scheduler_loop, args=(stop,), daemon=True, name='backup-scheduler')
    worker.start()
    yield
    stop.set()
    worker.join(timeout=5)


app = FastAPI(title='Secrets Hub', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
operation_lock = asyncio.Lock()


@app.middleware('http')
async def security(request: Request, call_next):
    async def process_exclusively(validated_request: Request):
        async with operation_lock:
            if (key_path().parent / 'restore-journal.json').exists():
                return JSONResponse({'detail': 'Restore was interrupted. Restart Secrets Hub to finalize the encryption key'}, status_code=503)
            return await call_next(validated_request)

    try:
        handler = process_exclusively if request.url.path.startswith('/api/') else call_next
        response = await secured_request(request, handler)
    except Exception:
        logger.error('{"event":"operation_failed"}')
        response = JSONResponse({'detail': 'Operation failed'}, status_code=500)
    response.headers.update({
        'Cache-Control': 'no-store', 'Pragma': 'no-cache', 'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    })
    if config.secure_cookies:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response


async def secured_request(request: Request, call_next):
    if (key_path().parent / 'restore-journal.json').exists() and request.url.path.startswith('/api/'):
        return JSONResponse({'detail': 'Restore was interrupted. Restart Secrets Hub to finalize the encryption key'}, status_code=503)
    size_limit = 96 * 1024 * 1024 if request.url.path == '/api/backups/restore' else config.max_request_bytes
    try:
        claimed_length = int(request.headers.get('content-length', '0'))
    except ValueError:
        return JSONResponse({'detail': 'Invalid request'}, status_code=400)
    if claimed_length < 0 or claimed_length > size_limit:
        return JSONResponse({'detail': 'Request is too large'}, status_code=413)
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and request.url.path.startswith('/api/'):
        if request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'detail': 'Invalid request origin'}, status_code=403)
        origin = request.headers.get('origin')
        if origin:
            expected = {str(request.base_url).rstrip('/')}
            if config.public_url:
                expected.add(config.public_url)
            with SessionLocal() as db:
                settings = db.get(AppSettings, 1)
                if settings and settings.app_url:
                    expected.add(settings.app_url)
            if origin not in expected:
                return JSONResponse({'detail': 'Invalid request origin'}, status_code=403)
        with SessionLocal() as db:
            session = auth.lookup_session(db, request)
            provided = request.headers.get('x-csrf-token', '')
            if session is None and request.cookies.get(config.cookie_name):
                return JSONResponse({'detail': 'Authentication required'}, status_code=401)
            if session is None or not provided or not secrets.compare_digest(provided, session.csrf_token):
                return JSONResponse({'detail': 'CSRF verification failed'}, status_code=403)
        content_type = request.headers.get('content-type', '').split(';')[0]
        if content_type != 'application/json':
            return JSONResponse({'detail': 'JSON content type required'}, status_code=415)
        chunks, length = [], 0
        async for chunk in request.stream():
            length += len(chunk)
            if length > size_limit:
                return JSONResponse({'detail': 'Request is too large'}, status_code=413)
            chunks.append(chunk)
        request._body = b''.join(chunks)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse({'detail': 'Invalid input. Check required fields, lengths, and formats'}, status_code=422)


@app.exception_handler(IntegrityError)
async def constraint_error(request: Request, exc: IntegrityError):
    return JSONResponse({'detail': 'Operation conflicts with existing data'}, status_code=409)


@app.exception_handler(SQLAlchemyError)
async def database_error(request: Request, exc: SQLAlchemyError):
    logger.error('{"event":"database_operation_failed"}')
    return JSONResponse({'detail': 'Database operation failed'}, status_code=503)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    logger.error('{"event":"operation_failed"}')
    return JSONResponse({'detail': 'Operation failed'}, status_code=500)


@app.get('/health')
def health():
    from .backup import restore_in_progress
    if restore_in_progress or (key_path().parent / 'restore-journal.json').exists():
        return JSONResponse({'status': 'unavailable'}, status_code=503)
    try:
        with SessionLocal() as db:
            db.execute(text('SELECT 1'))
            settings = db.get(AppSettings, 1)
            if settings is None:
                return JSONResponse({'status': 'unavailable'}, status_code=503)
            from pathlib import Path
            probe = config.data_dir / ('.health-' + secrets.token_hex(8))
            probe.write_bytes(b'health')
            probe.unlink()
            if settings.initialized:
                if not secrets.compare_digest(key_path().read_bytes(), get_key()):
                    raise ValueError('Encryption unavailable')
                nonce = secrets.token_hex(8)
                if decrypt_json(encrypt_json({'probe': nonce}, 'health'), 'health').get('probe') != nonce:
                    raise ValueError('Encryption unavailable')
            return {'status': 'ok', 'database': 'ok', 'storage': 'ok', 'encryption': 'ok' if settings.initialized else 'setup_required'}
    except Exception:
        return JSONResponse({'status': 'unavailable'}, status_code=503)


app.include_router(auth.router)
app.include_router(core.router)
from .features import router as features_router
app.include_router(features_router)
