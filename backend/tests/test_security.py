import hashlib
from datetime import timedelta

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import inspect, select

from app.crypto import decrypt_json, encrypt_json, hash_password, key_path, verify_password
from app.db import SessionLocal, utcnow
from app.models import AuditEvent, AuthSession, Secret, User
from .conftest import PASSWORD


def test_initial_setup_is_once_only_and_password_is_argon2id(admin):
    result = admin.post('/api/setup', {'username': 'attacker', 'password': PASSWORD,
                        'master_password': PASSWORD, 'instance_name': 'Changed', 'app_url': 'http://testserver'})
    assert result.status_code == 409
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == 'admin'))
        assert user.password_hash.startswith('$argon2id$')
        assert PASSWORD not in user.password_hash
        assert verify_password(user.password_hash, PASSWORD)
    assert key_path().stat().st_mode & 0o777 == 0o600


def test_encryption_random_nonce_and_associated_record_authentication(admin):
    value = {'password': 'An unindexed private value'}
    first = encrypt_json(value, 'secret-a')
    second = encrypt_json(value, 'secret-a')
    assert first != second
    assert 'private value' not in first
    assert decrypt_json(first, 'secret-a') == value
    with pytest.raises(InvalidTag):
        decrypt_json(first, 'secret-b')
    with pytest.raises(Exception):
        decrypt_json(first[:-3] + 'ABC', 'secret-a')
    assert not verify_password(hash_password(PASSWORD), 'wrong')


def test_secret_values_do_not_leak_in_lists_search_audit_or_health(admin):
    value = 'sensitive-sentinel-4ad9ce-secret'
    record = admin.create_secret(data={'password': value})
    for path in ('/api/secrets', f"/api/secrets/{record['id']}", '/api/dashboard', '/api/audit', '/api/security', '/health'):
        result = admin.get(path)
        assert result.status_code == 200
        assert value not in result.text
    assert admin.get('/api/secrets', params={'search': value}).json() == []
    assert len(admin.get('/api/secrets', params={'search': 'debian.home'}).json()) == 1
    with SessionLocal() as db:
        stored = db.get(Secret, record['id'])
        assert 'ciphertext' in inspect(stored).unloaded
        assert value not in stored.ciphertext
        assert all(value not in str(event.__dict__) for event in db.scalars(select(AuditEvent)))


def test_csrf_origin_and_secure_headers(admin):
    result = admin.client.post('/api/collections', json={'name': 'Forged'})
    assert result.status_code == 403
    result = admin.post('/api/collections', {'name': 'Forged'}, headers={'Origin': 'https://evil.example'})
    assert result.status_code == 403
    result = admin.post('/api/collections', {'name': 'Forged'}, headers={'X-CSRF-Token': 'incorrect'})
    assert result.status_code == 403
    result = admin.get('/api/auth/session')
    assert result.headers['x-content-type-options'] == 'nosniff'
    assert "frame-ancestors 'none'" in result.headers['content-security-policy']
    assert result.headers['cache-control'] == 'no-store'
    cookie = result.headers.get('set-cookie', '')
    # Login must issue a new cookie with HttpOnly and SameSite protection.
    assert admin.post('/api/auth/logout', {'all_devices': False}).status_code == 200
    admin.refresh()
    login = admin.login()
    assert 'httponly' in login.headers['set-cookie'].lower()
    assert 'samesite=strict' in login.headers['set-cookie'].lower()


def test_no_raw_input_in_validation_errors(admin):
    marker = 'private-validation-sentinel'
    response = admin.post('/api/secrets', {'name': 'Invalid', 'type': marker, 'data': {'password': marker}})
    assert response.status_code in (400, 422)
    assert marker not in response.text


def test_bruteforce_lockout_is_persistent(admin):
    assert admin.post('/api/auth/logout', {'all_devices': False}).status_code == 200
    admin.refresh()
    responses = [admin.login(password='Wrong-password!') for _ in range(12)]
    assert any(result.status_code == 429 for result in responses)
    assert all(result.status_code in (401, 429) for result in responses)
    assert admin.login().status_code == 429
    # Resetting the browser session cannot reset the database limiter.
    admin.client.cookies.clear()
    admin.refresh()
    assert admin.login().status_code == 429


def test_logout_all_sessions_and_server_expiration(admin):
    from fastapi.testclient import TestClient
    from app.main import app
    from .conftest import API
    with TestClient(app) as client:
        second = API(client)
        assert second.login().status_code == 200
        assert admin.post('/api/auth/logout', {'all_devices': True}).status_code == 200
        assert second.get('/api/secrets').status_code == 401
    admin.refresh()
    assert admin.login().status_code == 200
    token = admin.client.cookies.get('secrets_hub_session')
    with SessionLocal() as db:
        session = db.scalar(select(AuthSession).where(AuthSession.token_hash == hashlib.sha256(token.encode()).hexdigest()))
        session.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert admin.get('/api/secrets').status_code == 401


def test_lock_blocks_reads_until_password_unlock(admin):
    admin.create_secret()
    assert admin.post('/api/auth/lock', {}).status_code == 200
    assert admin.get('/api/secrets').status_code in (401, 423)
    assert admin.post('/api/auth/unlock', {'password': 'wrong'}).status_code == 401
    assert admin.post('/api/auth/unlock', {'password': PASSWORD}).status_code == 200
    assert admin.get('/api/secrets').status_code == 200


def test_export_requires_reauth_and_respects_no_copy_grants(admin, outsider):
    record = admin.create_secret()
    assert admin.post('/api/export', {'format': 'json'}).status_code == 428
    admin.reauth()
    assert admin.post(f"/api/secrets/{record['id']}/shares", {'user_id': outsider.user_id,
                      'access': 'read', 'can_copy': False}).status_code == 200
    outsider.reauth()
    exported = outsider.post('/api/export', {'format': 'json'})
    assert exported.status_code == 200
    assert 'Private-value!6f987de' not in exported.text
    public_metadata = admin.post('/api/export', {'format': 'csv'})
    assert public_metadata.status_code == 200
    assert 'Private-value!6f987de' not in public_metadata.text
    assert admin.post('/api/export', {'format': 'json'}).json()['secrets'][0]['data']['password'] == 'Private-value!6f987de'
    import csv
    import io
    admin.create_secret(name='=HYPERLINK("https://example.com")',
                        metadata={'username': '\t=2+2', 'hostname': '@SUM(1)', 'service': '\rharmless service'})
    guarded = admin.post('/api/export', {'format': 'csv'})
    assert guarded.status_code == 200
    rows = list(csv.DictReader(io.StringIO(guarded.text)))
    dangerous = next(row for row in rows if 'HYPERLINK' in row['name'])
    assert dangerous['name'].startswith("'")
    assert dangerous['username'].startswith("'")
    assert dangerous['hostname'].startswith("'")
    assert dangerous['service'].startswith("'")


def test_file_limit_plaintext_absence_and_reveal(admin):
    import base64
    binary = b'sensitive-file-content\x00\x01'
    record = admin.create_secret(name='Recovery codes file', type='file', metadata={}, data={
              'filename': 'codes.txt', 'content_type': 'text/plain', 'content_base64': base64.b64encode(binary).decode()})
    assert 'sensitive-file-content' not in admin.get('/api/secrets').text
    result = admin.post(f"/api/secrets/{record['id']}/reveal", {'action': 'view'})
    assert base64.b64decode(result.json()['data']['content_base64']) == binary
    oversized = admin.post('/api/secrets', {'name': 'Oversized', 'type': 'file', 'data': {
                           'filename': 'oversized.bin', 'content_type': 'application/octet-stream',
                           'content_base64': base64.b64encode(b'a' * (2 * 1024 * 1024 + 1)).decode()}})
    assert oversized.status_code in (400, 422)
    assert len(admin.get('/api/secrets').json()) == 1
