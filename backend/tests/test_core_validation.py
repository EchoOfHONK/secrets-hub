from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from app import crypto
from app.auth import token_hash
from app.crypto import key_path
from app.db import SessionLocal, utcnow
from app.models import AppSettings, AuthSession, Secret
from .conftest import PASSWORD


def certificate_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'debian.home')])
    expiration = utcnow().replace(microsecond=0) + timedelta(days=90)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(utcnow() - timedelta(days=1)).not_valid_after(expiration)
                   .sign(key, hashes.SHA256()))
    data = {'certificate': certificate.public_bytes(serialization.Encoding.PEM).decode(),
            'private_key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()).decode()}
    return data, expiration


def test_certificate_validation_derives_expiration_and_rejects_mismatched_private_key(admin):
    data, expiration = certificate_pair()
    result = admin.post('/api/secrets', {'name': 'TLS certificate', 'type': 'certificate',
                         'metadata': {'hostname': 'debian.home'}, 'data': data})
    assert result.status_code == 200
    value = result.json()
    assert value['expires_at'].replace('Z', '+00:00') == expiration.isoformat()
    assert value['metadata']['issuer'] == 'CN=debian.home'
    assert 'PRIVATE KEY' not in result.text
    other, _ = certificate_pair()
    invalid = admin.post('/api/secrets', {'name': 'Invalid TLS', 'type': 'certificate',
                          'data': {**data, 'private_key': other['private_key']}})
    assert invalid.status_code == 400
    assert 'PRIVATE KEY' not in invalid.text
    assert len(admin.get('/api/secrets').json()) == 1


def test_corrupt_ciphertext_api_does_not_log_raw_material(admin, caplog):
    secret = admin.create_secret()
    marker = 'sensitive-corrupt-record-sentinel'
    with SessionLocal() as db:
        db.get(Secret, secret['id']).ciphertext = marker
        db.commit()
    result = admin.post(f"/api/secrets/{secret['id']}/reveal", {'action': 'view'})
    assert result.status_code == 500
    assert marker not in result.text
    assert marker not in caplog.text
    assert 'Traceback' not in caplog.text


def test_server_enforces_idle_timeout_and_never_lock_option(admin):
    token = admin.client.cookies.get('secrets_hub_session')
    with SessionLocal() as db:
        session = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(token)))
        session.last_seen = utcnow() - timedelta(minutes=6)
        db.commit()
    assert admin.refresh()['locked'] is True
    assert admin.get('/api/secrets').status_code == 423
    assert admin.post('/api/auth/unlock', {'password': PASSWORD}).status_code == 200
    with SessionLocal() as db:
        db.get(AppSettings, 1).lock_timeout = 0
        session = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(token)))
        session.last_seen = utcnow() - timedelta(hours=1)
        db.commit()
    assert admin.get('/api/secrets').status_code == 200


def test_last_administrator_and_settings_identity_proof_validation(admin):
    me = admin.refresh()['user']['id']
    assert admin.put(f'/api/users/{me}', {'role': 'viewer'}).status_code == 428
    admin.reauth()
    assert admin.put(f'/api/users/{me}', {'role': 'viewer'}).status_code == 409
    assert admin.put(f'/api/users/{me}', {'disabled': True}).status_code == 409
    settings = admin.get('/api/settings').json()
    forged = admin.put('/api/settings', {**settings, 'app_url': 'javascript:alert(1)'})
    assert forged.status_code == 422
    value = admin.put('/api/settings', {**settings, 'instance_name': 'Updated vault', 'lock_timeout': 15})
    assert value.status_code == 200
    assert admin.refresh()['settings']['instance_name'] == 'Updated vault'


def test_recovery_rehydrates_lost_master_key_and_revokes_sessions(admin):
    secret = admin.create_secret()
    key_path().unlink()
    crypto._key = None
    assert admin.get('/health').status_code == 503
    response = admin.post('/api/auth/recover', {'username': 'admin', 'recovery_key': admin.recovery_key,
                          'new_password': 'Recovered!2026-strong-password'})
    assert response.status_code == 200
    assert key_path().stat().st_mode & 0o777 == 0o600
    assert admin.get('/api/secrets').status_code == 401
    admin.refresh()
    assert admin.login(password='Recovered!2026-strong-password').status_code == 200
    reveal = admin.post(f"/api/secrets/{secret['id']}/reveal", {'action': 'view'})
    assert reveal.status_code == 200
    assert reveal.json()['data']['password'] == 'Private-value!6f987de'
    assert admin.get('/health').status_code == 200


def test_delegated_editor_cannot_move_restore_or_delegate_owner_secret(admin):
    from fastapi.testclient import TestClient
    from app.main import app
    from .conftest import API
    collection_a = admin.post('/api/collections', {'name': 'Granted collection'}).json()
    collection_b = admin.post('/api/collections', {'name': 'Private collection'}).json()
    editor_info = admin.post('/api/users', {'username': 'limited-editor', 'password': PASSWORD, 'role': 'editor'}).json()
    secret = admin.create_secret(collection_id=collection_b['id'])
    first = admin.get(f"/api/secrets/{secret['id']}/versions").json()[0]
    payload = {'name': secret['name'], 'type': 'login', 'collection_id': collection_a['id'],
               'metadata': secret['metadata'], 'tags': secret['tags'], 'data': {'password': 'Changed-owner-password!'}}
    assert admin.put(f"/api/secrets/{secret['id']}", payload).status_code == 200
    assert admin.put(f"/api/collections/{collection_a['id']}/permissions", [
        {'user_id': editor_info['id'], 'access': 'write', 'can_copy': False}]).status_code == 200
    with TestClient(app) as client:
        editor = API(client)
        assert editor.login('limited-editor').status_code == 200
        own_collection = editor.post('/api/collections', {'name': 'Editor personal collection'}).json()
        assert editor.get(f"/api/secrets/{secret['id']}").json()['can_share'] is False
        granted = next(item for item in editor.get('/api/collections').json() if item['id'] == collection_a['id'])
        assert granted['can_edit'] is True and granted['can_manage'] is False
        moved = editor.put(f"/api/secrets/{secret['id']}", {**payload, 'collection_id': own_collection['id']})
        assert moved.status_code == 403
        restored = editor.post(f"/api/secrets/{secret['id']}/restore", {'version_id': first['id']})
        assert restored.status_code == 403
        assert editor.put(f"/api/collections/{collection_a['id']}/permissions", []).status_code == 403
        assert editor.post(f"/api/secrets/{secret['id']}/reveal", {'action': 'copy'}).status_code == 403
        edited = editor.put(f"/api/secrets/{secret['id']}", {**payload, 'data': {'password': 'Editor-rotation!2026'}})
        assert edited.status_code == 200
    final = admin.get(f"/api/secrets/{secret['id']}").json()
    assert final['owner_id'] == secret['owner_id']
    assert final['collection_id'] == collection_a['id']


def test_legacy_note_and_csv_metadata_remain_visible_after_import(admin):
    import json
    note = admin.post('/api/import', {'format': 'json', 'content': json.dumps([
        {'name': 'Legacy secure note', 'type': 'note', 'data': {'text': 'Private imported note text'}}])})
    assert note.status_code == 200
    csv = admin.post('/api/import', {'format': 'csv', 'content': 'name,type,username,password\nImported account,login,alice,Private-password!2026\n'})
    assert csv.status_code == 200
    for record in admin.get('/api/secrets').json():
        value = admin.post(f"/api/secrets/{record['id']}/reveal", {'action': 'view'}).json()['data']
        if record['type'] == 'note':
            assert value['content'] == 'Private imported note text'
        else:
            assert value['username'] == 'alice'


def test_expired_cookie_mutation_requests_authentication_instead_of_csrf_error(admin):
    secret = admin.create_secret()
    cookie = admin.client.cookies.get('secrets_hub_session')
    with SessionLocal() as db:
        session = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(cookie)))
        session.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    response = admin.post(f"/api/secrets/{secret['id']}/reveal", {'action': 'view'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Authentication required'}
    admin.refresh()
    assert admin.login().status_code == 200
    assert admin.post(f"/api/secrets/{secret['id']}/reveal", {'action': 'view'}).status_code == 200


def test_slow_upload_body_does_not_block_other_api_requests(admin):
    import asyncio
    import httpx
    from app.main import app

    async def exercise():
        started, release = asyncio.Event(), asyncio.Event()

        async def slow_body():
            yield b'{"name":'
            started.set()
            await release.wait()
            yield b'"Slow upload collection"}'

        cookies = dict(admin.client.cookies)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://testserver', cookies=cookies) as client:
            upload = asyncio.create_task(client.post('/api/collections', content=slow_body(),
                    headers={'Content-Type': 'application/json', 'Origin': 'http://testserver',
                             'X-CSRF-Token': admin.csrf}))
            try:
                await asyncio.wait_for(started.wait(), timeout=2)
                response = await asyncio.wait_for(client.get('/api/auth/session'), timeout=2)
                assert response.status_code == 200
                assert response.json()['user']['username'] == 'admin'
                assert not upload.done()
            finally:
                release.set()
            assert (await upload).status_code == 200

    asyncio.run(exercise())
