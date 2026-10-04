from datetime import timedelta

from sqlalchemy import select

from app.db import SessionLocal, utcnow
from app.models import SecretVersion, TemporaryLink


def test_crud_versions_restore_and_audit(admin):
    record = admin.create_secret()
    identity = record['id']
    assert 'data' not in record
    reveal = admin.post(f'/api/secrets/{identity}/reveal', {'action': 'copy'})
    assert reveal.status_code == 200
    assert reveal.json()['data']['password'] == 'Private-value!6f987de'
    edited = admin.put(f'/api/secrets/{identity}', {'name': 'Rotated password', 'type': 'login',
                       'metadata': record['metadata'], 'tags': record['tags'],
                       'data': {'username': 'service-account', 'password': 'Rotated-value!2026'}})
    assert edited.status_code == 200
    versions = admin.get(f'/api/secrets/{identity}/versions').json()
    assert len(versions) == 2
    first = next(item for item in versions if item['number'] == 1)
    assert 'ciphertext' not in str(versions)
    assert 'Private-value' not in str(versions)
    assert admin.post(f'/api/secrets/{identity}/restore', {'version_id': first['id']}).status_code == 200
    restored = admin.post(f'/api/secrets/{identity}/reveal', {'action': 'view'})
    assert restored.json()['data']['password'] == 'Private-value!6f987de'
    actions = {item['action'] for item in admin.get('/api/audit').json()}
    assert {'secret_created', 'secret_copied', 'secret_edited'} <= actions
    assert admin.delete(f'/api/secrets/{identity}').status_code in (200, 204)
    assert admin.get(f'/api/secrets/{identity}').status_code == 404
    with SessionLocal() as db:
        assert db.scalar(select(SecretVersion).where(SecretVersion.secret_id == identity)) is None


def test_collection_permissions_share_copy_restriction_and_revocation(admin, outsider):
    collection = admin.post('/api/collections', {'name': 'Infrastructure', 'description': 'Home services',
                            'icon': 'server', 'color': '#6366f1'}).json()
    record = admin.create_secret(collection_id=collection['id'])
    path = f"/api/secrets/{record['id']}"
    assert outsider.get('/api/secrets').json() == []
    assert outsider.get(path).status_code in (403, 404)
    assert outsider.post(path + '/reveal', {'action': 'view'}).status_code in (403, 404)
    permissions = [{'user_id': outsider.user_id, 'access': 'read', 'can_copy': False}]
    assert admin.put(f"/api/collections/{collection['id']}/permissions", permissions).status_code == 200
    assert outsider.get(path).status_code == 200
    assert outsider.post(path + '/reveal', {'action': 'view'}).status_code == 200
    assert outsider.post(path + '/reveal', {'action': 'copy'}).status_code == 403
    assert outsider.delete(path).status_code == 403
    assert outsider.post('/api/temporary-links', {'secret_id': record['id'], 'expires_minutes': 5,
                         'max_views': 1, 'allow_copy': True}).status_code == 403
    assert admin.put(f"/api/collections/{collection['id']}/permissions", []).status_code == 200
    assert outsider.get(path).status_code in (403, 404)
    assert admin.post(path + '/shares', {'user_id': outsider.user_id, 'access': 'read', 'can_copy': True}).status_code == 200
    assert len(outsider.get('/api/shared').json()) == 1
    assert outsider.post(path + '/reveal', {'action': 'copy'}).status_code == 200
    assert admin.delete(path + f'/shares/{outsider.user_id}').status_code in (200, 204)
    assert outsider.get('/api/shared').json() == []
    directory = outsider.get('/api/users')
    assert directory.status_code == 200
    assert 'password_hash' not in directory.text
    assert outsider.post('/api/users', {'username': 'forbidden', 'password': 'Forbidden-password!2026', 'role': 'admin'}).status_code == 403


def test_expiration_dashboard_and_private_metadata_scope(admin, outsider):
    admin.create_secret(name='Expired token', type='token', expires_at=(utcnow() - timedelta(days=1)).isoformat(),
                        data={'token': 'private-expired-token'})
    admin.create_secret(name='Expiring token', type='token', expires_at=(utcnow() + timedelta(days=2)).isoformat(), data={'token': 'expiring-token!value'})
    result = admin.get('/api/dashboard').json()
    assert result['counts']['expired'] == 1
    assert result['counts']['expiring'] >= 1
    assert outsider.get('/api/dashboard').json()['counts']['secrets'] == 0
    assert outsider.get('/api/audit').status_code in (200, 403)


def test_temporary_link_password_single_use_expiration_revoke_and_hashed_tokens(admin):
    record = admin.create_secret()
    payload = {'secret_id': record['id'], 'expires_minutes': 5, 'max_views': 1,
               'password': 'Temporary-link!password', 'allow_copy': False}
    result = admin.post('/api/temporary-links', payload)
    assert result.status_code in (200, 201)
    link = result.json()
    assert '#'+link['token'] in link['url']
    assert len(link['token']) >= 32
    with SessionLocal() as db:
        stored = db.get(TemporaryLink, link['id'])
        assert stored.token_hash != link['token']
        assert 'Temporary-link!password' not in stored.password_hash
    wrong = admin.post('/api/public/temporary', {'token': link['token'], 'password': 'wrong'})
    assert wrong.status_code == 410
    used = admin.post('/api/public/temporary', {'token': link['token'], 'password': payload['password']})
    assert used.status_code == 200
    assert used.json()['allow_copy'] is False
    assert admin.post('/api/public/temporary', {'token': link['token'], 'password': payload['password']}).status_code == 410
    expired = admin.post('/api/temporary-links', {**payload, 'password': None}).json()
    with SessionLocal() as db:
        db.get(TemporaryLink, expired['id']).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert admin.post('/api/public/temporary', {'token': expired['token']}).status_code == 410
    revoked = admin.post('/api/temporary-links', {**payload, 'password': None}).json()
    assert admin.delete('/api/temporary-links/' + revoked['id']).status_code in (200, 204)
    assert admin.post('/api/public/temporary', {'token': revoked['token']}).status_code == 410


def test_editor_cannot_grant_self_access_or_escalate_role(admin):
    from fastapi.testclient import TestClient
    from app.main import app
    from .conftest import API, PASSWORD
    user = admin.post('/api/users', {'username': 'editor', 'password': PASSWORD, 'role': 'editor'}).json()
    record = admin.create_secret()
    with TestClient(app) as client:
        editor = API(client)
        assert editor.login('editor').status_code == 200
        assert editor.put(f"/api/users/{user['id']}", {'role': 'admin'}).status_code == 403
        assert editor.post(f"/api/secrets/{record['id']}/shares", {'user_id': user['id'], 'access': 'write'}).status_code in (403, 404)
        own = editor.create_secret(name='Editor credential')
        assert editor.post(f"/api/secrets/{own['id']}/reveal", {'action': 'view'}).status_code == 200
        assert len(editor.get('/api/secrets').json()) == 1


def test_individual_write_share_duplicates_to_personal_without_collection_access(admin, outsider):
    from fastapi.testclient import TestClient
    from app.main import app
    from .conftest import API, PASSWORD
    collection = admin.post('/api/collections', {'name': 'Restricted infrastructure'}).json()
    source = admin.create_secret(collection_id=collection['id'])
    editor_user = admin.post('/api/users', {'username': 'shared-editor', 'password': PASSWORD, 'role': 'editor'}).json()
    source_path = f"/api/secrets/{source['id']}"
    for user_id in (editor_user['id'], outsider.user_id):
        assert admin.post(source_path + '/shares', {'user_id': user_id, 'access': 'write', 'can_copy': True}).status_code == 200
    with TestClient(app) as client:
        editor = API(client)
        assert editor.login('shared-editor').status_code == 200
        assert collection['id'] not in {row['id'] for row in editor.get('/api/collections').json()}
        duplicate = editor.post(source_path + '/duplicate', {})
        assert duplicate.status_code == 200
        record = duplicate.json()
        assert record['id'] != source['id']
        assert record['collection_id'] is None
        assert record['owner_id'] == editor_user['id']
        revealed = editor.post(f"/api/secrets/{record['id']}/reveal", {'action': 'view'})
        assert revealed.json()['data']['password'] == 'Private-value!6f987de'
        # A copy restriction must still apply independently of destination access.
        assert admin.post(source_path + '/shares', {'user_id': editor_user['id'], 'access': 'write', 'can_copy': False}).status_code == 200
        assert editor.post(source_path + '/duplicate', {}).status_code == 403
    assert outsider.post(source_path + '/duplicate', {}).status_code == 403
    assert admin.get(source_path).json()['collection_id'] == collection['id']


def test_one_time_link_concurrent_requests_only_one_consumes(admin):
    from concurrent.futures import ThreadPoolExecutor
    record = admin.create_secret()
    link = admin.post('/api/temporary-links', {'secret_id': record['id'], 'expires_minutes': 5,
                      'max_views': 1, 'allow_copy': True}).json()
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: admin.post('/api/public/temporary', {'token': link['token']}), range(2)))
    assert sorted(result.status_code for result in results) == [200, 410]
    with SessionLocal() as db:
        assert db.get(TemporaryLink, link['id']).views == 1


def test_temporary_copy_audit_password_copy_policy_and_live_permission_revocation(admin):
    from fastapi.testclient import TestClient
    from app.main import app
    from .conftest import API, PASSWORD
    record = admin.create_secret()
    denied = admin.post('/api/temporary-links', {'secret_id': record['id'], 'expires_minutes': 5,
                        'max_views': 1, 'allow_copy': False}).json()
    assert admin.post('/api/public/temporary', {'token': denied['token']}).status_code == 200
    assert admin.post('/api/public/temporary/copy', {'token': denied['token']}).status_code == 410
    allowed = admin.post('/api/temporary-links', {'secret_id': record['id'], 'expires_minutes': 5,
                         'max_views': 1, 'allow_copy': True, 'password': 'Temporary-copy!password'}).json()
    proof = {'token': allowed['token'], 'password': 'Temporary-copy!password'}
    assert admin.post('/api/public/temporary', proof).status_code == 200
    assert admin.post('/api/public/temporary/copy', {**proof, 'password': 'incorrect'}).status_code == 410
    assert admin.post('/api/public/temporary/copy', proof).json() == {'recorded': True}
    with SessionLocal() as db:
        assert db.get(TemporaryLink, allowed['id']).views == 1
    assert any(item['action'] == 'secret_copied' and item['username'] == 'temporary visitor'
               for item in admin.get('/api/audit').json())
    admin.reauth()
    user = admin.post('/api/users', {'username': 'delegate', 'password': PASSWORD, 'role': 'editor'}).json()
    assert admin.post(f"/api/secrets/{record['id']}/shares", {'user_id': user['id'], 'access': 'write', 'can_copy': True}).status_code == 200
    with TestClient(app) as client:
        editor = API(client)
        assert editor.login('delegate').status_code == 200
        delegated = editor.post('/api/temporary-links', {'secret_id': record['id'], 'expires_minutes': 5,
                                 'max_views': 5, 'allow_copy': True}).json()
        assert admin.post(f"/api/secrets/{record['id']}/shares", {'user_id': user['id'], 'access': 'write', 'can_copy': False}).status_code == 200
        assert admin.post('/api/public/temporary/copy', {'token': delegated['token']}).status_code == 410
        assert admin.post('/api/public/temporary', {'token': delegated['token']}).status_code == 410
        assert admin.post(f"/api/secrets/{record['id']}/shares", {'user_id': user['id'], 'access': 'write', 'can_copy': True}).status_code == 200
        assert admin.put(f"/api/users/{user['id']}", {'disabled': True}).status_code == 200
        assert admin.post('/api/public/temporary/copy', {'token': delegated['token']}).status_code == 410
        assert admin.post('/api/public/temporary', {'token': delegated['token']}).status_code == 410
    assert admin.delete('/api/temporary-links/' + allowed['id']).status_code == 200
    assert admin.post('/api/public/temporary/copy', proof).status_code == 410
