import base64
import json
from datetime import timedelta

import pyotp
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from sqlalchemy import select

from app import backup
from app.crypto import decrypt_json
from app.db import SessionLocal, utcnow
from app.formats import generate_ssh, parse_env, parse_ssh, parse_wireguard, render_wireguard
from app.models import BackupRecord, User
from .conftest import PASSWORD


def wireguard_config():
    private = x25519.X25519PrivateKey.generate()
    peer = x25519.X25519PrivateKey.generate().public_key()
    key = base64.b64encode(private.private_bytes(serialization.Encoding.Raw,
                          serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode()
    public = base64.b64encode(peer.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return f'[Interface]\nPrivateKey = {key}\nAddress = 10.20.0.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = {public}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n'


def test_wireguard_import_parse_qr_export_duplicate_and_invalid_inputs(admin):
    content = wireguard_config()
    parsed = parse_wireguard(content)
    assert parsed['endpoint'] == 'vpn.example.com:51820'
    assert 'PrivateKey = ' in render_wireguard(parsed)
    result = admin.post('/api/import', {'format': 'wireguard', 'name': 'Home VPN', 'content': content})
    assert result.status_code == 200 and result.json()['created'] == 1
    record = admin.get('/api/secrets', params={'type': 'wireguard'}).json()[0]
    shown = admin.post(f"/api/wireguard/{record['id']}/config", {'action': 'view'})
    assert shown.status_code == 200
    assert shown.json()['qr_data_url'].startswith('data:image/png;base64,')
    assert 'PrivateKey = ' in shown.json()['config']
    # Export requires fresh identity proof even with an authenticated session.
    assert admin.post(f"/api/wireguard/{record['id']}/config", {'action': 'export'}).status_code == 428
    admin.reauth()
    assert admin.post(f"/api/wireguard/{record['id']}/config", {'action': 'export'}).status_code == 200
    duplicate = admin.post(f"/api/secrets/{record['id']}/duplicate", {})
    assert duplicate.status_code in (200, 201)
    assert duplicate.json()['id'] != record['id']
    for bad in ('[Interface]\nPrivateKey=invalid\n', content + '\nPostUp = rm -rf /\n'):
        with pytest.raises(ValueError):
            parse_wireguard(bad)


def test_wireguard_full_config_edit_canonicalizes_endpoint_metadata(admin):
    content = wireguard_config()
    assert admin.post('/api/import', {'format': 'wireguard', 'name': 'Home VPN', 'content': content}).status_code == 200
    record = admin.get('/api/secrets', params={'type': 'wireguard'}).json()[0]
    path = f"/api/secrets/{record['id']}"
    old_data = admin.post(path + '/reveal', {'action': 'view'}).json()['data']
    new_endpoint = 'rotated-vpn.example.com:51821'
    edited = admin.put(path, {'name': record['name'], 'type': 'wireguard', 'tags': record['tags'],
                             'metadata': record['metadata'],
                             'data': {**old_data, 'config': content.replace('vpn.example.com:51820', new_endpoint)}})
    assert edited.status_code == 200
    assert edited.json()['metadata']['endpoint'] == new_endpoint
    assert edited.json()['metadata']['hostname'] == new_endpoint
    assert admin.get(path).json()['metadata']['endpoint'] == new_endpoint
    revealed = admin.post(path + '/reveal', {'action': 'view'}).json()['data']
    assert revealed['endpoint'] == new_endpoint
    assert revealed['private_key'] == old_data['private_key']


def test_ssh_generation_private_key_protection_fingerprint_and_import(admin):
    result = admin.post('/api/ssh/generate', {'name': 'Debian SSH', 'host': 'debian.home',
                        'username': 'alice', 'passphrase': 'Protected-key!passphrase',
                        'tags': ['critical'], 'metadata': {'notes': 'First device key'},
                        'expires_at': (utcnow() + timedelta(days=365)).isoformat()})
    assert result.status_code in (200, 201), result.text
    record = result.json()
    assert record['type'] == 'ssh_key'
    assert record['tags'] == ['critical']
    assert record['metadata']['notes'] == 'First device key'
    assert record['metadata']['hostname'] == 'debian.home'
    assert record['expires_at'] is not None
    assert 'PRIVATE KEY' not in json.dumps(record)
    data = admin.post(f"/api/secrets/{record['id']}/reveal", {'action': 'view'}).json()['data']
    assert data['fingerprint'].startswith('SHA256:')
    assert data['public_key'].startswith('ssh-ed25519 ')
    loaded = serialization.load_ssh_private_key(data['private_key'].encode(), b'Protected-key!passphrase')
    assert loaded.public_key().public_bytes(serialization.Encoding.OpenSSH,
           serialization.PublicFormat.OpenSSH).decode() == data['public_key']
    generated = generate_ssh()
    assert parse_ssh(generated['private_key'])['fingerprint'] == generated['fingerprint']
    imported = admin.post('/api/import', {'format': 'ssh', 'name': 'Imported SSH', 'content': generated['private_key']})
    assert imported.status_code == 200 and imported.json()['created'] == 1
    assert len(admin.get('/api/secrets', params={'type': 'ssh_key'}).json()) == 2


def test_env_json_csv_import_and_all_or_nothing_transaction(admin):
    assert parse_env('TOKEN="private token"\nexport PORT=443\n')['TOKEN'] == 'private token'
    env = admin.post('/api/import', {'format': 'env', 'name': 'Application env',
                     'content': 'API_TOKEN=private-env-sentinel\nPORT=443\n'})
    assert env.status_code == 200 and env.json()['created'] == 1
    record = admin.get('/api/secrets', params={'type': 'environment'}).json()[0]
    assert 'private-env-sentinel' not in json.dumps(record)
    items = [{'name': 'Imported note', 'type': 'note', 'data': {'text': 'private JSON content'}},
             {'name': 'Invalid type', 'type': 'not-a-secret-type', 'data': {'text': 'invalid'}}]
    before = len(admin.get('/api/secrets').json())
    invalid = admin.post('/api/import', {'format': 'json', 'content': json.dumps(items)})
    assert invalid.status_code in (400, 422)
    assert len(admin.get('/api/secrets').json()) == before
    valid = admin.post('/api/import', {'format': 'json', 'content': json.dumps(items[:1])})
    assert valid.status_code == 200 and valid.json()['created'] == 1
    csv = admin.post('/api/import', {'format': 'csv', 'content': 'name,type,password,username\nCSV account,login,private-csv-password,alice\n'})
    assert csv.status_code == 200 and csv.json()['created'] == 1


def test_generators_use_requested_policy_and_reject_empty_alphabet(admin):
    numbers = admin.post('/api/generate', {'kind': 'password', 'length': 40, 'uppercase': False,
                          'lowercase': False, 'numbers': True, 'symbols': False, 'exclude_ambiguous': True})
    assert numbers.status_code == 200
    assert len(numbers.json()['value']) == 40
    assert set(numbers.json()['value']) <= set('23456789')
    empty = admin.post('/api/generate', {'kind': 'password', 'length': 40, 'uppercase': False,
                       'lowercase': False, 'numbers': False, 'symbols': False})
    assert empty.status_code in (400, 422)
    phrase = admin.post('/api/generate', {'kind': 'passphrase', 'words': 8})
    assert phrase.status_code == 200
    assert len(phrase.json()['value'].split('-')) == 8
    first = admin.post('/api/generate', {'kind': 'token', 'length': 32}).json()['value']
    second = admin.post('/api/generate', {'kind': 'token', 'length': 32}).json()['value']
    assert first != second


def test_totp_recovery_codes_replay_and_global_recovery(admin):
    assert admin.post('/api/auth/totp/setup', {}).status_code == 428
    admin.reauth()
    pending = admin.post('/api/auth/totp/setup', {})
    assert pending.status_code == 200
    assert pending.json()['qr_data_url'].startswith('data:image/png;base64,')
    code = pyotp.TOTP(pending.json()['secret']).now()
    enabled = admin.post('/api/auth/totp/enable', {'code': code})
    assert enabled.status_code == 200
    codes = enabled.json()['recovery_codes']
    assert len(codes) >= 8
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == 'admin'))
        assert codes[0] not in str(user.recovery_codes)
        assert pending.json()['secret'] not in user.totp_secret
        assert decrypt_json(user.totp_secret, 'totp:' + user.id)['secret'] == pending.json()['secret']
    assert admin.post('/api/auth/logout', {'all_devices': False}).status_code == 200
    admin.refresh()
    assert admin.login(otp=code).status_code == 401
    assert admin.login(otp=codes[0]).status_code == 200
    assert admin.post('/api/auth/logout', {'all_devices': False}).status_code == 200
    admin.refresh()
    assert admin.login(otp=codes[0]).status_code == 401
    recover = admin.post('/api/auth/recover', {'username': 'admin', 'recovery_key': admin.recovery_key,
                         'new_password': 'Recovered-vault!new-password'})
    assert recover.status_code == 200
    admin.refresh()
    assert admin.login(password='Recovered-vault!new-password').status_code == 200
    assert admin.refresh()['user']['totp_enabled'] is False


def test_encrypted_backup_restore_identity_proof_no_plaintext_and_session_revocation(admin):
    record = admin.create_secret()
    temporary = admin.post('/api/temporary-links', {'secret_id': record['id'], 'expires_minutes': 5,
                           'max_views': 1, 'allow_copy': True}).json()
    password = 'Portable-backup!separate-passphrase'
    assert admin.post('/api/backups', {'password': password}).status_code == 428
    admin.reauth()
    created = admin.post('/api/backups', {'password': password})
    assert created.status_code in (200, 201), created.text
    downloaded = admin.post(f"/api/backups/{created.json()['id']}/download", {})
    assert downloaded.status_code == 200
    content = downloaded.content
    assert b'Private-value!6f987de' not in content
    assert PASSWORD.encode() not in content
    with pytest.raises(ValueError):
        backup.open_backup(content, 'Incorrect-password!')
    decoded = backup.open_backup(content, password)
    assert decoded['tables']['secrets'][0]['id'] == record['id']
    assert len(base64.b64decode(decoded['master_key'])) == 32
    assert admin.post('/api/public/temporary', {'token': temporary['token']}).status_code == 200
    assert admin.delete('/api/temporary-links/' + temporary['id']).status_code == 200
    assert admin.delete(f"/api/secrets/{record['id']}").status_code in (200, 204)
    assert admin.get('/api/secrets').json() == []
    restored = admin.post('/api/backups/restore', {'content_base64': base64.b64encode(content).decode(), 'password': password})
    assert restored.status_code == 200, restored.text
    assert admin.get('/api/secrets').status_code == 401
    admin.refresh()
    assert admin.login().status_code == 200
    value = admin.post(f"/api/secrets/{record['id']}/reveal", {'action': 'view'})
    assert value.json()['data']['password'] == 'Private-value!6f987de'
    assert admin.post('/api/public/temporary', {'token': temporary['token']}).status_code == 410
    catalog = admin.get('/api/backups').json()
    assert [row['id'] for row in catalog] == [created.json()['id']]
    assert catalog[0]['filename'] == created.json()['filename']
    assert (backup.backup_dir() / catalog[0]['filename']).read_bytes() == content
    assert admin.get('/api/security').json()['last_backup'] is not None
    with SessionLocal() as db:
        assert db.get(BackupRecord, created.json()['id']) is not None
    admin.reauth()
    assert admin.post(f"/api/backups/{created.json()['id']}/download", {}).content == content


def test_corrupt_backup_cannot_replace_live_state_and_machine_backup_roundtrip(admin):
    record = admin.create_secret()
    with SessionLocal() as db:
        saved = backup.create_backup(db, scheduled=True)
        db.commit()
        content = (backup.backup_dir() / saved.filename).read_bytes()
    snapshot = backup.open_backup(content)
    assert snapshot['tables']['secrets'][0]['id'] == record['id']
    corrupted = dict(snapshot)
    corrupted['tables'] = dict(snapshot['tables'])
    corrupted['tables']['secrets'] = [dict(snapshot['tables']['secrets'][0], ciphertext='damaged-ciphertext')]
    with pytest.raises(Exception):
        backup.restore_snapshot(corrupted)
    assert admin.get(f"/api/secrets/{record['id']}").status_code == 200
    assert (backup.backup_dir() / saved.filename).stat().st_mode & 0o777 == 0o600


def test_scheduled_backup_retention_keeps_daily_weekly_monthly_union(admin):
    admin.create_secret()
    with SessionLocal() as db:
        from app.models import AppSettings
        settings = db.get(AppSettings, 1)
        settings.retention_daily, settings.retention_weekly, settings.retention_monthly = 2, 1, 1
        for days in (0, 1, 2, 40, 90):
            record = backup.create_backup(db, scheduled=True)
            record.created_at = utcnow() - timedelta(days=days)
        db.commit()
        backup.retain_backups(db, settings)
        db.commit()
        remaining = db.scalars(select(BackupRecord)).all()
        assert 2 <= len(remaining) <= 4
        assert all((backup.backup_dir() / item.filename).exists() for item in remaining)


def test_offline_cli_backup_restore_and_wrong_password_safe_failure(admin, tmp_path):
    import os
    import subprocess
    import sys
    record = admin.create_secret()
    password_file = tmp_path / 'backup-password'
    password_file.write_text('Offline-backup!distinct-password')
    password_file.chmod(0o600)
    destination = tmp_path / 'portable.shbak'
    command = [sys.executable, '-m', 'app.backup']
    created = subprocess.run(command + ['backup', '--output', str(destination), '--password-file', str(password_file)],
                             env=os.environ.copy(), capture_output=True, text=True, check=False)
    assert created.returncode == 0, created.stderr
    assert destination.stat().st_mode & 0o777 == 0o600
    assert admin.delete(f"/api/secrets/{record['id']}").status_code == 200
    wrong = tmp_path / 'wrong-password'
    wrong.write_text('Wrong-backup!distinct-password')
    wrong.chmod(0o600)
    refused = subprocess.run(command + ['restore', '--input', str(destination), '--password-file', str(wrong)],
                             env=os.environ.copy(), capture_output=True, text=True, check=False)
    assert refused.returncode != 0
    assert 'Wrong-backup!distinct-password' not in refused.stderr
    assert 'Traceback' not in refused.stderr
    assert admin.get('/api/secrets').json() == []
    # A migrated empty vault has no users or master.key; portable restore must bootstrap both.
    from app.db import Base, engine
    from app.models import AppSettings
    from app.crypto import key_path
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.add(AppSettings(id=1))
        db.commit()
    key_path().unlink()
    restored = subprocess.run(command + ['restore', '--input', '-', '--password-stdin'],
                              input=password_file.read_bytes() + b'\n' + destination.read_bytes(),
                              env=os.environ.copy(), capture_output=True, check=False)
    assert restored.returncode == 0, restored.stderr
    assert admin.get('/api/secrets').status_code == 401
    admin.refresh()
    assert admin.login().status_code == 200
    assert admin.post(f"/api/secrets/{record['id']}/reveal", {'action': 'view'}).status_code == 200


def test_restore_key_journal_recovers_committed_database_after_interruption(admin, monkeypatch):
    import secrets
    from app.crypto import get_key, set_key, wrap_key
    from app.models import AppSettings
    record = admin.create_secret()
    saved = backup.snapshot()
    saved_key = get_key()
    assert admin.delete(f"/api/secrets/{record['id']}").status_code == 200
    set_key(secrets.token_bytes(32))
    with SessionLocal() as db:
        db.get(AppSettings, 1).master_wrap = wrap_key('Another-master!password', 'master-key')
        db.commit()
    actual_set_key = backup.set_key
    monkeypatch.setattr(backup, 'set_key', lambda key: (_ for _ in ()).throw(OSError('Simulated power failure')))
    with pytest.raises(backup.RestoreInterrupted):
        backup.restore_snapshot(saved)
    assert backup._journal_path().stat().st_mode & 0o777 == 0o600
    assert admin.get('/health').status_code == 503
    assert admin.get('/api/secrets').status_code == 503
    backup.scheduler_tick()
    assert backup._journal_path().exists()
    monkeypatch.setattr(backup, 'set_key', actual_set_key)
    backup.recover_interrupted_restore()
    assert get_key() == saved_key
    assert not backup._journal_path().exists()
    admin.refresh()
    assert admin.login().status_code == 200
    assert admin.post(f"/api/secrets/{record['id']}/reveal", {'action': 'view'}).json()['data']['password'] == 'Private-value!6f987de'


def test_malformed_env_does_not_log_secret_contents(caplog):
    marker = 'private-malformed-env-value'
    with pytest.raises(ValueError):
        parse_env('BROKEN="' + marker)
    assert marker not in caplog.text


def test_scheduler_purges_expired_sessions_and_inactive_rate_limits_only(admin):
    from app.auth import token_hash
    from app.models import AuthSession, RateLimit, uid
    token = admin.client.cookies.get('secrets_hub_session')
    expired_id = uid()
    with SessionLocal() as db:
        db.add(AuthSession(id=expired_id, token_hash='f' * 64, csrf_token='unused',
                           expires_at=utcnow() - timedelta(days=1), last_seen=utcnow() - timedelta(days=2)))
        db.add(RateLimit(key='a' * 64, window_start=utcnow() - timedelta(days=2), attempts=10))
        db.add(RateLimit(key='b' * 64, window_start=utcnow() - timedelta(days=2), attempts=10,
                        blocked_until=utcnow() + timedelta(hours=1)))
        db.commit()
    backup.scheduler_tick()
    with SessionLocal() as db:
        assert db.get(AuthSession, expired_id) is None
        assert db.get(RateLimit, 'a' * 64) is None
        assert db.get(RateLimit, 'b' * 64) is not None
        assert db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(token))) is not None
    assert admin.get('/api/secrets').status_code == 200


def test_restore_preserves_totp_seed_but_revokes_recovery_codes_and_regeneration_replaces_them(admin):
    admin.reauth()
    assert admin.post('/api/auth/totp/recovery-codes', {}).status_code == 409
    pending = admin.post('/api/auth/totp/setup', {}).json()
    totp = pyotp.TOTP(pending['secret'])
    enabled = admin.post('/api/auth/totp/enable', {'code': totp.now()})
    assert enabled.status_code == 200
    original_codes = enabled.json()['recovery_codes']
    admin.reauth(otp=original_codes[0])
    created = admin.post('/api/backups', {'password': 'TOTP-backup!separate-password'}).json()
    content = admin.post(f"/api/backups/{created['id']}/download", {}).content
    snapshot = backup.open_backup(content, 'TOTP-backup!separate-password')
    assert snapshot['tables']['users'][0]['recovery_codes']
    assert snapshot['tables']['users'][0]['totp_secret']
    restored = admin.post('/api/backups/restore', {'content_base64': base64.b64encode(content).decode(),
                          'password': 'TOTP-backup!separate-password'})
    assert restored.status_code == 200, restored.text
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == 'admin'))
        assert user.recovery_codes == []
        assert user.totp_pending is None
        assert decrypt_json(user.totp_secret, 'totp:' + user.id)['secret'] == pending['secret']
    admin.refresh()
    assert admin.login(otp=original_codes[1]).status_code == 401
    assert admin.login(otp=totp.now()).status_code == 200
    assert admin.post('/api/auth/totp/recovery-codes', {}).status_code == 428
    admin.reauth(otp=totp.at(int(utcnow().timestamp()) + 30))
    first = admin.post('/api/auth/totp/recovery-codes', {})
    assert first.status_code == 200 and len(first.json()['recovery_codes']) == 10
    second = admin.post('/api/auth/totp/recovery-codes', {})
    assert second.status_code == 200 and len(second.json()['recovery_codes']) == 10
    assert not set(first.json()['recovery_codes']) & set(second.json()['recovery_codes'])
    assert any(event['action'] == 'recovery_codes_regenerated' for event in admin.get('/api/audit').json())
    assert admin.post('/api/auth/logout', {'all_devices': False}).status_code == 200
    admin.refresh()
    assert admin.login(otp=first.json()['recovery_codes'][0]).status_code == 401
    assert admin.login(otp=second.json()['recovery_codes'][0]).status_code == 200
