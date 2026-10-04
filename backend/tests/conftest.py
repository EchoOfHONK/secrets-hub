"""Integration fixtures use an isolated DB; never point TEST_DATABASE_URL at real data."""
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEST_DATA = Path(tempfile.mkdtemp(prefix='secrets-hub-tests-'))
os.environ['DATABASE_URL'] = os.getenv('TEST_DATABASE_URL', f'sqlite:///{TEST_DATA}/database.sqlite')
os.environ['DATA_DIR'] = str(TEST_DATA)
os.environ['SECURE_COOKIES'] = 'false'
os.environ['APP_URL'] = 'http://testserver'

from app import crypto  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AppSettings  # noqa: E402

PASSWORD = 'Vault-user!2026-strong-password'
MASTER_PASSWORD = 'Master-envelope!2026-separate-password'


class API:
    def __init__(self, client: TestClient):
        self.client = client
        self.csrf = ''
        self.refresh()

    def refresh(self):
        result = self.client.get('/api/auth/session')
        assert result.status_code == 200, result.text
        self.csrf = result.json()['csrf_token']
        return result.json()

    def get(self, path: str, **kwargs):
        return self.client.get(path, **kwargs)

    def request(self, method: str, path: str, data=None, **kwargs):
        headers = {'Origin': 'http://testserver', 'X-CSRF-Token': self.csrf}
        headers.update(kwargs.pop('headers', {}))
        result = self.client.request(method, path, json={} if data is None else data, headers=headers, **kwargs)
        if result.status_code < 300 and result.headers.get('content-type', '').startswith('application/json'):
            value = result.json()
            if isinstance(value, dict) and 'csrf_token' in value:
                self.csrf = value['csrf_token']
        return result

    def post(self, path: str, data=None, **kwargs):
        return self.request('POST', path, data, **kwargs)

    def put(self, path: str, data=None, **kwargs):
        return self.request('PUT', path, data, **kwargs)

    def delete(self, path: str, **kwargs):
        return self.request('DELETE', path, **kwargs)

    def login(self, username='admin', password=PASSWORD, otp=None):
        payload = {'username': username, 'password': password}
        if otp is not None:
            payload['otp'] = otp
        result = self.post('/api/auth/login', payload)
        return result

    def reauth(self, password=PASSWORD, otp=None):
        payload = {'password': password}
        if otp is not None:
            payload['otp'] = otp
        result = self.post('/api/auth/reauth', payload)
        assert result.status_code == 200, result.text
        return result

    def create_secret(self, **changes):
        payload = {'name': 'Production credential', 'type': 'login', 'tags': ['production'],
                   'metadata': {'username': 'service-account', 'hostname': 'debian.home', 'service': 'router'},
                   'data': {'username': 'service-account', 'password': 'Private-value!6f987de'}}
        payload.update(changes)
        result = self.post('/api/secrets', payload)
        assert result.status_code in (200, 201), result.text
        return result.json()


@pytest.fixture(autouse=True)
def isolated_state():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.add(AppSettings(id=1))
        db.commit()
    crypto._key = None
    for folder in ('keys', 'backups'):
        shutil.rmtree(TEST_DATA / folder, ignore_errors=True)
    yield


@pytest.fixture
def api():
    with TestClient(app) as client:
        yield API(client)


@pytest.fixture
def admin(api):
    result = api.post('/api/setup', {'username': 'admin', 'password': PASSWORD,
                     'master_password': MASTER_PASSWORD, 'instance_name': 'Family Vault',
                     'app_url': 'http://testserver'})
    assert result.status_code in (200, 201), result.text
    api.recovery_key = result.json()['recovery_key']
    return api


@pytest.fixture
def outsider(admin):
    result = admin.post('/api/users', {'username': 'viewer', 'password': PASSWORD, 'role': 'viewer'})
    assert result.status_code in (200, 201), result.text
    with TestClient(app) as client:
        viewer = API(client)
        assert viewer.login('viewer').status_code == 200
        viewer.user_id = result.json()['id']
        yield viewer
