import base64
import json
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from .config import config

SecretType = Literal['login', 'api_key', 'token', 'ssh_key', 'wireguard', 'environment', 'certificate', 'note', 'file']
Role = Literal['admin', 'editor', 'viewer']


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=False)


class Credentials(StrictModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=1024)
    otp: str | None = Field(default=None, max_length=100)


class PasswordProof(StrictModel):
    password: str = Field(min_length=1, max_length=1024)
    otp: str | None = Field(default=None, max_length=100)


class SetupWrite(StrictModel):
    username: str = Field(min_length=3, max_length=80, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=12, max_length=1024)
    master_password: str = Field(min_length=16, max_length=1024)
    instance_name: str = Field(min_length=1, max_length=100)
    app_url: str = Field(default='', max_length=500)

    @field_validator('app_url')
    @classmethod
    def validate_url(cls, value: str) -> str:
        if value:
            parsed = urlsplit(value)
            if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
                raise ValueError('Application URL must be an HTTP(S) origin')
        return value.rstrip('/')


class SecretWrite(StrictModel):
    name: str = Field(min_length=1, max_length=180)
    type: SecretType
    collection_id: str | None = Field(default=None, max_length=36)
    tags: list[str] = Field(default_factory=list, max_length=30)
    expires_at: datetime | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    data: dict[str, str] = Field(default_factory=dict)

    @field_validator('tags')
    @classmethod
    def valid_tags(cls, tags: list[str]) -> list[str]:
        if any(not tag.strip() or len(tag) > 40 for tag in tags):
            raise ValueError('Invalid tags')
        return sorted(set(tag.strip() for tag in tags))

    @field_validator('metadata')
    @classmethod
    def valid_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {'username', 'hostname', 'host', 'service', 'notes', 'environment', 'url', 'endpoint', 'address', 'dns', 'allowed_ips', 'fingerprint', 'issuer', 'filename'}
        if set(value) - allowed or any(len(v) > (2000 if k == 'notes' else 500) for k, v in value.items()):
            raise ValueError('Invalid metadata')
        if value.get('url') and urlsplit(value['url']).scheme not in ('http', 'https'):
            raise ValueError('Website URL must use HTTP(S)')
        return value

    @field_validator('expires_at')
    @classmethod
    def valid_expiration(cls, value: datetime | None) -> datetime | None:
        return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value

    @model_validator(mode='after')
    def valid_data(self):
        if len(self.data) > 30 or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,59}', k) for k in self.data) or len(json.dumps(self.data).encode()) > 4 * 1024 * 1024:
            raise ValueError('Secret is too large')
        if self.type == 'file':
            try:
                raw = base64.b64decode(self.data['content_base64'], validate=True)
                filename = self.data['filename']
                if len(raw) > config.max_file_bytes or not filename or len(filename) > 255 or '/' in filename or '\\' in filename:
                    raise ValueError('Invalid file')
            except (KeyError, ValueError) as exc:
                raise ValueError('Invalid encrypted file') from exc
        if not any(self.data.values()):
            raise ValueError('Secret content is required')
        return self


class RevealWrite(StrictModel):
    action: Literal['view', 'copy', 'export'] = 'view'
    version_id: str | None = None


class RestoreVersionWrite(StrictModel):
    version_id: str = Field(max_length=36)


class CollectionWrite(StrictModel):
    name: str = Field(min_length=1, max_length=180)
    description: str = Field(default='', max_length=1000)
    icon: str = Field(default='folder', max_length=40, pattern=r'^[a-zA-Z0-9_-]+$')
    color: str = Field(default='#818cf8', pattern=r'^#[0-9a-fA-F]{6}$')


class GrantWrite(StrictModel):
    user_id: str = Field(max_length=36)
    access: Literal['read', 'write', 'none']
    can_copy: bool = True


class UserWrite(StrictModel):
    username: str = Field(min_length=3, max_length=80, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=12, max_length=1024)
    role: Role


class UserUpdate(StrictModel):
    role: Role | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class SettingsWrite(StrictModel):
    instance_name: str = Field(min_length=1, max_length=100)
    app_url: str = Field(max_length=500)
    lock_timeout: Literal[0, 1, 5, 15, 30]
    session_hours: int = Field(ge=1, le=168)
    backup_enabled: bool
    backup_hour: int = Field(ge=0, le=23)
    retention_daily: int = Field(ge=1, le=365)
    retention_weekly: int = Field(ge=0, le=52)
    retention_monthly: int = Field(ge=0, le=60)
    _url = field_validator('app_url')(SetupWrite.validate_url.__func__)
