from datetime import datetime
from uuid import uuid4
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, utcnow


def uid() -> str:
    return str(uuid4())


class AppSettings(Base):
    __tablename__ = 'app_settings'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    initialized: Mapped[bool] = mapped_column(Boolean, default=False)
    instance_name: Mapped[str] = mapped_column(String(100), default='Secrets Hub')
    app_url: Mapped[str] = mapped_column(String(500), default='')
    lock_timeout: Mapped[int] = mapped_column(Integer, default=5)
    session_hours: Mapped[int] = mapped_column(Integer, default=12)
    backup_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    backup_hour: Mapped[int] = mapped_column(Integer, default=3)
    retention_daily: Mapped[int] = mapped_column(Integer, default=7)
    retention_weekly: Mapped[int] = mapped_column(Integer, default=4)
    retention_monthly: Mapped[int] = mapped_column(Integer, default=6)
    master_wrap: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovery_wrap: Mapped[str | None] = mapped_column(Text, nullable=True)


class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(10), default='viewer')
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_pending: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=-1)
    recovery_codes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthSession(Base):
    __tablename__ = 'sessions'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(128))
    user_id: Mapped[str | None] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reauth_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked: Mapped[bool] = mapped_column(Boolean, default=False)


class Collection(Base):
    __tablename__ = 'collections'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    name: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(String(1000), default='')
    icon: Mapped[str] = mapped_column(String(40), default='folder')
    color: Mapped[str] = mapped_column(String(20), default='#818cf8')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectionPermission(Base):
    __tablename__ = 'collection_permissions'
    collection_id: Mapped[str] = mapped_column(ForeignKey('collections.id', ondelete='CASCADE'), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    access: Mapped[str] = mapped_column(String(10))
    can_copy: Mapped[bool] = mapped_column(Boolean, default=True)


class Secret(Base):
    __tablename__ = 'secrets'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    collection_id: Mapped[str | None] = mapped_column(ForeignKey('collections.id', ondelete='SET NULL'), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(180), index=True)
    type: Mapped[str] = mapped_column(String(30), index=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    meta: Mapped[dict] = mapped_column('metadata', JSON, default=dict)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ciphertext: Mapped[str] = mapped_column(Text, deferred=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    weak_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SecretVersion(Base):
    __tablename__ = 'secret_versions'
    __table_args__ = (UniqueConstraint('secret_id', 'number'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    secret_id: Mapped[str] = mapped_column(ForeignKey('secrets.id', ondelete='CASCADE'), index=True)
    number: Mapped[int] = mapped_column(Integer)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    ciphertext: Mapped[str] = mapped_column(Text, deferred=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    changed_fields: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecretShare(Base):
    __tablename__ = 'secret_shares'
    secret_id: Mapped[str] = mapped_column(ForeignKey('secrets.id', ondelete='CASCADE'), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    access: Mapped[str] = mapped_column(String(10))
    can_copy: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditEvent(Base):
    __tablename__ = 'audit_events'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80), index=True)
    target: Mapped[str] = mapped_column(String(180), default='')
    ip: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class RateLimit(Base):
    __tablename__ = 'rate_limits'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TemporaryLink(Base):
    __tablename__ = 'temporary_links'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    secret_id: Mapped[str] = mapped_column(ForeignKey('secrets.id', ondelete='CASCADE'))
    creator_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_views: Mapped[int] = mapped_column(Integer)
    views: Mapped[int] = mapped_column(Integer, default=0)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    allow_copy: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BackupRecord(Base):
    __tablename__ = 'backups'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    filename: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scheduled: Mapped[bool] = mapped_column(Boolean, default=False)
