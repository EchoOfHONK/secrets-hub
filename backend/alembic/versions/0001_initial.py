"""Initial Secrets Hub schema and setup singleton."""
from alembic import op
import sqlalchemy as sa

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('app_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('initialized', sa.Boolean(), nullable=False),
    sa.Column('instance_name', sa.String(length=100), nullable=False),
    sa.Column('app_url', sa.String(length=500), nullable=False),
    sa.Column('lock_timeout', sa.Integer(), nullable=False),
    sa.Column('session_hours', sa.Integer(), nullable=False),
    sa.Column('backup_enabled', sa.Boolean(), nullable=False),
    sa.Column('backup_hour', sa.Integer(), nullable=False),
    sa.Column('retention_daily', sa.Integer(), nullable=False),
    sa.Column('retention_weekly', sa.Integer(), nullable=False),
    sa.Column('retention_monthly', sa.Integer(), nullable=False),
    sa.Column('master_wrap', sa.Text(), nullable=True),
    sa.Column('recovery_wrap', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('backups',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('filename', sa.String(length=150), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('scheduled', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('rate_limits',
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('window_start', sa.DateTime(timezone=True), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('blocked_until', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('users',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=False),
    sa.Column('role', sa.String(length=10), nullable=False),
    sa.Column('disabled', sa.Boolean(), nullable=False),
    sa.Column('totp_secret', sa.Text(), nullable=True),
    sa.Column('totp_pending', sa.Text(), nullable=True),
    sa.Column('totp_last_step', sa.Integer(), nullable=False),
    sa.Column('recovery_codes', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_table('audit_events',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=True),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('action', sa.String(length=80), nullable=False),
    sa.Column('target', sa.String(length=180), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_events_action'), 'audit_events', ['action'], unique=False)
    op.create_index(op.f('ix_audit_events_created_at'), 'audit_events', ['created_at'], unique=False)
    op.create_index(op.f('ix_audit_events_user_id'), 'audit_events', ['user_id'], unique=False)
    op.create_table('collections',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('owner_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=180), nullable=False),
    sa.Column('description', sa.String(length=1000), nullable=False),
    sa.Column('icon', sa.String(length=40), nullable=False),
    sa.Column('color', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('sessions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('csrf_token', sa.String(length=128), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('reauth_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('locked', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sessions_token_hash'), 'sessions', ['token_hash'], unique=True)
    op.create_index(op.f('ix_sessions_user_id'), 'sessions', ['user_id'], unique=False)
    op.create_table('collection_permissions',
    sa.Column('collection_id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('access', sa.String(length=10), nullable=False),
    sa.Column('can_copy', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['collection_id'], ['collections.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('collection_id', 'user_id')
    )
    op.create_table('secrets',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('owner_id', sa.String(length=36), nullable=False),
    sa.Column('collection_id', sa.String(length=36), nullable=True),
    sa.Column('name', sa.String(length=180), nullable=False),
    sa.Column('type', sa.String(length=30), nullable=False),
    sa.Column('tags', sa.JSON(), nullable=False),
    sa.Column('metadata', sa.JSON(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('ciphertext', sa.Text(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('weak_password', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_used', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['collection_id'], ['collections.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_secrets_collection_id'), 'secrets', ['collection_id'], unique=False)
    op.create_index(op.f('ix_secrets_name'), 'secrets', ['name'], unique=False)
    op.create_index(op.f('ix_secrets_type'), 'secrets', ['type'], unique=False)
    op.create_table('secret_shares',
    sa.Column('secret_id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('access', sa.String(length=10), nullable=False),
    sa.Column('can_copy', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('secret_id', 'user_id')
    )
    op.create_table('secret_versions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('secret_id', sa.String(length=36), nullable=False),
    sa.Column('number', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('ciphertext', sa.Text(), nullable=False),
    sa.Column('snapshot', sa.JSON(), nullable=False),
    sa.Column('changed_fields', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('secret_id', 'number')
    )
    op.create_index(op.f('ix_secret_versions_secret_id'), 'secret_versions', ['secret_id'], unique=False)
    op.create_table('temporary_links',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('secret_id', sa.String(length=36), nullable=False),
    sa.Column('creator_id', sa.String(length=36), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('max_views', sa.Integer(), nullable=False),
    sa.Column('views', sa.Integer(), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=True),
    sa.Column('allow_copy', sa.Boolean(), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['creator_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_temporary_links_token_hash'), 'temporary_links', ['token_hash'], unique=True)
    op.get_bind().execute(sa.text("INSERT INTO app_settings (id, initialized, instance_name, app_url, lock_timeout, session_hours, backup_enabled, backup_hour, retention_daily, retention_weekly, retention_monthly) VALUES (1, false, 'Secrets Hub', '', 5, 12, false, 3, 7, 4, 6)"))


def downgrade():
    op.drop_index(op.f('ix_temporary_links_token_hash'), table_name='temporary_links')
    op.drop_table('temporary_links')
    op.drop_index(op.f('ix_secret_versions_secret_id'), table_name='secret_versions')
    op.drop_table('secret_versions')
    op.drop_table('secret_shares')
    op.drop_index(op.f('ix_secrets_type'), table_name='secrets')
    op.drop_index(op.f('ix_secrets_name'), table_name='secrets')
    op.drop_index(op.f('ix_secrets_collection_id'), table_name='secrets')
    op.drop_table('secrets')
    op.drop_table('collection_permissions')
    op.drop_index(op.f('ix_sessions_user_id'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_token_hash'), table_name='sessions')
    op.drop_table('sessions')
    op.drop_table('collections')
    op.drop_index(op.f('ix_audit_events_user_id'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_created_at'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_action'), table_name='audit_events')
    op.drop_table('audit_events')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_table('users')
    op.drop_table('rate_limits')
    op.drop_table('backups')
    op.drop_table('app_settings')
