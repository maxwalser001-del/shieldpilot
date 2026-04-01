"""add_custom_rules_team_invites

Revision ID: a1b2c3d4e5f6
Revises: e2aa7efdd342
Create Date: 2026-02-18 12:00:00.000000

Adds the custom_rules and team_invites tables, plus the missing
composite index ix_ratelimit_name_key_at on rate_limit_attempts.

Note: ix_prompt_scans_timestamp is already created by the initial
migration via ``index=True`` on the timestamp column.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'e2aa7efdd342'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(name: str) -> bool:
    """Check if a table already exists in the database."""
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT name FROM sqlite_master WHERE type='table' AND name=:n"),
        {"n": name},
    )
    return result.fetchone() is not None


def _index_exists(name: str) -> bool:
    """Check if an index already exists in the database."""
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT name FROM sqlite_master WHERE type='index' AND name=:n"),
        {"n": name},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    """Create custom_rules and team_invites tables, add missing indexes."""

    # ── custom_rules ──────────────────────────────────────────────
    if not _table_exists('custom_rules'):
        op.create_table(
            'custom_rules',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('tenant_id', sa.String(64), nullable=True),
            sa.Column('name', sa.String(128), nullable=False),
            sa.Column('description', sa.String(512), nullable=True),
            sa.Column('pattern', sa.Text(), nullable=False),
            sa.Column('severity', sa.String(20), nullable=False, server_default='medium'),
            sa.Column('category', sa.String(50), nullable=False, server_default='custom'),
            sa.Column('enabled', sa.Boolean(), server_default='1'),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
        )
    if not _index_exists('ix_custom_rules_tenant'):
        op.create_index('ix_custom_rules_tenant', 'custom_rules', ['tenant_id'])
    if not _index_exists('ix_custom_rules_enabled'):
        op.create_index('ix_custom_rules_enabled', 'custom_rules', ['enabled'])

    # ── team_invites ──────────────────────────────────────────────
    if not _table_exists('team_invites'):
        op.create_table(
            'team_invites',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('tenant_id', sa.String(64), nullable=True),
            sa.Column('email', sa.String(256), nullable=False),
            sa.Column('role', sa.String(20), nullable=False, server_default='viewer'),
            sa.Column('invited_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('accepted', sa.Boolean(), server_default='0'),
        )
    if not _index_exists('ix_team_invites_email'):
        op.create_index('ix_team_invites_email', 'team_invites', ['email'])
    if not _index_exists('ix_team_invites_tenant'):
        op.create_index('ix_team_invites_tenant', 'team_invites', ['tenant_id'])

    # ── Missing composite index on existing table ──────────────────

    # Composite index for sliding-window rate-limit queries
    if not _index_exists('ix_ratelimit_name_key_at'):
        op.create_index(
            'ix_ratelimit_name_key_at',
            'rate_limit_attempts',
            ['limiter_name', 'key', 'attempted_at'],
        )


def downgrade() -> None:
    """Drop tables and indexes added in this migration."""

    # Drop index first
    op.drop_index('ix_ratelimit_name_key_at', table_name='rate_limit_attempts')

    # Drop tables (reverse order of creation)
    op.drop_table('team_invites')
    op.drop_table('custom_rules')
