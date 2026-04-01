"""initial_schema

Revision ID: e2aa7efdd342
Revises:
Create Date: 2026-02-12 18:15:38.009932

Creates all tables matching the SQLAlchemy models in sentinelai.logger.database.
This migration should produce the same schema as Base.metadata.create_all().
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e2aa7efdd342'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all tables from scratch."""

    # ── tenants (referenced by users and usage) ──────────────────
    op.create_table(
        'tenants',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('name', sa.String(256), nullable=False),
        sa.Column('email', sa.String(256), nullable=False, unique=True),
        sa.Column('api_key_hash', sa.String(64), nullable=False),
        sa.Column('tier', sa.String(20), nullable=False, server_default='free'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='1'),
    )

    # ── commands ─────────────────────────────────────────────────
    op.create_table(
        'commands',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, index=True),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('raw_command_hash', sa.String(64), nullable=False),
        sa.Column('working_directory', sa.String(1024)),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('risk_level', sa.String(20), nullable=False),
        sa.Column('action_taken', sa.String(10), nullable=False),
        sa.Column('executed', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('output_snippet', sa.Text(), nullable=True),
        sa.Column('signals_json', sa.Text(), nullable=False),
        sa.Column('llm_used', sa.Boolean(), server_default='0'),
        sa.Column('llm_reasoning', sa.Text(), nullable=True),
        sa.Column('execution_time_ms', sa.Float(), nullable=True),
        sa.Column('tenant_id', sa.String(64), nullable=True, index=True),
        sa.Column('session_id', sa.String(64), nullable=True, index=True),
        sa.Column('chain_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('previous_hash', sa.String(64), nullable=False),
    )
    op.create_index('ix_commands_risk_score', 'commands', ['risk_score'])
    op.create_index('ix_commands_action', 'commands', ['action_taken'])

    # ── prompt_scans ─────────────────────────────────────────────
    op.create_table(
        'prompt_scans',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, index=True),
        sa.Column('source', sa.String(512), nullable=False),
        sa.Column('content_hash', sa.String(64), nullable=False),
        sa.Column('content_length', sa.Integer(), nullable=False),
        sa.Column('overall_score', sa.Integer(), nullable=False),
        sa.Column('threat_count', sa.Integer(), nullable=False),
        sa.Column('threats_json', sa.Text(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=True),
        sa.Column('tenant_id', sa.String(64), nullable=True, index=True),
        sa.Column('chain_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('previous_hash', sa.String(64), nullable=False),
    )

    # ── file_changes ─────────────────────────────────────────────
    op.create_table(
        'file_changes',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, index=True),
        sa.Column('file_path', sa.String(1024), nullable=False),
        sa.Column('change_type', sa.String(20), nullable=False),
        sa.Column('hash_before', sa.String(64), nullable=True),
        sa.Column('hash_after', sa.String(64), nullable=True),
        sa.Column('size_before', sa.Integer(), nullable=True),
        sa.Column('size_after', sa.Integer(), nullable=True),
        sa.Column('command_id', sa.Integer(), sa.ForeignKey('commands.id'), nullable=True),
        sa.Column('tenant_id', sa.String(64), nullable=True, index=True),
        sa.Column('chain_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('previous_hash', sa.String(64), nullable=False),
    )

    # ── network_access ───────────────────────────────────────────
    op.create_table(
        'network_access',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, index=True),
        sa.Column('destination', sa.String(512), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(10), nullable=True),
        sa.Column('direction', sa.String(10), nullable=False, server_default='outbound'),
        sa.Column('blocked', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('command_id', sa.Integer(), sa.ForeignKey('commands.id'), nullable=True),
        sa.Column('bytes_sent', sa.Integer(), nullable=True),
        sa.Column('tenant_id', sa.String(64), nullable=True, index=True),
        sa.Column('chain_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('previous_hash', sa.String(64), nullable=False),
    )

    # ── incidents ────────────────────────────────────────────────
    op.create_table(
        'incidents',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, index=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('category', sa.String(50), nullable=False),
        sa.Column('title', sa.String(256), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('command_id', sa.Integer(), sa.ForeignKey('commands.id'), nullable=True),
        sa.Column('resolved', sa.Boolean(), server_default='0'),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('tenant_id', sa.String(64), nullable=True, index=True),
        sa.Column('chain_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('previous_hash', sa.String(64), nullable=False),
    )
    op.create_index('ix_incidents_severity', 'incidents', ['severity'])
    op.create_index('ix_incidents_resolved', 'incidents', ['resolved'])

    # ── usage ────────────────────────────────────────────────────
    op.create_table(
        'usage',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id'), nullable=True, index=True),
        sa.Column('date', sa.String(10), nullable=False),
        sa.Column('commands_evaluated', sa.Integer(), server_default='0'),
        sa.Column('scans_performed', sa.Integer(), server_default='0'),
        sa.Column('llm_calls', sa.Integer(), server_default='0'),
        sa.Column('api_requests', sa.Integer(), server_default='0'),
    )
    op.create_index('ix_usage_tenant_date', 'usage', ['tenant_id', 'date'])

    # ── users ────────────────────────────────────────────────────
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('username', sa.String(128), nullable=False, unique=True),
        sa.Column('email', sa.String(256), nullable=True, unique=True),
        sa.Column('password_hash', sa.String(256), nullable=True),
        sa.Column('google_id', sa.String(256), nullable=True, unique=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id'), nullable=True),
        sa.Column('role', sa.String(20), nullable=False, server_default='viewer'),
        sa.Column('tier', sa.String(20), nullable=False, server_default='free'),
        sa.Column('is_super_admin', sa.Boolean(), server_default='0'),
        sa.Column('email_verified', sa.Boolean(), server_default='0'),
        sa.Column('api_key_hash', sa.String(64), nullable=True, unique=True),
        sa.Column('stripe_customer_id', sa.String(256), nullable=True, unique=True),
        sa.Column('stripe_subscription_id', sa.String(256), nullable=True),
        sa.Column('subscription_status', sa.String(20), nullable=True),
        sa.Column('current_period_end', sa.Integer(), nullable=True),
        sa.Column('cancel_at_period_end', sa.Boolean(), server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='1'),
        sa.Column('tos_accepted_at', sa.DateTime(), nullable=True),
        sa.Column('tos_version', sa.String(20), nullable=True),
        sa.Column('tos_ip_address', sa.String(45), nullable=True),
        sa.Column('tos_user_agent', sa.String(512), nullable=True),
    )

    # ── webhook_events ───────────────────────────────────────────
    op.create_table(
        'webhook_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('stripe_event_id', sa.String(256), unique=True, nullable=False, index=True),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('processed_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='processed'),
    )

    # ── password_reset_tokens ────────────────────────────────────
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used', sa.Boolean(), server_default='0'),
    )

    # ── email_verification_tokens ────────────────────────────────
    op.create_table(
        'email_verification_tokens',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used', sa.Boolean(), server_default='0'),
    )

    # ── oauth_states ─────────────────────────────────────────────
    op.create_table(
        'oauth_states',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('state', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

    # ── rate_limit_attempts ──────────────────────────────────────
    op.create_table(
        'rate_limit_attempts',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('limiter_name', sa.String(64), nullable=False),
        sa.Column('key', sa.String(256), nullable=False),
        sa.Column('attempted_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_ratelimit_name_key', 'rate_limit_attempts', ['limiter_name', 'key'])

    # ── library_topics (referenced by library_items) ─────────────
    op.create_table(
        'library_topics',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(256), nullable=False),
        sa.Column('slug', sa.String(256), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('icon', sa.String(50), nullable=True),
        sa.Column('parent_id', sa.Integer(), sa.ForeignKey('library_topics.id'), nullable=True),
        sa.Column('display_order', sa.Integer(), server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_library_topics_parent_id', 'library_topics', ['parent_id'])
    op.create_index('ix_library_topics_slug', 'library_topics', ['slug'])

    # ── library_items ────────────────────────────────────────────
    op.create_table(
        'library_items',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('type', sa.String(20), nullable=False),
        sa.Column('title', sa.String(256), nullable=False),
        sa.Column('tags', sa.Text(), nullable=True),
        sa.Column('short_preview', sa.String(512), nullable=False),
        sa.Column('full_content', sa.Text(), nullable=False),
        sa.Column('category', sa.String(100), nullable=True),
        sa.Column('display_order', sa.Integer(), server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('is_published', sa.Boolean(), server_default='0'),
        sa.Column('topic_id', sa.Integer(), sa.ForeignKey('library_topics.id'), nullable=True),
    )
    op.create_index('ix_library_items_type', 'library_items', ['type'])
    op.create_index('ix_library_items_is_published', 'library_items', ['is_published'])
    op.create_index('ix_library_items_category', 'library_items', ['category'])
    op.create_index('ix_library_items_topic_id', 'library_items', ['topic_id'])


def downgrade() -> None:
    """Drop all tables in reverse dependency order."""
    op.drop_table('library_items')
    op.drop_table('library_topics')
    op.drop_table('rate_limit_attempts')
    op.drop_table('oauth_states')
    op.drop_table('email_verification_tokens')
    op.drop_table('password_reset_tokens')
    op.drop_table('webhook_events')
    op.drop_table('users')
    op.drop_table('usage')
    op.drop_table('incidents')
    op.drop_table('network_access')
    op.drop_table('file_changes')
    op.drop_table('prompt_scans')
    op.drop_table('commands')
    op.drop_table('tenants')
