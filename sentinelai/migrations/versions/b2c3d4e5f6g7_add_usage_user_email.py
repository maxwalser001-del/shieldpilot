"""add_usage_user_email

Revision ID: b2c3d4e5f6g7
Revises: a1b2c3d4e5f6
Create Date: 2026-02-18 16:00:00.000000

Adds user_email column to usage table for per-user usage tracking.
Previously all usage was tracked globally (tenant_id=NULL).
Now each user gets their own usage counter keyed by email.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6g7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_exists(table: str, column: str) -> bool:
    """Check if a column already exists in a table."""
    conn = op.get_bind()
    result = conn.execute(sa.text(f"PRAGMA table_info({table})"))
    return any(row[1] == column for row in result.fetchall())


def _index_exists(name: str) -> bool:
    """Check if an index already exists in the database."""
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT name FROM sqlite_master WHERE type='index' AND name=:n"),
        {"n": name},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    """Add user_email column and index to usage table."""
    if not _column_exists('usage', 'user_email'):
        op.add_column('usage', sa.Column('user_email', sa.String(256), nullable=True))
    if not _index_exists('ix_usage_user_date'):
        op.create_index('ix_usage_user_date', 'usage', ['user_email', 'date'])


def downgrade() -> None:
    """Remove user_email column and index from usage table."""
    op.drop_index('ix_usage_user_date', table_name='usage')
    op.drop_column('usage', 'user_email')
