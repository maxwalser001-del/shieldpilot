"""add_booster_credits

Revision ID: c3d4e5f6g7h8
Revises: b2c3d4e5f6g7
Create Date: 2026-03-23 22:00:00.000000

Adds booster_credits table for one-time command booster purchases.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6g7h8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6g7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(name: str) -> bool:
    """Check if a table already exists."""
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT name FROM sqlite_master WHERE type='table' AND name=:n"),
        {"n": name},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    if _table_exists("booster_credits"):
        return

    op.create_table(
        "booster_credits",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_email", sa.String(256), nullable=False, index=True),
        sa.Column("credits_remaining", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("purchased_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.String(10), nullable=False),
        sa.Column("stripe_payment_id", sa.String(256), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("booster_credits")
