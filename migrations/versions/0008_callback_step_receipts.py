"""Persist callback effect plans and acknowledged per-step progress.

Revision ID: 0008
Revises: 0007
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "supervision_terminal_callbacks",
        sa.Column("effect_steps", JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("supervision_terminal_callbacks", "effect_steps")
