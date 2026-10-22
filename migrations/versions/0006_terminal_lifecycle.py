"""Atomic execution terminal receipt and callback reconciliation.

Revision ID: 0006
Revises: 0005
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "supervision_terminal_callbacks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id"),
            nullable=False,
        ),
        sa.Column("task_id", sa.String(64), nullable=False, unique=True),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("worker_id", sa.String(128), nullable=True),
        sa.Column("lease_id", sa.String(64), nullable=True),
        sa.Column("leased_until", sa.DateTime, nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("receipt", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )
    op.create_index(
        "ix_supervision_terminal_callbacks_pending",
        "supervision_terminal_callbacks",
        ["status", "leased_until", "created_at"],
    )
    op.create_index(
        "ix_supervision_terminal_callbacks_engagement",
        "supervision_terminal_callbacks",
        ["engagement_id", "status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_supervision_terminal_callbacks_engagement", table_name="supervision_terminal_callbacks"
    )
    op.drop_index(
        "ix_supervision_terminal_callbacks_pending", table_name="supervision_terminal_callbacks"
    )
    op.drop_table("supervision_terminal_callbacks")
