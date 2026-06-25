"""Add dlq_entries table

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-23

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create dlq_entries table."""
    op.create_table(
        "dlq_entries",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("task_id", sa.String(64), index=True),
        sa.Column("engagement_id", sa.String(64), index=True),
        sa.Column("task_type", sa.String(64)),
        sa.Column("agent_type", sa.String(64)),
        sa.Column("reason", sa.String(128)),
        sa.Column("final_error", sa.String(2048)),
        sa.Column("task_payload", postgresql.JSONB),
        sa.Column("status", sa.String(32), index=True),
        sa.Column("operator_notes", sa.String(2048), nullable=True),
        sa.Column("retry_count", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime, nullable=True),
    )


def downgrade() -> None:
    """Drop dlq_entries table."""
    op.drop_table("dlq_entries")
