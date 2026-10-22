"""Durable admission and provider-reported model usage.

Revision ID: 0007
Revises: 0006
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "supervision_model_usage",
        sa.Column("call_id", sa.String(64), primary_key=True),
        sa.Column("engagement_id", sa.String(64), sa.ForeignKey("session_states.session_id"), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=True),
        sa.Column("model", sa.String(90), nullable=False),
        sa.Column("operation", sa.String(24), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("input_tokens", sa.BigInteger(), nullable=True),
        sa.Column("output_tokens", sa.BigInteger(), nullable=True),
        sa.Column("billed_cost_usd", sa.Numeric(18, 8), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_supervision_model_usage_engagement", "supervision_model_usage", ["engagement_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_supervision_model_usage_engagement", table_name="supervision_model_usage")
    op.drop_table("supervision_model_usage")
