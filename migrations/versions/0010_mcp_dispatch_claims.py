"""Persist globally fenced MCP dispatch identities and reconciliation state.

Revision ID: 0010
Revises: 0009

Legacy in-memory remote requests are NOT backfilled as verified: on restart
they remain uncertain and are never silently granted dispatch ownership.
"""

from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "supervision_mcp_dispatches",
        sa.Column("server_id", sa.String(128), nullable=False),
        sa.Column("request_id", sa.String(128), nullable=False),
        sa.Column(
            "engagement_id", sa.String(64),
            sa.ForeignKey("session_states.session_id"), nullable=False,
        ),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("server_id", "request_id"),
        sa.CheckConstraint("authorization_version > 0", name="ck_mcp_dispatch_auth_version"),
    )
    op.create_index(
        "ix_supervision_mcp_dispatch_task",
        "supervision_mcp_dispatches", ["engagement_id", "task_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_supervision_mcp_dispatch_task", table_name="supervision_mcp_dispatches")
    op.drop_table("supervision_mcp_dispatches")
