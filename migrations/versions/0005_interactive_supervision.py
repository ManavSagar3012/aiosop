"""Leased human inbox and fenced execution ownership.

Revision ID: 0005
Revises: 0004
"""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "supervision_messages",
        sa.Column("delivery_state", sa.String(24), nullable=False, server_default="queued"),
    )
    op.add_column("supervision_messages", sa.Column("inbox_consumer_id", sa.String(128)))
    op.add_column("supervision_messages", sa.Column("inbox_leased_until", sa.DateTime))
    op.add_column(
        "supervision_messages",
        sa.Column("delivery_attempts", sa.Integer, nullable=False, server_default="0"),
    )
    op.add_column("supervision_messages", sa.Column("consumed_at", sa.DateTime))
    # Existing non-operator history is never eligible for operator inbox delivery.
    op.execute(
        "UPDATE supervision_messages SET delivery_state='not_applicable' WHERE role <> 'operator'"
    )
    op.create_index(
        "ix_supervision_messages_inbox",
        "supervision_messages",
        ["engagement_id", "task_id", "delivery_state", "inbox_leased_until"],
    )
    op.create_table(
        "supervision_execution_leases",
        sa.Column("task_id", sa.String(64), primary_key=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id"),
            nullable=False,
        ),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("owner_id", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_supervision_execution_leases_owner",
        "supervision_execution_leases",
        ["engagement_id", "owner_id", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_supervision_execution_leases_owner", table_name="supervision_execution_leases"
    )
    op.drop_table("supervision_execution_leases")
    op.drop_index("ix_supervision_messages_inbox", table_name="supervision_messages")
    op.drop_column("supervision_messages", "consumed_at")
    op.drop_column("supervision_messages", "delivery_attempts")
    op.drop_column("supervision_messages", "inbox_leased_until")
    op.drop_column("supervision_messages", "inbox_consumer_id")
    op.drop_column("supervision_messages", "delivery_state")
