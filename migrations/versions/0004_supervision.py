"""Durable operator supervision, task attempts and transactional event outbox.

Revision ID: 0004
Revises: 0003
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "supervision_events",
        sa.Column("sequence", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id"),
            nullable=False,
        ),
        sa.Column("task_id", sa.String(64)),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.Column("idempotency_key", sa.String(128)),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("engagement_id", "idempotency_key", name="uq_supervision_event_dedupe"),
    )
    op.create_index(
        "ix_supervision_events_timeline", "supervision_events", ["engagement_id", "sequence"]
    )
    op.create_index(
        "ix_supervision_events_task", "supervision_events", ["engagement_id", "task_id", "sequence"]
    )
    op.create_table(
        "supervision_messages",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id"),
            nullable=False,
        ),
        sa.Column("session_id", sa.String(64), nullable=False),
        sa.Column("task_id", sa.String(64)),
        sa.Column("role", sa.String(24), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("content", sa.String(4096), nullable=False),
        sa.Column("idempotency_key", sa.String(128)),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "engagement_id", "session_id", "idempotency_key", name="uq_supervision_message_dedupe"
        ),
    )
    op.create_index(
        "ix_supervision_messages_thread",
        "supervision_messages",
        ["engagement_id", "session_id", "created_at"],
    )
    op.create_table(
        "supervision_controls",
        sa.Column("request_id", sa.String(128), primary_key=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id"),
            nullable=False,
        ),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("receipt", postgresql.JSONB),
        sa.Column("revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_supervision_controls_task",
        "supervision_controls",
        ["engagement_id", "task_id", "created_at"],
    )
    op.create_table(
        "supervision_attempts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id"),
            nullable=False,
        ),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("attempt", sa.Integer, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("external_id", sa.String(128)),
        sa.Column("receipt", postgresql.JSONB),
        sa.Column("revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "engagement_id", "task_id", "attempt", name="uq_supervision_attempt_number"
        ),
    )
    op.create_index(
        "ix_supervision_attempts_task",
        "supervision_attempts",
        ["engagement_id", "task_id", "attempt"],
    )
    op.create_table(
        "supervision_outbox",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "event_id",
            sa.String(64),
            sa.ForeignKey("supervision_events.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("topic", sa.String(64), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("lease_id", sa.String(64)),
        sa.Column("leased_until", sa.DateTime),
        sa.Column("delivered_at", sa.DateTime),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_supervision_outbox_pending", "supervision_outbox", ["delivered_at", "leased_until"]
    )


def downgrade() -> None:
    op.drop_table("supervision_outbox")
    op.drop_table("supervision_attempts")
    op.drop_table("supervision_controls")
    op.drop_table("supervision_messages")
    op.drop_table("supervision_events")
