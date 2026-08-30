"""Initial schema for AI-OSOP

Revision ID: 0001
Revises: 
Create Date: 2026-06-21

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial tables."""
    # approval_requests
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("task_id", sa.String(64), index=True),
        sa.Column("agent_id", sa.String(64)),
        sa.Column("action_type", sa.String(64)),
        sa.Column("target", sa.String(512)),
        sa.Column("payload_summary", sa.String(1024)),
        sa.Column("risk_assessment", sa.String(1024)),
        sa.Column("evidence", postgresql.JSONB),
        sa.Column("status", sa.String(16), index=True),
        sa.Column("operator_id", sa.String(64), nullable=True),
        sa.Column("operator_notes", sa.String(2048), nullable=True),
        sa.Column("requested_at", sa.DateTime),
        sa.Column("responded_at", sa.DateTime, nullable=True),
        sa.Column("engagement_id", sa.String(64), index=True),
    )

    # tasks
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("type", sa.String(64)),
        sa.Column("priority", sa.Integer),
        sa.Column("agent_type", sa.String(64)),
        sa.Column("payload", postgresql.JSONB),
        sa.Column("dependencies", postgresql.JSONB),
        sa.Column("max_retries", sa.Integer),
        sa.Column("timeout_seconds", sa.Integer),
        sa.Column("scope_check", sa.Boolean, default=True),
        sa.Column("approval_required", sa.Boolean, default=False),
        sa.Column("status", sa.String(32), index=True),
        sa.Column("result", postgresql.JSONB, nullable=True),
        sa.Column("retry_count", sa.Integer),
        sa.Column("created_at", sa.DateTime),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("engagement_id", sa.String(64), index=True),
        sa.Column("assigned_agent_id", sa.String(64), nullable=True),
    )

    # session_states
    op.create_table(
        "session_states",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("scope", postgresql.JSONB),
        sa.Column("roe", postgresql.JSONB),
        sa.Column("phase", sa.String(32)),
        sa.Column("agents", postgresql.JSONB),
        sa.Column("checkpoint_id", sa.String(64)),
        sa.Column("audit_log_position", sa.String(64)),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )

    # audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("event_id", sa.String(64), primary_key=True),
        sa.Column("timestamp", sa.DateTime, index=True),
        sa.Column("event_type", sa.String(64), index=True),
        sa.Column("severity", sa.String(16)),
        sa.Column("actor_type", sa.String(32)),
        sa.Column("actor_id", sa.String(64), index=True),
        sa.Column("action", postgresql.JSONB),
        sa.Column("result", postgresql.JSONB),
        sa.Column("context", postgresql.JSONB),
        sa.Column("integrity_hash", sa.String(128)),
        sa.Column("engagement_id", sa.String(64), index=True),
    )

    # user_sessions
    op.create_table(
        "user_sessions",
        sa.Column("pk", sa.String(160), primary_key=True),
        sa.Column("engagement_id", sa.String(80), index=True, nullable=False),
        sa.Column("user_label", sa.String(64), nullable=False),
        sa.Column("cookies", postgresql.JSONB, default=list),
        sa.Column("bearer_token", sa.Text, default=""),
        sa.Column("local_storage", postgresql.JSONB, default=dict),
        sa.Column("session_storage", postgresql.JSONB, default=dict),
        sa.Column("csrf_token", sa.String(512), default=""),
        sa.Column("extra_headers", postgresql.JSONB, default=dict),
        sa.Column("user_agent", sa.String(512), default=""),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_blob", postgresql.JSONB, default=dict),
    )


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table("user_sessions")
    op.drop_table("audit_logs")
    op.drop_table("session_states")
    op.drop_table("tasks")
    op.drop_table("approval_requests")
