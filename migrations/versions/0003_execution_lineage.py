"""Persist flow/subtask/action execution lineage.

Revision ID: 0003
Revises: 0002
"""

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.is_offline_mode() or not any(
        col["name"] == "last_accessed"
        for col in sa.inspect(op.get_bind()).get_columns("session_states")
    ):
        op.add_column(
            "session_states", sa.Column("last_accessed", sa.DateTime, nullable=True)
        )
    op.create_table(
        "execution_flows",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("objective", sa.String(2048), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_execution_flows_engagement_id", "execution_flows", ["engagement_id"])
    op.add_column("tasks", sa.Column("flow_id", sa.String(64), nullable=True))
    op.add_column("tasks", sa.Column("subtask_id", sa.String(64), nullable=True))
    op.add_column("tasks", sa.Column("parent_task_id", sa.String(64), nullable=True))
    op.create_index("ix_tasks_flow_id", "tasks", ["flow_id"])

    op.create_table(
        "execution_subtasks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), sa.ForeignKey("execution_flows.id", ondelete="CASCADE"), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.String(4096), nullable=False),
        sa.Column("task_type", sa.String(128), nullable=False),
        sa.Column("agent_type", sa.String(64), nullable=False),
        sa.Column("approval_required", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("order", sa.Integer, nullable=False),
        sa.Column("dependencies", postgresql.JSONB, nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("refinement_count", sa.Integer, nullable=False),
        sa.Column("result_summary", sa.String(4096), nullable=True),
        sa.Column("execution_task_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_execution_subtasks_flow_task", "execution_subtasks", ["flow_id", "task_id"])
    op.create_index("ix_execution_subtasks_engagement_id", "execution_subtasks", ["engagement_id"])
    op.create_table(
        "execution_actions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=True),
        sa.Column("task_id", sa.String(64), nullable=True),
        sa.Column("subtask_id", sa.String(64), nullable=True),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("safe_metadata", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_execution_actions_engagement_created", "execution_actions", ["engagement_id", "created_at"])
    op.create_index("ix_execution_actions_task_id", "execution_actions", ["task_id"])


def downgrade() -> None:
    op.drop_index("ix_execution_actions_task_id", table_name="execution_actions")
    op.drop_index("ix_execution_actions_engagement_created", table_name="execution_actions")
    op.drop_table("execution_actions")
    op.drop_index("ix_execution_subtasks_engagement_id", table_name="execution_subtasks")
    op.drop_index("ix_execution_subtasks_flow_task", table_name="execution_subtasks")
    op.drop_table("execution_subtasks")
    op.drop_index("ix_tasks_flow_id", table_name="tasks")
    op.drop_column("tasks", "parent_task_id")
    op.drop_column("tasks", "subtask_id")
    op.drop_column("tasks", "flow_id")
    op.drop_index("ix_execution_flows_engagement_id", table_name="execution_flows")
    op.drop_table("execution_flows")
    # Pre-existing databases may already have last_accessed; retain it.
