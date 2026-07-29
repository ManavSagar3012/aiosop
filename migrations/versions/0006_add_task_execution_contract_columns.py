"""Persist task MCP contracts and terminal errors.

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-29

Task-level MCP requirements prevent a stale server/tool deployment from
consuming an agent timeout.  They are only safe if the warm-store recovery path
retains them.  The ``error`` column also makes terminal failure classification
queryable without decoding the result JSON.  Both additions are guarded because
fresh databases created from the ORM already contain them.
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def _task_columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if "tasks" not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns("tasks")}


def upgrade() -> None:
    columns = _task_columns()
    if not columns:
        return
    if "mcp_requirements" not in columns:
        op.add_column(
            "tasks",
            sa.Column("mcp_requirements", sa.JSON(), nullable=True, server_default=sa.text("'[]'")),
        )
    if "error" not in columns:
        op.add_column("tasks", sa.Column("error", sa.String(length=2048), nullable=True))


def downgrade() -> None:
    columns = _task_columns()
    if "error" in columns:
        op.drop_column("tasks", "error")
    if "mcp_requirements" in columns:
        op.drop_column("tasks", "mcp_requirements")
