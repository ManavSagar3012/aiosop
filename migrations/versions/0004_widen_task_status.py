"""Widen tasks.status to varchar(32) and tasks.error to text.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-30

The tasks table was created with status varchar(16), but the task state
machine uses 'awaiting_approval' (17 chars). Every exploit-class task forces
approval_required=True and parks as 'awaiting_approval', so EVERY persist of a
gated exploit task failed with StringDataRightTruncationError — the approval
gate could not survive a restart and each write spammed DBAPIErrors
(found live 2026-08-30 while driving an exploit validation through the gate).

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "0003"


def upgrade() -> None:
    """Widen tasks.status; make tasks.error unbounded."""
    op.alter_column("tasks", "status",
                    existing_type=sa.String(16), type_=sa.String(32))
    op.alter_column("tasks", "error",
                    existing_type=sa.String(512), type_=sa.Text())


def downgrade() -> None:
    """Restore original (narrower) column types."""
    op.alter_column("tasks", "error",
                    existing_type=sa.Text(), type_=sa.String(512))
    op.alter_column("tasks", "status",
                    existing_type=sa.String(32), type_=sa.String(16))
