"""Allow durable task status values longer than the original 16 characters.

Revision ID: 0012
Revises: 0011

The active approval workflow writes `awaiting_approval` (17 characters).
The 0001 schema's VARCHAR(16) rejected the state at the PostgreSQL boundary,
even though in-memory unit tests accepted it. Do not rewrite 0001/legacy data.
"""

from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "tasks", "status", existing_type=sa.String(length=16),
        type_=sa.String(length=32), existing_nullable=True,
    )


def downgrade() -> None:
    # Fail rather than silently truncate persisted approval/unknown statuses.
    oversized = op.get_bind().execute(sa.text(
        "SELECT EXISTS (SELECT 1 FROM tasks WHERE length(status) > 16)"
    )).scalar()
    if oversized:
        raise RuntimeError(
            "Cannot downgrade tasks.status: persisted statuses exceed 16 characters"
        )
    op.alter_column(
        "tasks", "status", existing_type=sa.String(length=32),
        type_=sa.String(length=16), existing_nullable=True,
    )
