"""Add created_by to session_states

For existing deployments that upgraded from schema before created_by
was added to SessionStateORM.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-21

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add created_by column to session_states."""
    op.add_column(
        "session_states",
        sa.Column("created_by", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    """Remove created_by column from session_states."""
    op.drop_column("session_states", "created_by")
