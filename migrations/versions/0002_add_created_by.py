"""Add created_by to session_states

For existing deployments that upgraded from schema before created_by
was added to SessionStateORM.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-21

"""
from alembic import context, op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add created_by only when upgrading a truly old schema.

    Revision 0001 already included created_by in some installations.
    """
    if not context.is_offline_mode() and not any(
        col["name"] == "created_by"
        for col in sa.inspect(op.get_bind()).get_columns("session_states")
    ):
        op.add_column(
            "session_states", sa.Column("created_by", sa.String(64), nullable=True)
        )


def downgrade() -> None:
    # The original 0001 includes this column, so a downgrade must retain it.
    pass
