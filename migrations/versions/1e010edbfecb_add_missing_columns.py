"""Add missing columns

Revision ID: 1e010edbfecb
Revises: 0003
Create Date: 2026-07-07 22:33:15.186326

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1e010edbfecb'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add the missing last_accessed column to session_states
    op.add_column('session_states', sa.Column('last_accessed', sa.DateTime(), nullable=True))


def downgrade() -> None:
    # Remove the last_accessed column from session_states
    op.drop_column('session_states', 'last_accessed')
