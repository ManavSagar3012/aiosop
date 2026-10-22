"""Immutable two-source target-side audit digest for candidate evidence.

Revision ID: 0017
Revises: 0016

The digest is not a finding-verification or release approval flag.
"""

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "target_authority_assertions",
        sa.Column("audit_corroboration_sha256", sa.String(64), nullable=True),
    )
    op.create_check_constraint(
        "ck_target_authority_audit_corroboration_sha",
        "target_authority_assertions",
        "audit_corroboration_sha256 IS NULL OR audit_corroboration_sha256 ~ '^[0-9a-f]{64}$'",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_target_authority_audit_corroboration_sha", "target_authority_assertions", type_="check"
    )
    op.drop_column("target_authority_assertions", "audit_corroboration_sha256")
