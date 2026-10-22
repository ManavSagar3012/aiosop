"""Durable shared-PostgreSQL operator credential and account revocation.

Revision ID: 0014
Revises: 0013
"""

from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operator_token_revocations",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="ck_revocation_digest"),
    )
    op.create_index(
        "ix_operator_revocations_actor_expiry", "operator_token_revocations",
        ["actor_id", "expires_at"],
    )
    op.create_table(
        "operator_subject_controls",
        sa.Column("actor_id", sa.String(64), primary_key=True),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by", sa.String(64), nullable=False),
    )
    op.create_table(
        "operator_auth_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("subject_id", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_operator_auth_events_subject", "operator_auth_events",
        ["subject_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_operator_auth_events_subject", table_name="operator_auth_events")
    op.drop_table("operator_auth_events")
    op.drop_table("operator_subject_controls")
    op.drop_index("ix_operator_revocations_actor_expiry", table_name="operator_token_revocations")
    op.drop_table("operator_token_revocations")
