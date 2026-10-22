"""Immutable signed ROE versions, revocation fence and engagement-scoped ledger.

Revision ID: 0009
Revises: 0008

Historical sessions intentionally have no signed_authorizations rows. They
must NOT be backfilled or grandfathered: the runtime guard fails closed.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "signed_authorizations",
        sa.Column("authorization_id", sa.String(128), primary_key=True),
        sa.Column(
            "session_id", sa.String(64),
            sa.ForeignKey("session_states.session_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kid", sa.String(128), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_policy", JSONB(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by", sa.String(64), nullable=True),
        sa.Column("revocation_reason", sa.String(512), nullable=True),
        sa.UniqueConstraint("session_id", "version", name="uq_signed_authorization_version"),
        sa.CheckConstraint("version > 0", name="ck_signed_authorization_version"),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_signed_authorization_status",
        ),
        sa.CheckConstraint(
            "length(policy_sha256) = 64", name="ck_signed_authorization_hash",
        ),
    )
    op.create_index(
        "ix_signed_authorization_session_versions",
        "signed_authorizations", ["session_id", "version"],
    )
    op.create_index(
        "uq_signed_authorization_active",
        "signed_authorizations", ["session_id"], unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index("uq_signed_authorization_active", table_name="signed_authorizations")
    op.drop_index(
        "ix_signed_authorization_session_versions", table_name="signed_authorizations",
    )
    op.drop_table("signed_authorizations")
