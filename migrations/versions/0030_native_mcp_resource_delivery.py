"""One-shot, immutable audit of read-only native MCP artifact byte offerings.

Revises: 0029.  Offering bytes is NOT proof a remote worker received them.
The original 0027 Action and redeemed 0029 grant remain irreversible UNKNOWN
and consumed respectively.  Never replay after a lost HTTP acknowledgement.
"""

from alembic import op
import sqlalchemy as sa

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_mcp_resource_offers",
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("native_mcp_execution_grants.grant_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(80), nullable=False, unique=True),
        sa.Column("server_id", sa.String(128), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("claims_sha256", sa.String(64), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("total_size_bytes", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="offered"),
        sa.Column("offered_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "status='offered' AND file_count BETWEEN 1 AND 16 "
            "AND total_size_bytes BETWEEN 1 AND 4194304",
            name="ck_native_resource_offer_bounded",
        ),
        sa.CheckConstraint(
            "manifest_sha256 ~ '^[0-9a-f]{64}$' " "AND claims_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_native_resource_offer_hashes",
        ),
    )
    op.create_index(
        "ix_native_resource_offer_owner",
        "native_mcp_resource_offers",
        ["engagement_id", "flow_id", "action_id"],
    )
    op.execute(
        "CREATE TRIGGER trg_native_resource_offer_immutable "
        "BEFORE UPDATE OR DELETE ON native_mcp_resource_offers "
        "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_native_resource_offer_immutable " "ON native_mcp_resource_offers")
    op.drop_index("ix_native_resource_offer_owner", table_name="native_mcp_resource_offers")
    op.drop_table("native_mcp_resource_offers")
