"""Immutable one-shot self-attested original-resource sandbox stage readback.

Revision ID: 0032
Revises: 0031

Worker signature proves custody of a configured separate attestation key, NOT
independent target-owner verification or container-orchestrator attestation.
"""

import sqlalchemy as sa
from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_mcp_stage_receipts",
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("native_mcp_resource_offers.grant_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("request_id", sa.String(80), nullable=False, unique=True),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("server_id", sa.String(128), nullable=False),
        sa.Column("resource_sha256", sa.String(64), nullable=False),
        sa.Column("folder_staging_sha256", sa.String(64), nullable=False),
        sa.Column("readback_sha256", sa.String(64), nullable=False),
        sa.Column("claims_sha256", sa.String(64), nullable=False),
        sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("worker_key_id", sa.String(64), nullable=False),
        sa.Column("verified_at", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="worker_reported"),
        sa.Column("recorded_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "status='worker_reported' AND "
            "resource_sha256 ~ '^[a-f0-9]{64}$' AND "
            "folder_staging_sha256 ~ '^[a-f0-9]{64}$' AND "
            "readback_sha256 ~ '^[a-f0-9]{64}$' AND "
            "claims_sha256 ~ '^[a-f0-9]{64}$' AND "
            "signature_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_native_worker_stage_receipt_integrity",
        ),
    )
    op.create_index(
        "ix_native_worker_stage_tenant",
        "native_mcp_stage_receipts",
        ["engagement_id", "flow_id", "action_id"],
    )
    op.execute(
        "CREATE TRIGGER trg_native_worker_stage_receipt_immutable "
        "BEFORE UPDATE OR DELETE ON native_mcp_stage_receipts FOR EACH ROW "
        "EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_native_worker_stage_receipt_immutable " "ON native_mcp_stage_receipts"
    )
    op.drop_index(
        "ix_native_worker_stage_tenant",
        table_name="native_mcp_stage_receipts",
    )
    op.drop_table("native_mcp_stage_receipts")
