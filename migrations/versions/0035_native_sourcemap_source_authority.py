"""Immutable one-use issuer for a separately reviewed original SourceMap artifact.

No target fetch or source material is disclosed. This extends the current
0034 Browser chain; each original 0027 Action/request is redeemable once.
"""

import sqlalchemy as sa
from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_sourcemap_source_preflights",
        sa.Column("preflight_id", sa.String(36), primary_key=True),
        sa.Column("request_id", sa.String(80), nullable=False, unique=True),
        sa.Column(
            "action_id",
            sa.String(64),
            sa.ForeignKey("flow_mcp_action_dispatches.action_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("subtask_id", sa.String(64), nullable=False),
        sa.Column("owner_id", sa.String(64), nullable=False),
        sa.Column("server_id", sa.String(128), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("approval_id", sa.String(64), nullable=False),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("kid", sa.String(48), nullable=False),
        sa.Column("claims_sha256", sa.String(64), nullable=False),
        sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column(
            "committed_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "version=1 AND server_id='source-map-mcp' AND "
            "tool_name='inspect_local_original_sourcemap' AND authorization_version>=1",
            name="ck_native_sourcemap_source_identity",
        ),
        sa.CheckConstraint(
            "issued_at>0 AND expires_at>issued_at AND expires_at<=issued_at+10",
            name="ck_native_sourcemap_source_expiry",
        ),
        sa.CheckConstraint(
            "artifact_sha256 ~ '^[a-f0-9]{64}$' AND "
            "manifest_sha256 ~ '^[a-f0-9]{64}$' AND "
            "authorization_sha256 ~ '^[a-f0-9]{64}$' AND "
            "claims_sha256 ~ '^[a-f0-9]{64}$' AND "
            "signature_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_native_sourcemap_source_hashes",
        ),
    )
    op.create_index(
        "ix_native_sourcemap_source_flow",
        "native_sourcemap_source_preflights",
        ["engagement_id", "flow_id", "task_id"],
    )
    op.execute(
        "CREATE TRIGGER trg_native_sourcemap_source_immutable BEFORE UPDATE OR DELETE "
        "ON native_sourcemap_source_preflights FOR EACH ROW "
        "EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_native_sourcemap_source_immutable "
        "ON native_sourcemap_source_preflights"
    )
    op.drop_index(
        "ix_native_sourcemap_source_flow", table_name="native_sourcemap_source_preflights"
    )
    op.drop_table("native_sourcemap_source_preflights")
