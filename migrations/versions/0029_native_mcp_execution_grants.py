"""One-use, signed native MCP execution grants for inert authority status only.

Revision ID: 0029
Revises: 0028
"""

import sqlalchemy as sa
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_mcp_execution_grants",
        sa.Column("grant_id", sa.String(36), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(64),
            sa.ForeignKey("flow_mcp_action_dispatches.action_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("request_id", sa.String(80), nullable=False, unique=True),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("subtask_id", sa.String(64), nullable=False),
        sa.Column("owner_id", sa.String(64), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("approval_id", sa.String(64), nullable=False),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("lease_owner_id", sa.String(128), nullable=False),
        sa.Column("server_id", sa.String(128), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("side_effect_class", sa.String(32), nullable=False),
        sa.Column("parameters_sha256", sa.String(64), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("resource_sha256", sa.String(64), nullable=True),
        sa.Column("intent_sha256", sa.String(64), nullable=False),
        sa.Column("kid", sa.String(64), nullable=False),
        sa.Column("claims_sha256", sa.String(64), nullable=False),
        sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('issued','redeemed','unknown','revoked')",
            name="ck_native_mcp_grant_status",
        ),
        sa.CheckConstraint(
            "tool_name='authority_status' AND side_effect_class='READ_ONLY'",
            name="ck_native_mcp_grant_inert_tool",
        ),
        sa.CheckConstraint(
            "revision>=1 AND flow_revision>=0 AND authorization_version>=1 AND "
            "expires_at>issued_at AND expires_at-issued_at<=60",
            name="ck_native_mcp_grant_revision_expiry",
        ),
        sa.CheckConstraint(
            "authorization_sha256 ~ '^[0-9a-f]{64}$' AND "
            "parameters_sha256 ~ '^[0-9a-f]{64}$' AND "
            "manifest_sha256 ~ '^[0-9a-f]{64}$' AND "
            "intent_sha256 ~ '^[0-9a-f]{64}$' AND "
            "claims_sha256 ~ '^[0-9a-f]{64}$' AND "
            "signature_sha256 ~ '^[0-9a-f]{64}$' AND "
            "(resource_sha256 IS NULL OR resource_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_native_mcp_grant_digests",
        ),
        sa.CheckConstraint("grant_id ~ '^ngr-[0-9a-f]{32}$'", name="ck_native_mcp_grant_id"),
    )
    op.create_index(
        "ix_native_mcp_grants_tenant_flow",
        "native_mcp_execution_grants",
        ["engagement_id", "flow_id", "task_id"],
    )
    op.create_table(
        "native_mcp_execution_grant_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("native_mcp_execution_grants.grant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(80), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("claims_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("grant_id", "revision", name="uq_native_mcp_grant_event_revision"),
        sa.CheckConstraint(
            "kind IN ('issued','redeemed','unknown','revoked')",
            name="ck_native_mcp_grant_event_kind",
        ),
        sa.CheckConstraint(
            "status IN ('issued','redeemed','unknown','revoked')",
            name="ck_native_mcp_grant_event_status",
        ),
        sa.CheckConstraint("revision >= 1", name="ck_native_mcp_grant_event_revision"),
        sa.CheckConstraint(
            "claims_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_native_mcp_grant_event_digest",
        ),
    )
    op.create_index(
        "ix_native_mcp_grant_events_tenant",
        "native_mcp_execution_grant_events",
        ["engagement_id", "flow_id", "created_at"],
    )
    op.execute(
        "CREATE TRIGGER trg_native_mcp_grant_events_immutable "
        "BEFORE UPDATE OR DELETE ON native_mcp_execution_grant_events "
        "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_native_mcp_grant_events_immutable " "ON native_mcp_execution_grant_events"
    )
    op.drop_index(
        "ix_native_mcp_grant_events_tenant", table_name="native_mcp_execution_grant_events"
    )
    op.drop_table("native_mcp_execution_grant_events")
    op.drop_index("ix_native_mcp_grants_tenant_flow", table_name="native_mcp_execution_grants")
    op.drop_table("native_mcp_execution_grants")
