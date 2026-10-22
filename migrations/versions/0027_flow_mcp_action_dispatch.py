"""Independent signed Flow MCP action reservations and immutable status history.

Revision ID: 0027
Revises: 0026

Reservation grants exactly one caller a pre-dispatch token. A committed
dispatch attempt remains UNKNOWN until a current trusted provider receipt is
verified; process failure never returns a token or retries an external effect.
"""

import sqlalchemy as sa
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "flow_mcp_action_dispatches",
        sa.Column("action_id", sa.String(64), primary_key=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "flow_id",
            sa.String(64),
            sa.ForeignKey("execution_flows.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "task_id", sa.String(64), sa.ForeignKey("tasks.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "subtask_id",
            sa.String(64),
            sa.ForeignKey("execution_subtasks.id", ondelete="RESTRICT"),
            nullable=False,
        ),
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
        sa.Column("declaration_sha256", sa.String(64), nullable=False),
        sa.Column("parameters_sha256", sa.String(64), nullable=False),
        sa.Column("safe_parameters", sa.JSON(), nullable=False),
        sa.Column("intent_sha256", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(80), nullable=False, unique=True),
        sa.Column("reservation_token_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "cancel_requested", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("receipt_sha256", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "flow_revision >= 0 AND authorization_version >= 1 AND revision >= 1",
            name="ck_flow_mcp_action_revisions",
        ),
        sa.CheckConstraint(
            "status IN ('prepared','reserved','unknown','finished','cancelled')",
            name="ck_flow_mcp_action_status",
        ),
        sa.CheckConstraint(
            "side_effect_class IN ('READ_ONLY','RECON_ACTIVE','INVASIVE_EXPLOIT')",
            name="ck_flow_mcp_action_effect",
        ),
        sa.CheckConstraint(
            "authorization_sha256 ~ '^[a-f0-9]{64}$' AND declaration_sha256 ~ '^[a-f0-9]{64}$' AND parameters_sha256 ~ '^[a-f0-9]{64}$' AND intent_sha256 ~ '^[a-f0-9]{64}$' AND reservation_token_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_flow_mcp_action_digests",
        ),
        sa.CheckConstraint(
            "receipt_sha256 IS NULL OR receipt_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_flow_mcp_action_receipt",
        ),
    )
    op.create_index(
        "ix_flow_mcp_actions_tenant_flow",
        "flow_mcp_action_dispatches",
        ["engagement_id", "flow_id", "task_id"],
    )
    op.create_table(
        "flow_mcp_action_dispatch_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(64),
            sa.ForeignKey("flow_mcp_action_dispatches.action_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("intent_sha256", sa.String(64), nullable=False),
        sa.Column("receipt_sha256", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("action_id", "revision", name="uq_flow_mcp_action_event_revision"),
        sa.CheckConstraint("revision >= 1", name="ck_flow_mcp_action_event_revision"),
        sa.CheckConstraint(
            "kind IN ('prepared','reserved','dispatch_attempted','cancelled_before_dispatch','cancel_requested_unknown','reconciled','status_unknown')",
            name="ck_flow_mcp_action_event_kind",
        ),
        sa.CheckConstraint(
            "status IN ('prepared','reserved','unknown','finished','cancelled')",
            name="ck_flow_mcp_action_event_status",
        ),
        sa.CheckConstraint(
            "intent_sha256 ~ '^[a-f0-9]{64}$' AND (receipt_sha256 IS NULL OR receipt_sha256 ~ '^[a-f0-9]{64}$')",
            name="ck_flow_mcp_action_event_sha",
        ),
    )
    op.create_index(
        "ix_flow_mcp_action_event_tenant",
        "flow_mcp_action_dispatch_events",
        ["engagement_id", "flow_id", "created_at"],
    )
    op.execute(
        "CREATE TRIGGER trg_flow_mcp_action_events_immutable "
        "BEFORE UPDATE OR DELETE ON flow_mcp_action_dispatch_events "
        "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_flow_mcp_action_events_immutable ON flow_mcp_action_dispatch_events"
    )
    op.drop_index("ix_flow_mcp_action_event_tenant", table_name="flow_mcp_action_dispatch_events")
    op.drop_table("flow_mcp_action_dispatch_events")
    op.drop_index("ix_flow_mcp_actions_tenant_flow", table_name="flow_mcp_action_dispatches")
    op.drop_table("flow_mcp_action_dispatches")
