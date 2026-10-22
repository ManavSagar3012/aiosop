"""Immutable central one-shot source admission for original native browser Action."""

import sqlalchemy as sa
from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_browser_source_preflights",
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
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("url_sha256", sa.String(64), nullable=False),
        sa.Column("origin", sa.String(260), nullable=False),
        sa.Column("user_label", sa.String(64), nullable=False),
        sa.Column("evidence_mode", sa.String(32), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("approval_id", sa.String(64), nullable=False),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("kid", sa.String(48), nullable=False),
        sa.Column("claims_sha256", sa.String(64), nullable=False),
        sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("committed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "version=1 AND server_id='browser-mcp' AND tool_name='execute' "
            "AND action='navigate' AND authorization_version>=1 "
            "AND evidence_mode IN ('none','screenshot_dom_har')",
            name="ck_native_browser_source_identity",
        ),
        sa.CheckConstraint(
            "issued_at>0 AND expires_at>issued_at AND expires_at<=issued_at+10",
            name="ck_native_browser_source_expiry",
        ),
        sa.CheckConstraint(
            "url_sha256 ~ '^[a-f0-9]{64}$' AND "
            "authorization_sha256 ~ '^[a-f0-9]{64}$' AND "
            "claims_sha256 ~ '^[a-f0-9]{64}$' AND "
            "signature_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_native_browser_source_hashes",
        ),
    )
    op.create_index(
        "ix_native_browser_source_flow",
        "native_browser_source_preflights",
        ["engagement_id", "flow_id", "task_id"],
    )
    op.execute(
        "CREATE TRIGGER trg_native_browser_source_immutable BEFORE UPDATE OR DELETE "
        "ON native_browser_source_preflights FOR EACH ROW "
        "EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_native_browser_source_immutable ON native_browser_source_preflights"
    )
    op.drop_index("ix_native_browser_source_flow", table_name="native_browser_source_preflights")
    op.drop_table("native_browser_source_preflights")
