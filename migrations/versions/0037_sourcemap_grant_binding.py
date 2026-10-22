"""One-use SourceMap post-commit 0035 to 0029 provenance join; no issuer.

Revision ID: 0037
Revises: 0036

The two independent signed capabilities must ALREADY be committed before a
central-only verifier may insert this immutable binding. This table never
issues, redeems, stages, offers bytes, or replays a 0027 UNKNOWN Action.
"""

import sqlalchemy as sa
from alembic import op

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_sourcemap_grant_bindings",
        sa.Column("binding_id", sa.String(36), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(64),
            sa.ForeignKey("flow_mcp_action_dispatches.action_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("request_id", sa.String(80), nullable=False, unique=True),
        sa.Column(
            "preflight_id",
            sa.String(36),
            sa.ForeignKey("native_sourcemap_source_preflights.preflight_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("native_mcp_execution_grants.grant_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "artifact_id",
            sa.String(64),
            sa.ForeignKey("flow_artifacts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("subtask_id", sa.String(64), nullable=False),
        sa.Column("owner_id", sa.String(64), nullable=False),
        sa.Column("reviewer_id", sa.String(64), nullable=False),
        sa.Column("approval_id", sa.String(64), nullable=False),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("lease_owner_id", sa.String(128), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("resource_manifest_sha256", sa.String(64), nullable=False),
        sa.Column("declaration_sha256", sa.String(64), nullable=False),
        sa.Column("parameters_sha256", sa.String(64), nullable=False),
        sa.Column("preflight_claims_sha256", sa.String(64), nullable=False),
        sa.Column("preflight_signature_sha256", sa.String(64), nullable=False),
        sa.Column("grant_claims_sha256", sa.String(64), nullable=False),
        sa.Column("grant_signature_sha256", sa.String(64), nullable=False),
        sa.Column("join_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="bound_only"),
        sa.Column("committed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "binding_id ~ '^snb-[0-9a-f]{32}$' AND "
            "preflight_id ~ '^nsp-[0-9a-f]{32}$' AND "
            "grant_id ~ '^ngr-[0-9a-f]{32}$' AND "
            "artifact_id ~ '^artifact-[0-9a-f]{32}$'",
            name="ck_sourcemap_grant_binding_ids",
        ),
        sa.CheckConstraint(
            "status='bound_only' AND flow_revision>=0 AND authorization_version>=1 "
            "AND owner_id<>reviewer_id",
            name="ck_sourcemap_grant_binding_inert",
        ),
        sa.CheckConstraint(
            "authorization_sha256 ~ '^[0-9a-f]{64}$' AND "
            "artifact_sha256 ~ '^[0-9a-f]{64}$' AND "
            "resource_manifest_sha256 ~ '^[0-9a-f]{64}$' AND "
            "declaration_sha256 ~ '^[0-9a-f]{64}$' AND "
            "parameters_sha256 ~ '^[0-9a-f]{64}$' AND "
            "preflight_claims_sha256 ~ '^[0-9a-f]{64}$' AND "
            "preflight_signature_sha256 ~ '^[0-9a-f]{64}$' AND "
            "grant_claims_sha256 ~ '^[0-9a-f]{64}$' AND "
            "grant_signature_sha256 ~ '^[0-9a-f]{64}$' AND "
            "join_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_sourcemap_grant_binding_hashes",
        ),
    )
    op.create_index(
        "ix_sourcemap_grant_binding_tenant_flow",
        "native_sourcemap_grant_bindings",
        ["engagement_id", "flow_id", "task_id"],
    )
    op.execute(
        "CREATE TRIGGER trg_sourcemap_grant_binding_immutable "
        "BEFORE UPDATE OR DELETE ON native_sourcemap_grant_bindings "
        "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    # Never discard an already-committed, immutable post-commit one-shot join.
    conn = op.get_bind()
    if op.get_context().as_sql or conn.dialect.name != "postgresql" or not conn.in_transaction():
        raise RuntimeError("0037 downgrade requires a live transactional PostgreSQL connection")
    conn.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
    conn.exec_driver_sql("LOCK TABLE native_sourcemap_grant_bindings IN ACCESS EXCLUSIVE MODE")
    if conn.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM native_sourcemap_grant_bindings) ")
    ).scalar_one():
        raise RuntimeError("0037 downgrade denied: immutable SourceMap grant bindings exist")
    op.execute(
        "DROP TRIGGER trg_sourcemap_grant_binding_immutable ON native_sourcemap_grant_bindings"
    )
    op.drop_index(
        "ix_sourcemap_grant_binding_tenant_flow", table_name="native_sourcemap_grant_bindings"
    )
    op.drop_table("native_sourcemap_grant_bindings")
