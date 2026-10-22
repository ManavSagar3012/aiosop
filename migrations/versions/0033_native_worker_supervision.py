"""Independent, immutable observer testimony for isolated native MCP workers.

The observer ledger is distinct from a worker's self-attested 0032 receipt.
Neither changes an original 0027 UNKNOWN Action or authorizes a target effect.
"""

import sqlalchemy as sa
from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SEQUENCE native_mcp_worker_epoch_seq AS bigint NO CYCLE")
    op.create_table(
        "native_mcp_worker_supervisions",
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("native_mcp_execution_grants.grant_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("request_id", sa.String(80), nullable=False, unique=True),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=False),
        sa.Column("subtask_id", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False, unique=True),
        sa.Column("owner_id", sa.String(64), nullable=False),
        sa.Column("server_id", sa.String(128), nullable=False),
        sa.Column("worker_id", sa.String(96), nullable=False, unique=True),
        sa.Column("container_id", sa.String(64), nullable=True, unique=True),
        sa.Column("supervisor_id", sa.String(96), nullable=False),
        sa.Column("supervisor_kid", sa.String(48), nullable=False),
        sa.Column("approval_id", sa.String(64), nullable=False),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("lease_owner_id", sa.String(128), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("grant_claims_sha256", sa.String(64), nullable=False),
        sa.Column("resource_sha256", sa.String(64), nullable=True),
        sa.Column("folder_staging_sha256", sa.String(64), nullable=True),
        sa.Column("epoch", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "epoch>0 AND revision>=1 AND flow_revision>=0 AND authorization_version>=1",
            name="ck_native_worker_versions",
        ),
        sa.CheckConstraint(
            "state IN ('provisioned','running','terminating','terminated','unknown','reaped')",
            name="ck_native_worker_state",
        ),
        sa.CheckConstraint(
            "grant_claims_sha256 ~ '^[a-f0-9]{64}$' AND authorization_sha256 ~ '^[a-f0-9]{64}$' AND (resource_sha256 IS NULL OR resource_sha256 ~ '^[a-f0-9]{64}$') AND (folder_staging_sha256 IS NULL OR folder_staging_sha256 ~ '^[a-f0-9]{64}$')",
            name="ck_native_worker_source_digest",
        ),
        sa.CheckConstraint(
            "container_id IS NULL OR container_id ~ '^[a-f0-9]{64}$'",
            name="ck_native_worker_container_id",
        ),
        sa.CheckConstraint(
            "state NOT IN ('running','terminated') OR container_id IS NOT NULL",
            name="ck_native_worker_container_observed",
        ),
    )
    op.create_index(
        "ix_native_worker_supervision_flow",
        "native_mcp_worker_supervisions",
        ["engagement_id", "flow_id", "task_id"],
    )
    op.create_table(
        "native_mcp_worker_supervision_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("native_mcp_worker_supervisions.grant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("epoch", sa.BigInteger(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("supervisor_id", sa.String(96), nullable=False),
        sa.Column("kid", sa.String(48), nullable=False),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("claims_sha256", sa.String(64), nullable=False),
        sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("grant_id", "revision", name="uq_native_worker_event_revision"),
        sa.UniqueConstraint("epoch", "revision", name="uq_native_worker_event_epoch_revision"),
        sa.CheckConstraint("epoch>0 AND revision>=1", name="ck_native_worker_event_versions"),
        sa.CheckConstraint(
            "state IN ('provisioned','running','terminating','terminated','unknown','reaped')",
            name="ck_native_worker_event_state",
        ),
        sa.CheckConstraint(
            "evidence_sha256 ~ '^[a-f0-9]{64}$' AND claims_sha256 ~ '^[a-f0-9]{64}$' AND signature_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_native_worker_event_digests",
        ),
    )
    op.create_index(
        "ix_native_worker_event_flow",
        "native_mcp_worker_supervision_events",
        ["engagement_id", "flow_id", "recorded_at"],
    )
    op.execute(
        "CREATE TRIGGER trg_native_worker_supervision_events_immutable BEFORE UPDATE OR DELETE ON native_mcp_worker_supervision_events FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )
    # Operator intent is a separate immutable record. It never updates the
    # independent signed supervisor observation or authorizes worker replay.
    op.create_table(
        "native_mcp_worker_recovery_intents",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("native_mcp_worker_supervisions.grant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("epoch", sa.BigInteger(), nullable=False),
        sa.Column("expected_revision", sa.Integer(), nullable=False),
        sa.Column("observed_state", sa.String(16), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column(
            "kind", sa.String(32), nullable=False, server_default="operator_recovery_requested"
        ),
        sa.Column("requested_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "grant_id", "expected_revision", name="uq_native_worker_recovery_revision"
        ),
        sa.CheckConstraint(
            "epoch>0 AND expected_revision>=1 AND observed_state IN ('unknown','terminating')",
            name="ck_native_worker_recovery_fence",
        ),
        sa.CheckConstraint(
            "kind='operator_recovery_requested' AND authorization_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_native_worker_recovery_intent",
        ),
    )
    op.create_index(
        "ix_native_worker_recovery_flow",
        "native_mcp_worker_recovery_intents",
        ["engagement_id", "flow_id", "requested_at"],
    )
    op.execute(
        "CREATE TRIGGER trg_native_worker_recovery_intents_immutable BEFORE UPDATE OR DELETE ON native_mcp_worker_recovery_intents FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_native_worker_recovery_intents_immutable ON native_mcp_worker_recovery_intents"
    )
    op.drop_index("ix_native_worker_recovery_flow", table_name="native_mcp_worker_recovery_intents")
    op.drop_table("native_mcp_worker_recovery_intents")
    op.execute(
        "DROP TRIGGER trg_native_worker_supervision_events_immutable ON native_mcp_worker_supervision_events"
    )
    op.drop_index("ix_native_worker_event_flow", table_name="native_mcp_worker_supervision_events")
    op.drop_table("native_mcp_worker_supervision_events")
    op.drop_index("ix_native_worker_supervision_flow", table_name="native_mcp_worker_supervisions")
    op.drop_table("native_mcp_worker_supervisions")
    op.execute("DROP SEQUENCE native_mcp_worker_epoch_seq")
