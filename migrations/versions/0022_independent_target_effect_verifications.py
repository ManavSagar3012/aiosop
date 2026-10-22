"""Sealed, finding-specific independent LIVE target-effect verdicts.

Revision ID: 0022
Revises: 0021

0021's UNKNOWN-only attempts are immutable and remain UNKNOWN. The separate
0022 ledger can store VERIFIED only after a trusted, independently provisioned
production observer signs a current finding/source/three-identity verdict and
the senior reviewer admits that certificate under one signed PG transaction.
This migration does NOT authorize report release or rewrite any 0021 row.
"""

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Server-minted, tenant/UNKNOWN-revision-scoped nonce. Never trust the
    # witness response or a caller to invent the expected challenge.
    op.create_table(
        "independent_target_effect_challenges",
        sa.Column("id", sa.String(64), primary_key=True),
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
        sa.Column("finding_id", sa.String(128), nullable=False),
        sa.Column(
            "qualification_id",
            sa.String(64),
            sa.ForeignKey("target_effect_qualification_attempts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("qualification_sha256", sa.String(64), nullable=False),
        sa.Column("nonce_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "issued_at > 0 AND expires_at > issued_at " "AND expires_at <= issued_at + 60",
            name="ck_independent_effect_challenge_short_lived",
        ),
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_independent_target_effect_challenges_immutable "
            "BEFORE UPDATE OR DELETE ON independent_target_effect_challenges "
            "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
        )
    )
    op.create_table(
        "independent_target_effect_verifications",
        sa.Column("id", sa.String(64), primary_key=True),
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
        sa.Column("finding_id", sa.String(128), nullable=False),
        sa.Column(
            "review_decision_id",
            sa.String(64),
            sa.ForeignKey("verified_target_finding_decisions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("review_decision_sha256", sa.String(64), nullable=False),
        sa.Column("review_revision", sa.Integer(), nullable=False),
        sa.Column(
            "qualification_id",
            sa.String(64),
            sa.ForeignKey("target_effect_qualification_attempts.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("qualification_sha256", sa.String(64), nullable=False),
        sa.Column("qualification_revision", sa.Integer(), nullable=False),
        sa.Column(
            "challenge_id",
            sa.String(64),
            sa.ForeignKey("independent_target_effect_challenges.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "original_source_task_id",
            sa.String(64),
            sa.ForeignKey("tasks.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_task_id",
            sa.String(64),
            sa.ForeignKey("tasks.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "target_task_id",
            sa.String(64),
            sa.ForeignKey("tasks.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("proof_sha256", sa.String(64), nullable=False),
        sa.Column("audit_corroboration_sha256", sa.String(64), nullable=False),
        sa.Column("observation_binding_sha256", sa.String(64), nullable=False),
        sa.Column("report_source_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("senior_reviewer_sub", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=False),
        sa.Column("resource_owner_identity_sha256", sa.String(64), nullable=False),
        sa.Column("resource_visibility", sa.String(16), nullable=False),
        sa.Column("source_http_status", sa.Integer(), nullable=False),
        sa.Column("target_http_status", sa.Integer(), nullable=False),
        sa.Column("anonymous_http_status", sa.Integer(), nullable=False),
        sa.Column("private_content_sha256", sa.String(64), nullable=False),
        sa.Column("verifier_key_id", sa.String(64), nullable=False),
        sa.Column("verifier_origin", sa.String(256), nullable=False),
        sa.Column("verifier_public_key_sha256", sa.String(64), nullable=False),
        sa.Column("verifier_registry_sha256", sa.String(64), nullable=False),
        sa.Column("verifier_nonce_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("verdict_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("signed_verdict_json", sa.LargeBinary(), nullable=False),
        sa.Column("verdict_signature_b64url", sa.String(86), nullable=False),
        sa.Column("verdict_issued_at", sa.BigInteger(), nullable=False),
        sa.Column("verdict_expires_at", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("independent_effect_verified", sa.Boolean(), nullable=False),
        sa.Column("finding_verified", sa.Boolean(), nullable=False),
        sa.Column(
            "report_release_approved",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "engagement_id",
            "flow_id",
            "finding_id",
            name="uq_independent_effect_one_promotion_per_finding",
        ),
        sa.CheckConstraint(
            "status = 'VERIFIED' AND independent_effect_verified = true "
            "AND finding_verified = true AND report_release_approved = false "
            "AND resource_visibility = 'private' AND "
            "source_http_status = 200 AND target_http_status = 200 "
            "AND anonymous_http_status IN (401,403,404)",
            name="ck_independent_effect_verified_not_released",
        ),
        sa.CheckConstraint(
            "authorization_version > 0 AND flow_revision >= 0 "
            "AND qualification_revision > 0 AND review_revision > 0 "
            "AND verdict_issued_at > 0 AND verdict_expires_at > verdict_issued_at "
            "AND verdict_expires_at <= verdict_issued_at + 60",
            name="ck_independent_effect_revisions_and_freshness",
        ),
        sa.CheckConstraint(
            "original_source_task_id <> source_task_id AND "
            "original_source_task_id <> target_task_id AND "
            "source_task_id <> target_task_id",
            name="ck_independent_effect_distinct_task_sources",
        ),
        sa.CheckConstraint(
            "engagement_id ~ '^eng-[A-Za-z0-9._-]{1,60}$' AND "
            "flow_id ~ '^flow-[A-Za-z0-9._-]{1,59}$' AND "
            "finding_id ~ '^[A-Za-z0-9_.-]{1,128}$' AND "
            "id ~ '^itefv-[0-9a-f]{32}$' AND "
            "verifier_key_id ~ '^[A-Za-z0-9._-]{1,64}$' AND "
            "senior_reviewer_sub ~ '^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}$'",
            name="ck_independent_effect_scoped_ids",
        ),
        sa.CheckConstraint(
            "review_decision_sha256 ~ '^[0-9a-f]{64}$' AND "
            "qualification_sha256 ~ '^[0-9a-f]{64}$' AND "
            "proof_sha256 ~ '^[0-9a-f]{64}$' AND "
            "audit_corroboration_sha256 ~ '^[0-9a-f]{64}$' AND "
            "observation_binding_sha256 ~ '^[0-9a-f]{64}$' AND "
            "report_source_evidence_sha256 ~ '^[0-9a-f]{64}$' AND "
            "authorization_sha256 ~ '^[0-9a-f]{64}$' AND "
            "resource_owner_identity_sha256 ~ '^[0-9a-f]{64}$' AND "
            "private_content_sha256 ~ '^[0-9a-f]{64}$' AND "
            "verifier_public_key_sha256 ~ '^[0-9a-f]{64}$' AND "
            "verifier_registry_sha256 ~ '^[0-9a-f]{64}$' AND "
            "verifier_nonce_sha256 ~ '^[0-9a-f]{64}$' AND "
            "verdict_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_independent_effect_digest_shapes",
        ),
    )
    op.create_index(
        "ix_independent_effect_current_finding",
        "independent_target_effect_verifications",
        ["engagement_id", "flow_id", "finding_id"],
    )
    # Reuse 0016's existing immutable records trigger. No updates, deletes or
    # replay-safe upserts are permitted, including administrative corrections.
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_independent_target_effect_verifications_immutable "
            "BEFORE UPDATE OR DELETE ON independent_target_effect_verifications "
            "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
        )
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_independent_target_effect_verifications_immutable "
        "ON independent_target_effect_verifications"
    )
    op.drop_index(
        "ix_independent_effect_current_finding",
        table_name="independent_target_effect_verifications",
    )
    op.drop_table("independent_target_effect_verifications")
    op.execute(
        "DROP TRIGGER trg_independent_target_effect_challenges_immutable "
        "ON independent_target_effect_challenges"
    )
    op.drop_table("independent_target_effect_challenges")
