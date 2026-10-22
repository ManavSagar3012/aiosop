"""Immutable UNKNOWN-only target effect qualification admission ledger.

Revision ID: 0021
Revises: 0020

No production independently trusted target-effect observer currently exists.
Consequently this migration cannot create a VERIFIED finding/release record:
the database enforces `UNKNOWN` and false effect/release flags for every row.
"""

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "target_effect_qualification_attempts",
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
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column(
            "review_decision_id",
            sa.String(64),
            sa.ForeignKey("verified_target_finding_decisions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("review_decision_sha256", sa.String(64), nullable=False),
        sa.Column("review_revision", sa.Integer(), nullable=False),
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
        sa.Column(
            "proof_sha256",
            sa.String(64),
            sa.ForeignKey("target_authority_assertions.proof_sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("audit_corroboration_sha256", sa.String(64), nullable=False),
        sa.Column("observation_binding_sha256", sa.String(64), nullable=False),
        sa.Column("report_source_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("reviewer_sub", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=False),
        sa.Column("resource_owner_identity_sha256", sa.String(64), nullable=False),
        sa.Column("resource_visibility", sa.String(16), nullable=False),
        sa.Column("source_http_status", sa.Integer(), nullable=False),
        sa.Column("target_http_status", sa.Integer(), nullable=False),
        sa.Column("anonymous_http_status", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False, server_default="UNKNOWN"),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column(
            "independent_effect_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "finding_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "report_release_approved",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "previous_attempt_id",
            sa.String(64),
            sa.ForeignKey("target_effect_qualification_attempts.id", ondelete="RESTRICT"),
            nullable=True,
            unique=True,
        ),
        sa.Column("previous_attempt_sha256", sa.String(64), nullable=True),
        sa.Column("attempt_sha256", sa.String(64), nullable=False, unique=True),
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
            "revision",
            name="uq_target_effect_qualification_revision",
        ),
        sa.CheckConstraint(
            "status = 'UNKNOWN' AND reason_code = 'independent_target_effect_service_missing' "
            "AND independent_effect_verified = false AND finding_verified = false "
            "AND report_release_approved = false",
            name="ck_target_effect_no_unproven_promotion",
        ),
        sa.CheckConstraint(
            "revision >= 1 AND review_revision >= 1 AND "
            "authorization_version > 0 AND flow_revision >= 0",
            name="ck_target_effect_positive_revisions",
        ),
        sa.CheckConstraint(
            "(revision = 1 AND previous_attempt_id IS NULL AND "
            "previous_attempt_sha256 IS NULL) OR "
            "(revision > 1 AND previous_attempt_id IS NOT NULL "
            "AND previous_attempt_sha256 IS NOT NULL)",
            name="ck_target_effect_attempt_chain",
        ),
        sa.CheckConstraint(
            "source_task_id <> target_task_id AND "
            "original_source_task_id <> source_task_id AND "
            "original_source_task_id <> target_task_id "
            "AND resource_visibility = 'private' "
            "AND source_http_status = 200 AND target_http_status = 200 "
            "AND anonymous_http_status IN (401,403,404)",
            name="ck_target_effect_candidate_observations",
        ),
        sa.CheckConstraint(
            "engagement_id ~ '^eng-[A-Za-z0-9._-]{1,60}$' "
            "AND flow_id ~ '^flow-[A-Za-z0-9._-]{1,59}$' "
            "AND finding_id ~ '^[A-Za-z0-9_.-]{1,128}$' "
            "AND resource_id ~ '^[A-Za-z0-9._:-]{1,128}$' "
            "AND reviewer_sub ~ '^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}$'",
            name="ck_target_effect_scoped_identifiers",
        ),
        sa.CheckConstraint(
            "review_decision_sha256 ~ '^[0-9a-f]{64}$' "
            "AND proof_sha256 ~ '^[0-9a-f]{64}$' "
            "AND audit_corroboration_sha256 ~ '^[0-9a-f]{64}$' "
            "AND observation_binding_sha256 ~ '^[0-9a-f]{64}$' "
            "AND report_source_evidence_sha256 ~ '^[0-9a-f]{64}$' "
            "AND authorization_sha256 ~ '^[0-9a-f]{64}$' "
            "AND resource_owner_identity_sha256 ~ '^[0-9a-f]{64}$' "
            "AND attempt_sha256 ~ '^[0-9a-f]{64}$' "
            "AND (previous_attempt_sha256 IS NULL OR "
            "previous_attempt_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_target_effect_signed_digest_shapes",
        ),
    )
    op.create_index(
        "ix_target_effect_qualification_scope",
        "target_effect_qualification_attempts",
        ["engagement_id", "flow_id", "finding_id", "revision"],
    )
    # The same immutable trigger from revision 0016 protects every admission.
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_target_effect_qualifications_immutable "
            "BEFORE UPDATE OR DELETE ON target_effect_qualification_attempts "
            "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
        )
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_target_effect_qualifications_immutable "
        "ON target_effect_qualification_attempts"
    )
    op.drop_index(
        "ix_target_effect_qualification_scope",
        table_name="target_effect_qualification_attempts",
    )
    op.drop_table("target_effect_qualification_attempts")
