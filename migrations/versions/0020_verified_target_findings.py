"""Append-only human review records for target-signed finding candidates.

Revision ID: 0020
Revises: 0019

These are records of review of independent signature *sources*, never a
verified vulnerability, exploit effect, report release or certification.
"""

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verified_target_finding_decisions",
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
        sa.Column("review_revision", sa.Integer(), nullable=False),
        sa.Column(
            "previous_decision_id",
            sa.String(64),
            sa.ForeignKey("verified_target_finding_decisions.id", ondelete="RESTRICT"),
            nullable=True,
            unique=True,
        ),
        sa.Column("previous_decision_sha256", sa.String(64), nullable=True),
        sa.Column("decision_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("decision_status", sa.String(40), nullable=False),
        sa.Column("reviewer_sub", sa.String(64), nullable=False),
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
            "replay_parent_task_id",
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
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("source_event_id", sa.String(82), nullable=False),
        sa.Column("target_event_id", sa.String(82), nullable=False),
        sa.Column("source_provider_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("target_provider_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("source_request_sha256", sa.String(64), nullable=False),
        sa.Column("target_request_sha256", sa.String(64), nullable=False),
        sa.Column("source_session_sha256", sa.String(64), nullable=False),
        sa.Column("target_session_sha256", sa.String(64), nullable=False),
        sa.Column("source_response_sha256", sa.String(64), nullable=False),
        sa.Column("target_response_sha256", sa.String(64), nullable=False),
        sa.Column("source_identity_sha256", sa.String(64), nullable=False),
        sa.Column("target_identity_sha256", sa.String(64), nullable=False),
        sa.Column("observation_binding_sha256", sa.String(64), nullable=False),
        sa.Column("report_source_evidence_sha256", sa.String(64), nullable=False),
        sa.Column(
            "reviewed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "engagement_id",
            "flow_id",
            "finding_id",
            "review_revision",
            name="uq_verified_target_finding_revision",
        ),
        sa.CheckConstraint(
            "review_revision > 0 AND authorization_version > 0 AND flow_revision >= 0",
            name="ck_verified_target_review_versions",
        ),
        sa.CheckConstraint(
            "(review_revision = 1 AND previous_decision_id IS NULL AND "
            "previous_decision_sha256 IS NULL) OR "
            "(review_revision > 1 AND previous_decision_id IS NOT NULL "
            "AND previous_decision_sha256 IS NOT NULL)",
            name="ck_verified_target_review_chain",
        ),
        sa.CheckConstraint(
            "decision_status IN "
            "('candidate_only','UNKNOWN','independent_verification_required')",
            name="ck_verified_target_review_candidate_only",
        ),
        sa.CheckConstraint(
            "original_source_task_id <> source_task_id AND "
            "original_source_task_id <> target_task_id AND "
            "source_task_id <> target_task_id AND "
            "source_event_id <> target_event_id AND "
            "source_provider_receipt_sha256 <> target_provider_receipt_sha256",
            name="ck_verified_target_review_distinct_sources",
        ),
        sa.CheckConstraint(
            "engagement_id ~ '^eng-[A-Za-z0-9._-]{1,60}$' AND "
            "flow_id ~ '^flow-[A-Za-z0-9._-]{1,59}$' AND "
            "reviewer_sub ~ '^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}$' AND "
            "finding_id ~ '^[A-Za-z0-9_.-]{1,128}$'",
            name="ck_verified_target_review_identifiers",
        ),
        sa.CheckConstraint(
            "source_event_id ~ '^evt-[A-Za-z0-9._-]{1,78}$' AND "
            "target_event_id ~ '^evt-[A-Za-z0-9._-]{1,78}$'",
            name="ck_verified_target_review_events",
        ),
        sa.CheckConstraint(
            "authorization_sha256 ~ '^[0-9a-f]{64}$' AND "
            "proof_sha256 ~ '^[0-9a-f]{64}$' AND "
            "audit_corroboration_sha256 ~ '^[0-9a-f]{64}$' AND "
            "decision_sha256 ~ '^[0-9a-f]{64}$' AND "
            "(previous_decision_sha256 IS NULL OR "
            "previous_decision_sha256 ~ '^[0-9a-f]{64}$') AND "
            "source_provider_receipt_sha256 ~ '^[0-9a-f]{64}$' AND "
            "target_provider_receipt_sha256 ~ '^[0-9a-f]{64}$' AND "
            "source_request_sha256 ~ '^[0-9a-f]{64}$' AND "
            "target_request_sha256 ~ '^[0-9a-f]{64}$' AND "
            "source_session_sha256 ~ '^[0-9a-f]{64}$' AND "
            "target_session_sha256 ~ '^[0-9a-f]{64}$' AND "
            "source_response_sha256 ~ '^[0-9a-f]{64}$' AND "
            "target_response_sha256 ~ '^[0-9a-f]{64}$' AND "
            "source_identity_sha256 ~ '^[0-9a-f]{64}$' AND "
            "target_identity_sha256 ~ '^[0-9a-f]{64}$' AND "
            "observation_binding_sha256 ~ '^[0-9a-f]{64}$' AND "
            "report_source_evidence_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_verified_target_review_sha256",
        ),
    )
    op.create_index(
        "ix_verified_target_finding_tenant_flow",
        "verified_target_finding_decisions",
        ["engagement_id", "flow_id", "finding_id", "review_revision"],
    )
    # 0016's immutable-record trigger is present before this migration.
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_verified_target_finding_decisions_immutable "
            "BEFORE UPDATE OR DELETE ON verified_target_finding_decisions "
            "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
        )
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_verified_target_finding_decisions_immutable "
        "ON verified_target_finding_decisions"
    )
    op.drop_index(
        "ix_verified_target_finding_tenant_flow",
        table_name="verified_target_finding_decisions",
    )
    op.drop_table("verified_target_finding_decisions")
