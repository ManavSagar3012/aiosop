"""Immutable independent senior review receipts for exact Flow artifact bytes.

Revision ID: 0015
Revises: 0014
"""

from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "flow_artifact_reviews",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "artifact_id",
            sa.String(64),
            sa.ForeignKey("flow_artifacts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "flow_id",
            sa.String(64),
            sa.ForeignKey("execution_flows.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("uploader_sub", sa.String(64), nullable=False),
        sa.Column("reviewer_sub", sa.String(64), nullable=False),
        sa.Column("reviewer_role", sa.String(24), nullable=False),
        sa.Column("decision", sa.String(8), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("artifact_id", name="uq_flow_artifact_single_review"),
        sa.CheckConstraint(
            "decision IN ('approve','reject')",
            name="ck_flow_artifact_review_decision",
        ),
        sa.CheckConstraint(
            "uploader_sub <> reviewer_sub",
            name="ck_flow_artifact_independent_reviewer",
        ),
        sa.CheckConstraint(
            "reviewer_role = 'senior_operator'",
            name="ck_flow_artifact_senior_role",
        ),
        sa.CheckConstraint(
            "length(reason) BETWEEN 1 AND 512",
            name="ck_flow_artifact_review_reason",
        ),
        sa.CheckConstraint(
            "flow_revision >= 0 AND authorization_version > 0",
            name="ck_flow_artifact_review_versions",
        ),
        sa.CheckConstraint(
            "artifact_sha256 ~ '^[0-9a-f]{64}$' AND " "authorization_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_flow_artifact_review_hashes",
        ),
    )
    op.create_index(
        "ix_flow_artifact_reviews_tenant_flow",
        "flow_artifact_reviews",
        ["engagement_id", "flow_id", "created_at"],
    )
    op.execute(
        sa.text(
            """
            CREATE FUNCTION reject_flow_artifact_review_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'Flow artifact review receipts are immutable';
            END;
            $$
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER trg_flow_artifact_review_immutable
            BEFORE UPDATE OR DELETE ON flow_artifact_reviews
            FOR EACH ROW EXECUTE FUNCTION reject_flow_artifact_review_mutation()
            """
        )
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_flow_artifact_review_immutable ON flow_artifact_reviews")
    op.execute("DROP FUNCTION reject_flow_artifact_review_mutation()")
    op.drop_index("ix_flow_artifact_reviews_tenant_flow", table_name="flow_artifact_reviews")
    op.drop_table("flow_artifact_reviews")
