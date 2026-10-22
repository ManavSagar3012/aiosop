"""Inert signed-Flow provider policy intent reviews and immutable review audit.

Revision ID: 0025
Revises: 0024

These records are human declarations, never credentials, served model attestations,
provider dispatch configuration or expenditure authorizations.
"""

import sqlalchemy as sa
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "provider_route_policy_reviews",
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
        sa.Column("creator_sub", sa.String(64), nullable=False),
        sa.Column("policy", sa.JSON(), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("senior_sub", sa.String(64), nullable=True),
        sa.Column("decision_reason", sa.String(256), nullable=True),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "policy_revision > 0 AND flow_revision >= 0 AND authorization_version > 0",
            name="ck_provider_review_versions",
        ),
        sa.CheckConstraint(
            "status IN ('pending','approved','revoked')", name="ck_provider_review_status"
        ),
        sa.CheckConstraint(
            "policy_sha256 ~ '^[0-9a-f]{64}$' AND authorization_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_provider_review_hashes",
        ),
        sa.CheckConstraint(
            "(status='pending' AND senior_sub IS NULL AND decision_reason IS NULL) "
            "OR (status IN ('approved','revoked') AND senior_sub IS NOT NULL AND decision_reason IS NOT NULL)",
            name="ck_provider_review_decision",
        ),
        sa.CheckConstraint(
            "senior_sub IS NULL OR senior_sub <> creator_sub",
            name="ck_provider_review_distinct_senior",
        ),
    )
    op.create_index(
        "ix_provider_review_tenant_flow",
        "provider_route_policy_reviews",
        ["engagement_id", "flow_id", "created_at"],
    )
    op.create_table(
        "provider_route_policy_review_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "review_id",
            sa.String(64),
            sa.ForeignKey("provider_route_policy_reviews.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("actor_sub", sa.String(64), nullable=False),
        sa.Column("event", sa.String(16), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "event IN ('created','updated','approved','revoked')", name="ck_provider_review_event"
        ),
        sa.CheckConstraint(
            "policy_revision > 0 AND policy_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_provider_review_event_hash",
        ),
        sa.UniqueConstraint(
            "review_id", "policy_revision", name="uq_provider_review_revision_event"
        ),
    )
    op.create_index(
        "ix_provider_review_events_parent",
        "provider_route_policy_review_events",
        ["review_id", "created_at"],
    )
    op.execute(
        "CREATE TRIGGER trg_provider_review_events_immutable "
        "BEFORE UPDATE OR DELETE ON provider_route_policy_review_events "
        "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_provider_review_events_immutable ON provider_route_policy_review_events"
    )
    op.drop_index(
        "ix_provider_review_events_parent", table_name="provider_route_policy_review_events"
    )
    op.drop_table("provider_route_policy_review_events")
    op.drop_index("ix_provider_review_tenant_flow", table_name="provider_route_policy_reviews")
    op.drop_table("provider_route_policy_reviews")
