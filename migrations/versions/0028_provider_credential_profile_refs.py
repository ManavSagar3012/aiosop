"""Nonsecret signed-Flow symbolic credential references; never credential material.

Revision ID: 0028
Revises: 0027
"""

import sqlalchemy as sa
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "provider_credential_profile_refs",
        sa.Column("id", sa.String(40), primary_key=True),
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
        sa.Column("owner_sub", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("slot", sa.String(16), nullable=False),
        sa.Column(
            "policy_review_id",
            sa.String(64),
            sa.ForeignKey("provider_route_policy_reviews.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("reference_sha256", sa.String(64), nullable=False),
        sa.Column("reference_revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("senior_sub", sa.String(64), nullable=True),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "engagement_id", "flow_id", "provider", "slot", name="uq_provider_credential_ref_slot"
        ),
        sa.CheckConstraint(
            "status IN ('pending','approved','revoked')", name="ck_provider_credential_ref_status"
        ),
        sa.CheckConstraint(
            "reference_revision >= 1 AND generation >= 1 AND flow_revision >= 0 AND authorization_version >= 1",
            name="ck_provider_credential_ref_revisions",
        ),
        sa.CheckConstraint("slot IN ('primary','backup')", name="ck_provider_credential_ref_slot"),
        sa.CheckConstraint(
            "reference_sha256 ~ '^[a-f0-9]{64}$' AND policy_sha256 ~ '^[a-f0-9]{64}$' AND authorization_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_provider_credential_ref_hashes",
        ),
        sa.CheckConstraint(
            "senior_sub IS NULL OR senior_sub <> owner_sub",
            name="ck_provider_credential_ref_distinct_senior",
        ),
        sa.CheckConstraint(
            "(status='approved' AND senior_sub IS NOT NULL) OR status<>'approved'",
            name="ck_provider_credential_ref_senior_approval",
        ),
    )
    op.create_index(
        "ix_provider_credential_ref_flow",
        "provider_credential_profile_refs",
        ["engagement_id", "flow_id", "created_at"],
    )
    op.create_table(
        "provider_credential_profile_ref_events",
        sa.Column("operation_id", sa.String(40), primary_key=True),
        sa.Column(
            "ref_id",
            sa.String(40),
            sa.ForeignKey("provider_credential_profile_refs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("actor_sub", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("reference_revision", sa.Integer(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reference_sha256", sa.String(64), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "ref_id", "reference_revision", name="uq_provider_credential_ref_event_revision"
        ),
        sa.CheckConstraint(
            "operation IN ('register','rotate','approve','revoke')",
            name="ck_provider_credential_ref_event_operation",
        ),
        sa.CheckConstraint(
            "status IN ('pending','approved','revoked')",
            name="ck_provider_credential_ref_event_status",
        ),
        sa.CheckConstraint(
            "reference_revision >= 1 AND generation >= 1",
            name="ck_provider_credential_ref_event_revisions",
        ),
        sa.CheckConstraint(
            "reference_sha256 ~ '^[a-f0-9]{64}$' AND request_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_provider_credential_ref_event_sha",
        ),
    )
    op.create_index(
        "ix_provider_credential_ref_events_tenant",
        "provider_credential_profile_ref_events",
        ["engagement_id", "flow_id", "created_at"],
    )
    op.execute(
        "CREATE TRIGGER trg_provider_credential_ref_events_immutable BEFORE UPDATE OR DELETE ON provider_credential_profile_ref_events FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_provider_credential_ref_events_immutable ON provider_credential_profile_ref_events"
    )
    op.drop_index(
        "ix_provider_credential_ref_events_tenant",
        table_name="provider_credential_profile_ref_events",
    )
    op.drop_table("provider_credential_profile_ref_events")
    op.drop_index("ix_provider_credential_ref_flow", table_name="provider_credential_profile_refs")
    op.drop_table("provider_credential_profile_refs")
