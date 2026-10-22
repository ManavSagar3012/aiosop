"""Immutable independent target-authority replay admission receipts.

Revision ID: 0016
Revises: 0015
"""

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "target_authority_nonce_receipts",
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
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("nonce_sha256", sa.String(64), nullable=False),
        sa.Column("proof_sha256", sa.String(64), nullable=False),
        sa.Column("received_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "engagement_id", "flow_id", "key_id", "nonce_sha256", name="uq_target_authority_nonce"
        ),
        sa.CheckConstraint(
            "engagement_id LIKE 'eng-%' AND flow_id LIKE 'flow-%'", name="ck_target_authority_scope"
        ),
        sa.CheckConstraint(
            "nonce_sha256 ~ '^[0-9a-f]{64}$' AND proof_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_target_authority_digest",
        ),
    )
    op.create_index(
        "ix_target_authority_nonce_tenant",
        "target_authority_nonce_receipts",
        ["engagement_id", "flow_id"],
    )
    op.execute(
        sa.text(
            """
        CREATE FUNCTION reject_target_authority_nonce_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Target authority replay receipts are immutable';
        END;
        $$
    """
        )
    )
    op.execute(
        sa.text(
            """
        CREATE TRIGGER trg_target_authority_nonce_immutable
        BEFORE UPDATE OR DELETE ON target_authority_nonce_receipts
        FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()
    """
        )
    )
    op.create_table(
        "target_authority_assertions",
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
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("proof_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("received_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "source_task_id <> target_task_id", name="ck_target_authority_distinct_observations"
        ),
        sa.CheckConstraint(
            "authorization_version > 0 AND flow_revision >= 0",
            name="ck_target_authority_assertion_versions",
        ),
        sa.CheckConstraint(
            "proof_sha256 ~ '^[0-9a-f]{64}$'", name="ck_target_authority_assertion_sha"
        ),
    )
    op.create_index(
        "ix_target_authority_assertions_flow",
        "target_authority_assertions",
        ["engagement_id", "flow_id", "received_at"],
    )
    op.execute(
        sa.text(
            """
        CREATE TRIGGER trg_target_authority_assertions_immutable
        BEFORE UPDATE OR DELETE ON target_authority_assertions
        FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()
    """
        )
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_target_authority_assertions_immutable ON target_authority_assertions"
    )
    op.drop_index("ix_target_authority_assertions_flow", table_name="target_authority_assertions")
    op.drop_table("target_authority_assertions")
    op.execute(
        "DROP TRIGGER trg_target_authority_nonce_immutable ON target_authority_nonce_receipts"
    )
    op.execute("DROP FUNCTION reject_target_authority_nonce_mutation()")
    op.drop_index("ix_target_authority_nonce_tenant", table_name="target_authority_nonce_receipts")
    op.drop_table("target_authority_nonce_receipts")
