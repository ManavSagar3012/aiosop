"""Tenant-owned immutable, PostgreSQL-backed Flow artifacts.

Revision ID: 0013
Revises: 0012

Content is BYTEA, never interpreted as an executable path. SHA-256 is a
content integrity checksum, not a trusted provenance or malware certificate.
"""

from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "flow_artifacts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("flow_id", sa.String(64), sa.ForeignKey(
            "execution_flows.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("engagement_id", sa.String(64), sa.ForeignKey(
            "session_states.session_id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("owner_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("flow_id", "name", name="uq_flow_artifact_name"),
        sa.CheckConstraint("size_bytes > 0 AND size_bytes <= 2097152", name="ck_flow_artifact_size"),
        sa.CheckConstraint("octet_length(content) = size_bytes", name="ck_flow_artifact_length"),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="ck_flow_artifact_hash"),
        sa.CheckConstraint("authorization_version > 0 AND flow_revision >= 0", name="ck_flow_artifact_versions"),
        sa.CheckConstraint("authorization_sha256 ~ '^[0-9a-f]{64}$'", name="ck_flow_artifact_auth_hash"),
    )
    op.create_index(
        "ix_flow_artifacts_tenant_flow", "flow_artifacts",
        ["engagement_id", "flow_id", "created_at"],
    )
    # The normal API has no mutation/delete path, but a database-level fence
    # also prevents accidental ORM/admin updates from silently rewriting the
    # immutable content digest or changing an artifact's ownership metadata.
    op.execute(sa.text("""
        CREATE FUNCTION reject_flow_artifact_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'flow artifacts are immutable';
        END;
        $$
    """))
    op.execute(sa.text("""
        CREATE TRIGGER trg_flow_artifact_immutable
        BEFORE UPDATE OR DELETE ON flow_artifacts
        FOR EACH ROW EXECUTE FUNCTION reject_flow_artifact_mutation()
    """))


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_flow_artifact_immutable ON flow_artifacts")
    op.execute("DROP FUNCTION reject_flow_artifact_mutation()")
    op.drop_index("ix_flow_artifacts_tenant_flow", table_name="flow_artifacts")
    op.drop_table("flow_artifacts")
