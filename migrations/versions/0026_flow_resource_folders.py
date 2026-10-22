"""Durable tenant-owned metadata-only Flow resource virtual folders.

Revision ID: 0026
Revises: 0025

Neither artifact content nor host/container filesystem paths are mutable.
All mutations require an application signed Flow authorization/manifest/CAS
fence; a bounded append-only audit is immutable at the database layer.
"""

import sqlalchemy as sa
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "flow_resource_folder_catalogs",
        sa.Column(
            "flow_id",
            sa.String(64),
            sa.ForeignKey("execution_flows.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("owner_sub", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "revision >= 0 AND flow_revision >= 0 AND authorization_version >= 1",
            name="ck_flow_resource_catalog_revisions",
        ),
        sa.CheckConstraint(
            "authorization_sha256 ~ '^[0-9a-f]{64}$' AND manifest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_flow_resource_catalog_hashes",
        ),
    )
    op.create_index(
        "ix_flow_resource_catalog_tenant_owner",
        "flow_resource_folder_catalogs",
        ["engagement_id", "owner_sub"],
    )
    op.create_table(
        "flow_resource_virtual_folders",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column(
            "flow_id",
            sa.String(64),
            sa.ForeignKey("flow_resource_folder_catalogs.flow_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(48), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("flow_id", "name", name="uq_flow_resource_folder_name"),
        sa.CheckConstraint(
            "name ~ '^[a-z][a-z0-9_-]{0,47}$'", name="ck_flow_resource_folder_safe_name"
        ),
    )
    op.create_index(
        "ix_flow_resource_folders_tenant_flow",
        "flow_resource_virtual_folders",
        ["engagement_id", "flow_id"],
    )
    op.create_table(
        "flow_resource_folder_assignments",
        sa.Column(
            "flow_id",
            sa.String(64),
            sa.ForeignKey("flow_resource_folder_catalogs.flow_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column(
            "artifact_id",
            sa.String(64),
            sa.ForeignKey("flow_artifacts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column(
            "folder_id",
            sa.String(64),
            sa.ForeignKey("flow_resource_virtual_folders.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("assigned_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("flow_id", "artifact_id", name="pk_flow_resource_assignment"),
        sa.CheckConstraint(
            "artifact_sha256 ~ '^[0-9a-f]{64}$'", name="ck_flow_resource_assignment_sha"
        ),
    )
    op.create_index(
        "ix_flow_resource_assignments_folder",
        "flow_resource_folder_assignments",
        ["engagement_id", "flow_id", "folder_id"],
    )
    op.create_table(
        "flow_resource_folder_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "flow_id",
            sa.String(64),
            sa.ForeignKey("flow_resource_folder_catalogs.flow_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("actor_sub", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("catalog_revision", sa.Integer(), nullable=False),
        sa.Column("folder_id", sa.String(64), nullable=True),
        sa.Column("folder_name", sa.String(48), nullable=True),
        sa.Column("artifact_id", sa.String(64), nullable=True),
        sa.Column("artifact_sha256", sa.String(64), nullable=True),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("authorization_id", sa.String(128), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("flow_id", "catalog_revision", name="uq_flow_resource_event_revision"),
        sa.CheckConstraint("catalog_revision >= 1", name="ck_flow_resource_event_revision"),
        sa.CheckConstraint(
            "operation IN ('create','rename','delete','assign','unassign')",
            name="ck_flow_resource_event_operation",
        ),
        sa.CheckConstraint(
            "manifest_sha256 ~ '^[0-9a-f]{64}$' AND authorization_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_flow_resource_event_hashes",
        ),
    )
    op.create_index(
        "ix_flow_resource_events_tenant_flow",
        "flow_resource_folder_events",
        ["engagement_id", "flow_id", "created_at"],
    )
    # Existing reviewed 0016 immutable mutation function, already reused by
    # the 0024/0025 immutable ledgers. Never permit UPDATE/DELETE of audit.
    op.execute(
        "CREATE TRIGGER trg_flow_resource_folder_events_immutable "
        "BEFORE UPDATE OR DELETE ON flow_resource_folder_events "
        "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_flow_resource_folder_events_immutable ON flow_resource_folder_events"
    )
    op.drop_index("ix_flow_resource_events_tenant_flow", table_name="flow_resource_folder_events")
    op.drop_table("flow_resource_folder_events")
    op.drop_index(
        "ix_flow_resource_assignments_folder", table_name="flow_resource_folder_assignments"
    )
    op.drop_table("flow_resource_folder_assignments")
    op.drop_index(
        "ix_flow_resource_folders_tenant_flow", table_name="flow_resource_virtual_folders"
    )
    op.drop_table("flow_resource_virtual_folders")
    op.drop_index(
        "ix_flow_resource_catalog_tenant_owner", table_name="flow_resource_folder_catalogs"
    )
    op.drop_table("flow_resource_folder_catalogs")
