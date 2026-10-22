"""Tenant and Flow owned inert operator knowledge with CAS and tombstones.

Revision ID: 0019
Revises: 0018

No vector embeddings, model context, execution/graph trust flags, or external
providers are involved in this operator-maintained text store.
"""

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operator_knowledge_documents",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey(
                "session_states.session_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column(
            "flow_id",
            sa.String(64),
            sa.ForeignKey(
                "execution_flows.id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("owner_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(128), nullable=False),
        sa.Column("doc_type", sa.String(16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("source_flow_revision", sa.Integer(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "doc_type IN ('guide','answer','code')", name="ck_operator_knowledge_type"
        ),
        sa.CheckConstraint("content_bytes BETWEEN 1 AND 8192", name="ck_operator_knowledge_bytes"),
        sa.CheckConstraint(
            "octet_length(convert_to(content, 'UTF8')) = content_bytes",
            name="ck_operator_knowledge_content_length",
        ),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="ck_operator_knowledge_sha"),
        sa.CheckConstraint(
            "revision > 0 AND source_flow_revision >= 0 AND authorization_version > 0",
            name="ck_operator_knowledge_revisions",
        ),
        sa.CheckConstraint(
            "authorization_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_operator_knowledge_authorization_sha",
        ),
    )
    op.create_index(
        "ix_operator_knowledge_owner_flow",
        "operator_knowledge_documents",
        ["engagement_id", "flow_id", "owner_id", "created_at"],
    )
    op.create_index(
        "ix_operator_knowledge_active_kind",
        "operator_knowledge_documents",
        ["engagement_id", "flow_id", "owner_id", "doc_type"],
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_operator_knowledge_active_kind", table_name="operator_knowledge_documents")
    op.drop_index("ix_operator_knowledge_owner_flow", table_name="operator_knowledge_documents")
    op.drop_table("operator_knowledge_documents")
