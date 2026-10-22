"""Tenant-isolated, signed-version-fenced pgvector knowledge storage.

Revision ID: 0011
Revises: 0010

Legacy semantic_payloads is intentionally NOT copied. Its rows have no
trustworthy tenant or signed authorization lineage and cannot be treated as
authorized knowledge or surfaced to another engagement.
"""

from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute(
        """
        CREATE TABLE supervision_semantic_knowledge (
            id BIGSERIAL PRIMARY KEY,
            engagement_id VARCHAR(64) NOT NULL
                REFERENCES session_states(session_id) ON DELETE RESTRICT,
            task_id VARCHAR(64) NOT NULL,
            authorization_version INTEGER NOT NULL
                CHECK (authorization_version > 0),
            category VARCHAR(24) NOT NULL
                CHECK (category IN ('payload', 'summary', 'guide', 'answer', 'code')),
            payload_type VARCHAR(50) NOT NULL,
            content TEXT NOT NULL CHECK (length(content) BETWEEN 1 AND 4096),
            content_sha256 VARCHAR(64) NOT NULL CHECK (length(content_sha256) = 64),
            embedding vector(1536) NOT NULL,
            metadata JSONB NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT now(),
            UNIQUE (
                engagement_id, authorization_version,
                category, payload_type, content_sha256
            )
        )
        """
    )
    op.create_index(
        "ix_semantic_knowledge_engagement_category",
        "supervision_semantic_knowledge",
        ["engagement_id", "authorization_version", "category", "created_at"],
    )
    op.execute(
        """
        CREATE INDEX ix_semantic_knowledge_vector
        ON supervision_semantic_knowledge
        USING hnsw (embedding vector_cosine_ops)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX ix_semantic_knowledge_vector")
    op.drop_index(
        "ix_semantic_knowledge_engagement_category",
        table_name="supervision_semantic_knowledge",
    )
    op.drop_table("supervision_semantic_knowledge")
