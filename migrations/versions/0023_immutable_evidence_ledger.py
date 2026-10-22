"""Immutable evidence ledger capturing SHA-256 digests and replay recipes.

Revision ID: 0023
Revises: 0022
"""

import sqlalchemy as sa
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column("finding_id", sa.String(128), nullable=False, index=True),
        sa.Column("source_tool", sa.String(128), nullable=False),
        sa.Column("source_tool_version", sa.String(64), nullable=False, server_default="1.0.0"),
        sa.Column("target_url", sa.String(1024), nullable=False),
        sa.Column("http_method", sa.String(16), nullable=False, server_default="GET"),
        sa.Column("request_headers_sha256", sa.String(64), nullable=False),
        sa.Column("request_body_sha256", sa.String(64), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=False),
        sa.Column("response_headers_sha256", sa.String(64), nullable=False),
        sa.Column("response_body_sha256", sa.String(64), nullable=False),
        sa.Column("raw_storage_uri", sa.String(512), nullable=False, server_default=""),
        sa.Column("approval_id", sa.String(64), nullable=True),
        sa.Column("replay_recipe", sa.JSON(), nullable=False),
        sa.Column("merkle_leaf_hash", sa.String(64), nullable=False, index=True),
        sa.Column("captured_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("evidence_artifacts")
