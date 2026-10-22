"""Preserve operator-knowledge tenant lineage and exact original text digest.

Revision ID: 0038
Revises: 0037

The original 0019 independent parent FKs permit an existing Flow belonging to
another engagement, and its hex-shaped sha256 CHECK cannot prove the contents
match. Fail before changing any constraint on inconsistent existing data. This
does NOT make Flow-owned text a user-global trusted agent knowledge base.
"""

import sqlalchemy as sa
from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None

_DOC = "operator_knowledge_documents"
_FLOW = "execution_flows"
_PARENT_UNIQUE = "uq_execution_flows_id_engagement_knowledge"
_TENANT_FK = "fk_operator_knowledge_exact_flow_tenant"
_DIGEST = "ck_operator_knowledge_content_digest"


def _locked_pg_connection() -> sa.engine.Connection:
    """Serialize existing-data validation and DDL with bounded wait/duration."""
    connection = op.get_bind()
    if (
        op.get_context().as_sql
        or connection.dialect.name != "postgresql"
        or not connection.in_transaction()
    ):
        raise RuntimeError("0038 requires a live transactional PostgreSQL connection")
    connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
    connection.exec_driver_sql("SET LOCAL statement_timeout = '15s'")
    # Locks make prechecks meaningful: concurrent cross-tenant insert or
    # content alteration cannot slip between verification and new constraints.
    connection.exec_driver_sql(
        "LOCK TABLE execution_flows, operator_knowledge_documents " "IN ACCESS EXCLUSIVE MODE"
    )
    return connection


def upgrade() -> None:
    conn = _locked_pg_connection()
    if conn.execute(
        sa.text("SELECT current_setting('server_version_num')::integer < 140000")
    ).scalar_one():
        raise RuntimeError("0038 requires PostgreSQL SHA-256 built-in function")
    mismatch = conn.execute(
        sa.text(
            "SELECT EXISTS (SELECT 1 FROM operator_knowledge_documents k "
            "LEFT JOIN execution_flows f ON f.id=k.flow_id "
            "WHERE f.id IS NULL OR f.engagement_id<>k.engagement_id "
            "OR k.sha256<>encode(sha256(convert_to(k.content,'UTF8')),'hex'))"
        )
    ).scalar_one()
    if mismatch:
        raise RuntimeError("0038 denied: existing knowledge tenant or content digest mismatch")
    # A composite FK must reference a composite UNIQUE or PK even though the
    # first field already has its own PK. The existing 0019 single-column FKs
    # remain in place, and the new FK closes their cross-tenant join gap.
    op.create_unique_constraint(_PARENT_UNIQUE, _FLOW, ["id", "engagement_id"])
    op.create_foreign_key(
        _TENANT_FK,
        _DOC,
        _FLOW,
        ["flow_id", "engagement_id"],
        ["id", "engagement_id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        _DIGEST,
        _DOC,
        "sha256=encode(sha256(convert_to(content,'UTF8')),'hex')",
    )


def downgrade() -> None:
    conn = _locked_pg_connection()
    # Never remove knowledge integrity guarantees while any user content,
    # including tombstoned rows, would immediately become writable unguarded.
    if conn.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM operator_knowledge_documents)")
    ).scalar_one():
        raise RuntimeError("0038 downgrade denied: operator knowledge rows remain")
    op.drop_constraint(_DIGEST, _DOC, type_="check")
    op.drop_constraint(_TENANT_FK, _DOC, type_="foreignkey")
    op.drop_constraint(_PARENT_UNIQUE, _FLOW, type_="unique")
