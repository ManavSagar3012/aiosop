"""Admit an exact SourceMap *schema identity* alongside six inert Go pairs.

Revision ID: 0036
Revises: 0035

This changes only the 0029 grant CHECK. It does not issue a SourceMap grant,
install a redemption handler, or change any existing single-use lifecycle.
The current Python issuer/validators intentionally still reject SourceMap.

Both directions demand an online PostgreSQL transaction, serialize grant
writes, and reject unsafe existing rows BEFORE changing the constraint.
Downgrade refuses to discard SourceMap grants or silently delete any data.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None

_TABLE = "native_mcp_execution_grants"
_CHECK = "ck_native_mcp_grant_inert_tool"

_ORIGINAL = "tool_name='authority_status' AND side_effect_class='READ_ONLY'"

# Keep the finite Go allowlist in sync with the existing central executor.
# Pair server AND tool before applying READ_ONLY to the entire expression.
_PAIRWISE = (
    "side_effect_class='READ_ONLY' AND ("
    "(server_id IN ('recon-mcp','payload-mcp','nuclei-mcp','shodan-mcp',"
    "'threat-intel-mcp','security-bridge') AND tool_name='authority_status') "
    "OR (server_id='source-map-mcp' "
    "AND tool_name='inspect_local_original_sourcemap'))"
)


def _locked_pg_connection():
    """Hold a transaction-wide table lock through precheck and CHECK DDL."""
    context = op.get_context()
    connection = op.get_bind()
    if (
        context.as_sql
        or context.impl.transactional_ddl is not True
        or connection.dialect.name != "postgresql"
        or not connection.in_transaction()
    ):
        raise RuntimeError("0036 requires online transactional PostgreSQL migration")

    # SET LOCAL is transaction-scoped. If concurrent writes hold the table,
    # abort without changing any schema or taking an unbounded blocking lock.
    connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
    connection.exec_driver_sql("LOCK TABLE native_mcp_execution_grants IN ACCESS EXCLUSIVE MODE")
    return connection


def _has_invalid_rows(connection, predicate: str) -> bool:
    # SQL comes only from our two fixed module constants, never from a caller.
    return bool(
        connection.execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM native_mcp_execution_grants "
                "WHERE NOT (" + predicate + "))"
            )
        ).scalar_one()
    )


def upgrade() -> None:
    connection = _locked_pg_connection()
    if _has_invalid_rows(connection, _PAIRWISE):
        raise RuntimeError(
            "0036 blocked: existing native grants fall outside the six Go "
            "authority_status pairs and exact SourceMap READ_ONLY pair"
        )
    op.drop_constraint(_CHECK, _TABLE, type_="check")
    op.create_check_constraint(_CHECK, _TABLE, _PAIRWISE)


def downgrade() -> None:
    connection = _locked_pg_connection()
    # Checking server_id, rather than just the new tool name, means any
    # SourceMap grant row prevents an accidental destructive downgrade.
    has_sourcemap = connection.execute(
        sa.text(
            "SELECT EXISTS (SELECT 1 FROM native_mcp_execution_grants "
            "WHERE server_id='source-map-mcp')"
        )
    ).scalar_one()
    if has_sourcemap:
        raise RuntimeError(
            "0036 downgrade blocked: SourceMap native grant rows exist; "
            "reconcile them independently without deleting records"
        )
    if _has_invalid_rows(connection, _ORIGINAL):
        raise RuntimeError("0036 downgrade blocked: a native grant violates original 0029 CHECK")
    op.drop_constraint(_CHECK, _TABLE, type_="check")
    op.create_check_constraint(_CHECK, _TABLE, _ORIGINAL)
