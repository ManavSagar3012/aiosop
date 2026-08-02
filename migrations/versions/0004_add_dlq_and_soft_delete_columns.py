"""Add outbox DLQ + audit-log soft-delete columns

Revision ID: 0004
Revises: 1e010edbfecb
Create Date: 2026-07-20

Phase-1 issues #12 (outbox DLQ) and #15 (audit-log soft-delete). The ORM in
session_memory.py already declares these columns, so a fresh DB built by
``Base.metadata.create_all`` has them; this migration patches an EXISTING DB
so the two paths converge:

    outbox.attempt_count    INTEGER   retry counter (0 on existing rows)
    outbox.dlq              BOOLEAN   dead-letter flag (indexed)
    audit_logs.archived     BOOLEAN   soft-delete flag (indexed)
    audit_logs.archived_at  DATETIME  when soft-deleted (NULL for live rows)

This repo runs create_all AND alembic (outbox / audit_logs / session_states are
create_all-only tables that later migrations still patch, e.g. 1e010edbfecb
adds session_states.last_accessed). Because a create_all-built DB may ALREADY
have these columns, every add here is guarded by a live-schema inspection so
``alembic upgrade`` is safe whether the target DB came from create_all, from
pure migrations, or a mix.

The booleans/counter are added WITH a server_default (0 / false). This is
functionally required, not cosmetic: existing rows would otherwise get NULL,
and the hot-path queries filter ``dlq == False`` (outbox_processor) and
``archived == False`` (retention_service) -- a NULL would fail those predicates
under SQL three-valued logic, so old rows would be silently skipped forever
(never processed / never archived). The server_default is left in place: it is
semantically identical to the ORM's client-side ``default=False`` and, unlike an
``ALTER COLUMN ... DROP DEFAULT`` step, keeps this migration portable
(Postgres + SQLite).
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "1e010edbfecb"
branch_labels = None
depends_on = None


def _cols(insp, table):
    return {c["name"] for c in insp.get_columns(table)}


def _indexes(insp, table):
    return {ix["name"] for ix in insp.get_indexes(table)}


def _tables(insp):
    return set(insp.get_table_names())


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    tables = _tables(insp)

    # --- outbox DLQ (issue #12) ---
    if "outbox" in tables:
        cols = _cols(insp, "outbox")
        if "attempt_count" not in cols:
            op.add_column(
                "outbox",
                sa.Column("attempt_count", sa.Integer(), nullable=True, server_default="0"),
            )
        if "dlq" not in cols:
            op.add_column(
                "outbox",
                sa.Column("dlq", sa.Boolean(), nullable=True, server_default=sa.false()),
            )
        if "ix_outbox_dlq" not in _indexes(insp, "outbox"):
            op.create_index("ix_outbox_dlq", "outbox", ["dlq"])

    # --- audit-log soft-delete (issue #15) ---
    if "audit_logs" in tables:
        cols = _cols(insp, "audit_logs")
        if "archived" not in cols:
            op.add_column(
                "audit_logs",
                sa.Column("archived", sa.Boolean(), nullable=True, server_default=sa.false()),
            )
        if "archived_at" not in cols:
            op.add_column("audit_logs", sa.Column("archived_at", sa.DateTime(), nullable=True))
        if "ix_audit_logs_archived" not in _indexes(insp, "audit_logs"):
            op.create_index("ix_audit_logs_archived", "audit_logs", ["archived"])


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    tables = _tables(insp)

    if "audit_logs" in tables:
        if "ix_audit_logs_archived" in _indexes(insp, "audit_logs"):
            op.drop_index("ix_audit_logs_archived", table_name="audit_logs")
        cols = _cols(insp, "audit_logs")
        if "archived_at" in cols:
            op.drop_column("audit_logs", "archived_at")
        if "archived" in cols:
            op.drop_column("audit_logs", "archived")

    if "outbox" in tables:
        if "ix_outbox_dlq" in _indexes(insp, "outbox"):
            op.drop_index("ix_outbox_dlq", table_name="outbox")
        cols = _cols(insp, "outbox")
        if "dlq" in cols:
            op.drop_column("outbox", "dlq")
        if "attempt_count" in cols:
            op.drop_column("outbox", "attempt_count")
