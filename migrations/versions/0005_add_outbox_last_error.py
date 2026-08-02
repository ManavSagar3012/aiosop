"""Add the missing outbox.last_error column

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-20

AIOSOP-OUTBOX-LASTERR-2026-07-20. The ORM (session_memory.OutboxORM) declares
three DLQ columns: ``attempt_count``, ``dlq`` and ``last_error``. Migration 0004
added the first two to EXISTING databases but forgot ``last_error`` — so a DB
that was originally built by ``Base.metadata.create_all`` *before* last_error was
added to the ORM, then upgraded via alembic, ends up WITHOUT the column. The
outbox processor writes ``last_error=str(e)[:512]`` on a failed entry
(outbox_processor.py), so every failure path then blows up with
``UndefinedColumnError: column "last_error" of relation "outbox" does not exist``
— which is exactly the agent-recovery E2E failure this migration fixes.

Fresh create_all DBs already have the column (the ORM declares it), so the add
is guarded by a live-schema inspection: ``alembic upgrade`` is a no-op where the
column already exists and only patches the DBs that are missing it. Portable
across Postgres and SQLite. ``last_error`` is nullable with no server_default —
it is legitimately NULL for entries that have never failed, and no hot-path
predicate filters on it, so (unlike dlq/attempt_count in 0004) no default is
required.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def _cols(insp, table):
    return {c["name"] for c in insp.get_columns(table)}


def _tables(insp):
    return set(insp.get_table_names())


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "outbox" in _tables(insp):
        if "last_error" not in _cols(insp, "outbox"):
            op.add_column(
                "outbox",
                sa.Column("last_error", sa.String(length=512), nullable=True),
            )


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "outbox" in _tables(insp):
        if "last_error" in _cols(insp, "outbox"):
            op.drop_column("outbox", "last_error")
