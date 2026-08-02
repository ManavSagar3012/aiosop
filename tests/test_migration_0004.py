"""Tests for alembic migration 0004 (outbox DLQ + audit-log soft-delete columns).

The migration must be safe on every DB the project can produce, because this
repo uses BOTH ``Base.metadata.create_all`` (fresh DBs get the columns from the
ORM) and alembic (existing DBs get patched). The migration therefore guards
every add with a live-schema inspection. These tests exercise it against
throwaway in-memory SQLite DBs -- no real Postgres required -- covering:

- ADD path: an old-schema DB missing the columns gets them, existing rows are
  backfilled, and (critically) the backfilled rows satisfy the hot-path
  predicates ``dlq == False`` / ``archived == False`` (a NULL would not, and old
  rows would be silently skipped forever).
- idempotency: running upgrade twice is a clean no-op.
- downgrade: removes exactly what upgrade added.
- guard paths: columns already present (create_all DB) and tables absent.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

_MIG = (
    Path(__file__).resolve().parents[1]
    / "migrations"
    / "versions"
    / "0004_add_dlq_and_soft_delete_columns.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("m0004", _MIG)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _apply(fn, engine):
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            fn()


def _cols(engine, table):
    return sorted(c["name"] for c in sa.inspect(engine).get_columns(table))


def _indexes(engine, table):
    return sorted(i["name"] for i in sa.inspect(engine).get_indexes(table))


def _old_schema_engine():
    """A DB predating the new columns, with one pre-existing row per table."""
    engine = sa.create_engine("sqlite://")
    with engine.begin() as c:
        c.exec_driver_sql("CREATE TABLE outbox (id TEXT PRIMARY KEY, processed INT)")
        c.exec_driver_sql("INSERT INTO outbox VALUES ('e1', 0)")
        c.exec_driver_sql("CREATE TABLE audit_logs (id TEXT PRIMARY KEY, event_type TEXT)")
        c.exec_driver_sql("INSERT INTO audit_logs VALUES ('a1', 'login')")
    return engine


def test_upgrade_adds_columns_and_indexes():
    m = _load()
    engine = _old_schema_engine()
    _apply(m.upgrade, engine)
    assert _cols(engine, "outbox") == ["attempt_count", "dlq", "id", "processed"]
    assert _cols(engine, "audit_logs") == ["archived", "archived_at", "event_type", "id"]
    assert "ix_outbox_dlq" in _indexes(engine, "outbox")
    assert "ix_audit_logs_archived" in _indexes(engine, "audit_logs")


def test_upgrade_backfills_existing_rows_to_match_hotpath_predicates():
    """The whole point of the server_default: old rows must be visible to the
    ``dlq == False`` / ``archived == False`` queries, not NULL-invisible."""
    m = _load()
    engine = _old_schema_engine()
    _apply(m.upgrade, engine)
    with engine.begin() as c:
        ob = c.exec_driver_sql("SELECT attempt_count, dlq FROM outbox WHERE id='e1'").fetchone()
        al = c.exec_driver_sql(
            "SELECT archived, archived_at FROM audit_logs WHERE id='a1'"
        ).fetchone()
        n_outbox = c.exec_driver_sql("SELECT COUNT(*) FROM outbox WHERE dlq = 0").scalar()
        n_audit = c.exec_driver_sql(
            "SELECT COUNT(*) FROM audit_logs WHERE archived = 0"
        ).scalar()
    assert tuple(ob) == (0, 0)
    assert al[0] == 0 and al[1] is None
    # Backfilled rows are matched by the hot-path predicates (not NULL-skipped).
    assert n_outbox == 1
    assert n_audit == 1


def test_upgrade_is_idempotent():
    m = _load()
    engine = _old_schema_engine()
    _apply(m.upgrade, engine)
    _apply(m.upgrade, engine)  # must not raise
    assert _cols(engine, "outbox") == ["attempt_count", "dlq", "id", "processed"]


def test_downgrade_removes_columns_and_indexes():
    m = _load()
    engine = _old_schema_engine()
    _apply(m.upgrade, engine)
    _apply(m.downgrade, engine)
    assert _cols(engine, "outbox") == ["id", "processed"]
    assert _cols(engine, "audit_logs") == ["event_type", "id"]
    assert "ix_outbox_dlq" not in _indexes(engine, "outbox")
    assert "ix_audit_logs_archived" not in _indexes(engine, "audit_logs")


def test_upgrade_noop_when_columns_already_present():
    """create_all-built DB already has the columns; upgrade must no-op, not error."""
    m = _load()
    engine = sa.create_engine("sqlite://")
    with engine.begin() as c:
        c.exec_driver_sql(
            "CREATE TABLE outbox (id TEXT PRIMARY KEY, attempt_count INT, dlq INT)"
        )
        c.exec_driver_sql("CREATE INDEX ix_outbox_dlq ON outbox(dlq)")
        c.exec_driver_sql(
            "CREATE TABLE audit_logs (id TEXT PRIMARY KEY, archived INT, archived_at TIMESTAMP)"
        )
        c.exec_driver_sql("CREATE INDEX ix_audit_logs_archived ON audit_logs(archived)")
    _apply(m.upgrade, engine)  # must not raise
    assert "attempt_count" in _cols(engine, "outbox")
    assert "archived" in _cols(engine, "audit_logs")


def test_upgrade_skips_when_tables_absent():
    m = _load()
    engine = sa.create_engine("sqlite://")
    _apply(m.upgrade, engine)  # must not raise
    assert "outbox" not in sa.inspect(engine).get_table_names()
