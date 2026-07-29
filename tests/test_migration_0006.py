"""Regression coverage for durable task execution-contract columns."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

_MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "migrations"
    / "versions"
    / "0006_add_task_execution_contract_columns.py"
)


def _migration():
    spec = importlib.util.spec_from_file_location("migration_0006", _MIGRATION)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _apply(operation, engine) -> None:
    with engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            operation()


def _columns(engine) -> list[str]:
    return sorted(column["name"] for column in sa.inspect(engine).get_columns("tasks"))


def _legacy_tasks_engine():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE tasks (id TEXT PRIMARY KEY, result JSON)")
        connection.exec_driver_sql("INSERT INTO tasks (id, result) VALUES ('task-1', '{}')")
    return engine


def test_upgrade_persists_task_contract_and_error_columns() -> None:
    engine = _legacy_tasks_engine()
    migration = _migration()

    _apply(migration.upgrade, engine)

    assert _columns(engine) == ["error", "id", "mcp_requirements", "result"]
    with engine.begin() as connection:
        row = connection.exec_driver_sql(
            "SELECT mcp_requirements, error FROM tasks WHERE id = 'task-1'"
        ).fetchone()
    assert row[0] in ("[]", [])
    assert row[1] is None


def test_migration_is_idempotent_and_downgrade_is_exact() -> None:
    engine = _legacy_tasks_engine()
    migration = _migration()

    _apply(migration.upgrade, engine)
    _apply(migration.upgrade, engine)
    _apply(migration.downgrade, engine)

    assert _columns(engine) == ["id", "result"]
