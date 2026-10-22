"""Opt-in REAL PostgreSQL/Alembic Operations test for 0036 schema ONLY.

This starts its own nonroot PostgreSQL 16 cluster in /tmp and restricts access
to a private Unix socket (listen_addresses=''). Its miniature 0029-like table
contains only the original CHECK and unique Action/request keys: it is NOT the
application schema, full migration chain, a production grant or a worker.

Run with OSOP_DISPOSABLE_0036_PG=1 on Linux with local initdb/pg_ctl and the
SQLAlchemy + Alembic + psycopg dependencies available. No external targets,
Docker, application database or migration stamp is contacted/changed.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.exc import DBAPIError, IntegrityError


_ROOT = Path(__file__).resolve().parents[2]
_FILE = _ROOT / "migrations/versions/0036_sourcemap_native_grant_pair.py"
_BIN = Path("/usr/lib/postgresql/16/bin")
_TABLE = "native_mcp_execution_grants"
_CONSTRAINT = "ck_native_mcp_grant_inert_tool"


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("test_0036_real_alembic_ops", _FILE)
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    assert result.revision == "0036" and result.down_revision == "0035"
    return result


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, text=True, capture_output=True, timeout=45)


@pytest.fixture(scope="module")
def disposable_pg() -> Iterator[sa.Engine]:
    if sys.platform != "linux" or os.name != "posix":
        pytest.skip("Disposable PostgreSQL socket-only qualification requires Linux")
    if os.environ.get("OSOP_DISPOSABLE_0036_PG") != "1":
        pytest.skip("Set OSOP_DISPOSABLE_0036_PG=1 for isolated PostgreSQL")
    if os.geteuid() == 0:
        pytest.skip("Cannot initialize disposable PostgreSQL as root")
    if not all((_BIN / tool).is_file() for tool in ("initdb", "pg_ctl")):
        pytest.skip("Local PostgreSQL 16 initdb/pg_ctl absent")
    try:
        import psycopg  # noqa: F401 - explicit availability check
    except ImportError:
        pytest.skip("SQLAlchemy psycopg DBAPI missing")

    with tempfile.TemporaryDirectory(prefix="osop-0036-alembic-", dir="/tmp") as temp:
        root = Path(temp)
        root.chmod(stat.S_IRWXU)
        data = root / "data"
        log = root / "postgres.log"
        port = 54000 + secrets.randbelow(1000)
        init = _run(
            [
                str(_BIN / "initdb"),
                "-D",
                str(data),
                "-A",
                "trust",
                "-U",
                "osop_disposable",
                "--no-instructions",
            ]
        )
        assert init.returncode == 0, init.stderr[-900:]
        started = False
        engine: sa.Engine | None = None
        try:
            boot = _run(
                [
                    str(_BIN / "pg_ctl"),
                    "-D",
                    str(data),
                    "-l",
                    str(log),
                    "-o",
                    (
                        "-c listen_addresses='' "
                        f"-c unix_socket_directories={root} "
                        "-c unix_socket_permissions=0700 "
                        f"-c port={port} -c fsync=on -c synchronous_commit=on"
                    ),
                    "-w",
                    "-t",
                    "20",
                    "start",
                ]
            )
            assert boot.returncode == 0, boot.stderr[-900:]
            started = True
            assert (root / f".s.PGSQL.{port}").is_socket()
            engine = sa.create_engine(
                "postgresql+psycopg://osop_disposable@/postgres",
                connect_args={"host": str(root), "port": port, "connect_timeout": 3},
                pool_size=2,
                max_overflow=2,
            )
            with engine.connect() as connection:
                assert connection.scalar(sa.text("SHOW listen_addresses")) == ""
                assert connection.scalar(sa.text("SHOW port")) == str(port)
                assert connection.scalar(sa.text("SELECT current_database()")) == "postgres"
            yield engine
        finally:
            if engine is not None:
                engine.dispose()
            if started:
                stop = _run([str(_BIN / "pg_ctl"), "-D", str(data), "-w", "-m", "fast", "stop"])
                assert stop.returncode == 0, stop.stderr[-900:]


def _install_minimal_0029(engine: sa.Engine, migration: ModuleType) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "CREATE TABLE native_mcp_execution_grants ("
                "grant_id TEXT PRIMARY KEY, "
                "action_id TEXT NOT NULL UNIQUE, "
                "request_id TEXT NOT NULL UNIQUE, "
                "server_id TEXT NOT NULL, "
                "tool_name TEXT NOT NULL, "
                "side_effect_class TEXT NOT NULL, "
                "CONSTRAINT ck_native_mcp_grant_inert_tool CHECK (" + migration._ORIGINAL + "))"
            )
        )


def _insert(
    connection: sa.Connection,
    key: str,
    server: str,
    tool: str,
    effect: str = "READ_ONLY",
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO native_mcp_execution_grants "
            "(grant_id, action_id, request_id, server_id, tool_name, side_effect_class) "
            "VALUES (:key, :action, :request, :server, :tool, :effect)"
        ),
        {
            "key": "ngr-" + key,
            "action": "action-" + key,
            "request": "req-" + key,
            "server": server,
            "tool": tool,
            "effect": effect,
        },
    )


def _actual_check(connection: sa.Connection) -> str:
    result = connection.scalar(
        sa.text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'native_mcp_execution_grants'::regclass "
            "AND conname=:name"
        ),
        {"name": _CONSTRAINT},
    )
    assert type(result) is str and result.startswith("CHECK (")
    return result


def _operations(connection: sa.Connection) -> Any:
    context = MigrationContext.configure(connection, opts={"transactional_ddl": True})
    assert context.impl.transactional_ddl is True
    assert not context.as_sql
    return Operations.context(context)


def _invoke(connection: sa.Connection, migration: ModuleType, direction: str) -> None:
    assert direction in {"upgrade", "downgrade"}
    assert connection.in_transaction()
    with _operations(connection):
        getattr(migration, direction)()


def test_0036_real_alembic_ops_upgrade_and_downgrade_fail_closed(
    disposable_pg: sa.Engine,
) -> None:
    migration = _migration()
    _install_minimal_0029(disposable_pg, migration)
    with disposable_pg.begin() as connection:
        _insert(connection, "good", "recon-mcp", "authority_status")
        # Original 0029 CHECK has no server allowlist. Existing unexpected
        # inert services therefore require an explicit 0036 preflight denial.
        _insert(connection, "legacy", "unlisted-mcp", "authority_status")
    with disposable_pg.connect() as connection:
        original = _actual_check(connection)

    with pytest.raises(RuntimeError, match="existing native grants fall outside"):
        with disposable_pg.begin() as connection:
            _invoke(connection, migration, "upgrade")
    with disposable_pg.begin() as connection:
        assert _actual_check(connection) == original
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM native_mcp_execution_grants")) == 2
        connection.execute(
            sa.text("DELETE FROM native_mcp_execution_grants WHERE grant_id='ngr-legacy'")
        )
    with disposable_pg.begin() as connection:
        _invoke(connection, migration, "upgrade")
        paired = _actual_check(connection)
        assert "source-map-mcp" in paired
        assert "inspect_local_original_sourcemap" in paired
        assert paired != original

    with disposable_pg.begin() as connection:
        _insert(connection, "source", "source-map-mcp", "inspect_local_original_sourcemap")
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM native_mcp_execution_grants")) == 2
    for key, server, tool, effect in (
        ("wrong-tool", "source-map-mcp", "authority_status", "READ_ONLY"),
        ("wrong-server", "recon-mcp", "inspect_local_original_sourcemap", "READ_ONLY"),
        ("wrong-class", "source-map-mcp", "inspect_local_original_sourcemap", "RECON_ACTIVE"),
        ("wrong-unknown", "unlisted-mcp", "authority_status", "READ_ONLY"),
    ):
        with pytest.raises(IntegrityError):
            with disposable_pg.begin() as connection:
                _insert(connection, key, server, tool, effect)

    with pytest.raises(RuntimeError, match="SourceMap native grant rows exist"):
        with disposable_pg.begin() as connection:
            _invoke(connection, migration, "downgrade")
    with disposable_pg.begin() as connection:
        assert _actual_check(connection) == paired
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM native_mcp_execution_grants")) == 2
        connection.execute(
            sa.text("DELETE FROM native_mcp_execution_grants WHERE grant_id='ngr-source'")
        )  # Fixture-only cleanup of one synthetic row; never migration logic.
    with disposable_pg.begin() as connection:
        _invoke(connection, migration, "downgrade")
        assert _actual_check(connection) == original
    with pytest.raises(IntegrityError):
        with disposable_pg.begin() as connection:
            _insert(connection, "after", "source-map-mcp", "inspect_local_original_sourcemap")
    with disposable_pg.connect() as connection:
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM native_mcp_execution_grants")) == 1


def test_0036_real_alembic_ops_precheck_write_fence_and_one_use(
    disposable_pg: sa.Engine,
) -> None:
    migration = _migration()
    with disposable_pg.begin() as connection:
        connection.execute(sa.text("TRUNCATE native_mcp_execution_grants"))
        _insert(connection, "safe", "recon-mcp", "authority_status")

    # The real migration takes ACCESS EXCLUSIVE before the precheck. A second
    # connection attempting to insert a formerly valid *unlisted* service must
    # time out while the first migration transaction owns that lock. This is a
    # DB lock/DDL qualification, not a production multi-worker grant issuance.
    with disposable_pg.connect() as connection:
        with connection.begin():
            context = MigrationContext.configure(connection, opts={"transactional_ddl": True})
            with Operations.context(context):
                observed = migration._locked_pg_connection()
                assert observed is connection
                assert migration._has_invalid_rows(connection, migration._PAIRWISE) is False

                def blocked_writer() -> str:
                    try:
                        with disposable_pg.connect() as writer:
                            with writer.begin():
                                writer.execute(sa.text("SET LOCAL lock_timeout='400ms'"))
                                _insert(writer, "racing", "unlisted-mcp", "authority_status")
                    except DBAPIError as exc:
                        return str(getattr(exc.orig, "sqlstate", ""))
                    return "UNEXPECTED_SUCCESS"

                with ThreadPoolExecutor(max_workers=1) as pool:
                    outcome = pool.submit(blocked_writer).result(timeout=8)
                assert outcome == "55P03", outcome  # PG lock_not_available
                migration.upgrade()  # Actual Alembic Operations; reentrant table lock.
    with disposable_pg.begin() as connection:
        assert "source-map-mcp" in _actual_check(connection)

    # Original UNIQUE(action_id) and UNIQUE(request_id) remain in place after
    # real Alembic constraint replacement. Exactly one duplicate source wins.
    def issue_one(key: str) -> bool:
        try:
            with disposable_pg.begin() as connection:
                connection.execute(
                    sa.text(
                        "INSERT INTO native_mcp_execution_grants "
                        "(grant_id, action_id, request_id, server_id, tool_name, side_effect_class) "
                        "VALUES (:id, 'action-race', :req, "
                        "'source-map-mcp', 'inspect_local_original_sourcemap', 'READ_ONLY')"
                    ),
                    {"id": "ngr-" + key, "req": "req-" + key},
                )
        except IntegrityError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        winners = list(pool.map(issue_one, ("winner-one", "winner-two")))
    assert sum(winners) == 1
    with disposable_pg.begin() as connection:
        assert (
            connection.scalar(
                sa.text(
                    "SELECT COUNT(*) FROM native_mcp_execution_grants WHERE action_id='action-race'"
                )
            )
            == 1
        )
        connection.execute(
            sa.text("DELETE FROM native_mcp_execution_grants WHERE action_id='action-race'")
        )  # Scope-limited fixture cleanup, not operational replay.
        migration_op = MigrationContext.configure(connection, opts={"transactional_ddl": True})
        with Operations.context(migration_op):
            migration.downgrade()
        assert "source-map-mcp" not in _actual_check(connection)
