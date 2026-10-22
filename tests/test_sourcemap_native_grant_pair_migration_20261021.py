"""Schema-only 0036 qualifications; no live PostgreSQL, Docker or target IO.

Runs real migration functions against an in-memory SQLite SELECT evaluator and
an explicit PostgreSQL/Alembic *facade* recording the attempted DDL. The facade
does not apply constraints to PostgreSQL; tests cannot certify a deployment.
"""

from __future__ import annotations

import ast
import importlib.util
import sqlite3
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Optional

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPGrantDenied,
    _native_manifest_sha256,
    _validate_claims,
)

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/versions/0036_sourcemap_native_grant_pair.py"
PRIOR = ROOT / "migrations/versions/0029_native_mcp_execution_grants.py"
GO = (
    "recon-mcp",
    "payload-mcp",
    "nuclei-mcp",
    "shodan-mcp",
    "threat-intel-mcp",
    "security-bridge",
)
SOURCE = "source-map-mcp"
SOURCE_TOOL = "inspect_local_original_sourcemap"


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sourcemap_grant_pair_0036_test", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prior_check() -> str:
    tree = ast.parse(PRIOR.read_text(encoding="utf-8"))
    matches: list[str] = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "CheckConstraint":
            continue
        names = {keyword.arg: keyword.value for keyword in call.keywords}
        if "name" in names and ast.literal_eval(names["name"]) == "ck_native_mcp_grant_inert_tool":
            matches.append(ast.literal_eval(call.args[0]))
    assert len(matches) == 1
    return matches[0]


def _sql_accepts(condition: str, server: str, tool: str, effect: str) -> bool:
    """Evaluate an actual, constant Alembic CHECK in isolated SQLite only."""
    with sqlite3.connect(":memory:") as db:
        db.execute(
            "CREATE TABLE native_mcp_execution_grants ("
            "server_id TEXT NOT NULL, tool_name TEXT NOT NULL, "
            "side_effect_class TEXT NOT NULL, CHECK (" + condition + "))"
        )
        try:
            db.execute(
                "INSERT INTO native_mcp_execution_grants VALUES (?, ?, ?)",
                (server, tool, effect),
            )
        except sqlite3.IntegrityError:
            return False
        return True


class _Scalar:
    def __init__(self, value: Any) -> None:
        self.value = value

    def scalar_one(self) -> Any:
        return self.value


class _SimulatedPG:
    """SQLite SELECT truth oracle, with explicit *simulated* PG facade."""

    def __init__(self, rows: list[tuple[str, str, str]]) -> None:
        self.dialect = SimpleNamespace(name="postgresql")
        self.tx_active = True
        self.statements: list[str] = []
        self.memory = sqlite3.connect(":memory:")
        self.memory.execute(
            "CREATE TABLE native_mcp_execution_grants ("
            "server_id TEXT NOT NULL, tool_name TEXT NOT NULL, "
            "side_effect_class TEXT NOT NULL)"
        )
        self.memory.executemany("INSERT INTO native_mcp_execution_grants VALUES (?, ?, ?)", rows)

    def in_transaction(self) -> bool:
        return self.tx_active

    def exec_driver_sql(self, sql: str) -> None:
        assert sql.startswith("SET LOCAL ") or sql.startswith("LOCK TABLE ")
        self.statements.append(sql)

    def execute(self, statement: Any) -> _Scalar:
        query = str(statement)
        assert query.startswith("SELECT EXISTS (SELECT 1 FROM native_mcp_execution_grants ")
        self.statements.append(query)
        return _Scalar(bool(self.memory.execute(query).fetchone()[0]))


class _Operations:
    def __init__(self, connection: _SimulatedPG) -> None:
        self.connection = connection
        self.context = SimpleNamespace(as_sql=False, impl=SimpleNamespace(transactional_ddl=True))
        self.ddl: list[tuple[str, str, str, Optional[str]]] = []

    def get_context(self) -> Any:
        return self.context

    def get_bind(self) -> Any:
        return self.connection

    def drop_constraint(self, name: str, table: str, *, type_: str) -> None:
        self.ddl.append(("drop", name, table, type_))

    def create_check_constraint(self, name: str, table: str, sqltext: str) -> None:
        self.ddl.append(("create", name, table, sqltext))


def _run_migration(
    monkeypatch: pytest.MonkeyPatch, rows: list[tuple[str, str, str]]
) -> tuple[ModuleType, _Operations, _SimulatedPG]:
    module = _migration()
    connection = _SimulatedPG(rows)
    operation = _Operations(connection)
    monkeypatch.setattr(module, "op", operation)
    return module, operation, connection


def test_alembic_head_and_immediate_parent_are_exact() -> None:
    directory = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    # 0037 is an additive, separately denied SourceMap provenance binding;
    # it does not widen the 0036 CHECK or authorize any native grant.
    assert len(directory.get_heads()) == 1
    assert "0038" in {revision.revision for revision in directory.walk_revisions()}
    assert directory.get_revision("0038").down_revision == "0037"
    assert directory.get_revision("0037").down_revision == "0036"
    assert directory.get_revision("0036").down_revision == "0035"
    assert directory.get_revision("0035").down_revision == "0034"
    assert directory.get_revision("0029").down_revision == "0028"
    m = _migration()
    assert m.revision == "0036" and m.down_revision == "0035"


def test_only_old_inert_check_changes_and_exact_constraint_is_retained() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    script = ast.parse(source)
    invoked_alembic = {
        node.func.attr
        for node in ast.walk(script)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "op"
    }
    assert invoked_alembic == {
        "get_context",
        "get_bind",
        "drop_constraint",
        "create_check_constraint",
    }
    assert "INSERT INTO" not in source
    assert "DELETE FROM native_mcp_execution_grants" not in source
    assert "UPDATE native_mcp_execution_grants" not in source
    assert "DROP TABLE" not in source
    assert "DROP COLUMN" not in source
    m = _migration()
    assert m._TABLE == "native_mcp_execution_grants"
    assert m._CHECK == "ck_native_mcp_grant_inert_tool"
    assert m._ORIGINAL == _prior_check()
    assert "side_effect_class='READ_ONLY' AND (" in m._PAIRWISE
    assert "OR (server_id='source-map-mcp' " in m._PAIRWISE


@pytest.mark.parametrize(
    ("server", "tool", "effect", "expected"),
    [
        *((name, "authority_status", "READ_ONLY", True) for name in GO),
        (SOURCE, SOURCE_TOOL, "READ_ONLY", True),
        (SOURCE, SOURCE_TOOL, "RECON_ACTIVE", False),
        (SOURCE, SOURCE_TOOL, "INVASIVE_EXPLOIT", False),
        (SOURCE, "authority_status", "READ_ONLY", False),
        ("recon-mcp", SOURCE_TOOL, "READ_ONLY", False),
        ("browser-mcp", SOURCE_TOOL, "READ_ONLY", False),
        ("other-mcp", "authority_status", "READ_ONLY", False),
        ("other-mcp", SOURCE_TOOL, "READ_ONLY", False),
        ("recon-mcp", "authority_status", "RECON_ACTIVE", False),
        ("recon-mcp", "run_shell", "READ_ONLY", False),
    ],
)
def test_literal_0036_check_is_pairwise_and_cannot_mint_broad_grants(
    server: str, tool: str, effect: str, expected: bool
) -> None:
    new = _migration()._PAIRWISE
    assert _sql_accepts(new, server, tool, effect) is expected
    if server == SOURCE and tool == SOURCE_TOOL and expected:
        assert not _sql_accepts(_prior_check(), server, tool, effect)


def test_upgrade_uses_atomic_lock_and_precheck_before_any_ddl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, op, db = _run_migration(monkeypatch, [("recon-mcp", "authority_status", "READ_ONLY")])
    module.upgrade()
    assert db.statements[0] == "SET LOCAL lock_timeout = '5s'"
    assert db.statements[1] == ("LOCK TABLE native_mcp_execution_grants IN ACCESS EXCLUSIVE MODE")
    assert len(db.statements) == 3
    assert "WHERE NOT (" + module._PAIRWISE + ")" in db.statements[2]
    assert op.ddl == [
        ("drop", module._CHECK, module._TABLE, "check"),
        ("create", module._CHECK, module._TABLE, module._PAIRWISE),
    ]


@pytest.mark.parametrize(
    "legacy",
    [
        ("browser-mcp", "authority_status", "READ_ONLY"),
        ("other-mcp", "authority_status", "READ_ONLY"),
        ("source-map-mcp", "authority_status", "READ_ONLY"),
        ("recon-mcp", "authority_status", "RECON_ACTIVE"),
    ],
)
def test_upgrade_denies_outside_finite_map_before_drop(
    monkeypatch: pytest.MonkeyPatch, legacy: tuple[str, str, str]
) -> None:
    module, op, db = _run_migration(monkeypatch, [legacy])
    with pytest.raises(RuntimeError, match="0036 blocked: existing native grants"):
        module.upgrade()
    assert len(db.statements) == 3
    assert op.ddl == []


def test_upgrade_accepts_eligible_sourcemap_row_only_as_schema_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, op, _ = _run_migration(monkeypatch, [(SOURCE, SOURCE_TOOL, "READ_ONLY")])
    module.upgrade()
    assert len(op.ddl) == 2
    assert op.ddl[1][3] == module._PAIRWISE


def test_downgrade_returns_exact_old_check_when_no_sourcemap_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, op, db = _run_migration(
        monkeypatch,
        [("recon-mcp", "authority_status", "READ_ONLY")],
    )
    module.downgrade()
    assert len(db.statements) == 4
    assert "WHERE server_id='source-map-mcp'" in db.statements[2]
    assert "WHERE NOT (" + _prior_check() + ")" in db.statements[3]
    assert op.ddl == [
        ("drop", module._CHECK, module._TABLE, "check"),
        ("create", module._CHECK, module._TABLE, module._ORIGINAL),
    ]


@pytest.mark.parametrize(
    "source_row",
    [
        (SOURCE, SOURCE_TOOL, "READ_ONLY"),
        (SOURCE, "authority_status", "READ_ONLY"),
    ],
)
def test_downgrade_refuses_any_sourcemap_rows_without_mutation(
    monkeypatch: pytest.MonkeyPatch, source_row: tuple[str, str, str]
) -> None:
    module, op, db = _run_migration(monkeypatch, [source_row])
    with pytest.raises(RuntimeError, match="SourceMap native grant rows exist"):
        module.downgrade()
    assert len(db.statements) == 3
    assert op.ddl == []


def test_downgrade_denies_unexpected_non_sourcemap_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, op, db = _run_migration(monkeypatch, [("other-mcp", "suspicious", "READ_ONLY")])
    with pytest.raises(RuntimeError, match="original 0029 CHECK"):
        module.downgrade()
    assert len(db.statements) == 4
    assert op.ddl == []


@pytest.mark.parametrize("change", ["offline", "non_postgresql", "non_atomic", "no_transaction"])
def test_migration_refuses_unverifiable_transaction_before_lock_or_ddl(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    module, op, db = _run_migration(monkeypatch, [])
    if change == "offline":
        op.context.as_sql = True
    elif change == "non_postgresql":
        db.dialect.name = "sqlite"
    elif change == "non_atomic":
        op.context.impl.transactional_ddl = False
    elif change == "no_transaction":
        db.tx_active = False
    with pytest.raises(RuntimeError, match="online transactional PostgreSQL"):
        module.upgrade()
    with pytest.raises(RuntimeError, match="online transactional PostgreSQL"):
        module.downgrade()
    assert db.statements == []
    assert op.ddl == []


def test_python_grant_tool_validator_remains_closed_after_schema_revision() -> None:
    safe_server = "recon-mcp"
    inert = {
        "version": 1,
        "grant_id": "ngr-" + "a" * 32,
        "request_id": "req-" + "b" * 48,
        "engagement_id": "eng-contract",
        "flow_id": "flow-contract",
        "task_id": "task-contract",
        "subtask_id": "subtask-contract",
        "action_id": "action-" + "c" * 32,
        "server_id": safe_server,
        "tool_name": "authority_status",
        "parameters_sha256": __import__("hashlib").sha256(b"{}").hexdigest(),
        "manifest_sha256": _native_manifest_sha256(safe_server),
        "authorization_version": 1,
        "authorization_sha256": "d" * 64,
        "lease_id": "lease-contract",
        "resource_sha256": None,
        "issued_at": 1234567890,
        "expires_at": 1234567900,
        "side_effect_class": "READ_ONLY",
    }
    assert _validate_claims(inert) is inert
    with pytest.raises(NativeMCPGrantDenied, match="cannot authorize this tool"):
        _validate_claims({**inert, "server_id": SOURCE, "tool_name": SOURCE_TOOL})
