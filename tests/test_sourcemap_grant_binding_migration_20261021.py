"""0037 additive immutable join schema and downgrade contract (NO live DB).

Inspects actual SQLAlchemy Alembic operations; it does not claim PostgreSQL
execution or a valid SourceMap grant was produced. A separate owner qualifies
disposable PG; this suite never contacts a database or worker.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/versions/0037_sourcemap_grant_binding.py"


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("sourcemap_bind_0037_qualification", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeConnection:
    def __init__(self, *, rows: bool = False) -> None:
        self.dialect = SimpleNamespace(name="postgresql")
        self.transactional = True
        self.rows = rows
        self.calls: list[str] = []

    def in_transaction(self) -> bool:
        return self.transactional

    def exec_driver_sql(self, sql: str) -> None:
        self.calls.append(sql)

    def execute(self, sql: Any) -> Any:
        query = str(sql)
        self.calls.append(query)
        assert query.strip() == ("SELECT EXISTS (SELECT 1 FROM native_sourcemap_grant_bindings)")
        return SimpleNamespace(scalar_one=lambda: self.rows)


class _FakeOperations:
    def __init__(self, *, rows: bool = False) -> None:
        self.connection = _FakeConnection(rows=rows)
        self.context = SimpleNamespace(as_sql=False)
        self.calls: list[tuple[str, Any]] = []

    def get_bind(self) -> _FakeConnection:
        return self.connection

    def get_context(self) -> Any:
        return self.context

    def create_table(self, *args: Any) -> None:
        self.calls.append(("create_table", args))

    def create_index(self, *args: Any) -> None:
        self.calls.append(("create_index", args))

    def execute(self, sql: Any) -> None:
        self.calls.append(("execute", str(sql)))

    def drop_index(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(("drop_index", args))

    def drop_table(self, *args: Any) -> None:
        self.calls.append(("drop_table", args))


def test_only_one_additive_0037_head_and_source_parent() -> None:
    revisions = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    assert revisions.get_heads() == ["0038"]
    assert revisions.get_revision("0038").down_revision == "0037"
    assert revisions.get_revision("0037").down_revision == "0036"
    assert revisions.get_revision("0036").down_revision == "0035"
    assert revisions.get_revision("0035").down_revision == "0034"


def test_0037_upgrade_creates_only_immutable_binding_table_and_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _module()
    op = _FakeOperations()
    monkeypatch.setattr(mod, "op", op)
    mod.upgrade()
    assert [kind for kind, _ in op.calls] == ["create_table", "create_index", "execute"]
    name, *columns = op.calls[0][1]
    assert name == "native_sourcemap_grant_bindings"
    actual: dict[str, sa.Column] = {
        item.name: item for item in columns if isinstance(item, sa.Column)
    }
    for name in (
        "action_id",
        "request_id",
        "preflight_id",
        "grant_id",
        "artifact_id",
        "reviewer_id",
        "resource_manifest_sha256",
        "preflight_claims_sha256",
        "preflight_signature_sha256",
        "grant_claims_sha256",
        "grant_signature_sha256",
        "declaration_sha256",
        "parameters_sha256",
        "join_sha256",
        "status",
    ):
        assert name in actual
        assert actual[name].nullable is False
    assert actual["binding_id"].primary_key is True
    for name in ("action_id", "request_id", "preflight_id", "grant_id"):
        assert actual[name].unique is True
    expected_fk = {
        "action_id": "flow_mcp_action_dispatches.action_id",
        "preflight_id": "native_sourcemap_source_preflights.preflight_id",
        "grant_id": "native_mcp_execution_grants.grant_id",
        "artifact_id": "flow_artifacts.id",
    }
    for name, target in expected_fk.items():
        keys = list(actual[name].foreign_keys)
        assert len(keys) == 1
        assert keys[0].target_fullname == target
        assert keys[0].ondelete == "RESTRICT"
    constraints = {
        item.name: str(item.sqltext) for item in columns if isinstance(item, sa.CheckConstraint)
    }
    assert "status='bound_only'" in constraints["ck_sourcemap_grant_binding_inert"]
    assert "owner_id<>reviewer_id" in constraints["ck_sourcemap_grant_binding_inert"]
    assert "join_sha256 ~" in constraints["ck_sourcemap_grant_binding_hashes"]
    assert "ck_sourcemap_grant_binding_ids" in constraints
    assert "trg_sourcemap_grant_binding_immutable" in op.calls[-1][1]
    assert "BEFORE UPDATE OR DELETE" in op.calls[-1][1]
    assert "reject_target_authority_nonce_mutation()" in op.calls[-1][1]
    assert op.connection.calls == []


def test_0037_downgrade_denies_persisted_bindings_before_any_ddl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _module()
    op = _FakeOperations(rows=True)
    monkeypatch.setattr(mod, "op", op)
    with pytest.raises(RuntimeError, match="immutable SourceMap grant bindings exist"):
        mod.downgrade()
    assert op.calls == []
    assert op.connection.calls[0] == "SET LOCAL lock_timeout = '5s'"
    assert "ACCESS EXCLUSIVE MODE" in op.connection.calls[1]
    assert "SELECT EXISTS" in op.connection.calls[2]


@pytest.mark.parametrize("bad", ["offline", "sqlite", "no_transaction"])
def test_0037_rejects_unprotected_downgrade_before_lock_or_mutation(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    mod = _module()
    op = _FakeOperations()
    monkeypatch.setattr(mod, "op", op)
    if bad == "offline":
        op.context.as_sql = True
    elif bad == "sqlite":
        op.connection.dialect.name = "sqlite"
    else:
        op.connection.transactional = False
    with pytest.raises(RuntimeError, match="live transactional PostgreSQL"):
        mod.downgrade()
    assert op.connection.calls == []
    assert op.calls == []


def test_0037_downgrade_empty_only_reverts_own_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _module()
    op = _FakeOperations(rows=False)
    monkeypatch.setattr(mod, "op", op)
    mod.downgrade()
    assert [action for action, _ in op.calls] == ["execute", "drop_index", "drop_table"]
    assert "trg_sourcemap_grant_binding_immutable" in op.calls[0][1]
    assert op.calls[1][1] == ("ix_sourcemap_grant_binding_tenant_flow",)
    assert op.calls[2][1] == ("native_sourcemap_grant_bindings",)
