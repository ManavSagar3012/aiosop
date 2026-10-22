"""Fail-closed 0038 online migration contract (live PG qualified separately)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/versions/0038_operator_knowledge_integrity.py"


def _module():
    spec = importlib.util.spec_from_file_location("qual_0038_knowledge_integrity", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Result:
    def __init__(self, value: bool):
        self.value = value

    def scalar_one(self):
        return self.value


class _PG:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self, *, old_data_bad=False, populated=False, old_version=False, in_tx=True):
        self.old_data_bad = old_data_bad
        self.populated = populated
        self.old_version = old_version
        self.in_tx = in_tx
        self.statements = []

    def in_transaction(self):
        return self.in_tx

    def exec_driver_sql(self, sql):
        self.statements.append(sql)

    def execute(self, statement):
        text = str(statement)
        self.statements.append(text)
        if "server_version_num" in text:
            return _Result(self.old_version)
        if "LEFT JOIN execution_flows" in text:
            return _Result(self.old_data_bad)
        if "SELECT EXISTS" in text and "operator_knowledge_documents" in text:
            return _Result(self.populated)
        raise AssertionError("Unexpected migration query: " + text)


def _op(
    monkeypatch,
    *,
    old_data_bad=False,
    populated=False,
    old_version=False,
    offline=False,
    dialect="postgresql",
    in_tx=True,
):
    migration = _module()
    conn = _PG(old_data_bad=old_data_bad, populated=populated, old_version=old_version, in_tx=in_tx)
    conn.dialect = SimpleNamespace(name=dialect)
    operations = Mock()
    operations.get_bind.return_value = conn
    operations.get_context.return_value = SimpleNamespace(as_sql=offline)
    monkeypatch.setattr(migration, "op", operations)
    return migration, conn, operations


def test_0038_is_additive_to_0037_without_misrepresenting_0036_pair():
    revisions = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    # 0038 is still a linear ancestor; newer 0039 global library and 0040
    # durable subscriptions are additive, not competing Alembic heads.
    assert len(revisions.get_heads()) == 1
    assert "0040" in {revision.revision for revision in revisions.walk_revisions()}
    assert revisions.get_revision("0040").down_revision == "0039"
    assert revisions.get_revision("0039").down_revision == "0038"
    assert revisions.get_revision("0038").down_revision == "0037"
    assert revisions.get_revision("0037").down_revision == "0036"
    assert revisions.get_revision("0036").down_revision == "0035"


@pytest.mark.parametrize(
    "offline,dialect,in_tx",
    [
        (True, "postgresql", True),
        (False, "sqlite", True),
        (False, "postgresql", False),
    ],
)
def test_requires_actual_online_transactional_postgres(monkeypatch, offline, dialect, in_tx):
    m, conn, operations = _op(monkeypatch, offline=offline, dialect=dialect, in_tx=in_tx)
    with pytest.raises(RuntimeError, match="live transactional PostgreSQL"):
        m.upgrade()
    operations.create_unique_constraint.assert_not_called()
    assert not conn.statements


@pytest.mark.parametrize(
    "old_data_bad,old_version",
    [
        (True, False),
        (False, True),
    ],
)
def test_existing_wrong_tenant_digest_or_unsupported_pg_deny_before_ddl(
    monkeypatch, old_data_bad, old_version
):
    m, conn, operations = _op(monkeypatch, old_data_bad=old_data_bad, old_version=old_version)
    with pytest.raises(RuntimeError):
        m.upgrade()
    assert conn.statements[:3] == [
        "SET LOCAL lock_timeout = '5s'",
        "SET LOCAL statement_timeout = '15s'",
        "LOCK TABLE execution_flows, operator_knowledge_documents IN ACCESS EXCLUSIVE MODE",
    ]
    operations.create_unique_constraint.assert_not_called()
    operations.create_foreign_key.assert_not_called()
    operations.create_check_constraint.assert_not_called()


def test_exact_same_tenant_composite_fk_and_digest_additive_no_backfill(monkeypatch):
    m, conn, operations = _op(monkeypatch)
    m.upgrade()
    operations.create_unique_constraint.assert_called_once_with(
        "uq_execution_flows_id_engagement_knowledge",
        "execution_flows",
        ["id", "engagement_id"],
    )
    operations.create_foreign_key.assert_called_once_with(
        "fk_operator_knowledge_exact_flow_tenant",
        "operator_knowledge_documents",
        "execution_flows",
        ["flow_id", "engagement_id"],
        ["id", "engagement_id"],
        ondelete="RESTRICT",
    )
    check = operations.create_check_constraint.call_args
    assert check.args == (
        "ck_operator_knowledge_content_digest",
        "operator_knowledge_documents",
        "sha256=encode(sha256(convert_to(content,'UTF8')),'hex')",
    )
    assert not any("UPDATE " in stmt or "DELETE " in stmt for stmt in conn.statements)


def test_downgrade_refuses_existing_including_tombstones_without_dropping_constraints(monkeypatch):
    m, _, operations = _op(monkeypatch, populated=True)
    with pytest.raises(RuntimeError, match="rows remain"):
        m.downgrade()
    operations.drop_constraint.assert_not_called()


def test_only_empty_downgrade_restores_old_schema_and_preserves_data(monkeypatch):
    m, _, operations = _op(monkeypatch, populated=False)
    m.downgrade()
    assert [call.args for call in operations.drop_constraint.call_args_list] == [
        ("ck_operator_knowledge_content_digest", "operator_knowledge_documents"),
        ("fk_operator_knowledge_exact_flow_tenant", "operator_knowledge_documents"),
        ("uq_execution_flows_id_engagement_knowledge", "execution_flows"),
    ]
    assert [call.kwargs["type_"] for call in operations.drop_constraint.call_args_list] == [
        "check",
        "foreignkey",
        "unique",
    ]
