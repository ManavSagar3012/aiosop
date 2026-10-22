"""Migration startup and tenant-boundary tests without PostgreSQL or Docker.

Mocks exercise ordering and fail-closed behavior, not actual PostgreSQL DDL
transactions. The suite retains regression checks for historical migration and
Flow API trust-boundary vulnerabilities.
"""

import asyncio
import importlib.util
import runpy
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.security import HTTPAuthorizationCredentials

from ai_osop.api import deps
from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers.flows import router as flows_router
from ai_osop.core.models import (
    ExecutionActionRecord,
    FlowRecord,
    ScopeDefinition,
    SessionState,
    Task,
)
from ai_osop.core.config import AgentType
from ai_osop.memory import schema_migrations


REQUIRED_LEGACY_TABLES = {
    "tasks",
    "session_states",
    "approval_requests",
    "audit_logs",
    "user_sessions",
}
BASELINE_COLUMNS = {
    "tasks": {
        "id",
        "type",
        "priority",
        "agent_type",
        "payload",
        "dependencies",
        "max_retries",
        "timeout_seconds",
        "scope_check",
        "approval_required",
        "status",
        "result",
        "retry_count",
        "created_at",
        "started_at",
        "completed_at",
        "engagement_id",
        "assigned_agent_id",
    },
    "session_states": {
        "session_id",
        "scope",
        "roe",
        "phase",
        "agents",
        "checkpoint_id",
        "audit_log_position",
        "created_at",
        "updated_at",
    },
    "approval_requests": {
        "id",
        "task_id",
        "agent_id",
        "action_type",
        "target",
        "payload_summary",
        "risk_assessment",
        "evidence",
        "status",
        "operator_id",
        "operator_notes",
        "requested_at",
        "responded_at",
        "engagement_id",
    },
    "audit_logs": {
        "event_id",
        "timestamp",
        "event_type",
        "severity",
        "actor_type",
        "actor_id",
        "action",
        "result",
        "context",
        "integrity_hash",
        "engagement_id",
    },
    "user_sessions": {
        "pk",
        "engagement_id",
        "user_label",
        "cookies",
        "bearer_token",
        "local_storage",
        "session_storage",
        "csrf_token",
        "extra_headers",
        "user_agent",
        "captured_at",
        "expires_at",
        "metadata_blob",
    },
}
LOCK = "SELECT pg_advisory_lock(805060110003)"
UNLOCK = "SELECT pg_advisory_unlock(805060110003)"


class _Inspector:
    def __init__(self, tables, columns=("created_by",), versioned=False, overrides=None):
        self.tables = set(tables)
        self.columns = {name: set(baseline) for name, baseline in BASELINE_COLUMNS.items()}
        self.columns["session_states"].update(columns)
        self.columns.update({name: set(value) for name, value in (overrides or {}).items()})
        self.versioned = versioned

    def has_table(self, name):
        return self.versioned if name == "alembic_version" else name in self.tables

    def get_table_names(self):
        return list(self.tables)

    def get_columns(self, name):
        assert name in self.tables
        return [{"name": column} for column in sorted(self.columns[name])]


class _MockConnection:
    """AsyncConnection surrogate with a sync facade and transactional state.

    This deliberately models commit/rollback bookkeeping, not real PG DDL.
    """

    def __init__(self, engine, *, transactional=False):
        self.engine = engine
        self.transactional = transactional
        self.sync_connection = SimpleNamespace(engine=engine, async_connection=self)
        self._snapshot = None

    async def __aenter__(self):
        if self.transactional:
            self.engine.events.append("begin")
            self._snapshot = {
                "revision": self.engine.db_state["revision"],
                "tables": set(self.engine.db_state["tables"]),
            }
            self.engine.active_transactions += 1
            self.engine.max_active_transactions = max(
                self.engine.max_active_transactions, self.engine.active_transactions
            )
        else:
            self.engine.events.append("connect")
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        if self.transactional:
            if exc_type is None:
                self.engine.events.append("commit")
                self.engine.commits += 1
            else:
                self.engine.events.append("rollback")
                self.engine.rollbacks += 1
                self.engine.db_state = self._snapshot
            self.engine.active_transactions -= 1
        else:
            self.engine.events.append("close")
            # PostgreSQL releases session-scoped locks when the connection
            # closes, even if an explicit unlock statement itself has failed.
            if self.engine.lock.locked():
                self.engine.lock.release()

    async def execute(self, sql):
        statement = str(sql)
        self.engine.events.append(statement)
        if statement == LOCK:
            if self.engine.lock_error:
                raise self.engine.lock_error
            await self.engine.lock.acquire()
        elif statement == UNLOCK:
            if self.engine.unlock_error:
                raise self.engine.unlock_error
            self.engine.lock.release()
        else:
            pytest.fail(f"Unexpected SQL: {statement}")

    async def run_sync(self, function, *args):
        self.engine.events.append("run_sync_migration" if self.transactional else "inspect")
        # Yield while the transaction is open to expose interleaving attempts
        # by concurrent API startups in the lock-serialization test.
        await asyncio.sleep(0)
        return function(self.sync_connection, *args)


class _MockEngine:
    def __init__(self, inspector=None):
        self.inspector = inspector or _Inspector(REQUIRED_LEGACY_TABLES)
        self.events = []
        self.lock = asyncio.Lock()
        self.lock_error = None
        self.unlock_error = None
        self.db_state = {"revision": None, "tables": set()}
        self.commits = 0
        self.rollbacks = 0
        self.active_transactions = 0
        self.max_active_transactions = 0

    def connect(self):
        return _MockConnection(self)

    def begin(self):
        return _MockConnection(self, transactional=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tables", "columns", "versioned", "expected"),
    [
        (set(), (), False, None),
        (REQUIRED_LEGACY_TABLES, ("created_by",), True, None),
        (REQUIRED_LEGACY_TABLES, ("created_by",), False, "0002"),
        (REQUIRED_LEGACY_TABLES, (), False, "0001"),
    ],
)
async def test_legacy_revision_classification(monkeypatch, tables, columns, versioned, expected):
    engine = _MockEngine(_Inspector(tables, columns, versioned))
    monkeypatch.setattr(schema_migrations, "inspect", lambda _: engine.inspector)
    assert await schema_migrations._legacy_revision(engine) == expected


@pytest.mark.asyncio
async def test_partial_unversioned_schema_refuses_stamp(monkeypatch):
    engine = _MockEngine(_Inspector({"tasks", "session_states"}, ("created_by",)))
    monkeypatch.setattr(schema_migrations, "inspect", lambda _: engine.inspector)
    with pytest.raises(RuntimeError, match="Partial legacy database"):
        await schema_migrations._legacy_revision(engine)


@pytest.mark.asyncio
async def test_unversioned_schema_missing_required_columns_must_not_be_stamped(monkeypatch):
    engine = _MockEngine(
        _Inspector(
            REQUIRED_LEGACY_TABLES,
            columns=("created_by",),
            overrides={"tasks": {"id", "engagement_id"}},
        )
    )
    monkeypatch.setattr(schema_migrations, "inspect", lambda _: engine.inspector)
    # A table can have the expected name but be missing baseline columns.
    # Reject it rather than stamping revision 0002 and skipping those columns.
    with pytest.raises(RuntimeError, match="Legacy table tasks missing required"):
        await schema_migrations._legacy_revision(engine)


@pytest.mark.asyncio
async def test_ensure_schema_serializes_upgrade_and_unlocks(monkeypatch):
    engine = _MockEngine()
    upgrade_calls = []
    monkeypatch.setattr(schema_migrations, "_legacy_revision", AsyncMock(return_value="0002"))

    def upgrade(sync_connection, uri, legacy):
        assert engine.lock.locked()
        assert sync_connection.engine is engine
        assert sync_connection.async_connection.transactional
        upgrade_calls.append((sync_connection, uri, legacy))
        engine.events.append("upgrade")

    monkeypatch.setattr(schema_migrations, "_upgrade_migrations", upgrade)
    await schema_migrations.ensure_schema(engine, "postgresql+asyncpg://test/db")

    assert [(uri, rev) for _, uri, rev in upgrade_calls] == [
        ("postgresql+asyncpg://test/db", "0002")
    ]
    assert engine.events.index(LOCK) < engine.events.index("begin")
    assert engine.events.index("begin") < engine.events.index("upgrade")
    assert engine.events.index("upgrade") < engine.events.index("commit")
    assert engine.events.index("commit") < engine.events.index(UNLOCK)
    assert engine.commits == 1
    assert engine.rollbacks == 0
    assert not engine.lock.locked()


@pytest.mark.asyncio
async def test_ensure_schema_lock_keeps_concurrent_startups_sequential(monkeypatch):
    engine = _MockEngine()
    monkeypatch.setattr(schema_migrations, "_legacy_revision", AsyncMock(return_value=None))
    seen = []

    def upgrade(sync_connection, uri, legacy):
        assert engine.lock.locked()
        assert sync_connection.async_connection.transactional
        seen.append((sync_connection, uri, legacy))

    monkeypatch.setattr(schema_migrations, "_upgrade_migrations", upgrade)
    await asyncio.gather(
        schema_migrations.ensure_schema(engine, "postgresql+asyncpg://test/db"),
        schema_migrations.ensure_schema(engine, "postgresql+asyncpg://test/db"),
    )
    assert len(seen) == 2
    assert seen[0][0] is not seen[1][0]
    assert engine.max_active_transactions == 1
    assert engine.events.count(LOCK) == 2
    assert engine.events.count(UNLOCK) == 2
    assert engine.events.count("commit") == 2
    assert engine.events.index("commit") < engine.events.index(UNLOCK)
    assert not engine.lock.locked()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_stage", ["legacy", "upgrade"])
async def test_ensure_schema_propagates_failure_and_releases_lock(monkeypatch, failure_stage):
    engine = _MockEngine()
    upgrade_mock = MagicMock()
    legacy_mock = AsyncMock(return_value=None)
    if failure_stage == "legacy":
        legacy_mock.side_effect = RuntimeError("broken metadata")
    else:
        upgrade_mock.side_effect = RuntimeError("alembic upgrade failed")
    monkeypatch.setattr(schema_migrations, "_legacy_revision", legacy_mock)
    monkeypatch.setattr(schema_migrations, "_upgrade_migrations", upgrade_mock)

    with pytest.raises(RuntimeError):
        await schema_migrations.ensure_schema(engine, "postgresql+asyncpg://test/db")

    assert engine.events.count(UNLOCK) == 1
    assert not engine.lock.locked()
    if failure_stage == "legacy":
        upgrade_mock.assert_not_called()
        assert engine.commits == 0
        assert engine.rollbacks == 0
    else:
        upgrade_mock.assert_called_once()
        sync_connection, uri, revision = upgrade_mock.call_args.args
        assert sync_connection.async_connection.transactional
        assert (uri, revision) == ("postgresql+asyncpg://test/db", None)
        assert engine.commits == 0
        assert engine.rollbacks == 1
        assert engine.events.index("rollback") < engine.events.index(UNLOCK)


@pytest.mark.asyncio
async def test_lock_failure_does_not_run_upgrade_or_unlock(monkeypatch):
    engine = _MockEngine()
    engine.lock_error = RuntimeError("cannot acquire migration lock")
    upgrade = MagicMock()
    monkeypatch.setattr(schema_migrations, "_upgrade_migrations", upgrade)
    with pytest.raises(RuntimeError, match="cannot acquire"):
        await schema_migrations.ensure_schema(engine, "postgresql+asyncpg://test/db")
    assert UNLOCK not in engine.events
    upgrade.assert_not_called()


@pytest.mark.asyncio
async def test_unlock_failure_is_not_silenced(monkeypatch):
    engine = _MockEngine()
    engine.unlock_error = RuntimeError("advisory unlock failed")
    monkeypatch.setattr(schema_migrations, "_legacy_revision", AsyncMock(return_value=None))
    monkeypatch.setattr(schema_migrations, "_upgrade_migrations", MagicMock())
    with pytest.raises(RuntimeError, match="advisory unlock failed"):
        await schema_migrations.ensure_schema(engine, "postgresql+asyncpg://test/db")
    assert engine.commits == 1
    assert not engine.lock.locked()


def test_alembic_stamps_before_upgrade_only_for_verified_legacy(monkeypatch):
    commands = []
    sync_connection = object()
    fake_config = MagicMock(attributes={})
    fake_config_cls = MagicMock(return_value=fake_config)
    monkeypatch.setattr("alembic.config.Config", fake_config_cls)

    def stamp(config, revision):
        commands.append(("stamp", revision, config.attributes["connection"]))

    def upgrade(config, revision):
        commands.append(("upgrade", revision, config.attributes["connection"]))

    monkeypatch.setattr("alembic.command.stamp", stamp)
    monkeypatch.setattr("alembic.command.upgrade", upgrade)

    schema_migrations._upgrade_migrations(
        sync_connection, "postgresql+asyncpg://user:some%password@host/db", "0001"
    )
    assert commands == [
        ("stamp", "0001", sync_connection),
        ("upgrade", "head", sync_connection),
    ]
    assert all(item[2] is sync_connection for item in commands)
    assert fake_config.attributes["connection"] is sync_connection
    fake_config.set_main_option.assert_any_call(
        "sqlalchemy.url", "postgresql+asyncpg://user:some%%password@host/db"
    )
    commands.clear()
    schema_migrations._upgrade_migrations(sync_connection, "postgresql+asyncpg://host/db", None)
    assert commands == [("upgrade", "head", sync_connection)]


def test_alembic_upgrade_failure_is_not_swallowed(monkeypatch):
    stamp = MagicMock()
    upgrade = MagicMock(side_effect=RuntimeError("cannot apply DDL"))
    monkeypatch.setattr("alembic.config.Config", MagicMock(return_value=MagicMock(attributes={})))
    monkeypatch.setattr("alembic.command.stamp", stamp)
    monkeypatch.setattr("alembic.command.upgrade", upgrade)
    sync_connection = object()
    with pytest.raises(RuntimeError, match="cannot apply DDL"):
        schema_migrations._upgrade_migrations(
            sync_connection, "postgresql+asyncpg://host/db", "0002"
        )
    stamp.assert_called_once()
    upgrade.assert_called_once()
    assert stamp.call_args.args[0].attributes["connection"] is sync_connection
    assert upgrade.call_args.args[0].attributes["connection"] is sync_connection
    # The surrounding AsyncConnection.begin() owns rollback; this sync helper
    # must preserve the raised exception rather than committing independently.


def test_alembic_env_uses_injected_connection_instead_of_new_engine(monkeypatch):
    """Alembic env.py must honor the active transaction passed by the caller."""
    from alembic import context
    import sqlalchemy

    sync_connection = object()
    config = MagicMock()
    config.config_file_name = None
    config.attributes = {"connection": sync_connection}
    configure = MagicMock()
    migrate = MagicMock()

    monkeypatch.setattr(context, "config", config, raising=False)
    monkeypatch.setattr(context, "is_offline_mode", lambda: False, raising=False)
    monkeypatch.setattr(context, "configure", configure, raising=False)
    monkeypatch.setattr(context, "begin_transaction", lambda: nullcontext(), raising=False)
    monkeypatch.setattr(context, "run_migrations", migrate, raising=False)
    # Executing env.py must neither allocate its own engine nor start an
    # asyncio event loop inside the already-running migration transaction.
    monkeypatch.setattr(
        sqlalchemy,
        "engine_from_config",
        MagicMock(side_effect=AssertionError("Independent engine must not be created")),
    )
    monkeypatch.setattr(
        asyncio,
        "run",
        MagicMock(side_effect=AssertionError("Nested asyncio.run must not execute")),
    )
    path = Path(__file__).resolve().parents[1] / "migrations" / "env.py"
    runpy.run_path(str(path))

    assert configure.call_count == 1
    assert configure.call_args.kwargs["connection"] is sync_connection
    migrate.assert_called_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_upgrade", [False, True])
async def test_transactional_stamp_and_ddl_commit_or_rollback_together(monkeypatch, fail_upgrade):
    """Model PostgreSQL transaction semantics, including the version marker.

    Both mocked Alembic commands must use the one connection passed to
    AsyncConnection.run_sync, inside engine.begin and under the advisory lock.
    This is not a substitute for executing transactional DDL against Postgres.
    """
    engine = _MockEngine()
    monkeypatch.setattr(schema_migrations, "_legacy_revision", AsyncMock(return_value="0002"))
    config_factory = MagicMock(side_effect=lambda *_: MagicMock(attributes={}))
    monkeypatch.setattr("alembic.config.Config", config_factory)
    observed = []

    def stamp(config, revision):
        sync_connection = config.attributes["connection"]
        assert sync_connection.async_connection.transactional
        assert sync_connection.engine is engine
        assert engine.lock.locked()
        engine.db_state["revision"] = revision
        observed.append(("stamp", revision, sync_connection))

    def upgrade(config, revision):
        sync_connection = config.attributes["connection"]
        assert sync_connection.async_connection.transactional
        assert engine.lock.locked()
        engine.db_state["tables"].add("execution_flows")
        observed.append(("upgrade", revision, sync_connection))
        if fail_upgrade:
            raise RuntimeError("DDL upgrade failed")
        engine.db_state["revision"] = "0003"

    monkeypatch.setattr("alembic.command.stamp", stamp)
    monkeypatch.setattr("alembic.command.upgrade", upgrade)

    if fail_upgrade:
        with pytest.raises(RuntimeError, match="DDL upgrade failed"):
            await schema_migrations.ensure_schema(engine, "postgresql+asyncpg://test/db")
        assert engine.db_state == {"revision": None, "tables": set()}
        assert (engine.commits, engine.rollbacks) == (0, 1)
        assert engine.events.index("rollback") < engine.events.index(UNLOCK)
    else:
        await schema_migrations.ensure_schema(engine, "postgresql+asyncpg://test/db")
        assert engine.db_state == {"revision": "0003", "tables": {"execution_flows"}}
        assert (engine.commits, engine.rollbacks) == (1, 0)
        assert engine.events.index("commit") < engine.events.index(UNLOCK)
    assert [entry[:2] for entry in observed] == [
        ("stamp", "0002"),
        ("upgrade", "head"),
    ]
    assert observed[0][2] is observed[1][2]
    assert not engine.lock.locked()


def _load_revision_0003():
    path = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "0003_execution_lineage.py"
    )
    spec = importlib.util.spec_from_file_location("migration_0003_read_only", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0003_upgrade_creates_lineage_tables_and_is_inspection_safe(monkeypatch):
    migration = _load_revision_0003()
    op = MagicMock()
    migration.op = op
    migration.context = SimpleNamespace(is_offline_mode=lambda: False)
    monkeypatch.setattr(
        migration.sa, "inspect", lambda _: _Inspector({"session_states"}, ("last_accessed",))
    )
    migration.upgrade()
    assert [item.args[0] for item in op.add_column.call_args_list] == [
        "tasks",
        "tasks",
        "tasks",
    ]
    assert [item.args[0] for item in op.create_table.call_args_list] == [
        "execution_flows",
        "execution_subtasks",
        "execution_actions",
    ]
    assert not any(item.args[0] == "session_states" for item in op.add_column.call_args_list)
    assert migration.revision == "0003" and migration.down_revision == "0002"


def test_0003_upgrade_adds_missing_last_accessed_and_downgrade_reverses_lineage(monkeypatch):
    migration = _load_revision_0003()
    op = MagicMock()
    migration.op = op
    migration.context = SimpleNamespace(is_offline_mode=lambda: False)
    monkeypatch.setattr(migration.sa, "inspect", lambda _: _Inspector({"session_states"}, ()))
    migration.upgrade()
    assert any(item.args[0] == "session_states" for item in op.add_column.call_args_list)
    op.reset_mock()
    migration.downgrade()
    assert [item.args[0] for item in op.drop_table.call_args_list] == [
        "execution_actions",
        "execution_subtasks",
        "execution_flows",
    ]
    assert [item.args[:2] for item in op.drop_column.call_args_list] == [
        ("tasks", "parent_task_id"),
        ("tasks", "subtask_id"),
        ("tasks", "flow_id"),
    ]
    assert not any(item.args[0] == "session_states" for item in op.drop_column.call_args_list)


@pytest.fixture
def tenant_api():
    app = FastAPI()
    app.include_router(flows_router)
    operator = {"role": "operator", "sub": "alice"}
    app.dependency_overrides[verify_token] = lambda: dict(operator)
    first = SessionState(
        session_id="eng-alice",
        scope=ScopeDefinition(
            engagement_id="eng-alice", domains=["alice.example.com"], authorization_ref="auth"
        ),
        created_by="alice",
        phase="reconnaissance",
    )
    second = SessionState(
        session_id="eng-bob",
        scope=ScopeDefinition(
            engagement_id="eng-bob", domains=["bob.example.com"], authorization_ref="auth"
        ),
        created_by="bob",
        phase="reconnaissance",
    )
    flow = FlowRecord(engagement_id="eng-bob", objective="Bob's private flow")
    action = ExecutionActionRecord(
        engagement_id="eng-bob",
        flow_id=flow.id,
        tool_name="mcp.recon",
        outcome="success",
        safe_metadata={"request_id": "req-bob"},
    )
    db = SimpleNamespace(
        load_flow=AsyncMock(return_value=flow),
        list_flows=AsyncMock(return_value=[flow]),
        list_flow_tasks=AsyncMock(return_value=[]),
        list_subtasks=AsyncMock(return_value=[]),
        list_actions=AsyncMock(return_value=[action]),
        store_flow=AsyncMock(),
    )
    orch = SimpleNamespace(
        _sessions={first.session_id: first, second.session_id: second},
        session_memory=db,
        halt_engagement=AsyncMock(),
    )
    previous = state.get("orchestrator")
    state["orchestrator"] = orch
    try:
        with TestClient(app) as client:
            yield client, operator, flow, orch
    finally:
        state["orchestrator"] = previous


def test_flow_tenant_isolation_rejects_cross_owner_reads_and_mutations(tenant_api):
    client, operator, flow, orch = tenant_api
    other = flow.id
    assert client.get("/flows", params={"engagement_id": "eng-bob"}).status_code == 403
    assert client.get(f"/flows/{other}").status_code == 403
    assert client.get(f"/flows/{other}/actions").status_code == 403
    assert (
        client.post(
            "/flows", json={"engagement_id": "eng-bob", "objective": "Cross-tenant"}
        ).status_code
        == 403
    )
    assert client.post(f"/flows/{other}/tasks", json={"title": "Cross-tenant"}).status_code == 403
    assert (
        client.post(
            f"/flows/{other}/subtasks",
            json={
                "task_id": "task-does-not-matter",
                "title": "Cross-tenant",
            },
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/flows/{other}/subtasks/subtask-other",
            json={
                "expected_revision": 0,
                "title": "Cross-tenant",
            },
        ).status_code
        == 403
    )
    assert (
        client.post(f"/flows/{other}/subtasks/subtask-other/dispatch", json={}).status_code == 403
    )
    assert client.post(f"/flows/{other}/halt").status_code == 403
    orch.session_memory.list_actions.assert_not_awaited()
    orch.session_memory.store_flow.assert_not_awaited()
    orch.halt_engagement.assert_not_awaited()
    operator["role"] = "senior_operator"
    assert client.get(f"/flows/{other}/actions").status_code == 200
    assert client.get(f"/flows/{other}/actions").json()["actions"][0]["engagement_id"] == "eng-bob"


@pytest.mark.asyncio
async def test_single_shared_bearer_token_has_no_operator_role(monkeypatch):
    """Shared development credentials cannot impersonate an engagement owner."""
    monkeypatch.setattr(deps.settings, "jwt_secret", None)
    monkeypatch.setattr(deps.settings, "api_token", "shared-api-token")
    principal = await verify_token(
        credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials="shared-api-token"),
        token=None,
    )
    assert principal == {"sub": "shared-development-token", "role": "dev_api_token"}


@pytest.fixture
def scoped_flow_api():
    """Real FastAPI checks with in-memory persistence and no remote execution."""
    app = FastAPI()
    app.include_router(flows_router)
    app.dependency_overrides[verify_token] = lambda: {"role": "operator", "sub": "alice"}
    session = SessionState(
        session_id="eng-scoped",
        created_by="alice",
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id="eng-scoped",
            domains=["allowed.example.org"],
            authorization_ref="signed-authorization",
            approval_required_for=["rce"],
        ),
    )
    flow = FlowRecord(engagement_id=session.session_id, objective="Authorized research")
    parent = Task(
        type="flow_objective",
        agent_type=AgentType.RECON,
        engagement_id=session.session_id,
        flow_id=flow.id,
        status="planned",
    )
    subtasks = {}
    scheduled = []

    async def list_subtasks(flow_id, task_id=None):
        return [
            step
            for step in subtasks.values()
            if step.flow_id == flow_id and (task_id is None or step.task_id == task_id)
        ]

    async def store_subtask(step):
        subtasks[step.id] = step

    async def commit_flow_refinement(
        flow, engagement, expected_subtask_ids, additions, source=None,
        revised_step=None, activate_flow=True,
    ):
        """Simulate the guarded operation now required by the Flow API."""
        if (
            flow.engagement_id != engagement.session_id
            or flow.status not in {"pending", "running"}
            or {row.id for row in subtasks.values()} != set(expected_subtask_ids)
        ):
            return None
        if any(row.id in subtasks for row in additions):
            return None
        for row in additions:
            subtasks[row.id] = row.model_copy(deep=True)
        if revised_step is not None:
            current = subtasks.get(revised_step.id)
            if current is None or current.status != "pending":
                return None
            subtasks[revised_step.id] = revised_step.model_copy(deep=True)
        flow.revision += 1
        if activate_flow and flow.status == "pending":
            flow.status = "running"
        return flow

    async def schedule_task(task):
        scheduled.append(task)

    db = SimpleNamespace(
        load_flow=AsyncMock(return_value=flow),
        load_task=AsyncMock(return_value=parent),
        list_subtasks=AsyncMock(side_effect=list_subtasks),
        store_subtask=AsyncMock(side_effect=store_subtask),
        store_flow=AsyncMock(),
        commit_flow_refinement=AsyncMock(side_effect=commit_flow_refinement),
        claim_subtask=AsyncMock(return_value=True),
    )
    orch = SimpleNamespace(
        _sessions={session.session_id: session},
        session_memory=db,
        _tasks={},
        schedule_task=AsyncMock(side_effect=schedule_task),
    )
    previous = state.get("orchestrator")
    state["orchestrator"] = orch
    try:
        with TestClient(app) as client:
            yield client, flow, parent, scheduled
    finally:
        state["orchestrator"] = previous


def test_flow_dispatch_must_respect_engagement_approval_required_for(scoped_flow_api):
    client, flow, parent, scheduled = scoped_flow_api
    step = client.post(
        f"/flows/{flow.id}/subtasks",
        json={
            "task_id": parent.id,
            "title": "ROE-controlled action",
            "task_type": "rce",
            "agent_type": "recon",
            "approval_required": False,
        },
    )
    assert step.status_code == 200, step.text
    assert step.json()["approval_required"] is True
    result = client.post(
        f"/flows/{flow.id}/subtasks/{step.json()['id']}/dispatch",
        json={"payload": {"target": "allowed.example.org"}},
    )
    assert result.status_code == 200
    assert scheduled and scheduled[0].approval_required is True


def test_flow_dispatch_checks_every_user_supplied_target_alias(scoped_flow_api):
    client, flow, parent, scheduled = scoped_flow_api
    step = client.post(
        f"/flows/{flow.id}/subtasks",
        json={
            "task_id": parent.id,
            "title": "Inspect valid target",
            "task_type": "recon",
            "agent_type": "recon",
        },
    )
    assert step.status_code == 200, step.text
    result = client.post(
        f"/flows/{flow.id}/subtasks/{step.json()['id']}/dispatch",
        json={
            "payload": {
                "target": "https://allowed.example.org",
                "url": "https://out-of-scope.example.net",
            }
        },
    )
    assert result.status_code == 403
    assert not scheduled
