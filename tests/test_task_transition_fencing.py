"""The generic Task writer cannot bypass signed, owner-fenced transitions."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.core.config import AgentType, settings
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory


class _FakeSession:
    def __init__(self, rowcount=1):
        self.statements = []
        self.rowcount = rowcount
        self.commit = AsyncMock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def execute(self, statement):
        self.statements.append(statement)
        return SimpleNamespace(rowcount=self.rowcount)


def _task(status="pending", *, signed=True):
    return Task(
        id="task-fence-one", engagement_id="eng-fence-one",
        type="full_recon", agent_type=AgentType.RECON,
        payload={"target": "https://example.test", **(
            {"_authorization_version": 1} if signed else {}
        )},
        status=status,
        assigned_agent_id="agent-owner", approval_required=True,
        flow_id="flow-one", subtask_id="subtask-one", parent_task_id="task-parent",
        dependencies=["task-parent"],
    )


async def _store(task, *, rowcount=1):
    db = _FakeSession(rowcount=rowcount)
    memory = SessionMemory()
    memory._async_session = lambda: db
    memory.store_hot = AsyncMock()
    await memory.store_task(task)
    statement = db.statements[0]
    sql = str(statement.compile(dialect=postgresql.dialect()))
    return memory, db, sql


@pytest.mark.asyncio
async def test_signed_generic_insert_only_allows_preclaim_work():
    _, db, sql = await _store(_task("completed"))
    assert sql.startswith("UPDATE tasks SET")
    assert "tasks.status =" in sql
    assert "tasks.assigned_agent_id" in sql
    assert "tasks.engagement_id" in sql
    assert "tasks.flow_id" in sql
    assert "tasks.parent_task_id" in sql
    assert "tasks.approval_required" in sql
    assert "CAST(tasks.payload AS JSONB)" in sql
    assert "CAST(tasks.dependencies AS JSONB)" in sql
    assert "tasks.retry_count <=" in sql
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_pending_signed_snapshot_cannot_replace_a_claim_or_approval():
    _, _, sql = await _store(_task())
    assert "ON CONFLICT (id) DO UPDATE" in sql
    # Only pending/planned durable statuses accept a pending replay.
    assert "tasks.status IN" in sql
    assert "CAST(tasks.payload AS JSONB)" in sql
    assert "tasks.created_at" in sql
    assert "tasks.subtask_id" in sql


@pytest.mark.asyncio
async def test_generic_running_update_needs_existing_owner_claim():
    _, _, sql = await _store(_task("running"))
    assert sql.startswith("UPDATE tasks SET")
    assert "tasks.status =" in sql
    assert "tasks.assigned_agent_id IS NOT NULL" in sql
    assert "tasks.assigned_agent_id =" in sql
    assert "CAST(tasks.payload AS JSONB)" in sql


@pytest.mark.asyncio
async def test_generic_temporal_or_unknown_cannot_claim_execution():
    for status in ("scheduled", "dispatching", "dispatch_unknown"):
        db = _FakeSession()
        memory = SessionMemory()
        memory._async_session = lambda: db
        memory.store_hot = AsyncMock()
        await memory.store_task(_task(status))
        compiled = db.statements[0].compile(dialect=postgresql.dialect())
        sql = str(compiled)
        assert sql.startswith("UPDATE tasks SET")
        if status != "dispatch_unknown":
            assert "__no_generic_temporal_transition__" in compiled.params.values()
        else:
            assert "tasks.assigned_agent_id IS NOT NULL" in sql


@pytest.mark.asyncio
async def test_signed_preapproved_task_cannot_enter_generic_insert():
    bad = _task()
    bad.payload["operator_approved"] = True
    _, _, sql = await _store(bad)
    assert sql.startswith("UPDATE tasks SET")
    assert "CAST(tasks.payload AS JSONB)" in sql


@pytest.mark.asyncio
async def test_rejected_cas_never_publishes_stale_redis_shadow():
    memory, db, _ = await _store(_task("completed"), rowcount=0)
    memory.store_hot.assert_not_awaited()
    db.commit.assert_awaited_once()


class _ClockDB:
    def __init__(self, instant):
        self.instant = instant

    async def execute(self, _statement):
        return SimpleNamespace(scalar_one=lambda: self.instant)


@pytest.mark.asyncio
async def test_durable_approval_deadline_uses_database_clock(monkeypatch):
    monkeypatch.setattr(settings, "approval_timeout_seconds", 600)
    now = datetime(2026, 10, 14, 11, 30, tzinfo=timezone.utc)
    db = _ClockDB(now)
    deadline = datetime(2026, 10, 14, 11, 20)
    assert await SessionMemory._approval_deadline_elapsed(db, deadline)
    assert not await SessionMemory._approval_deadline_elapsed(
        db, deadline + timedelta(microseconds=1)
    )
    with pytest.raises(PermissionError, match="future"):
        await SessionMemory._approval_deadline_elapsed(db, deadline + timedelta(hours=1))
    with pytest.raises(PermissionError, match="durable deadline"):
        await SessionMemory._approval_deadline_elapsed(db, None)
