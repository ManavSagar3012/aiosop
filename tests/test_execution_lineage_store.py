"""Durable persistence invariants without requiring a live PostgreSQL service."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.core.config import AgentType
from ai_osop.core.models import ExecutionActionRecord, Task
from ai_osop.memory.session_memory import (
    Base, ExecutionActionORM, ExecutionFlowORM, ExecutionSubtaskORM,
    SessionMemory, TaskORM,
)


class FakeAsyncSession:
    def __init__(self, scalar=None, rowcount=1):
        self.statements = []
        self.commit = AsyncMock()
        self.scalar = scalar
        self.rowcount = rowcount

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def begin(self):
        # SessionMemory now commits redacted actions inside a PostgreSQL
        # transaction; this test adapter must model the context manager,
        # not require weakening production's atomic receipt/outbox write.
        db = self

        class Transaction:
            async def __aenter__(self):
                return db

            async def __aexit__(self, exc_type, *_args):
                if exc_type is None:
                    await db.commit()

        return Transaction()

    async def execute(self, stmt):
        self.statements.append(stmt)
        return SimpleNamespace(scalar_one_or_none=lambda: self.scalar, rowcount=self.rowcount)


def test_new_execution_tables_and_task_lineage_are_in_metadata():
    assert {
        "execution_flows", "execution_subtasks", "execution_actions",
    } <= set(Base.metadata.tables)
    assert {
        "flow_id", "subtask_id", "parent_task_id",
    } <= set(TaskORM.__table__.columns.keys())
    assert "task_id" in ExecutionSubtaskORM.__table__.columns
    assert "engagement_id" in ExecutionActionORM.__table__.columns
    assert "objective" in ExecutionFlowORM.__table__.columns


@pytest.mark.asyncio
async def test_action_record_drops_credentials_and_raw_arguments():
    db = FakeAsyncSession()
    memory = SessionMemory()
    memory._async_session = lambda: db
    await memory.record_action(
        ExecutionActionRecord(
            engagement_id="eng-one",
            tool_name="mcp.test",
            outcome="success",
            safe_metadata={
                "server_id": "nuclei-mcp",
                "password": "do-not-store",
                "authorization": "Bearer do-not-store",
                "input_tokens": 45,
            },
        )
    )
    assert len(db.statements) == 1
    assert db.commit.await_count == 1
    assert db.statements[0].compile().params["safe_metadata"] == {
        "server_id": "nuclei-mcp", "input_tokens": 45,
    }


@pytest.mark.asyncio
async def test_task_persists_when_redis_cache_fails():
    db = FakeAsyncSession()
    memory = SessionMemory()
    memory._async_session = lambda: db
    memory.store_hot = AsyncMock(side_effect=ConnectionError("redis unavailable"))
    task = Task(type="recon", agent_type=AgentType.RECON, engagement_id="eng-one")
    await memory.store_task(task)
    db.commit.assert_awaited_once()
    assert len(db.statements) == 1


@pytest.mark.asyncio
async def test_task_upsert_refreshes_authorized_payload_in_postgres():
    db = FakeAsyncSession()
    memory = SessionMemory()
    memory._async_session = lambda: db
    memory.store_hot = AsyncMock()
    task = Task(
        type="validate_exploit", agent_type=AgentType.EXPLOIT_VALIDATION,
        engagement_id="eng-one", approval_required=True,
        payload={"approval_id": "apr-verified", "operator_approved": True},
    )
    await memory.store_task(task)
    sql = str(db.statements[0].compile(dialect=postgresql.dialect()))
    update_clause = sql.split("ON CONFLICT (id) DO UPDATE SET", 1)[1]
    assert "payload =" in update_clause
    assert "approval_required =" in update_clause
    assert "dependencies =" in update_clause


@pytest.mark.asyncio
async def test_load_task_falls_back_to_database_during_cache_outage():
    db = FakeAsyncSession(scalar=None)
    memory = SessionMemory()
    memory._async_session = lambda: db
    memory.retrieve_hot = AsyncMock(side_effect=ConnectionError("redis unavailable"))
    assert await memory.load_task("task-missing") is None
    assert len(db.statements) == 1


@pytest.mark.asyncio
async def test_atomic_claim_does_not_reclaim_dispatched_subtask():
    db = FakeAsyncSession(rowcount=0)
    memory = SessionMemory()
    memory._async_session = lambda: db
    assert not await memory.claim_subtask("subtask-one", "eng-one")
    db.commit.assert_awaited_once()
