"""A blocked Flow dependency must not be timed out before it becomes runnable."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.recovery_service import RecoveryService


def harness(*, parent_status="completed", parent_age=10, other_tenant=False):
    now = datetime.utcnow()
    parent = Task(
        id="task-dependency-parent",
        engagement_id="eng-other" if other_tenant else "eng-dependency",
        type="full_recon",
        agent_type=AgentType.RECON,
        status=parent_status,
        created_at=now - timedelta(hours=3),
        completed_at=now - timedelta(seconds=parent_age) if parent_status == "completed" else None,
    )
    child = Task(
        id="task-dependency-child",
        engagement_id="eng-dependency",
        type="full_recon",
        agent_type=AgentType.RECON,
        dependencies=[parent.id],
        status="pending",
        created_at=now - timedelta(hours=2),
        timeout_seconds=60,
    )
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock(return_value=parent)
    memory.expire_pending_task_atomic = AsyncMock(return_value=True)
    memory.store_hot = AsyncMock()
    orch = SimpleNamespace(
        session_memory=memory,
        _tasks={child.id: child},
        _audit_log=AsyncMock(),
        graph_memory=SimpleNamespace(upsert_task=AsyncMock()),
    )
    return RecoveryService(orch), child, parent, memory, orch


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,age,foreign",
    [
        ("running", 10, False),
        ("pending", 10, False),
        ("failed", 2000, False),
        ("completed", 10, False),
        ("completed", 2000, True),
    ],
)
async def test_dependency_blocked_or_just_completed_does_not_expire(status, age, foreign):
    reaper, task, _, memory, orch = harness(
        parent_status=status, parent_age=age, other_tenant=foreign
    )
    assert await reaper._reap_stuck_tasks() == 0
    assert task.status == "pending"
    memory.expire_pending_task_atomic.assert_not_awaited()
    orch.graph_memory.upsert_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_pending_timer_begins_when_last_dependency_finishes():
    reaper, task, _, memory, orch = harness(parent_age=120)
    assert await reaper._reap_stuck_tasks() == 1
    memory.expire_pending_task_atomic.assert_awaited_once()
    assert task.status == "failed"
    orch.graph_memory.upsert_task.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_or_unavailable_authoritative_dependency_does_not_expire():
    reaper, task, _, memory, _ = harness()
    for result in (None, OSError("postgres down")):
        memory.load_task_authoritative.reset_mock()
        memory.load_task_authoritative.side_effect = None if result is None else result
        memory.load_task_authoritative.return_value = None
        assert await reaper._reap_stuck_tasks() == 0
        assert task.status == "pending"
    memory.expire_pending_task_atomic.assert_not_awaited()
