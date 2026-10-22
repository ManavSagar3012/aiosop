"""Temporal workflow network calls require committed PostgreSQL admission."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


def _case():
    durable = SessionMemory()
    durable.claim_temporal_dispatch = AsyncMock(return_value="temporal-claim-test")
    durable.settle_temporal_dispatch = AsyncMock()
    durable.store_task = AsyncMock()
    orch = Orchestrator(durable, AsyncMock(), AsyncMock(), AsyncMock())
    orch.temporal_enabled = True
    orch.temporal_scheduler = AsyncMock()
    orch.temporal_scheduler.start_task_workflow.return_value = "ai-osop-task-one"
    orch._validate_temporal_task_scope = MagicMock()
    task = Task(
        id="task-one", type="summarize_context", agent_type=AgentType.CONTEXT_MANAGER,
        engagement_id="eng-one", status="pending",
        payload={"_authorization_version": 1},
    )
    return orch, durable, task


@pytest.mark.asyncio
async def test_committed_claim_happens_before_temporal_start():
    orch, durable, task = _case()
    operations = []

    async def claim(candidate):
        operations.append("postgres-claim")
        assert candidate.status == "pending"
        return "temporal-claim-test"

    async def remote(candidate):
        operations.append("temporal-submit")
        assert candidate["status"] == "dispatching"
        return "ai-osop-task-one"

    durable.claim_temporal_dispatch.side_effect = claim
    orch.temporal_scheduler.start_task_workflow.side_effect = remote
    await orch.task_scheduler._dispatch_temporal_task(task)
    assert operations == ["postgres-claim", "temporal-submit"]
    assert task.status == "scheduled"
    durable.settle_temporal_dispatch.assert_awaited_once_with(
        task.id, task.engagement_id, "temporal-claim-test", "scheduled",
        workflow_id="ai-osop-task-one",
    )


@pytest.mark.asyncio
async def test_denied_claim_makes_no_remote_call():
    orch, durable, task = _case()
    durable.claim_temporal_dispatch.side_effect = PermissionError("claim already exists")
    with pytest.raises(PermissionError):
        await orch.task_scheduler._dispatch_temporal_task(task)
    assert task.status == "pending"
    orch.temporal_scheduler.start_task_workflow.assert_not_awaited()
    durable.store_task.assert_not_awaited()
    durable.settle_temporal_dispatch.assert_not_awaited()


@pytest.mark.asyncio
async def test_lost_temporal_response_stays_unknown_and_never_replays():
    orch, durable, task = _case()
    orch.temporal_scheduler.start_task_workflow.side_effect = TimeoutError("after send")
    with pytest.raises(TimeoutError):
        await orch.task_scheduler._dispatch_temporal_task(task)
    assert task.status == "dispatch_unknown"
    assert task.result["status"] == "unknown"
    durable.settle_temporal_dispatch.assert_awaited_once_with(
        task.id, task.engagement_id, "temporal-claim-test", "dispatch_unknown",
    )
    await orch.task_scheduler._dispatch_temporal_task(task)
    orch.temporal_scheduler.start_task_workflow.assert_awaited_once()


@pytest.mark.asyncio
async def test_lost_database_receipt_does_not_claim_scheduled():
    orch, durable, task = _case()
    durable.settle_temporal_dispatch.side_effect = OSError("postgres commit unavailable")
    with pytest.raises(WorkflowException, match="receipt"):
        await orch.task_scheduler._dispatch_temporal_task(task)
    assert task.status == "dispatch_unknown"
    assert task.result["status"] == "unknown"
    orch.temporal_scheduler.start_task_workflow.assert_awaited_once()
