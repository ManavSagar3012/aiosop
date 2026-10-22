"""Lifecycle coordination never broadcasts raw security evidence or secrets."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.task_scheduler import TaskScheduler


def _fixture():
    orchestrator = SimpleNamespace(
        graph_memory=AsyncMock(),
        session_memory=AsyncMock(),
        coordination_bus=AsyncMock(),
        _sync_subtask_result=AsyncMock(),
        _refine_completed_flow_subtask=AsyncMock(),
        adaptive_planner=AsyncMock(),
        dlq=AsyncMock(),
    )
    scheduler = TaskScheduler(orchestrator)
    scheduler._trigger_downstream_tasks = AsyncMock()
    scheduler._chain_authenticated_surface = AsyncMock()
    task = Task(
        id="task-audit-secret-test",
        engagement_id="eng-audit-secret-test",
        type="full_recon",
        agent_type=AgentType.RECON,
        assigned_agent_id="agent-one",
    )
    return scheduler, orchestrator, task


@pytest.mark.asyncio
async def test_success_bus_payload_keeps_only_safe_identifiers():
    scheduler, orchestrator, task = _fixture()
    await scheduler._on_task_success(
        task, {"status": "success", "api_token": "NEVER_BROADCAST_SECRET"}
    )
    topic, payload, actor = orchestrator.coordination_bus.publish.await_args.args
    assert topic == "task.completed"
    assert actor == "orchestrator"
    assert payload["task_id"] == task.id
    assert payload["status"] == "completed"
    assert "NEVER_BROADCAST_SECRET" not in str(payload)
    assert "result" not in payload
    orchestrator.session_memory.store_task.assert_awaited()


@pytest.mark.asyncio
async def test_failed_bus_payload_omits_external_response_content():
    scheduler, orchestrator, task = _fixture()
    await scheduler._on_task_failure(
        task, {"status": "failed", "error": "secret NEVER_BROADCAST_FAILURE"}
    )
    topic, payload, actor = orchestrator.coordination_bus.publish.await_args.args
    assert topic == "task.failed"
    assert actor == "orchestrator"
    assert payload["status"] == "failed"
    assert "NEVER_BROADCAST_FAILURE" not in str(payload)
