from unittest.mock import AsyncMock

import pytest

from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler, run_worker
from ai_osop.orchestrator import temporal_worker


@pytest.mark.asyncio
async def test_temporal_scheduler_starts_workflow_with_injected_client() -> None:
    client = AsyncMock()
    scheduler = TemporalTaskScheduler(client=client, task_queue="queue-a")

    workflow_id = await scheduler.start_task_workflow(
        {"id": "task-123", "timeout_seconds": 60, "type": "scan"}
    )

    assert workflow_id == "ai-osop-task-123"
    client.start_workflow.assert_awaited_once()
    _, task_data = client.start_workflow.call_args.args
    assert task_data["id"] == "task-123"
    assert client.start_workflow.call_args.kwargs["id"] == "ai-osop-task-123"
    assert client.start_workflow.call_args.kwargs["task_queue"] == "queue-a"


@pytest.mark.asyncio
async def test_worker_rejects_unbound_noop_activity(monkeypatch) -> None:
    monkeypatch.setattr(temporal_worker, "Worker", object())
    with pytest.raises(ValueError, match="requires bound activities"):
        await run_worker()


@pytest.mark.asyncio
async def test_retry_after_committed_temporal_start_is_idempotent() -> None:
    """A crash between Temporal startup and task-status persistence is safe."""
    client = AsyncMock()
    client.start_workflow.side_effect = temporal_worker.WorkflowAlreadyStartedError(
        "ai-osop-task-recovered", "TaskWorkflow"
    )
    scheduler = TemporalTaskScheduler(client=client, task_queue="queue-a")

    workflow_id = await scheduler.start_task_workflow({"id": "task-recovered"})

    assert workflow_id == "ai-osop-task-recovered"
    client.start_workflow.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_start_other_failures_remain_visible() -> None:
    client = AsyncMock()
    client.start_workflow.side_effect = RuntimeError("Temporal unavailable")
    scheduler = TemporalTaskScheduler(client=client)

    with pytest.raises(RuntimeError, match="Temporal unavailable"):
        await scheduler.start_task_workflow({"id": "task-no-ack"})
