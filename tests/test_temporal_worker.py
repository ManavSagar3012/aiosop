from unittest.mock import AsyncMock

import pytest

from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler


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
