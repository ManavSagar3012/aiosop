from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.temporal_worker import TaskActivities


@pytest.mark.asyncio
async def test_execute_task_activity_calls_orchestrator() -> None:
    # Setup
    mock_orchestrator = AsyncMock()
    mock_orchestrator._execute_task_durable.return_value = {"status": "success", "data": "test"}

    activities = TaskActivities(mock_orchestrator)
    task_data = {
        "id": "task-abc",
        "type": "test_task",
        "agent_type": "recon",
        "payload": {},
        "engagement_id": "eng-123",
    }

    # Act
    result = await activities.execute_task_activity(task_data)

    # Assert
    assert result["status"] == "success"
    mock_orchestrator._execute_task_durable.assert_awaited_once()
    passed_task = mock_orchestrator._execute_task_durable.call_args[0][0]
    assert isinstance(passed_task, Task)
    assert passed_task.id == "task-abc"


@pytest.mark.asyncio
async def test_execute_task_activity_handles_failure() -> None:
    # Setup
    mock_orchestrator = AsyncMock()
    mock_orchestrator._execute_task_durable.side_effect = Exception("System crash")

    activities = TaskActivities(mock_orchestrator)
    task_data = {
        "id": "task-fail",
        "type": "broken_task",
        "agent_type": "recon",
        "payload": {},
        "engagement_id": "eng-123",
    }

    # Act
    result = await activities.execute_task_activity(task_data)

    # Assert
    assert result["status"] == "failed"
    assert "System crash" in result["error"]
