from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.core.uncertainty_engine import UncertaintyEngine


@pytest.fixture
def mock_graph_memory():
    return AsyncMock()


@pytest.fixture
def engine(mock_graph_memory):
    return UncertaintyEngine(graph_memory=mock_graph_memory)


@pytest.mark.asyncio
async def test_analyze_mission_gaps(engine) -> None:
    engagement_id = "eng-1"

    # Act
    records = await engine.analyze_mission_gaps(engagement_id)

    # Assert
    assert len(records) > 0
    assert any(r.target_id == "/admin/billing" for r in records)
    assert any("MFA-Gateway" in u for r in records for u in r.unknowns)


def test_record_task_uncertainty(engine) -> None:
    task = Task(
        id="task-1",
        type="exploit",
        agent_type=AgentType.EXPLOIT_VALIDATION,
        payload={"url": "http://target.com/api"},
        engagement_id="eng-1",
    )

    # Test ambiguous error
    record = engine.record_task_uncertainty(task, "Connection timeout while probing")
    assert record is not None
    assert "timeout" in record.unknowns[0].lower()
    assert "http://target.com/api" in record.blocked_paths

    # Test clear error
    record = engine.record_task_uncertainty(task, "Task completed successfully")
    assert record is None
