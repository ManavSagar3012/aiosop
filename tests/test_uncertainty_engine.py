from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task
from ai_osop.core.uncertainty_engine import UncertaintyEngine


@pytest.fixture
def mock_graph_memory():
    return AsyncMock()


@pytest.fixture
def engine(mock_graph_memory):
    return UncertaintyEngine(graph_memory=mock_graph_memory)


@pytest.mark.asyncio
async def test_analyze_mission_gaps_returns_no_fabricated_data(engine) -> None:
    """De-fabricated (Sprint 0): the blocked-path / unknown-tech detectors are
    honest-empty stubs until graph-backed, so analyze_mission_gaps must NOT
    surface any invented findings (previously it fabricated ``/admin/billing``
    and an ``MFA-Gateway``)."""
    records = await engine.analyze_mission_gaps("eng-1")

    assert records == []
    assert not any(r.target_id == "/admin/billing" for r in records)


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
