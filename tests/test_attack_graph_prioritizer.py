from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.attack_graph_prioritizer import AttackGraphChainPrioritizer
from ai_osop.core.models import DiffAuthFinding


@pytest.mark.asyncio
async def test_prioritizer_calculates_impact():
    # Setup
    mock_graph = AsyncMock()
    mock_graph.run_read_query = AsyncMock(return_value=[{"path_count": 2, "max_depth": 2}])

    prioritizer = AttackGraphChainPrioritizer(mock_graph)

    finding = DiffAuthFinding(
        category="horizontal_pe",
        resource_id="res-1",
        test_identity_id="user_b",
        expected_result="403 Forbidden",
        observed_result="200 OK",
        confidence=0.8,
        engagement_id="eng-1",
    )

    # Act
    priority_data = await prioritizer.prioritize_finding(finding)

    # Assert
    assert priority_data["path_impact"] > 0
    assert priority_data["priority"] == "high"
