import pytest
from unittest.mock import AsyncMock, MagicMock
from ai_osop.core.attack_graph_prioritizer import AttackGraphChainPrioritizer
from ai_osop.core.models import DiffAuthFinding

@pytest.mark.asyncio
async def test_prioritizer_calculates_impact():
    # Setup
    mock_graph = MagicMock()
    mock_graph._driver = AsyncMock()
    
    # Correct mock setup: driver.session() returns a context manager
    mock_session = AsyncMock()
    mock_result = AsyncMock()
    mock_record = MagicMock()
    mock_record.__getitem__.side_effect = lambda k: {"path_count": 2, "max_depth": 2}[k]
    mock_result.single = AsyncMock(return_value=mock_record)
    mock_session.run.return_value = mock_result
    
    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_session
    mock_graph._driver.session = MagicMock(return_value=mock_context_manager)
    
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
