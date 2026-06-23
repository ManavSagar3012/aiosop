import pytest
from unittest.mock import AsyncMock, MagicMock
from ai_osop.core.submission_intelligence import SubmissionIntelligenceEngine
from ai_osop.core.models import DiffAuthFinding
from ai_osop.core.config import AgentType

@pytest.mark.asyncio
async def test_recommend_submission():
    # Setup
    mock_graph = MagicMock()
    # Mock result from the graph query
    mock_result = AsyncMock()
    mock_result.__aiter__.return_value = [
        {"outcome": "accepted", "count": 8},
        {"outcome": "duplicate", "count": 2}
    ]
    mock_session = AsyncMock()
    mock_session.run.return_value = mock_result
    mock_graph._driver.session.return_value.__aenter__.return_value = mock_session
    
    engine = SubmissionIntelligenceEngine(mock_graph)
    
    finding = DiffAuthFinding(
        category="horizontal_pe",
        resource_id="res-1",
        test_identity_id="user_b",
        expected_result="403 Forbidden",
        observed_result="200 OK",
        confidence=0.9,
        engagement_id="eng-1",
    )
    
    # Act
    recommendation = await engine.recommend_submission(finding)
    
    # Assert
    assert recommendation["acceptance_probability"] > 0
    assert recommendation["recommendation"] == "submit"
    assert recommendation["priority"] == "high"
