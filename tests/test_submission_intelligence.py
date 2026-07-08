from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import DiffAuthFinding
from ai_osop.core.submission_intelligence import SubmissionIntelligenceEngine


@pytest.mark.asyncio
async def test_recommend_submission():
    # Setup
    mock_graph = AsyncMock()
    mock_graph.run_read_query = AsyncMock(
        return_value=[{"outcome": "accepted", "count": 8}, {"outcome": "duplicate", "count": 2}]
    )

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
