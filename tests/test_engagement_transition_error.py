"""Tests verifying engagement phase transition exception handling (F-07 remediation)."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers.engagements import router as engagements_router
from ai_osop.core.exceptions import WorkflowException, WorkflowTransitionError
from ai_osop.core.models import SessionState, ScopeDefinition


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    app.include_router(engagements_router)
    # Override auth dependency to return senior_operator
    app.dependency_overrides[verify_token] = lambda: {"sub": "senior-1", "role": "senior_operator"}
    return app


@pytest.fixture
async def client(app: FastAPI) -> AsyncClient:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        yield client


class TestEngagementTransitionExceptions:
    async def test_workflow_transition_error_returns_400_with_detail(self, client: AsyncClient) -> None:
        """When orchestrator raises WorkflowTransitionError, endpoint returns HTTP 400 with detail."""
        mock_orch = MagicMock()
        mock_orch.transition_phase = AsyncMock(
            side_effect=WorkflowTransitionError("Illegal transition from initialized to completed")
        )
        # Mock load_session_state on session_memory
        mock_session = SessionState(
            session_id="eng-123",
            created_by="senior-1",
            phase="initialized",
            scope=ScopeDefinition(engagement_id="eng-123", domains=["example.com"]),
            roe={},
        )
        mock_orch.session_memory = MagicMock()
        mock_orch.session_memory.load_session_state = AsyncMock(return_value=mock_session)
        state["orchestrator"] = mock_orch

        response = await client.post(
            "/engagements/eng-123/transition",
            params={"new_phase": "completed"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Illegal transition from initialized to completed" in data["detail"]

    async def test_workflow_exception_returns_400(self, client: AsyncClient) -> None:
        """When orchestrator raises base WorkflowException, endpoint returns HTTP 400 with detail."""
        mock_orch = MagicMock()
        mock_orch.transition_phase = AsyncMock(
            side_effect=WorkflowException("Workflow state corrupted")
        )
        mock_session = SessionState(
            session_id="eng-456",
            created_by="senior-1",
            phase="initialized",
            scope=ScopeDefinition(engagement_id="eng-456", domains=["example.com"]),
            roe={},
        )
        mock_orch.session_memory = MagicMock()
        mock_orch.session_memory.load_session_state = AsyncMock(return_value=mock_session)
        state["orchestrator"] = mock_orch

        response = await client.post(
            "/engagements/eng-456/transition",
            params={"new_phase": "reconnaissance"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Workflow state corrupted" in data["detail"]

    async def test_invalid_phase_name_returns_400(self, client: AsyncClient) -> None:
        """Invalid phase enum string returns HTTP 400."""
        mock_orch = MagicMock()
        mock_session = SessionState(
            session_id="eng-789",
            created_by="senior-1",
            phase="initialized",
            scope=ScopeDefinition(engagement_id="eng-789", domains=["example.com"]),
            roe={},
        )
        mock_orch.session_memory = MagicMock()
        mock_orch.session_memory.load_session_state = AsyncMock(return_value=mock_session)
        state["orchestrator"] = mock_orch

        response = await client.post(
            "/engagements/eng-789/transition",
            params={"new_phase": "non_existent_phase"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Invalid phase" in data["detail"]
