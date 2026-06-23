"""Tests for ai_osop.api.health module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, PropertyMock

from fastapi import FastAPI
from httpx import AsyncClient
import pytest

from ai_osop.api.health import router as health_router



@pytest.fixture(autouse=True)
def clean_state():
    from ai_osop.api.deps import state
    state.pop("orchestrator", None)
    yield
    state.pop("orchestrator", None)
class TestHealthEndpoints:
    @pytest.fixture
    def app(self) -> FastAPI:
        app = FastAPI()
        app.include_router(health_router)
        return app

    @pytest.fixture
    async def client(self, app: FastAPI) -> AsyncClient:
        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client

    async def test_health_returns_200(self, client: AsyncClient) -> None:
        """/health should return 200 with status healthy."""
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    async def test_ready_without_deps_returns_200(self, client: AsyncClient) -> None:
        """/ready returns 200 when dependencies are healthy (or not initialized)."""
        response = await client.get("/ready")
        # Without orchestrator state, checks return "unknown" which counts as healthy
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("ready", "degraded")
        assert "checks" in data
        assert "redis" in data["checks"]
        assert "neo4j" in data["checks"]
        assert "postgres" in data["checks"]
        assert "mcp_registry" in data["checks"]

    async def test_ready_fails_when_redis_unhealthy(self, client: AsyncClient, app: FastAPI) -> None:
        """/ready returns 503 when Redis is unhealthy."""
        # Mock the orchestrator state with a failing Redis check
        mock_orchestrator = MagicMock()
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=Exception("Connection refused"))
        mock_orchestrator.session_memory = MagicMock()
        mock_orchestrator.session_memory._redis = mock_redis
        mock_orchestrator.session_memory._pg_engine = None
        mock_orchestrator.graph_memory = None
        mock_orchestrator.mcp_registry = None

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        response = await client.get("/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["detail"]["status"] == "not_ready"
        assert data["detail"]["checks"]["redis"]["status"] == "unhealthy"

    async def test_ready_fails_when_neo4j_unhealthy(self, client: AsyncClient, app: FastAPI) -> None:
        """/ready returns 503 when Neo4j is unhealthy."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.session_memory = None
        mock_orchestrator.graph_memory = MagicMock()
        mock_driver = AsyncMock()
        mock_driver.verify_connectivity = AsyncMock(side_effect=Exception("Neo4j down"))
        mock_orchestrator.graph_memory._driver = mock_driver
        mock_orchestrator.mcp_registry = None

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        response = await client.get("/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["detail"]["status"] == "not_ready"
        assert data["detail"]["checks"]["neo4j"]["status"] == "unhealthy"
