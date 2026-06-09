from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
import pytest

# Mock dependencies BEFORE importing app to prevent early connection attempts if any
with patch("ai_osop.memory.session_memory.SessionMemory"), \
     patch("ai_osop.memory.graph_memory.GraphMemory"), \
     patch("ai_osop.memory.vector_memory.VectorMemory"), \
     patch("ai_osop.orchestrator.orchestrator.Orchestrator.initialize", new_callable=AsyncMock):
    from ai_osop.api.main import app

@pytest.fixture
def client():
    # Use a context manager to trigger lifespan events
    with patch("ai_osop.api.main.SessionMemory") as mock_session, \
         patch("ai_osop.api.main.GraphMemory") as mock_graph, \
         patch("ai_osop.api.main.VectorMemory") as mock_vector, \
         patch("ai_osop.api.main.MCPRegistry") as mock_mcp_registry, \
         patch("ai_osop.api.main.Orchestrator") as mock_orch:
        
        # Setup mock memory methods that are awaited
        mock_vector.return_value.connect = AsyncMock()
        mock_vector.return_value.close = AsyncMock()
        
        mock_mcp_registry.return_value.register_server = AsyncMock()
        mock_mcp_registry.return_value.close_all = AsyncMock()

        # Setup mock orchestrator
        orch_instance = mock_orch.return_value
        orch_instance.initialize = AsyncMock()
        orch_instance.register_agent = AsyncMock()
        orch_instance.shutdown = AsyncMock()
        orch_instance.mcp_registry = mock_mcp_registry.return_value
        orch_instance._sessions = {}
        orch_instance._agents = {}
        
        with TestClient(app) as c:
            c.orch = orch_instance # Attach for inspection
            yield c

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_metrics_endpoint(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    # Check for some expected prometheus metrics
    assert "ai_osop_tasks_total" in response.text
    assert "ai_osop_active_agents" in response.text
    assert response.headers["content-type"].startswith("text/plain")

def test_api_startup_registers_agents(client):
    # Verify that register_agent was called for the expected agents
    # In main.py, 8 agents are registered.
    assert client.orch.register_agent.call_count == 8

def test_root_not_found(client):
    response = client.get("/")
    assert response.status_code == 404
