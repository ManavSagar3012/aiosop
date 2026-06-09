from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import pytest
import json

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
        
        # Mock session_memory for websocket
        mock_session_memory = mock_session.return_value
        orch_instance.session_memory = mock_session_memory
        
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

def test_websocket_endpoint(client):
    # Create an async generator that yields one test message then stops
    async def mock_listen():
        yield {"type": "message", "data": json.dumps({"event": "test_event"})}
        
    mock_pubsub = AsyncMock()
    mock_pubsub.listen = mock_listen
    mock_pubsub.unsubscribe = AsyncMock()
    
    # We must patch the global orchestrator used by the endpoint
    with patch("ai_osop.api.main.orchestrator.session_memory.subscribe_events", new_callable=AsyncMock) as mock_subscribe:
        mock_subscribe.return_value = mock_pubsub
        
        with client.websocket_connect("/ws/engagements/test-session") as websocket:
            data = websocket.receive_text()
            assert json.loads(data) == {"event": "test_event"}
            
        mock_subscribe.assert_called_once_with("engagement:test-session")
        mock_pubsub.unsubscribe.assert_awaited_once()
