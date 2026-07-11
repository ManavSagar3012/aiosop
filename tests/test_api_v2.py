import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Mock dependencies BEFORE importing app to prevent early connection attempts if any
with (
    patch("ai_osop.memory.session_memory.SessionMemory"),
    patch("ai_osop.memory.graph_memory.GraphMemory"),
    patch("ai_osop.memory.vector_memory.VectorMemory"),
    patch("ai_osop.orchestrator.orchestrator.Orchestrator.initialize", new_callable=AsyncMock),
):
    from ai_osop.api.main import app


def _async_ctx(return_value):
    """Build a MagicMock usable as an async context manager."""
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=return_value)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


@pytest.fixture
def client():
    # Use a context manager to trigger lifespan events.
    # The lifespan runs strict startup self-tests (Redis ping, Neo4j RETURN 1,
    # critical-MCP presence) so every awaited dependency must be an AsyncMock and
    # the MCP registry must expose a real _servers dict (AIOSOP-AUDIT-2026-06-16).
    with (
        patch("ai_osop.api.main.SessionMemory") as mock_session,
        patch("ai_osop.api.main.GraphMemory") as mock_graph,
        patch("ai_osop.api.main.VectorMemory") as mock_vector,
        patch("ai_osop.api.main.MCPRegistry") as mock_mcp_registry,
        patch("ai_osop.api.main.register_optional_mcp_servers", new_callable=AsyncMock),
        patch("ai_osop.api.main.Orchestrator") as mock_orch,
        patch("ai_osop.api.deps.settings.api_token", "dev-test-token"),
        patch("ai_osop.api.deps.settings.jwt_secret", None),
        # Hermetic startup: the lifespan's run_startup_self_test does real
        # dependency probes. With backends mocked those probes are meaningless,
        # and when live services happen to be up they add ~15-20s of latency and
        # make the suite hang. Stub it to a healthy result so this unit-level API
        # test never depends on live-service state (integration probes live in
        # the /health/* endpoint tests, not here).
        patch(
            "ai_osop.api.main.run_startup_self_test",
            new_callable=AsyncMock,
            return_value={"status": "healthy", "checks": {}, "summary": {"passed": 0, "failed": 0}},
        ),
    ):

        # --- SessionMemory: Redis ping + Postgres session-recovery query ---
        sess = mock_session.return_value
        sess.connect = AsyncMock()
        sess._redis = AsyncMock()  # ._redis.ping() awaitable
        pg_conn = AsyncMock()
        pg_conn.execute = AsyncMock(return_value=MagicMock(fetchall=MagicMock(return_value=[])))
        sess._pg_engine = MagicMock()
        sess._pg_engine.connect = MagicMock(return_value=_async_ctx(pg_conn))

        # --- GraphMemory: connect + driver.session() RETURN 1 ---
        graph = mock_graph.return_value
        graph.connect = AsyncMock()
        graph._driver = MagicMock()
        graph._driver.session = MagicMock(return_value=_async_ctx(AsyncMock()))

        # --- VectorMemory ---
        mock_vector.return_value.connect = AsyncMock()
        mock_vector.return_value.close = AsyncMock()

        # --- MCP registry: critical servers must be present ---
        mcp_inst = mock_mcp_registry.return_value
        mcp_inst.register_server = AsyncMock()
        mcp_inst.close_all = AsyncMock()
        mcp_inst._servers = {
            "browser-mcp": object(),
            "security-bridge": object(),
            "payload-mcp": object(),
            "nuclei-mcp": object(),
        }

        # --- Orchestrator (fully mocked) ---
        orch_instance = mock_orch.return_value
        orch_instance.initialize = AsyncMock()
        orch_instance.register_agent = AsyncMock()
        orch_instance.shutdown = AsyncMock()
        orch_instance.recover_state = AsyncMock(return_value={})
        orch_instance.mcp_registry = mcp_inst

        # session_memory used by the websocket endpoint
        orch_instance.session_memory = sess

        orch_instance._sessions = {}
        orch_instance._agents = {}

        with TestClient(app) as c:
            c.orch = orch_instance  # Attach for inspection
            yield c


def test_health_endpoint(client):
    response = client.get("/health", headers={"Authorization": "Bearer dev-test-token"})
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_metrics_endpoint(client):
    response = client.get("/metrics", headers={"Authorization": "Bearer dev-test-token"})
    assert response.status_code == 200
    # Check for some expected prometheus metrics
    assert "ai_osop_tasks_total" in response.text
    assert "ai_osop_active_agent_count" in response.text
    assert response.headers["content-type"].startswith("text/plain")


def test_api_startup_registers_agents(client):
    # Verify that register_agent was called for the expected agents.
    # main.py lifespan registers 11 agents: attack_chain, recon, vuln,
    # human_oversight, exploit, payload, reporting, context_manager,
    # concurrency, stack_profiler, playwright (AIOSOP-AUDIT-2026-06-16).
    # main.py lifespan registers 11 core agents + 10 specialist agents + new vulnerability scanner agents (total 32).
    # Note: the "experimental" designation was removed post-migration.
    assert client.orch.register_agent.call_count == 49


def test_root_not_found(client):
    response = client.get("/")
    assert response.status_code == 404


def test_websocket_endpoint(client):
    from ai_osop.core.models import ScopeDefinition, SessionState

    # Setup session in mock orchestrator
    client.orch._sessions["test-session"] = SessionState(
        session_id="test-session",
        phase="reconnaissance",
        scope=ScopeDefinition(engagement_id="test-session", domains=["example.com"]),
        roe={},
    )
    with client.websocket_connect("/ws/engagements/test-session?token=dev-test-token") as websocket:
        websocket.send_json({"action": "ping"})

        # Drain any background heartbeat/observation/phase_transition messages
        data = None
        for _ in range(10):
            msg = websocket.receive_json()
            if "type" in msg:
                data = msg
                break

        assert data == {"type": "pong"}

        websocket.send_json({"action": "status"})
        data = None
        for _ in range(10):
            msg = websocket.receive_json()
            if "type" in msg:
                data = msg
                break

        assert data is not None
        assert data["type"] == "status"
        assert data["session_id"] == "test-session"
