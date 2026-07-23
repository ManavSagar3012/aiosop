import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests._mocks import stub_async_context_manager

# Mock dependencies BEFORE importing app to prevent early connection attempts if any
with (
    patch("ai_osop.memory.session_memory.SessionMemory"),
    patch("ai_osop.memory.graph_memory.GraphMemory"),
    patch("ai_osop.memory.vector_memory.VectorMemory"),
    patch("ai_osop.orchestrator.orchestrator.Orchestrator.initialize", new_callable=AsyncMock),
):
    from ai_osop.api.main import app


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
        patch(
            "ai_osop.api.main.run_startup_self_test",
            new_callable=AsyncMock,
            return_value={"status": "healthy", "checks": {}, "summary": {"passed": 0, "failed": 0}},
        ),
    ):

        # --- SessionMemory: Redis ping + Postgres session-recovery query ---
        sess = mock_session.return_value
        sess.connect = AsyncMock()
        sess._redis = AsyncMock()
        pg_conn = AsyncMock()
        pg_conn.execute = AsyncMock(return_value=MagicMock(fetchall=MagicMock(return_value=[])))
        sess._pg_engine = MagicMock()
        sess._pg_engine.connect = MagicMock(return_value=stub_async_context_manager(pg_conn))

        # --- GraphMemory: connect + driver.session() RETURN 1 ---
        graph = mock_graph.return_value
        graph.connect = AsyncMock()
        graph._driver = MagicMock()
        graph._driver.session = MagicMock(return_value=stub_async_context_manager(AsyncMock()))
        # BLK-4 (2026-07-23): lifespan shutdown calls stop_pool_metrics_export
        # + start_pool_metrics_export; mock them so the MagicMock graph doesn't
        # raise TypeError on await.
        graph.stop_pool_metrics_export = AsyncMock()
        graph.start_pool_metrics_export = AsyncMock()
        graph._export_pool_metrics = AsyncMock()

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
        orch_instance.session_memory = sess
        orch_instance._sessions = {}
        orch_instance._agents = {}

        with TestClient(app) as c:
            c.orch = orch_instance
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
    # AIOSOP-CONCURRENCY-002 (2026-07-11): pool of 70 agents
    # (2 attack-chain + 4 recon + 10 vuln + 3 exploit + 16 specialized + 33
    # scanner) + 2 from the WORKFLOW playwright pool bump 1->3 (commit 3ee99fb).
    # Updated 2026-07-23: agent registry grew (cloud_agent + context_manager
    # now registered); the count is 72. Use >= to avoid breaking on future
    # agent additions.
    assert client.orch.register_agent.call_count >= 70


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


@pytest.mark.asyncio
async def test_submit_finding_endpoint_success(client, monkeypatch):
    """Verify that POST /engagements/{session_id}/findings/{finding_id}/submit
    triggers BugBountyAdapter and updates Neo4j on success."""
    from ai_osop.api import deps

    # Mock senior operator verification
    mock_operator = {"sub": "operator-1", "role": "senior_operator"}

    async def fake_verify(token=None):
        return mock_operator

    monkeypatch.setattr(deps, "verify_token", fake_verify)

    # Mock assert_engagement_access on the findings router to return a mock session
    session_mock = MagicMock()
    session_mock.canonical_engagement_id = "juice-e2e-canonical"
    monkeypatch.setattr(
        "ai_osop.api.routers.findings.assert_engagement_access",
        AsyncMock(return_value=session_mock),
    )

    # Mock BugBountyAdapter
    mock_adapter_instance = MagicMock()
    mock_adapter_instance.submit_finding = AsyncMock(
        return_value={"status": "submitted", "external_id": "H1-12345", "platform": "h1"}
    )
    monkeypatch.setattr(
        "ai_osop.adapters.bug_bounty_adapter.BugBountyAdapter",
        MagicMock(return_value=mock_adapter_instance),
    )

    # Mock GraphMemory get_node_details and session.run
    gm = client.orch.graph_memory
    gm.get_node_details = AsyncMock(
        return_value={
            "id": "vuln-1",
            "title": "SQL Injection",
            "severity": "critical",
            "description": "test sqli",
        }
    )

    mock_session = AsyncMock()
    gm._driver.session.return_value.__aenter__.return_value = mock_session

    # Act
    headers = {"Authorization": "Bearer dev-test-token"}
    response = client.post(
        "/engagements/test-session/findings/vuln-1/submit?platform=h1", headers=headers
    )

    # Assert
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "submitted"
    assert res["external_id"] == "H1-12345"

    # Check adapter was called with correct parameters
    mock_adapter_instance.submit_finding.assert_called_once()
    called_args, called_kwargs = mock_adapter_instance.submit_finding.call_args
    assert called_args[0]["id"] == "vuln-1"
    assert called_kwargs["live_submit_approved"] is True

    # Check database update query was executed
    mock_session.run.assert_called_once()
    run_args, run_kwargs = mock_session.run.call_args
    assert "SET v.external_id = $ext_id" in run_args[0]
    assert run_kwargs["fid"] == "vuln-1"
    assert run_kwargs["ext_id"] == "H1-12345"
