from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.mobile_agent import MobileAnalysisAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


def _install_mock_http(agent, routes):
    """Point the agent's HTTP client at an offline httpx.MockTransport.

    ``routes`` maps a URL path -> (status_code, body_text). Unknown paths
    return 404. This exercises the REAL httpx request/response path (the code
    under test is unchanged) while staying fully deterministic and offline.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        status, body = routes.get(request.url.path, (404, "not found"))
        return httpx.Response(status, text=body)

    def _make_client(headers=None):
        base = {"User-Agent": "test"}
        if headers:
            base.update(headers)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), headers=base)

    agent._make_client = _make_client


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "mobile-1"
    ctx.agent_type = AgentType.VULN_ANALYSIS
    ctx.session_id = "test-session"
    ctx.llm_client = AsyncMock()
    ctx.session_memory = AsyncMock()
    ctx.graph_memory = AsyncMock()
    ctx.persona = "test_persona"
    ctx.current_task = None
    ctx.cost_incurred = 0.0
    ctx.audit_callback = AsyncMock()
    ctx.coordination_bus = AsyncMock()
    ctx.mcp_registry = AsyncMock()
    ctx.scope = None
    return ctx


@pytest.fixture
def agent(mock_context):
    return MobileAnalysisAgent(mock_context)


# ──────────────────── tests ────────────────────


@pytest.mark.asyncio
async def test_analyze_deep_links_flags_real_leak(agent) -> None:
    """A link that actually carries a sensitive param in a reset flow is flagged.

    The finding is derived from the real link (not fabricated): a benign link
    with no params produces nothing, the leaking link is reported with the
    actual sensitive parameter name.
    """
    await agent.initialize()

    task = Task(
        id="task-1",
        type="analyze_deep_links",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "bundle_id": "com.example.app",
            "links": [
                "target://home",  # benign, no params
                "target://reset_password?token=abc123XYZ",  # real leak
            ],
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["analyzed_count"] == 2
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["type"] == "sensitive_param_in_deep_link"
    assert "token" in f["sensitive_params"]
    assert f["flow"] == "reset"
    assert f["severity"] == "high"
    assert "account takeover" in f["risk"].lower()


@pytest.mark.asyncio
async def test_analyze_deep_links_benign_params_not_flagged(agent) -> None:
    """Links without sensitive params produce no findings (no false positives)."""
    await agent.initialize()

    task = Task(
        id="task-2",
        type="analyze_deep_links",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "bundle_id": "com.example.app",
            "links": [
                "target://home",
                "target://product/42?ref=home&theme=dark",
            ],
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["analyzed_count"] == 2
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_analyze_deep_links_token_in_fragment(agent) -> None:
    """Sensitive params in the URL fragment (common in mobile links) are caught."""
    await agent.initialize()

    task = Task(
        id="task-2b",
        type="analyze_deep_links",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"links": ["target://login#access_token=eyJabc.def.ghi"]},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert len(result["findings"]) == 1
    assert "access_token" in result["findings"][0]["sensitive_params"]


@pytest.mark.asyncio
async def test_intercept_mobile_traffic_honest_without_proxy(agent) -> None:
    """Without a configured proxy, interception is honestly reported inactive."""
    await agent.initialize()

    task = Task(
        id="task-3",
        type="intercept_mobile_traffic",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"endpoint": "https://api.example.com/v1/users"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    # Old behavior fabricated True; new behavior reports the real (inactive) status.
    assert result["interception_active"] is False


@pytest.mark.asyncio
async def test_intercept_mobile_traffic_active_with_proxy(agent) -> None:
    """When an operator supplies a proxy, interception is reported active."""
    await agent.initialize()

    task = Task(
        id="task-3b",
        type="intercept_mobile_traffic",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"endpoint": "https://api.example.com/v1/users", "proxy": "127.0.0.1:8080"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["interception_active"] is True


@pytest.mark.asyncio
async def test_mobile_api_unauthenticated_access_and_data_exposure(agent) -> None:
    """A protected mobile endpoint served anonymously (2xx) is flagged, and
    sensitive fields in that anonymous body produce a second, escalated finding.
    Both are confirmed by objective HTTP oracles, not opinions."""
    await agent.initialize()
    _install_mock_http(
        agent,
        {
            # Protected endpoint served to an anonymous client WITH sensitive data.
            "/api/v1/profile": (200, '{"email":"a@b.c","password":"hunter2","ssn":"111-22-3333"}'),
        },
    )

    task = Task(
        id="m-1",
        type="test_mobile_api",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "base_url": "https://api.example.com",
            "endpoints": ["/api/v1/profile"],
            "debug_paths": [],  # isolate the endpoint check
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["capability"] == "http_api_only"
    types = {f["type"] for f in result["findings"]}
    assert "unauthenticated_mobile_endpoint_access" in types
    assert "sensitive_data_to_unauthenticated_client" in types
    data_finding = next(
        f for f in result["findings"] if f["type"] == "sensitive_data_to_unauthenticated_client"
    )
    assert "password" in data_finding["sensitive_fields"]
    assert "ssn" in data_finding["sensitive_fields"]


@pytest.mark.asyncio
async def test_mobile_api_secure_endpoint_no_false_positive(agent) -> None:
    """An endpoint that enforces auth (401) yields NO finding — no false positive."""
    await agent.initialize()
    _install_mock_http(
        agent,
        {"/api/v1/profile": (401, '{"error":"unauthorized"}')},
    )

    task = Task(
        id="m-2",
        type="test_mobile_api",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "base_url": "https://api.example.com",
            "endpoints": ["/api/v1/profile"],
            "debug_paths": [],
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["findings"] == []
    assert result["findings_count"] == 0


@pytest.mark.asyncio
async def test_mobile_api_debug_endpoint_exposed(agent) -> None:
    """A 2xx on a debug/actuator path is an objective info-disclosure finding."""
    await agent.initialize()
    _install_mock_http(
        agent,
        {
            "/actuator/env": (200, '{"activeProfiles":["prod"],"propertySources":[]}'),
            "/version": (404, "nope"),
        },
    )

    task = Task(
        id="m-3",
        type="test_mobile_api",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "base_url": "https://api.example.com",
            "debug_paths": ["/actuator/env", "/version"],
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    debug_findings = [f for f in result["findings"] if f["type"] == "debug_endpoint_exposed"]
    assert len(debug_findings) == 1
    assert debug_findings[0]["endpoint"].endswith("/actuator/env")
    assert debug_findings[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_mobile_api_reports_not_tested_capabilities(agent) -> None:
    """Cert-pinning / APK static analysis are honestly reported not_tested
    (requires_apk_tooling), never fabricated as findings."""
    await agent.initialize()
    _install_mock_http(agent, {})  # everything 404: no findings at all

    task = Task(
        id="m-4",
        type="test_mobile_api",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"base_url": "https://api.example.com", "endpoints": ["/api/v1/orders"]},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["capability"] == "http_api_only"
    assert result["findings"] == []
    not_tested = {n["check"]: n["reason"] for n in result["not_tested"]}
    assert not_tested["certificate_pinning"] == "requires_apk_tooling"
    assert not_tested["apk_static_analysis"] == "requires_apk_tooling"


@pytest.mark.asyncio
async def test_mobile_api_requires_base_url(agent) -> None:
    """Missing base_url is an honest failure, not a fabricated success."""
    await agent.initialize()

    task = Task(
        id="m-5",
        type="test_mobile_api",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"endpoints": ["/api/v1/profile"]},
        engagement_id="test-session",
    )

    result = await agent._execute(task)
    assert result["status"] == "failed"
    assert "base_url" in result["error"]


@pytest.mark.asyncio
async def test_unknown_task_type(agent) -> None:
    """Unknown task type returns an error dict."""
    await agent.initialize()

    task = Task(
        id="task-4",
        type="nonexistent_task",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "error"
    assert "Unknown task type" in result["message"]
