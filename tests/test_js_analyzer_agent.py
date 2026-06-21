from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.experimental.js_analyzer_agent import JSAnalyzerAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "js-analyzer-1"
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
    return JSAnalyzerAgent(mock_context)


# ------------------------------------------------------------------
# analyze_js: content provided with endpoints, no secrets
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_with_content_no_secrets(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-js-1",
        type="analyze_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "url": "https://example.com/bundle.js",
            "content": "const x = '/api/v1/users'; fetch('/api/v2/orders');",
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["endpoints_found"] == 2
    assert result["vulnerabilities_created"] == 0
    assert result["finding_ids"] == []
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ------------------------------------------------------------------
# analyze_js: content with an AWS AKIA key
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_with_aws_key(agent) -> None:
    await agent.initialize()

    fake_key = "AKIAIOSFODNN7EXAMPLE"
    js_body = f"const KEY = '{fake_key}'; fetch('/api/health');"

    task = Task(
        id="task-js-2",
        type="analyze_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://example.com/app.js", "content": js_body},
        engagement_id="test-session",
    )

    agent.ctx.graph_memory.add_vulnerability.return_value = "vuln-js-abc123"

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["vulnerabilities_created"] == 1
    assert "vuln-js-abc123" in result["finding_ids"]
    agent.ctx.graph_memory.add_vulnerability.assert_awaited_once()


# ------------------------------------------------------------------
# analyze_js: multiple AWS keys in content
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_with_multiple_aws_keys(agent) -> None:
    await agent.initialize()

    key1 = "AKIAIOSFODNN7EXAMPLE"
    key2 = "AKIAI44QH8DHBEXAMPLE"
    js_body = f"var a = '{key1}'; var b = '{key2}';"

    task = Task(
        id="task-js-3",
        type="analyze_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://example.com/bundle.js", "content": js_body},
        engagement_id="test-session",
    )

    agent.ctx.graph_memory.add_vulnerability.side_effect = ["vuln-1", "vuln-2"]

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["vulnerabilities_created"] == 2
    assert len(result["finding_ids"]) == 2
    assert agent.ctx.graph_memory.add_vulnerability.await_count == 2


# ------------------------------------------------------------------
# analyze_js: no content triggers simulated JS fetch
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_no_content_simulates_fetch(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-js-4",
        type="analyze_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://example.com/main.js"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    # Simulated JS contains '/api/v2' and '/user/delete' endpoints
    assert result["status"] == "success"
    assert result["endpoints_found"] >= 1
    # Simulated JS has no AKIA key
    assert result["vulnerabilities_created"] == 0


# ------------------------------------------------------------------
# analyze_js: empty content and no url (edge case)
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_empty_content_empty_url(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-js-5",
        type="analyze_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "", "content": ""},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["endpoints_found"] == 0
    assert result["vulnerabilities_created"] == 0


# ------------------------------------------------------------------
# Unknown task type
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_js_analyzer_unknown_task_type(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-js-6",
        type="unknown_task_type",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "error"
    assert "Unknown task type" in result["message"]
