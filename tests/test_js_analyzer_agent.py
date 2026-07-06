"""
Tests for the (de-simulated) JS Analyzer Agent.

These exercise the REAL behavior: inline content is scanned directly, missing
content triggers a real (here: mocked) HTTP fetch rather than fabricated data,
the multi-pattern secret ruleset detects realistic key formats while filtering
placeholders, and out-of-scope URLs are never fetched.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.js_analyzer_agent import JSAnalyzerAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, Task

# Realistic-format keys that are NOT AWS's canonical "...EXAMPLE" placeholders
# (those are intentionally filtered by the agent's placeholder guard).
AWS_KEY_1 = "AKIAJ7KZ3MQ9PXR2WDVC"
AWS_KEY_2 = "AKIAB5YH8NW4TLC6QRSF"


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
# analyze_js: inline content with endpoints, no secrets
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
    assert result["sources_analyzed"] == 1
    assert result["endpoints_found"] == 2
    assert result["vulnerabilities_created"] == 0
    assert result["finding_ids"] == []
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ------------------------------------------------------------------
# analyze_js: inline content with a realistic AWS key -> 1 real finding
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_with_aws_key(agent) -> None:
    await agent.initialize()

    js_body = f"const KEY = '{AWS_KEY_1}'; fetch('/api/health');"

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
    # Real evidence: the rule fired and the value is masked in the summary
    assert result["secrets"][0]["rule"] == "AWS Access Key ID"
    assert "***" in result["secrets"][0]["masked"] or "..." in result["secrets"][0]["masked"]


# ------------------------------------------------------------------
# analyze_js: AWS canonical "...EXAMPLE" key is filtered as a placeholder
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_example_key_is_filtered(agent) -> None:
    await agent.initialize()

    js_body = "const KEY = 'AKIAIOSFODNN7EXAMPLE';"  # AWS docs placeholder

    task = Task(
        id="task-js-ex",
        type="analyze_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://example.com/app.js", "content": js_body},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["vulnerabilities_created"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ------------------------------------------------------------------
# analyze_js: multiple distinct keys -> multiple findings
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_with_multiple_aws_keys(agent) -> None:
    await agent.initialize()

    js_body = f"var a = '{AWS_KEY_1}'; var b = '{AWS_KEY_2}';"

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
# detect_secrets_in_js: multi-pattern detection (Google, GitHub, Stripe)
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_detect_secrets_multi_pattern(agent) -> None:
    await agent.initialize()

    js_body = (
        "const g='AIzaSyA1234567890abcdefghijklmnopqrstuv';"
        "const gh='ghp_abcdefghijklmnopqrstuvwxyz0123456789';"
        "const s='sk_live_abcdefghij1234567890ABCD';"
    )

    task = Task(
        id="task-js-multi",
        type="detect_secrets_in_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://example.com/app.js", "content": js_body},
        engagement_id="test-session",
    )

    agent.ctx.graph_memory.add_vulnerability.side_effect = ["v1", "v2", "v3"]

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["vulnerabilities_created"] == 3
    rules = {s["rule"] for s in result["secrets"]}
    assert "Google API Key" in rules
    assert "GitHub Token" in rules
    assert "Stripe Live Secret Key" in rules
    # secrets-only task should not report endpoints
    assert result["endpoints_found"] == 0


# ------------------------------------------------------------------
# analyze_js: no content + unreachable URL -> honest empty (NO fabrication)
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_no_content_no_fabrication(agent, monkeypatch) -> None:
    await agent.initialize()

    # Simulate an unreachable bundle: the real fetch returns None.
    agent._fetch_js = AsyncMock(return_value=None)

    task = Task(
        id="task-js-4",
        type="analyze_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://example.com/main.js"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    # Old behavior fabricated '/api/v2' + '/user/delete'. New behavior must not.
    assert result["status"] == "success"
    assert result["sources_analyzed"] == 0
    assert result["endpoints_found"] == 0
    assert result["vulnerabilities_created"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ------------------------------------------------------------------
# analyze_js: real fetch path is used when only a URL is given
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_js_uses_fetch_when_url_only(agent) -> None:
    await agent.initialize()

    fetched = f"fetch('/api/orders'); const KEY='{AWS_KEY_1}';"
    agent._fetch_js = AsyncMock(return_value=fetched)
    agent.ctx.graph_memory.add_vulnerability.return_value = "vuln-fetched"

    task = Task(
        id="task-js-fetch",
        type="analyze_js",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://example.com/main.js"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    agent._fetch_js.assert_awaited_once_with("https://example.com/main.js")
    assert result["sources_analyzed"] == 1
    assert result["endpoints_found"] == 1
    assert result["vulnerabilities_created"] == 1


# ------------------------------------------------------------------
# Scope enforcement: out-of-scope URL is never fetched
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scope_blocks_out_of_scope_fetch(mock_context) -> None:
    mock_context.scope = ScopeDefinition(
        engagement_id="test",
        domains=["127.0.0.1"],
        ips=["127.0.0.1/32"],
        exclusions=[],
        testing_window_start=datetime.utcnow() - timedelta(hours=1),
        testing_window_end=datetime.utcnow() + timedelta(hours=1),
    )
    agent = JSAnalyzerAgent(mock_context)
    await agent.initialize()

    assert agent._in_scope("http://127.0.0.1:3000/main.js") is True
    assert agent._in_scope("http://evil.com/x.js") is False

    # An out-of-scope fetch returns None without raising.
    result = await agent._fetch_js("http://evil.com/secrets.js")
    assert result is None


# ------------------------------------------------------------------
# analyze_js: empty content and no url (edge case) -> honest empty
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
