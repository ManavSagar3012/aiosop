import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "test-reporting-agent"
    ctx.agent_type = AgentType.REPORTING
    ctx.session_id = "test-session"

    ctx.llm_client = AsyncMock()
    ctx.llm_client.complete.return_value = "Mocked Executive Risk Narrative."

    ctx.graph_memory = AsyncMock()
    ctx.graph_memory.get_graph_stats.return_value = {"total_assets": 5, "total_endpoints": 20}
    ctx.graph_memory.get_vulnerabilities_by_engagement.return_value = [
        {
            "id": "vuln-1",
            "title": "Test Vuln",
            "severity": "HIGH",
            "vuln_type": "xss",
            "description": "A test vulnerability",
            "evidence": [{"type": "proof", "payload": "<script>alert(1)</script>"}],
            "confidence": 0.9,
            "engagement_id": "test-session",
            "endpoint_id": "ep-1",
        }
    ]
    ctx.graph_memory.get_all_nodes_for_engagement.return_value = [
        {"id": "vuln-1", "labels": ["Vulnerability"], "type": "xss", "title": "Test Vuln"}
    ]
    ctx.graph_memory.get_all_edges_for_engagement.return_value = []

    ctx.session_memory = AsyncMock()
    ctx.session_memory.find_audit_events.return_value = []

    return ctx


@pytest.mark.asyncio
async def test_generate_report(mock_context, tmp_path):
    # Setup dummy templates for testing
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "executive.md.j2").write_text("Exec: {{ risk_narrative }}")
    (template_dir / "technical.md.j2").write_text(
        "Tech: {% for v in findings %}{{ v.title }}{% endfor %}"
    )
    (template_dir / "attack_graph.html.j2").write_text("Graph: {{ graph_json }}")

    agent = ReportingAgent(mock_context)
    await agent._setup_resources()

    # Override template dir to our temp one
    agent.exporter.env.loader.searchpath = [str(template_dir)]

    task = Task(
        type="generate_report",
        priority=5,
        agent_type=AgentType.REPORTING,
        payload={"version": "v1.1"},
        engagement_id="test-session",
    )
    # Set current task in context
    agent.ctx.current_task = task

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["version"] == "v1.1"
    assert result["requires_approval"] is True
    assert "report-test-session-v1.1" in agent.generated_reports

    report_data = agent.generated_reports["report-test-session-v1.1"]
    assert "Mocked Executive Risk Narrative" in report_data["markdown"]
    assert "Tech: Test Vuln" in report_data["markdown"]
    assert "Graph:" in report_data["graph_html"]


@pytest.mark.asyncio
async def test_compile_evidence(mock_context):
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()

    task = Task(
        type="compile_evidence",
        priority=5,
        agent_type=AgentType.REPORTING,
        payload={"evidence": ["test payload data"]},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert len(result["compiled_evidence"]) == 1
    assert result["compiled_evidence"][0]["content"] == "test payload data"
    # Check SHA-256 hash of "test payload data"
    import hashlib

    expected_hash = hashlib.sha256(b"test payload data").hexdigest()
    assert result["compiled_evidence"][0]["sha256"] == expected_hash
