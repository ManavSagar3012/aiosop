from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.core.attack_taxonomy import (
    ATTACK_TECHNIQUE_MAP,
    DEFAULT_ATTACK,
    DEFAULT_OWASP,
    OWASP_MAP,
    enrich_finding,
)
from ai_osop.core.bounty_report import _CVSS, _REMEDIATION
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


# ---------- mapping tests ----------

def test_attack_map_covers_specified_types():
    expected = {
        "sqli": "T1190",
        "ssrf": "T1190",
        "xss": "T1059.007",
        "jwt_abuse": "T1558",
        "broken_access_control": "T1213",
        "idor": "T1213",
        "rce": "T1210",
        "exposed_secret": "T1552.001",
        "subdomain_takeover": "T1584",
    }
    for vt, tid in expected.items():
        assert ATTACK_TECHNIQUE_MAP[vt][0] == tid, f"{vt} -> {tid}"


def test_owasp_map_covers_specified_types():
    expected = {
        "sqli": "A03",
        "xss": "A03",
        "ssrf": "A10",
        "idor": "A01",
        "broken_access_control": "A01",
        "jwt_abuse": "A07",
        "exposed_secret": "A02",
    }
    for vt, prefix in expected.items():
        assert OWASP_MAP[vt].startswith(prefix), f"{vt} -> {OWASP_MAP[vt]}"


# ---------- enrich_finding tests ----------

def test_enrich_finding_adds_taxonomy_fields():
    f = enrich_finding({"vuln_type": "sqli", "title": "SQLi"})
    assert f["attack_id"] == "T1190"
    assert "Exploit Public-Facing" in f["attack_name"]
    assert f["owasp"] == "A03:2021-Injection"


def test_enrich_finding_defaults_for_unknown_type():
    f = enrich_finding({"vuln_type": "space_weirdness"})
    assert f["attack_id"] == DEFAULT_ATTACK[0]
    assert f["attack_name"] == DEFAULT_ATTACK[1]
    assert f["owasp"] == DEFAULT_OWASP


def test_enrich_finding_missing_vuln_type_defaults():
    f = enrich_finding({})
    assert f["attack_id"] == DEFAULT_ATTACK[0]
    assert f["owasp"] == DEFAULT_OWASP


# ---------- reporting integration test ----------

@pytest.fixture
def mock_context():
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "test-reporting-agent"
    ctx.agent_type = AgentType.REPORTING
    ctx.session_id = "test-session"

    ctx.llm_client = AsyncMock()
    ctx.llm_client.complete.return_value = "Mocked Executive Risk Narrative."

    ctx.graph_memory = AsyncMock()
    ctx.graph_memory.get_graph_stats.return_value = {"assets": 5, "endpoints": 20}
    ctx.graph_memory.get_vulnerabilities_by_engagement.return_value = [
        {
            "id": "vuln-1",
            "title": "Reflected XSS",
            "severity": "HIGH",
            "vuln_type": "xss",
            "description": "Script reflection in search.",
            "evidence": [{"type": "proof", "payload": "<script>alert(1)</script>"}],
            "endpoint_id": "ep-1",
        }
    ]
    ctx.graph_memory.get_all_nodes_for_engagement.return_value = []
    ctx.graph_memory.get_all_edges_for_engagement.return_value = []

    ctx.session_memory = AsyncMock()
    ctx.session_memory.query_audit_log.return_value = []

    return ctx


@pytest.mark.asyncio
async def test_report_findings_enriched(mock_context):
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    task = Task(
        type="generate_report",
        priority=5,
        agent_type=AgentType.REPORTING,
        payload={"version": "v1.1"},
        engagement_id="test-session",
    )
    agent.ctx.current_task = task

    result = await agent._execute(task)
    assert result["status"] == "success"
    assert result["findings_included"] == 1

    # Enriched fields flow into the report context -> JSON export.
    import json as _json

    blob = agent.generated_reports["report-test-session-v1.1"]["json"]
    ctx = _json.loads(blob)
    f = ctx["findings"][0]
    assert f["attack_id"] == "T1059.007"
    assert f["attack_name"] == "Command and Scripting Interpreter: JavaScript"
    assert f["owasp"] == "A03:2021-Injection"
    assert f["cvss"] == _CVSS["high"]
    assert f["remediation"] == _REMEDIATION["xss"]

    # And render in the real technical template.
    tech_md = agent.exporter.generate_markdown("technical.md.j2", ctx)
    assert "T1059.007" in tech_md
    assert "A03:2021-Injection" in tech_md
    assert _CVSS["high"] in tech_md
    assert "#### Remediation" in tech_md
