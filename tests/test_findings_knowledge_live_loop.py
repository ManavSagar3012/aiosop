"""P2 learning-brain live-loop wiring tests.

Covers the two seams that make the loop run automatically end-to-end:
  1. GraphMemory.add_vulnerability auto-records real findings into the KB.
  2. BaseAgent.recall_prior_findings lets any agent consult that KB.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import BaseAgent
from ai_osop.core.enums import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.memory.graph_memory import GraphMemory


def _real_vuln(**kw):
    base = dict(
        vuln_type=VulnClass.SSRF,
        severity=Severity.HIGH,
        title="Blind SSRF",
        description="url param fetches metadata",
        tool_source="nuclei",
        confidence=0.9,
        engagement_id="e1",
    )
    base.update(kw)
    return Vulnerability(**base)


def _mock_neo4j_driver(returned_id="vuln-x"):
    """Build a driver whose session().run().single() yields {'v.id': returned_id}."""
    result = MagicMock()
    result.single = AsyncMock(return_value={"v.id": returned_id})
    session = MagicMock()
    session.run = AsyncMock(return_value=result)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=False)
    driver = MagicMock()
    driver.session = MagicMock(return_value=cm)
    return driver


@pytest.mark.asyncio
async def test_add_vulnerability_auto_records_real_finding():
    gm = GraphMemory()
    gm._driver = _mock_neo4j_driver("vuln-1")
    gm.findings_knowledge = MagicMock()
    gm.findings_knowledge.record_finding = AsyncMock(return_value=True)

    vid = await gm.add_vulnerability(_real_vuln(id="vuln-1"))

    assert vid == "vuln-1"
    gm.findings_knowledge.record_finding.assert_awaited_once()


@pytest.mark.asyncio
async def test_add_vulnerability_kb_failure_never_breaks_persistence():
    gm = GraphMemory()
    gm._driver = _mock_neo4j_driver("vuln-2")
    gm.findings_knowledge = MagicMock()
    gm.findings_knowledge.record_finding = AsyncMock(side_effect=RuntimeError("kb down"))

    # Persistence must still succeed even though the KB record raised.
    vid = await gm.add_vulnerability(_real_vuln(id="vuln-2"))
    assert vid == "vuln-2"


@pytest.mark.asyncio
async def test_no_kb_wired_is_a_noop():
    gm = GraphMemory()
    gm._driver = _mock_neo4j_driver("vuln-3")
    gm.findings_knowledge = None  # default: decoupled
    vid = await gm.add_vulnerability(_real_vuln(id="vuln-3"))
    assert vid == "vuln-3"  # no crash, no recording


class _BareAgent(BaseAgent):
    @property
    def agent_type(self):
        return AgentType.RECON

    async def _setup_resources(self):
        pass

    async def _cleanup_resources(self):
        pass

    async def _execute(self, task: Task):
        return {}


@pytest.mark.asyncio
async def test_recall_prior_findings_reads_kb_from_graph_memory():
    ctx = MagicMock()
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.findings_knowledge = MagicMock()
    ctx.graph_memory.findings_knowledge.recall_similar = AsyncMock(return_value=["hit1", "hit2"])
    agent = _BareAgent(ctx)

    hits = await agent.recall_prior_findings("blind ssrf url param", limit=3)
    assert hits == ["hit1", "hit2"]
    ctx.graph_memory.findings_knowledge.recall_similar.assert_awaited_once()


@pytest.mark.asyncio
async def test_recall_prior_findings_is_safe_without_kb():
    ctx = MagicMock()
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.findings_knowledge = None
    agent = _BareAgent(ctx)
    assert await agent.recall_prior_findings("anything") == []


@pytest.mark.asyncio
async def test_vuln_agent_enriches_context_with_prior_findings():
    """vuln_agent surfaces recalled prior findings into its reasoning context."""
    from ai_osop.agents.vuln_agent import VulnAnalysisAgent
    from ai_osop.core.findings_knowledge import KnowledgeHit

    ctx = MagicMock()
    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)  # skip heavy __init__
    agent.ctx = ctx
    agent.recall_prior_findings = AsyncMock(
        return_value=[
            KnowledgeHit(
                score=0.62,
                document="d",
                metadata={"severity": "high", "vuln_type": "ssrf", "title": "Blind SSRF via url"},
            ),
        ]
    )

    out = await agent._enrich_with_prior_findings("Analyzing endpoints for shop.com", "shop.com")
    assert "Prior similar findings" in out
    assert "ssrf" in out and "Blind SSRF via url" in out
    assert "0.62" in out


@pytest.mark.asyncio
async def test_vuln_agent_enrichment_noop_without_recall():
    from ai_osop.agents.vuln_agent import VulnAnalysisAgent

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = MagicMock()
    agent.recall_prior_findings = AsyncMock(return_value=[])
    base = "Analyzing endpoints for shop.com"
    assert await agent._enrich_with_prior_findings(base, "shop.com") == base
