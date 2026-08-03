"""AIOSOP-CONF-PERSIST-001: triage/correlation confidence deltas must persist.

Regression: ``_execute_triage`` (FP down-rank to 0.1) and ``_execute_correlation``
(cross-tool boost to 0.95) mutated the in-memory Vulnerability only — the graph
node kept its pre-triage confidence, so the triage verdict and the correlation
boost never reached the dashboard/report/bounty funnel. Both now re-persist the
updated finding through ``add_vulnerability`` (idempotent MERGE, safe on a
duplicate id).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.enums import Severity, VulnClass
from ai_osop.core.models import Vulnerability


def _vuln(vid: str = "v-1", conf: float = 0.9) -> Vulnerability:
    return Vulnerability(
        id=vid,
        vuln_type=VulnClass.SQLI,
        severity=Severity.HIGH,
        title="SQLi",
        description="d",
        tool_source="sqlmap",
        confidence=conf,
        engagement_id="eng-1",
        endpoint_id="e-1",
    )


def _agent(*, fp: bool = False) -> VulnAnalysisAgent:
    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.findings = {}
    agent.false_positive_patterns = []
    graph = SimpleNamespace(add_vulnerability=AsyncMock(return_value="v-1"))
    ctx = SimpleNamespace(graph_memory=graph)
    agent.ctx = ctx
    if fp:
        # A pattern in the title forces _check_false_positive -> True.
        agent.false_positive_patterns = ["default-login"]

    async def _fp(vuln):
        return bool(agent.false_positive_patterns)

    agent._check_false_positive = _fp
    return agent


@pytest.mark.asyncio
async def test_triage_fp_downrank_persists():
    """A finding triaged as likely-FP must have its 0.1 down-rank persisted to
    the graph, not left in-memory only."""
    agent = _agent(fp=True)
    vuln = _vuln(conf=0.9)
    agent.findings[vuln.id] = vuln

    out = await agent._execute_triage({"finding_id": vuln.id})

    assert out["triage_result"] == "likely_false_positive"
    assert vuln.confidence == 0.1
    agent.ctx.graph_memory.add_vulnerability.assert_awaited_once_with(vuln)


@pytest.mark.asyncio
async def test_triage_confirmed_keeps_and_persists():
    """A triage-confirmed finding is re-persisted so the confirmed verdict is
    durable (and the confidence stays where the detector set it)."""
    agent = _agent(fp=False)
    vuln = _vuln(conf=0.85)
    agent.findings[vuln.id] = vuln

    out = await agent._execute_triage({"finding_id": vuln.id})

    assert out["triage_result"] == "confirmed"
    assert vuln.confidence == 0.85
    agent.ctx.graph_memory.add_vulnerability.assert_awaited_once_with(vuln)


@pytest.mark.asyncio
async def test_correlation_boost_persists():
    """A cross-tool-confirmed finding must have its 0.95 boost persisted to the
    graph (and correlated_ids attached)."""
    agent = _agent()
    vuln_a = _vuln("a", conf=0.7)
    vuln_b = _vuln("b", conf=0.7)
    vuln_c = _vuln("c", conf=0.7)  # third finding, same endpoint -> matches both
    # Same vuln_type + endpoint_id -> _find_similar_findings matches them.
    agent.findings = {vuln_a.id: vuln_a, vuln_b.id: vuln_b, vuln_c.id: vuln_c}

    # graph.correlate_vulnerabilities is the only other graph call; mock it.
    agent.ctx.graph_memory.correlate_vulnerabilities = AsyncMock(return_value=[])
    agent.ctx.graph_memory.add_vulnerability = AsyncMock(return_value="x")

    out = await agent._execute_correlation({"engagement_id": "eng-1"})

    assert out["confirmed_findings"] == 3
    for v in (vuln_a, vuln_b, vuln_c):
        assert v.confidence == 0.95
        others = [x.id for x in (vuln_a, vuln_b, vuln_c) if x.id != v.id]
        assert v.correlated_ids == others
    # Every boosted finding was persisted.
    assert agent.ctx.graph_memory.add_vulnerability.await_count == 3


@pytest.mark.asyncio
async def test_correlation_no_cross_tool_no_boost():
    """A finding with no cross-tool confirmation is untouched and not persisted."""
    agent = _agent()
    vuln = _vuln("solo", conf=0.7)
    agent.findings = {vuln.id: vuln}
    agent.ctx.graph_memory.correlate_vulnerabilities = AsyncMock(return_value=[])
    agent.ctx.graph_memory.add_vulnerability = AsyncMock(return_value="x")

    out = await agent._execute_correlation({"engagement_id": "eng-1"})

    assert out["confirmed_findings"] == 0
    assert vuln.confidence == 0.7
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()
