"""Detector over-claim hardening tests (roadmap Phase 2.1, generalized).

Two detectors marked findings ``validated=True`` HIGH without active exploit proof — the
same reflection/noise false positive that gets reports rejected:

  - XSS: reflected-but-not-executed was validated HIGH. Reflection != execution (the
    context may not run the payload), so reflection-only is now a manual-confirm MEDIUM.
  - request smuggling: a single desync TIMING probe was validated HIGH. Timing is noisy
    (jitter/GC/cold cache), so the winning technique must now REPRODUCE (>=2 of 3) to be
    validated; otherwise it is a manual-confirm MEDIUM lead.

Hermetic — the browser/reflection probes and the desync probe are stubbed; no network.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import ai_osop.core.smuggle_probe as smuggle_probe
from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.enums import Severity
from tests._mocks import stub_session_memory


def _agent():
    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock()),
        session_memory=stub_session_memory(),
        current_task=None,
    )
    agent.findings = {}
    return agent


# --------------------------------------------------------------------------- #
# XSS: execution vs reflection                                                 #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_xss_execution_is_validated_high():
    agent = _agent()
    agent._confirm_xss_execution = AsyncMock(return_value=True)
    agent._confirm_xss_reflection = AsyncMock(return_value=False)

    res = await agent._execute_xss_scan({"url": "https://x/s?q=1", "engagement_id": "e1"})

    assert res["confirmed"] is True and res["method"] == "execution"
    assert res["manual_confirm_required"] is False
    vuln = next(iter(agent.findings.values()))
    assert vuln.validated is True and vuln.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_xss_reflection_only_is_manual_confirm_medium():
    agent = _agent()
    agent._confirm_xss_execution = AsyncMock(return_value=False)
    agent._confirm_xss_reflection = AsyncMock(return_value=True)

    res = await agent._execute_xss_scan({"url": "https://x/s?q=1", "engagement_id": "e1"})

    assert res["confirmed"] is True and res["method"] == "reflection"
    assert res["manual_confirm_required"] is True
    vuln = next(iter(agent.findings.values()))
    assert vuln.validated is False and vuln.severity == Severity.MEDIUM
    assert vuln.evidence[0]["manual_confirm_required"] is True


@pytest.mark.asyncio
async def test_xss_clean_when_neither():
    agent = _agent()
    agent._confirm_xss_execution = AsyncMock(return_value=False)
    agent._confirm_xss_reflection = AsyncMock(return_value=False)
    res = await agent._execute_xss_scan({"url": "https://x/s?q=1", "engagement_id": "e1"})
    assert res["confirmed"] is False
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# --------------------------------------------------------------------------- #
# Request smuggling: timing must reproduce                                     #
# --------------------------------------------------------------------------- #


def _probe_queue(monkeypatch, results):
    q = list(results)

    def fake(host, port, **kw):
        r = dict(q.pop(0))
        r.setdefault("technique", kw.get("technique", "cl.te"))
        r.setdefault("probe_ms", 5000)
        r.setdefault("baseline_ms", 100)
        return r

    monkeypatch.setattr(smuggle_probe, "probe_desync", fake)


@pytest.mark.asyncio
async def test_smuggling_reproduced_is_validated_high(monkeypatch):
    # first probe (cl.te) hits, then both re-runs hit -> 3/3 reproduced.
    _probe_queue(monkeypatch, [{"vulnerable": True}, {"vulnerable": True}, {"vulnerable": True}])
    agent = _agent()

    res = await agent._execute_request_smuggling_scan(
        {"url": "https://x.com/", "engagement_id": "e1"}
    )

    assert res["confirmed"] is True
    assert res["reproductions"] == 3
    assert res["manual_confirm_required"] is False
    vuln = next(iter(agent.findings.values()))
    assert vuln.validated is True and vuln.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_smuggling_not_reproduced_is_manual_confirm_medium(monkeypatch):
    # first probe hits (a jitter blip), re-runs do not -> 1/3, unconfirmed.
    _probe_queue(monkeypatch, [{"vulnerable": True}, {"vulnerable": False}, {"vulnerable": False}])
    agent = _agent()

    res = await agent._execute_request_smuggling_scan(
        {"url": "https://x.com/", "engagement_id": "e1"}
    )

    assert res["confirmed"] is True
    assert res["reproductions"] == 1
    assert res["manual_confirm_required"] is True
    vuln = next(iter(agent.findings.values()))
    assert vuln.validated is False and vuln.severity == Severity.MEDIUM
    assert vuln.evidence[0]["manual_confirm_required"] is True


@pytest.mark.asyncio
async def test_smuggling_clean_when_no_probe_hits(monkeypatch):
    _probe_queue(monkeypatch, [{"vulnerable": False}, {"vulnerable": False}])
    agent = _agent()
    res = await agent._execute_request_smuggling_scan(
        {"url": "https://x.com/", "engagement_id": "e1"}
    )
    assert res["confirmed"] is False
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()
