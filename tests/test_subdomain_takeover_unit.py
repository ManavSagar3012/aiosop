import asyncio
from types import SimpleNamespace

from ai_osop.agents.vuln_agent import VulnAnalysisAgent


def _capture(store, v):
    store.append(v)

    async def _ok():
        return None

    return _ok()


async def _none():
    return None


def _agent(fetch_body, captured):
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.findings = {}
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-st"),
        session_memory=SimpleNamespace(get_session_state=lambda _e: _none()),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )

    async def _probe(host):
        return fetch_body, ["example.github.io"]

    a._probe_host_for_takeover = _probe
    return a


def test_takeover_confirmed_mints_finding():
    captured = []
    agent = _agent("There isn't a GitHub Pages site here.", captured)
    res = asyncio.run(
        agent._execute_subdomain_takeover_scan(
            {"hosts": ["blog.example.com"], "engagement_id": "eng-st"}
        )
    )
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.vuln_type.value == "subdomain_takeover" and v.validated is True
    assert v.is_simulated() is False and "GitHub Pages" in v.title


def test_no_takeover_on_clean_host():
    captured = []
    agent = _agent("<html>normal site</html>", captured)
    res = asyncio.run(
        agent._execute_subdomain_takeover_scan(
            {"hosts": ["www.example.com"], "engagement_id": "eng-st"}
        )
    )
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
