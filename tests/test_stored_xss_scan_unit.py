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


class _FakeOAST:
    def __init__(self, hit):
        self._hit = hit
    async def initialize(self, *a, **k):
        return None
    async def register(self, label=""):
        return "tokstored", "http://127.0.0.1:8099/tokstored"
    async def poll(self, token):
        return [{"method": "GET", "path": "/tokstored", "source_ip": "127.0.0.1"}] if self._hit else []


def _agent(execution_confirms, oast, captured):
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.findings = {}
    a.oast = oast
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-sx"),
        session_memory=SimpleNamespace(get_session_state=lambda _e: _none()),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )

    async def _confirm(url, token, engagement_id):
        return execution_confirms
    a._confirm_xss_execution = _confirm
    return a


def test_stored_xss_confirmed_via_browser_execution():
    captured = []
    agent = _agent(execution_confirms=True, oast=_FakeOAST(hit=False), captured=captured)
    res = asyncio.run(agent._execute_stored_xss_scan({
        "store_url": "http://t/store", "store_field": "comment",
        "render_url": "http://t/view", "mode": "browser",
        "engagement_id": "eng-sx"}))
    assert res["confirmed"] is True and res["method"] == "execution"
    v = captured[0]
    assert v.vuln_type.value == "xss" and v.validated is True
    assert v.cwe == "CWE-79" and v.is_simulated() is False
    assert v.evidence[0].get("stored") is True


def test_stored_xss_confirmed_via_oast_beacon():
    captured = []
    agent = _agent(execution_confirms=False, oast=_FakeOAST(hit=True), captured=captured)
    res = asyncio.run(agent._execute_stored_xss_scan({
        "store_url": "http://t/store", "store_field": "comment",
        "render_url": "http://t/view", "mode": "auto",
        "poll_seconds": 0.1, "poll_interval": 0.05,
        "engagement_id": "eng-sx"}))
    assert res["confirmed"] is True and res["method"] == "oast_beacon"
    assert captured[0].vuln_type.value == "xss" and captured[0].validated is True


def test_stored_xss_not_confirmed():
    captured = []
    agent = _agent(execution_confirms=False, oast=_FakeOAST(hit=False), captured=captured)
    res = asyncio.run(agent._execute_stored_xss_scan({
        "store_url": "http://t/store", "store_field": "comment",
        "render_url": "http://t/view", "mode": "auto",
        "poll_seconds": 0.1, "poll_interval": 0.05,
        "engagement_id": "eng-sx"}))
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
