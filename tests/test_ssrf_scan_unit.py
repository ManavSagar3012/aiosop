import asyncio
from types import SimpleNamespace

from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from tests._mocks import stub_session_memory


def _capture(store, v):
    store.append(v)

    async def _ok():
        return None

    return _ok()


class _FakeOAST:
    def __init__(self, hit):
        self._hit = hit

    async def initialize(self, *a, **k):
        return None

    async def register(self, label="", context=None):
        return "tok123", "http://127.0.0.1:8099/tok123"

    async def poll(self, token):
        return [{"method": "GET", "path": "/tok123", "source_ip": "127.0.0.1"}] if self._hit else []


async def _none():
    return None


def _agent(oast, captured):
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.findings = {}
    a.oast = oast
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-ssrf"),
        session_memory=stub_session_memory(),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )
    return a


def test_ssrf_confirmed_on_callback():
    captured = []
    agent = _agent(_FakeOAST(hit=True), captured)
    res = asyncio.run(
        agent._execute_ssrf_scan(
            {
                "url": "http://t/profile/image/url",
                "body_field": "imageUrl",
                "engagement_id": "eng-ssrf",
                "poll_seconds": 0.1,
                "poll_interval": 0.05,
                "token": "x",
            }
        )
    )
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.vuln_type.value == "ssrf" and v.validated is True
    assert v.cwe == "CWE-918" and v.is_simulated() is False


def test_ssrf_not_confirmed_without_callback():
    captured = []
    agent = _agent(_FakeOAST(hit=False), captured)
    res = asyncio.run(
        agent._execute_ssrf_scan(
            {
                "url": "http://t/x?u=OASTINJECT",
                "param": "u",
                "engagement_id": "eng-ssrf",
                "poll_seconds": 0.1,
                "poll_interval": 0.05,
            }
        )
    )
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
