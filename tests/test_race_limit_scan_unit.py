import asyncio
from types import SimpleNamespace

from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from tests._mocks import stub_session_memory


def _capture(store, v):
    store.append(v)

    async def _ok():
        return None

    return _ok()


async def _none():
    return None


class _FakeTurbo:
    def __init__(self, dist):
        self._dist = dist

    async def initialize(self, *a, **k):
        return None

    async def execute_single_packet_attack(self, **k):
        return {
            "attack": "single_packet_last_byte_sync",
            "real": True,
            "completed": sum(self._dist.values()),
            "release_window_ms": 1.4,
            "status_distribution": self._dist,
            "distinct_response_bodies": 1,
            "results": [],
        }


def _agent(turbo, captured):
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.findings = {}
    a.turbo = turbo
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-race"),
        session_memory=stub_session_memory(),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )
    return a


def test_race_confirmed_when_successes_exceed_limit():
    # 5 requests returned the success status for a once-only action => double-spend.
    captured = []
    agent = _agent(_FakeTurbo({"200": 5, "409": 15}), captured)
    res = asyncio.run(
        agent._execute_race_limit_scan(
            {
                "url": "http://t/redeem",
                "success_status": 200,
                "expected_max_successes": 1,
                "concurrent_requests": 20,
                "engagement_id": "eng-race",
            }
        )
    )
    assert res["confirmed"] is True and res["findings_count"] == 1
    assert res["success_count"] == 5
    v = captured[0]
    assert v.vuln_type.value == "race_condition" and v.validated is True
    assert v.cwe == "CWE-362" and v.is_simulated() is False


def test_no_race_when_within_limit():
    captured = []
    agent = _agent(_FakeTurbo({"200": 1, "409": 19}), captured)
    res = asyncio.run(
        agent._execute_race_limit_scan(
            {
                "url": "http://t/redeem",
                "success_status": 200,
                "expected_max_successes": 1,
                "concurrent_requests": 20,
                "engagement_id": "eng-race",
            }
        )
    )
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
