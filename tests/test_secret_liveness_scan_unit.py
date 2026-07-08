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


def _agent(verdicts, captured):
    """verdicts: dict secret_value -> live(bool)."""
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.findings = {}
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-sec"),
        session_memory=SimpleNamespace(get_session_state=lambda _e: _none()),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )

    async def _verify(secret, base_override=None):
        live = verdicts.get(secret, False)
        return {
            "provider": "github" if secret.startswith("ghp_") else None,
            "classified": secret.startswith("ghp_"),
            "live": live,
            "status": 200 if live else 401,
            "detail": "authenticated" if live else "rejected",
        }

    a._verify_one_secret = _verify
    return a


def test_live_secret_mints_finding():
    captured = []
    agent = _agent({"ghp_LIVEKEY": True}, captured)
    res = asyncio.run(
        agent._execute_secret_liveness_scan(
            {"secrets": ["ghp_LIVEKEY"], "engagement_id": "eng-sec"}
        )
    )
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.vuln_type.value == "exposed_secret" and v.validated is True
    assert v.cwe == "CWE-798" and v.is_simulated() is False
    # The secret value must be redacted in evidence (never store raw creds).
    assert "LIVEKEY" not in str(v.evidence)


def test_dead_secret_no_finding():
    captured = []
    agent = _agent({"ghp_DEADKEY": False}, captured)
    res = asyncio.run(
        agent._execute_secret_liveness_scan(
            {"secrets": ["ghp_DEADKEY"], "engagement_id": "eng-sec"}
        )
    )
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
