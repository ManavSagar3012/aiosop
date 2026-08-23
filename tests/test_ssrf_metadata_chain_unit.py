import asyncio
from types import SimpleNamespace

from ai_osop.agents.vuln_agent import VulnAnalysisAgent

AWS_CREDS = (
    '{"Code":"Success","AccessKeyId":"ASIAEXAMPLE12345","SecretAccessKey":'
    '"s3cr3t/Key+VALUE","Token":"FwoEXAMPLE","Expiration":"2026-07-01"}'
)


def _capture(store, v):
    store.append(v)

    async def _ok():
        return None

    return _ok()


async def _none():
    return None


def _agent(fetch_map, captured):
    """fetch_map: dict metadata_url -> response body."""
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.findings = {}
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-meta"),
        session_memory=SimpleNamespace(get_session_state=lambda _e: _none()),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )

    async def _fetch(metadata_url):
        return fetch_map.get(metadata_url, "")

    a._ssrf_fetch_via_sink = _fetch
    return a


def test_chain_confirmed_two_step_aws():
    base = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    captured = []
    agent = _agent({base: "web-role", base + "web-role": AWS_CREDS}, captured)
    res = asyncio.run(
        agent._execute_ssrf_metadata_chain(
            {"url": "http://t/fetch", "param": "u", "engagement_id": "eng-meta"}
        )
    )
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.vuln_type.value == "ssrf" and v.severity.value == "critical"
    assert v.cwe == "CWE-918" and v.is_simulated() is False
    assert "s3cr3t/Key+VALUE" not in str(v.evidence)  # raw secret redacted


def test_chain_not_confirmed_without_creds():
    captured = []
    agent = _agent({}, captured)  # SSRF returns nothing useful
    res = asyncio.run(
        agent._execute_ssrf_metadata_chain(
            {"url": "http://t/fetch", "param": "u", "engagement_id": "eng-meta"}
        )
    )
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
