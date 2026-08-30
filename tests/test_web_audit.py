"""WEB-AUDIT-001: unit tests for the integrated active-scanner engine.

Covers the _execute_web_audit pipeline with fully mocked HTTP + memory:
  - scope gate: out-of-scope host raises OutOfScopeError before any request
  - scope gate: missing scope entirely fails closed
  - differential SQLi: control baseline vs error-signature probe -> VALIDATED finding
  - reflected XSS marker delta -> VALIDATED finding
  - SSTI template evaluation (7*9=63) -> VALIDATED finding
  - clean target -> success with zero findings (no false positives from probe noise)
  - crawl degradation: security-bridge failure falls back to seed URL only
"""

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import OutOfScopeError
from ai_osop.core.models import ScopeDefinition, Task


def _make_agent(seed_scope_domains=None, seed_scope_ips=None) -> VulnAnalysisAgent:
    """Build a VulnAnalysisAgent with mocked memory/registry (no I/O)."""
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "vuln-agent-test"
    ctx.agent_type = AgentType.VULN_ANALYSIS
    ctx.session_id = "eng-test"
    ctx.current_task = None
    # load_session_state returns a session carrying the signed engagement scope.
    session = MagicMock()
    session.scope = ScopeDefinition(
        engagement_id="eng-test",
        domains=list(seed_scope_domains or ["127.0.0.1"]),
        ips=list(seed_scope_ips if seed_scope_ips is not None else ["127.0.0.1"]),
        exclusions=[],
    )
    ctx.session_memory = MagicMock()
    ctx.session_memory.load_session_state = AsyncMock(return_value=session)
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.add_vulnerability = AsyncMock(return_value=True)
    # security-bridge crawl fails by default -> engine must degrade to seed URL.
    ctx.mcp_registry = MagicMock()
    ctx.mcp_registry.execute_tool = AsyncMock(side_effect=RuntimeError("bridge down"))
    ctx.findings = {}
    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = ctx
    agent.findings = {}
    return agent


class _FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


def _patch_http(monkeypatch, responses: Dict[str, _FakeResponse]):
    """Patch httpx.AsyncClient.get to serve canned responses keyed by URL substring.

    Keys are matched against the URL-DECODED request line, because probes are
    sent percent-encoded (e.g. "%7B%7B7%2A9%7D%7D" for "{{7*9}}") and the
    readable probe text only exists after decoding.
    """
    import ai_osop.agents.vuln_agent as va
    from urllib.parse import unquote_plus

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url: str):
            decoded = unquote_plus(url)
            for key, resp in responses.items():
                if key in decoded:
                    return resp
            return _FakeResponse(200, "benign page")

    monkeypatch.setattr(va.httpx, "AsyncClient", _Client)


async def test_web_audit_out_of_scope_host_refused(monkeypatch):
    agent = _make_agent(seed_scope_domains=["10.10.10.10"], seed_scope_ips=["10.10.10.10"])
    _patch_http(monkeypatch, {})
    with pytest.raises(OutOfScopeError):
        await agent._execute_web_audit(
            {"url": "http://127.0.0.1/login?user=x", "engagement_id": "eng-test"}
        )


async def test_web_audit_no_scope_fails_closed(monkeypatch):
    agent = _make_agent()
    # Session load returns None AND payload carries no scope dict.
    agent.ctx.session_memory.load_session_state = AsyncMock(return_value=None)
    _patch_http(monkeypatch, {})
    with pytest.raises(OutOfScopeError):
        await agent._execute_web_audit(
            {"url": "http://127.0.0.1/login?user=x", "engagement_id": "eng-test"}
        )


async def test_web_audit_sqli_differential_confirmed(monkeypatch):
    agent = _make_agent()
    # Baseline (control value) is clean; the SQLi probe value triggers a
    # distinctive DB error signature absent from the baseline.
    _patch_http(
        monkeypatch,
        {
            "audit_probe_baseline_77": _FakeResponse(200, "normal search results"),
            "OR '1'='1": _FakeResponse(200, "ERROR: sql syntax error near 'OR"),
        },
    )
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/search?q=seed", "engagement_id": "eng-test"}
    )
    assert result["status"] == "success"
    assert result["findings_count"] == 1
    finding = result["findings"][0]
    assert finding["cwe"] == "CWE-89"
    assert finding["validated"] is True
    assert finding["evidence"][0]["parameter"] == "q"
    assert finding["evidence"][0]["error_signature"] is True


async def test_web_audit_xss_marker_reflection(monkeypatch):
    agent = _make_agent()
    _patch_http(
        monkeypatch,
        {
            "audit_probe_baseline_77": _FakeResponse(200, "hello user"),
            "probe_xss_marker_9f3a": _FakeResponse(
                200, "<div>hello probe_xss_marker_9f3a</div>"
            ),
        },
    )
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/greet?name=seed", "engagement_id": "eng-test"}
    )
    assert result["findings_count"] == 1
    finding = result["findings"][0]
    assert finding["cwe"] == "CWE-79"


async def test_web_audit_ssti_evaluation(monkeypatch):
    agent = _make_agent()
    # "63" must be absent from baseline but present when the template evaluates.
    _patch_http(
        monkeypatch,
        {
            "audit_probe_baseline_77": _FakeResponse(200, "result: 42"),
            "7*9": _FakeResponse(200, "result: 63"),
        },
    )
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/render?tpl=seed", "engagement_id": "eng-test"}
    )
    assert result["findings_count"] == 1
    assert result["findings"][0]["cwe"] == "CWE-1336"


async def test_web_audit_clean_target_zero_findings(monkeypatch):
    agent = _make_agent()
    # Everything returns the same benign body: no behavioral delta anywhere.
    _patch_http(monkeypatch, {})
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/search?q=seed", "engagement_id": "eng-test"}
    )
    assert result["status"] == "success"
    assert result["findings_count"] == 0
    assert result["stats"]["params_probed"] == 1


async def test_web_audit_crawl_degrades_to_seed(monkeypatch):
    agent = _make_agent()
    # Registry raises (default mock) -> engine must audit just the seed URL.
    _patch_http(monkeypatch, {})
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/search?q=seed", "engagement_id": "eng-test"}
    )
    assert result["stats"]["crawl_degraded"] is True
    assert result["stats"]["crawled"] == 1


async def test_web_audit_requires_url():
    agent = _make_agent()
    from ai_osop.core.exceptions import AgentException

    with pytest.raises(AgentException):
        await agent._execute_web_audit({"engagement_id": "eng-test"})
