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
    """Patch httpx.AsyncClient to serve canned responses keyed by URL-DECODED substring.

    Keys are matched against the URL-DECODED request line, because probes are
    sent percent-encoded (e.g. "%7B%7B7%2A9%7D%7D" for "{{7*9}}") and the
    readable probe text only exists after decoding. GET and POST are both
    served; POST keys match against decoded form bodies too.
    """
    import ai_osop.agents.vuln_agent as va
    from urllib.parse import unquote_plus

    seen_calls: List[Dict[str, Any]] = []

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def _match(self, url: str, data: Any = None) -> _FakeResponse:
            decoded = unquote_plus(url)
            form_part = ""
            if data:
                try:
                    form_part = unquote_plus("&".join(f"{k}={v}" for k, v in data.items()))
                except Exception:  # noqa: BLE001
                    pass
            # POSTs match keys against the FORM BODY only (else a URL-substring
            # key like "/login" swallows every probe); GETs match the URL.
            target_str = form_part if data is not None else decoded
            for key, resp in responses.items():
                if key in target_str:
                    return resp
            return _FakeResponse(200, "benign page")

        async def get(self, url: str, headers: Dict[str, str] = None):
            seen_calls.append({"method": "GET", "url": url, "headers": headers or {}})
            return self._match(url)

        async def post(self, url: str, data: Dict[str, str] = None, headers: Dict[str, str] = None):
            seen_calls.append(
                {"method": "POST", "url": url, "data": dict(data or {}), "headers": headers or {}}
            )
            return self._match(url, data)

    monkeypatch.setattr(va.httpx, "AsyncClient", _Client)
    return seen_calls


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


async def test_web_audit_post_form_sqli_confirmed(monkeypatch):
    """WEB-AUDIT-002: a login form's POST body is discovered and differentially
    audited — control login fails, tautology payload succeeds -> VALIDATED."""
    agent = _make_agent()
    login_page = (
        "<html><body><form method='POST' action='/login'>"
        "<input name='username'><input name='password' type='password'>"
        "<input type='submit' value='go'></form></body></html>"
    )
    seen = _patch_http(
        monkeypatch,
        {
            "/login": _FakeResponse(200, login_page),  # page GET (no params on seed)
            "username=audit_probe_baseline_77": _FakeResponse(401, "Login failed"),
            "username=%27 OR %271%27%3D%271": _FakeResponse(200, "Welcome, admin!"),
            "OR '1'='1": _FakeResponse(200, "Welcome, admin!"),
        },
    )
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/login", "engagement_id": "eng-test"}
    )
    assert result["status"] == "success"
    assert result["stats"]["forms_audited"] == 1
    assert result["findings_count"] == 1
    finding = result["findings"][0]
    assert finding["cwe"] == "CWE-89"
    assert finding["validated"] is True
    assert finding["evidence"][0]["method"] == "POST"
    assert finding["evidence"][0]["parameter"] == "username"
    posts = [c for c in seen if c["method"] == "POST"]
    assert posts, "engine must POST the discovered form"
    assert "password" in posts[0]["data"], "other fields ride along with defaults"


async def test_web_audit_session_replay_sends_cookies(monkeypatch):
    """WEB-AUDIT-002: a stored engagement session is replayed on every probe."""
    agent = _make_agent()

    fake_sess = MagicMock()
    fake_sess.cookies = [{"name": "sid", "value": "abc123"}]
    fake_sess.bearer_token = "tok-1"
    fake_sess.extra_headers = {"X-Custom": "yes"}
    fake_sess.user_agent = "AIOSOP-Scanner/1.0"
    fake_sess.is_expired.return_value = False

    import ai_osop.auth.session_store as ss

    monkeypatch.setattr(
        ss.SessionStore, "get_session_or_none", AsyncMock(return_value=fake_sess)
    )
    seen = _patch_http(monkeypatch, {})
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/search?q=seed", "engagement_id": "eng-test", "session_label": "user1"}
    )
    assert result["stats"]["authenticated"] is True
    assert seen, "engine must have issued requests"
    for call in seen:
        h = call["headers"]
        assert h.get("Cookie") == "sid=abc123"
        assert h.get("Authorization") == "Bearer tok-1"
        assert h.get("X-Custom") == "yes"
        assert h.get("User-Agent") == "AIOSOP-Scanner/1.0"


async def test_web_audit_missing_session_degrades_anonymous(monkeypatch):
    """A missing session label must degrade to an anonymous audit, not fail."""
    agent = _make_agent()
    import ai_osop.auth.session_store as ss

    monkeypatch.setattr(ss.SessionStore, "get_session_or_none", AsyncMock(return_value=None))
    _patch_http(monkeypatch, {})
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/search?q=seed", "engagement_id": "eng-test", "session_label": "ghost"}
    )
    assert result["status"] == "success"
    assert result["stats"]["authenticated"] is False


class _FakeOAST:
    """Deterministic stand-in for OASTAdapter: captures injected callbacks."""

    def __init__(self, registry):
        self.hits = []

    async def initialize(self, scope, session_id):
        return None

    async def register(self, label="", context=None):
        self.cb_url = "http://127.0.0.1:8099/fake-token-123"
        return "fake-token-123", self.cb_url

    async def poll(self, token):
        return list(self.hits)


async def test_web_audit_blind_ssrf_oast_confirmed(monkeypatch):
    """WEB-AUDIT-003: injected callback URL fires -> OAST hit -> VALIDATED SSRF."""
    agent = _make_agent()
    import ai_osop.adapters.oast_mcp as om
    import ai_osop.agents.vuln_agent as va

    fake = _FakeOAST(None)
    fake.hits = [{"source_ip": "10.0.0.5", "kind": "http", "path": "/fake-token-123"}]
    monkeypatch.setattr(om, "OASTAdapter", lambda reg: fake)
    monkeypatch.setattr(va.asyncio, "sleep", AsyncMock(return_value=None))  # skip settle
    seen = _patch_http(monkeypatch, {})
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/fetch?url=seed", "engagement_id": "eng-test", "classes": ["ssrf"]}
    )
    assert result["status"] == "success"
    assert result["findings_count"] == 1
    finding = result["findings"][0]
    assert finding["cwe"] == "CWE-918"
    assert finding["validated"] is True
    ev = finding["evidence"][0]
    assert ev["type"] == "oast_callback"
    assert ev["interaction"]["source_ip"] == "10.0.0.5"
    # the callback URL must actually have been injected into a probe request
    injected = [c for c in seen if "fake-token-123" in c["url"]]
    assert injected, "callback URL was never injected"


async def test_web_audit_ssrf_no_callback_no_finding(monkeypatch):
    """The honest-empty rule: no OAST interaction => NO SSRF finding."""
    agent = _make_agent()
    import ai_osop.adapters.oast_mcp as om
    import ai_osop.agents.vuln_agent as va

    fake = _FakeOAST(None)  # zero hits
    monkeypatch.setattr(om, "OASTAdapter", lambda reg: fake)
    monkeypatch.setattr(va.asyncio, "sleep", AsyncMock(return_value=None))
    _patch_http(monkeypatch, {})
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/fetch?url=seed", "engagement_id": "eng-test", "classes": ["ssrf"]}
    )
    assert result["status"] == "success"
    assert result["findings_count"] == 0
    assert result["stats"]["oast_hits"] == 0


async def test_web_audit_ssrf_skipped_when_oast_unavailable(monkeypatch):
    """OAST server down => blind-SSRF pass degrades silently, scan still succeeds."""
    agent = _make_agent()
    import ai_osop.adapters.oast_mcp as om
    import ai_osop.agents.vuln_agent as va

    class _Broken:
        def __init__(self, reg):
            pass

        async def register(self, label="", context=None):
            raise RuntimeError("oast-mcp not registered")

    monkeypatch.setattr(om, "OASTAdapter", _Broken)
    monkeypatch.setattr(va.asyncio, "sleep", AsyncMock(return_value=None))
    _patch_http(monkeypatch, {})
    result = await agent._execute_web_audit(
        {"url": "http://127.0.0.1/fetch?url=seed", "engagement_id": "eng-test", "classes": ["ssrf"]}
    )
    assert result["status"] == "success"
    assert result["findings_count"] == 0
    assert "oast_hits" not in result["stats"] or result["stats"]["oast_hits"] == 0
