"""B4 honesty tests: SSTI + CSRF detectors cannot auto-submit unconfirmed noise.

These are the false-positive generators the gap analysis flagged:
  - SSTI flagged on REFLECTION (``{{7*7}}`` echoed verbatim), not EVALUATION.
  - CSRF flagged "no token string in response", no working cross-site PoC.

Both are now gated behind an objective signal (arithmetic evaluated -> result
present + control absent for SSTI; foreign-Origin request ACCEPTED for CSRF).
These tests prove the honest paths hermetically (httpx MockTransport — no network).
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from ai_osop.agents.csrf_agent import CSRFAgent
from ai_osop.agents.ssti_agent import SSTIAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task
from tests._mocks import stub_session_memory


def _ssti_agent(monkeypatch, transport_handler):
    """Construct an SSTIAgent with its httpx client wired to a MockTransport."""
    agent = SSTIAgent.__new__(SSTIAgent)
    agent.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock()),
        session_memory=stub_session_memory(),
    )
    agent.logger = SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None)
    agent.findings = {}

    real_async_client = httpx.AsyncClient

    def _fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(transport_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr("ai_osop.agents.ssti_agent.httpx.AsyncClient", _fake_client)
    return agent


def _make_task(url, param="q"):
    return Task(
        id="task-ssti-1",
        type="ssti_scan",
        agent_type=AgentType.SSTI_SCANNER,
        engagement_id="eng-test",
        priority=5,
        payload={"url": url, "param": param},
    )


@pytest.mark.asyncio
async def test_ssti_confirmed_on_evaluation(monkeypatch):
    """{{7*7}} -> response contains 49, control {{7*8}} does NOT contain 49 =>
    CONFIRMED HIGH with validated=True. This is the objective signal."""
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        # httpx URL-encodes the injected {{7*7}} into the query string; read the
        # decoded param value to detect which probe this is.
        injected = request.url.params.get("q") or ""
        # Server evaluates the injected expression: {{7*7}} -> 49
        if "7*7" in injected:
            return httpx.Response(200, text="Result is 49 here")
        # Control probe {{7*8}} must NOT yield 49
        if "7*8" in injected:
            return httpx.Response(200, text="Result is 56 here")
        return httpx.Response(200, text="nothing")

    agent = _ssti_agent(monkeypatch, handler)
    task = _make_task("https://target.test/search")
    result = await agent._execute_ssti_scan(task)

    assert result["confirmed"] is True
    assert result["findings_count"] == 1
    persisted = agent.ctx.graph_memory.add_vulnerability.await_args_list[0].args[0]
    assert persisted.vuln_type == VulnClass.SSTI
    assert persisted.severity == Severity.HIGH
    assert persisted.validated is True
    # Evidence proves evaluation, not reflection
    ev = persisted.evidence[0]
    assert ev["type"] == "ssti_evaluation"
    assert ev["control_did_not_collide"] is True


@pytest.mark.asyncio
async def test_ssti_reflection_only_not_confirmed(monkeypatch):
    """REFLECTION ONLY: response contains ``{{7*7}}`` verbatim (the payload echoed
    back) but does NOT contain ``49``. The old agent flagged this as HIGH
    validated. The new oracle must NOT confirm — it must emit no finding."""
    def handler(request: httpx.Request) -> httpx.Response:
        injected = request.url.params.get("q") or ""
        # Reflect the payload verbatim, no evaluation
        if "7*7" in injected:
            return httpx.Response(200, text="You searched for {{7*7}}")
        if "7*8" in injected:
            return httpx.Response(200, text="You searched for {{7*8}}")
        return httpx.Response(200, text="nothing")

    agent = _ssti_agent(monkeypatch, handler)
    task = _make_task("https://target.test/search")
    result = await agent._execute_ssti_scan(task)

    assert result["confirmed"] is False
    assert result["findings_count"] == 0
    # No finding persisted — the false-positive path emits nothing.
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


@pytest.mark.asyncio
async def test_ssti_control_collision_not_confirmed(monkeypatch):
    """If BOTH the {{7*7}} probe AND the {{7*8}} control probe yield ``49`` in
    the response, the signal is unreliable (the page contains 49 regardless of
    input). The oracle must NOT confirm in that case."""
    def handler(request: httpx.Request) -> httpx.Response:
        # Response always contains 49 (e.g. an order total) — evaluation signal
        # is meaningless. Both probes see it.
        return httpx.Response(200, text="Your order #49 is ready")

    agent = _ssti_agent(monkeypatch, handler)
    task = _make_task("https://target.test/search")
    result = await agent._execute_ssti_scan(task)

    assert result["confirmed"] is False
    assert result["findings_count"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ---------------------------------------------------------------------------


def _csrf_agent(monkeypatch, transport_handler, *, sessions=None, skip_applicability=False):
    """Construct a CSRFAgent with its httpx client wired to a MockTransport."""
    agent = CSRFAgent.__new__(CSRFAgent)
    gm = SimpleNamespace(
        add_vulnerability=AsyncMock(),
        log_skipped_scan=AsyncMock(),
    )
    agent.ctx = SimpleNamespace(
        graph_memory=gm,
        session_memory=stub_session_memory(),
    )
    agent.logger = SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None)
    agent.findings = {}

    real_async_client = httpx.AsyncClient

    def _fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(transport_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr("ai_osop.agents.csrf_agent.httpx.AsyncClient", _fake_client)

    if skip_applicability:
        async def _list_sessions(self, engagement_id):
            return sessions or []
        monkeypatch.setattr(
            "ai_osop.auth.session_store.SessionStore.list_sessions", _list_sessions
        )
    return agent


def _csrf_task(url, method="POST", cookie=None, body=None):
    payload = {"url": url, "method": method}
    if cookie is not None:
        payload["cookie"] = cookie
    if body is not None:
        payload["body"] = body
    return Task(
        id="task-csrf-1",
        type="csrf_scan",
        agent_type=AgentType.CSRF_SCANNER,
        engagement_id="eng-test",
        priority=5,
        payload=payload,
    )


@pytest.mark.asyncio
async def test_csrf_confirmed_when_foreign_origin_accepted(monkeypatch):
    """Cross-site request with foreign Origin + ambient cookie is ACCEPTED =>
    CONFIRMED (working PoC). This is the objective signal."""
    def handler(request: httpx.Request) -> httpx.Response:
        # The state-changing action succeeds despite the foreign Origin.
        return httpx.Response(200, text="OK")

    agent = _csrf_agent(monkeypatch, handler, skip_applicability=True)
    task = _csrf_task(
        "https://target.test/api/profile",
        method="POST",
        cookie="session=abc123",
        body={"name": "attacker"},
    )
    result = await agent._execute_csrf_scan(task)

    assert result["confirmed"] is True
    assert result["findings_count"] == 1
    persisted = agent.ctx.graph_memory.add_vulnerability.await_args_list[0].args[0]
    assert persisted.vuln_type == VulnClass.CSRF
    assert persisted.validated is True
    ev = persisted.evidence[0]
    assert ev["accepted_cross_site"] is True
    assert ev["csrf_token_in_request"] is False


@pytest.mark.asyncio
async def test_csrf_not_confirmed_when_request_rejected(monkeypatch):
    """The state-changing endpoint REJECTS the foreign-Origin request (403) =>
    NOT exploitable. No finding — this is the false-positive guard."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="Forbidden")

    agent = _csrf_agent(monkeypatch, handler, skip_applicability=True)
    task = _csrf_task(
        "https://target.test/api/profile",
        method="POST",
        cookie="session=abc123",
        body={"name": "attacker"},
    )
    result = await agent._execute_csrf_scan(task)

    assert result["confirmed"] is False
    assert result["findings_count"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


@pytest.mark.asyncio
async def test_csrf_not_confirmed_when_bearer_only(monkeypatch):
    """Bearer-token APIs are NOT CSRF-able (token isn't sent cross-site). No
    ambient cookie => no finding (the old 'no token string' heuristic would
    have flagged this)."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    agent = _csrf_agent(monkeypatch, handler, skip_applicability=True)
    # No cookie => bearer-only endpoint
    task = _csrf_task("https://target.test/api/profile", method="POST")
    result = await agent._execute_csrf_scan(task)

    assert result["confirmed"] is False
    assert result["findings_count"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()
