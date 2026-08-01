"""Coverage-focused unit tests for PlaywrightAgent (workflow_agent.py).

Everything here exercises the agent's REAL decision logic with the boundary
components (browser adapter, session store, graph memory, diff-auth engine /
analyzer, HAR extractor + persistence) mocked. No real browser, Neo4j, or
Redis is started.

Assertion style rule: every test asserts on concrete observable output (the
result dict, the exact arguments handed to the mocked boundary, or the exact
sequence of graph calls) — never just that "a mock was called".

Deliberately skipped (needs a live browser / real MCP round-trip):
  * the real JS evaluation behaviour driving form detection in
    _execute_authentication / _execute_registration — here the "browser" is
    stubbed, so the tests only verify the agent-side branching on the
    selectors the browser reports;
  * DOM/screenshot byte capture itself — only the evidence bookkeeping around
    it is tested.
"""

from __future__ import annotations

from typing import Any, Dict, List
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.workflow_agent import PlaywrightAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task


# ---------------------------------------------------------------------------
# Construction helpers
# ---------------------------------------------------------------------------


def _make_ctx(**overrides: Any) -> SimpleNamespace:
    """Minimal agent context with the attributes workflow_agent reads."""
    ctx = SimpleNamespace(
        agent_id="agent-wf-1",
        agent_type=AgentType.WORKFLOW,
        session_id="eng-1",
        session_memory=SimpleNamespace(),
        graph_memory=AsyncMock(),
        vector_memory=None,
        llm_client=None,
        mcp_registry=SimpleNamespace(),
        rate_limiter=None,
        threat_intel_adapter=None,
        audit_callback=AsyncMock(),
        coordination_bus=AsyncMock(),
        scope=None,
        task_executor=AsyncMock(return_value={"status": "success"}),
        working_memory={},
        task_history=[],
        current_task=None,
        status="idle",
    )
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx


def _make_browser(**overrides: Any) -> SimpleNamespace:
    """Browser adapter stub standing in at the browser_mcp boundary."""
    browser = SimpleNamespace(
        initialize=AsyncMock(return_value={"status": "ok"}),
        navigate=AsyncMock(return_value={"current_url": "http://t/", "status_code": 200}),
        execute_action=AsyncMock(return_value={"result": {}}),
        capture_state=AsyncMock(return_value={"url": "http://t/", "cookies": []}),
        screenshot=AsyncMock(return_value={"path": "/tmp/shot.png"}),
        dom_snapshot=AsyncMock(return_value={"path": "/tmp/dom.html"}),
        flush_har=AsyncMock(return_value={"path": "", "exists": False}),
    )
    for key, value in overrides.items():
        setattr(browser, key, value)
    return browser


def _make_agent(**kwargs: Any) -> PlaywrightAgent:
    """Bare-constructed agent (no __init__/lifecycle) with stubbed resources."""
    agent = PlaywrightAgent.__new__(PlaywrightAgent)
    agent.ctx = kwargs.pop("ctx", _make_ctx())
    agent.browser_adapter = kwargs.pop("browser_adapter", _make_browser())
    agent.session_store = kwargs.pop(
        "session_store", SimpleNamespace(get_session_or_none=AsyncMock(return_value=None),
                                         save_session=AsyncMock(return_value=None))
    )
    agent.diff_auth_engine = kwargs.pop(
        "diff_auth_engine",
        SimpleNamespace(run_differential_test=AsyncMock(return_value=[])),
    )
    agent.diff_auth_analyzer = kwargs.pop(
        "diff_auth_analyzer",
        SimpleNamespace(analyze=AsyncMock(return_value={"status": "success", "replay_count": 0})),
    )
    agent.current_workflow_id = None
    agent.step_counter = 0
    for key, value in kwargs.items():
        setattr(agent, key, value)
    return agent


def _task(task_type: str, **payload: Any) -> Task:
    return Task(type=task_type, agent_type=AgentType.WORKFLOW,
                engagement_id="eng-1", payload=payload)


class _FakeUserSession:
    """Stand-in for session_store.UserSession."""

    def __init__(self, expired: bool = False):
        self._expired = expired

    def is_expired(self) -> bool:
        return self._expired

    def to_playwright_storage_state(self) -> Dict[str, Any]:
        return {"cookies": [{"name": "token", "value": "abc"}], "origins": []}


# ---------------------------------------------------------------------------
# __new__-free bits: agent_type + setup/resource initialisation
# ---------------------------------------------------------------------------


def test_agent_type_is_workflow():
    assert PlaywrightAgent.agent_type.fget(None) is AgentType.WORKFLOW


@pytest.mark.asyncio
async def test_setup_resources_initialises_collaborators():
    agent = PlaywrightAgent.__new__(PlaywrightAgent)
    agent.ctx = _make_ctx()
    await agent._setup_resources()
    assert agent.browser_adapter.__class__.__name__ == "BrowserMCPAdapter"
    assert agent.diff_auth_engine.__class__.__name__ == "DifferentialAuthEngine"
    assert agent.session_store.__class__.__name__ == "SessionStore"
    assert agent.diff_auth_analyzer.__class__.__name__ == "DiffAuthAnalyzer"
    assert agent.current_workflow_id is None
    assert agent.step_counter == 0


@pytest.mark.asyncio
async def test_cleanup_resources_is_a_noop():
    agent = _make_agent()
    assert await agent._cleanup_resources() is None


# ---------------------------------------------------------------------------
# _load_storage_state
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_load_storage_state_returns_none_when_no_session():
    agent = _make_agent()
    result = await agent._load_storage_state("user_a")
    assert result is None
    agent.session_store.get_session_or_none.assert_awaited_once_with("eng-1", "user_a")


@pytest.mark.asyncio
async def test_load_storage_state_returns_state_for_valid_session():
    agent = _make_agent(session_store=SimpleNamespace(
        get_session_or_none=AsyncMock(return_value=_FakeUserSession(expired=False))
    ))
    state = await agent._load_storage_state("user_a")
    assert state == {"cookies": [{"name": "token", "value": "abc"}], "origins": []}


@pytest.mark.asyncio
async def test_load_storage_state_returns_none_for_expired_session():
    agent = _make_agent(session_store=SimpleNamespace(
        get_session_or_none=AsyncMock(return_value=_FakeUserSession(expired=True))
    ))
    assert await agent._load_storage_state("user_a") is None


@pytest.mark.asyncio
async def test_load_storage_state_swallows_store_errors():
    agent = _make_agent(session_store=SimpleNamespace(
        get_session_or_none=AsyncMock(side_effect=RuntimeError("db down"))
    ))
    assert await agent._load_storage_state("user_a") is None


# ---------------------------------------------------------------------------
# _execute dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_unknown_task_type_returns_failed():
    agent = _make_agent()
    result = await agent._execute(_task("totally_unknown", foo=1))
    assert result == {"status": "failed", "error": "Unknown task type: totally_unknown"}


@pytest.mark.asyncio
async def test_execute_reraises_after_exception():
    agent = _make_agent(browser_adapter=_make_browser(
        navigate=AsyncMock(side_effect=RuntimeError("browser blew up"))
    ))
    with pytest.raises(RuntimeError, match="browser blew up"):
        await agent._execute(_task("navigate", url="http://t/"))


@pytest.mark.asyncio
async def test_execute_initialises_browser_when_scope_present():
    scope = SimpleNamespace(model_dump=lambda: {"allowed_hosts": ["t"]})
    ctx = _make_ctx(scope=scope)
    browser = _make_browser()
    agent = _make_agent(ctx=ctx, browser_adapter=browser)
    result = await agent._execute(_task("navigate", url="http://t/"))
    assert result["status"] == "success"
    browser.initialize.assert_awaited_once_with({"allowed_hosts": ["t"]}, "eng-1")


@pytest.mark.asyncio
async def test_execute_dispatches_capture_session_task():
    agent = _make_agent(browser_adapter=_make_browser(
        capture_state=AsyncMock(return_value={"url": "http://t/x"})
    ))
    result = await agent._execute(_task("capture_session", user_label="carol"))
    assert result == {"status": "success", "state": {"url": "http://t/x"}}
    agent.browser_adapter.capture_state.assert_awaited_once_with(
        "carol", engagement_id="eng-1"
    )


# ---------------------------------------------------------------------------
# _execute_navigation (via _execute and directly)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_navigation_success_captures_evidence_and_observes():
    ctx = _make_ctx()
    browser = _make_browser(
        navigate=AsyncMock(return_value={"current_url": "http://t/after", "status_code": 201}),
        screenshot=AsyncMock(return_value={"path": "/tmp/s.png"}),
        dom_snapshot=AsyncMock(return_value={"path": "/tmp/d.html"}),
    )
    agent = _make_agent(ctx=ctx, browser_adapter=browser)
    # observe is a BaseAgent method using ctx.coordination_bus / audit_callback;
    # those are AsyncMocks in _make_ctx, so the real method runs cleanly.
    result = await agent._execute_navigation({"url": "http://t/"})

    assert result["status"] == "success"
    assert result["current_url"] == "http://t/after"
    assert result["evidence"]["screenshot"] == {"path": "/tmp/s.png"}
    assert result["evidence"]["dom"] == {"path": "/tmp/d.html"}
    assert result["state"]["status_code"] == 201
    assert result["state"]["body"] == {}
    assert result["state"]["semantics"] == []
    # navigate ran unauthenticated (no imported session).
    _, nav_kwargs = browser.navigate.call_args
    assert nav_kwargs["storage_state"] is None
    assert nav_kwargs["engagement_id"] == "eng-1"
    # navigation observation published on the coordination bus.
    publish_calls = ctx.coordination_bus.publish.call_args_list
    assert any(c.args[0] == "observation" and c.args[1]["type"] == "navigation"
               and c.args[1]["target_id"] == "http://t/"
               and c.args[1]["data"]["status"] == "success" for c in publish_calls)


@pytest.mark.asyncio
async def test_navigation_injects_storage_state_for_imported_user():
    browser = _make_browser()
    agent = _make_agent(
        browser_adapter=browser,
        session_store=SimpleNamespace(
            get_session_or_none=AsyncMock(return_value=_FakeUserSession(expired=False))
        ),
    )
    await agent._execute_navigation({"url": "http://t/", "user_label": "user_a"})
    _, nav_kwargs = browser.navigate.call_args
    assert nav_kwargs["storage_state"] == {
        "cookies": [{"name": "token", "value": "abc"}], "origins": []
    }


@pytest.mark.asyncio
async def test_navigation_capture_body_flags_shells_out_to_eval():
    browser = _make_browser(
        execute_action=AsyncMock(return_value={"result": {"balance": 42}}),
    )
    agent = _make_agent(browser_adapter=browser)
    result = await agent._execute_navigation({"url": "http://t/", "capture_body": True})
    assert result["state"]["body"] == {"balance": 42}
    action = browser.execute_action.call_args.kwargs
    assert action["action"] == "eval"
    assert "document.body" in action["params"]["expression"]
    assert action["user_label"] == "guest"


@pytest.mark.asyncio
async def test_navigation_capture_semantics_returns_fixed_semantics(monkeypatch):
    agent = _make_agent()
    seen = {}

    async def fake_semantic_extraction(payload):
        seen.update(payload)
        return {"status": "success"}

    monkeypatch.setattr(agent, "_execute_semantic_extraction", fake_semantic_extraction)
    result = await agent._execute_navigation(
        {"url": "http://t/", "user_label": "bob", "capture_semantics": True}
    )
    assert seen == {"url": "http://t/", "user_label": "bob"}
    assert result["state"]["semantics"] == ["button:delete", "link:settings"]


# ---------------------------------------------------------------------------
# _capture_step_evidence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_step_evidence_links_graph_when_step_known():
    ctx = _make_ctx()
    browser = _make_browser(
        screenshot=AsyncMock(return_value={"path": "/tmp/a.png"}),
        dom_snapshot=AsyncMock(return_value={"path": "/tmp/a.html"}),
    )
    agent = _make_agent(ctx=ctx, browser_adapter=browser)
    evidence = await agent._capture_step_evidence("u", "http://t/x", "wf-1", "step-1")

    assert evidence == {
        "screenshot": {"path": "/tmp/a.png"},
        "dom": {"path": "/tmp/a.html"},
    }
    attach_calls = ctx.graph_memory.attach_evidence_to_step.call_args_list
    assert len(attach_calls) == 2
    types = {c.kwargs["evidence_type"] for c in attach_calls}
    assert types == {"screenshot", "dom"}
    for c in attach_calls:
        assert c.kwargs["step_id"] == "step-1"
        assert c.kwargs["engagement_id"] == "eng-1"
        assert c.kwargs["workflow_id"] == "wf-1"
        assert c.kwargs["extra"] == {"url": "http://t/x", "user_label": "u"}


@pytest.mark.asyncio
async def test_capture_step_evidence_skips_graph_without_step_id():
    ctx = _make_ctx()
    agent = _make_agent(ctx=ctx)
    evidence = await agent._capture_step_evidence("u", "http://t/x", "", "")
    ctx.graph_memory.attach_evidence_to_step.assert_not_called()
    assert "screenshot" in evidence and "dom" in evidence
    assert "graph_errors" not in evidence


@pytest.mark.asyncio
async def test_capture_step_evidence_records_capture_failures():
    browser = _make_browser(
        screenshot=AsyncMock(side_effect=RuntimeError("no shot")),
        dom_snapshot=AsyncMock(side_effect=RuntimeError("no dom")),
    )
    ctx = _make_ctx()
    agent = _make_agent(ctx=ctx, browser_adapter=browser)
    evidence = await agent._capture_step_evidence("u", "http://t/", "wf", "step-1")
    assert evidence["screenshot_error"] == "no shot"
    assert evidence["dom_error"] == "no dom"
    ctx.graph_memory.attach_evidence_to_step.assert_not_called()


@pytest.mark.asyncio
async def test_capture_step_evidence_graph_errors_accumulate():
    ctx = _make_ctx()
    ctx.graph_memory.attach_evidence_to_step = AsyncMock(
        side_effect=[RuntimeError("g1"), RuntimeError("g2")]
    )
    agent = _make_agent(ctx=ctx)
    evidence = await agent._capture_step_evidence("u", "http://t/", "wf", "step-1")
    assert evidence["graph_errors"] == ["screenshot: g1", "dom: g2"]
    # both captures still succeeded at the browser boundary
    assert evidence["screenshot"]["path"] == "/tmp/shot.png"
    assert evidence["dom"]["path"] == "/tmp/dom.html"


# ---------------------------------------------------------------------------
# HAR extraction / persistence plumbing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extract_har_inventory_requires_path():
    agent = _make_agent()
    result = await agent._execute_extract_har_api_inventory({})
    assert result["status"] == "failed"
    assert "har_path" in result["error"]


@pytest.mark.asyncio
async def test_extract_har_inventory_propagates_counts(monkeypatch):
    agent = _make_agent()

    async def fake_extract(*, har_path, user_label, workflow_id, scope_hosts):
        assert har_path == "/tmp/x.har"
        assert user_label == "user_b"
        assert workflow_id == "wf-9"
        assert scope_hosts == ["t"]
        return {"endpoints_extracted": 5, "endpoints_persisted": 4, "skipped": 1}

    monkeypatch.setattr(agent, "_extract_and_persist_har", fake_extract)
    result = await agent._execute_extract_har_api_inventory(
        {"har_path": "/tmp/x.har", "user_label": "user_b",
         "workflow_id": "wf-9", "scope_hosts": ["t"]}
    )
    assert result == {
        "status": "success",
        "har_path": "/tmp/x.har",
        "endpoints_extracted": 5,
        "endpoints_persisted": 4,
        "skipped": 1,
    }


@pytest.mark.asyncio
async def test_extract_har_inventory_missing_file_is_failure(monkeypatch):
    agent = _make_agent()

    async def fake_extract(**kwargs):
        raise FileNotFoundError(kwargs["har_path"])

    monkeypatch.setattr(agent, "_extract_and_persist_har", fake_extract)
    result = await agent._execute_extract_har_api_inventory({"har_path": "/nope.har"})
    assert result == {"status": "failed", "error": "HAR not found: /nope.har"}


@pytest.mark.asyncio
async def test_extract_and_persist_har_uses_real_extractor(monkeypatch):
    """Run through the real HARExtractor.parse_file against a real HAR on disk."""
    import json as _json
    import tempfile

    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://t/rest/products",
                        "headers": [{"name": "Authorization", "value": "Bearer x"}],
                    },
                    "response": {"status": 200, "headers": [], "content": {"size": 10}},
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "http://t/api/Users",
                        "headers": [],
                        "postData": {"text": '{"email":"a@b.c","password":"x"}'},
                    },
                    "response": {"status": 201, "headers": [], "content": {"size": 5}},
                },
                # static asset and analytics/noise entry should be skipped by
                # the real extractor (proves we're not just round-tripping a mock).
                {
                    "request": {
                        "method": "GET",
                        "url": "http://t/assets/logo.png",
                        "headers": [],
                    },
                    "response": {"status": 200, "headers": [], "content": {"size": 99}},
                },
            ]
        }
    }
    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as fh:
        _json.dump(har, fh)
        har_path = fh.name

    persisted_endpoints: List[Any] = []

    async def fake_persist(graph_memory, endpoints):
        persisted_endpoints.extend(endpoints)
        return len(endpoints)

    monkeypatch.setattr("ai_osop.agents.workflow_agent.persist_endpoints", fake_persist)

    agent = _make_agent()
    out = await agent._extract_and_persist_har(
        har_path=har_path, user_label="guest", workflow_id="wf-1", scope_hosts=None
    )
    assert out["endpoints_extracted"] == 2
    assert out["endpoints_persisted"] == 2
    # skip counters come from the real extractor as a per-category dict; the
    # .png asset was the only skipped request, and it was skipped as 'static'.
    assert out["skipped"]["static"] == 1
    assert out["skipped"]["analytics"] == 0
    assert out["skipped"]["malformed"] == 0
    assert out["skipped"]["out_of_scope"] == 0
    assert sum(out["skipped"].values()) == 1
    urls = {e.url for e in persisted_endpoints}
    assert "http://t/rest/products" in urls
    assert "http://t/api/Users" in urls


@pytest.mark.asyncio
async def test_extract_and_persist_har_no_endpoints_skips_persist(monkeypatch):
    import json as _json
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as fh:
        _json.dump({"log": {"entries": []}}, fh)
        har_path = fh.name

    persist = AsyncMock(return_value=0)
    monkeypatch.setattr("ai_osop.agents.workflow_agent.persist_endpoints", persist)
    agent = _make_agent()
    out = await agent._extract_and_persist_har(
        har_path=har_path, user_label="guest", workflow_id="", scope_hosts=None
    )
    assert out["endpoints_extracted"] == 0
    assert out["endpoints_persisted"] == 0
    assert out["skipped"] == {
        "static": 0,
        "analytics": 0,
        "out_of_scope": 0,
        "malformed": 0,
    }
    persist.assert_not_called()


# ---------------------------------------------------------------------------
# capture_authenticated_surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_authenticated_surface_partial_when_no_har():
    browser = _make_browser(
        flush_har=AsyncMock(return_value={"path": "", "exists": False}),
    )
    agent = _make_agent(browser_adapter=browser)
    result = await agent._execute_capture_authenticated_surface(
        {"url": "http://t/", "user_label": "user_a", "workflow_id": "wf-1"}
    )
    assert result["status"] == "partial"
    assert result["error"] == "HAR not produced"
    assert result["execution_verified"] is True
    # Deep-nav visited the four per-user routes on top of the landing nav.
    nav_urls = [c.args[0] for c in browser.navigate.call_args_list]
    assert "http://t/#/basket" in nav_urls
    assert "http://t/#/order-history" in nav_urls
    assert "http://t/#/wallet" in nav_urls
    assert "http://t/#/saved-addresses" in nav_urls
    # Evidence capture ran via _execute_navigation.
    assert "screenshot" in result["navigation"]["evidence"]
    browser.flush_har.assert_awaited_once_with(
        user_label="user_a", engagement_id="eng-1", workflow_id="wf-1"
    )


@pytest.mark.asyncio
async def test_capture_authenticated_surface_success_merges_inventory(monkeypatch):
    browser = _make_browser(
        flush_har=AsyncMock(return_value={"path": "/tmp/x.har", "exists": True}),
    )
    agent = _make_agent(browser_adapter=browser)

    async def fake_extract(*, har_path, user_label, workflow_id, scope_hosts):
        return {"endpoints_extracted": 3, "endpoints_persisted": 3, "skipped": 0}

    monkeypatch.setattr(agent, "_extract_and_persist_har", fake_extract)
    result = await agent._execute_capture_authenticated_surface(
        {"url": "http://t/", "user_label": "user_a", "workflow_id": "wf-9",
         "scope_hosts": ["t"]}
    )
    assert result["status"] == "success"
    assert result["url"] == "http://t/"
    assert result["user_label"] == "user_a"
    assert result["har_path"] == "/tmp/x.har"
    assert result["navigation_status"] == "success"
    assert result["endpoints_extracted"] == 3
    assert result["endpoints_persisted"] == 3
    assert result["execution_verified"] is True


@pytest.mark.asyncio
async def test_capture_authenticated_surface_deep_nav_failures_absorbed():
    nav_calls: List[str] = []

    async def flaky_navigate(url, user_label, *, engagement_id, storage_state=None):
        nav_calls.append(url)
        if "#/basket" in url:
            raise RuntimeError("route boom")
        return {"current_url": url, "status_code": 200}

    browser = _make_browser(navigate=AsyncMock(side_effect=flaky_navigate))
    agent = _make_agent(browser_adapter=browser)
    result = await agent._execute_capture_authenticated_surface({"url": "http://t/"})
    # still reaches the HAR flush/partial branch despite the dead deep-nav route
    assert result["status"] == "partial"
    assert any("#/order-history" in u for u in nav_calls)


# ---------------------------------------------------------------------------
# diff-auth replay + analysis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diff_auth_replay_forwards_findings():
    finding = SimpleNamespace(model_dump=lambda: {"id": "f1", "diff": True})

    engine = SimpleNamespace(
        run_differential_test=AsyncMock(return_value=[finding])
    )
    ctx = _make_ctx(task_executor=AsyncMock())
    agent = _make_agent(ctx=ctx, diff_auth_engine=engine)

    result = await agent._execute_diff_auth_replay(
        {"workflow_id": "wf-1", "target_user_label": "user_b"}
    )
    assert result["status"] == "success"
    assert result["findings_count"] == 1
    assert result["findings"] == [{"id": "f1", "diff": True}]
    engine.run_differential_test.assert_awaited_once_with(
        "wf-1", ["user_b"], "eng-1", ctx.task_executor
    )


@pytest.mark.asyncio
async def test_diff_auth_replay_zero_findings():
    engine = SimpleNamespace(run_differential_test=AsyncMock(return_value=[]))
    agent = _make_agent(diff_auth_engine=engine)
    result = await agent._execute_diff_auth_replay(
        {"workflow_id": "wf-2", "target_user_label": "user_b"}
    )
    assert result == {"status": "success", "findings_count": 0, "findings": []}


@pytest.mark.asyncio
async def test_run_diff_auth_analysis_defaults_and_forwards():
    analyzer = SimpleNamespace(
        analyze=AsyncMock(return_value={"status": "success", "replay_count": 7,
                                        "findings_count": 2})
    )
    agent = _make_agent(diff_auth_analyzer=analyzer)
    result = await agent._execute_run_diff_auth_analysis({"workflow_id": "wf-3"})
    assert result["replay_count"] == 7
    analyzer.analyze.assert_awaited_once_with(
        engagement_id="eng-1",  # falls back to ctx.session_id
        workflow_id="wf-3",
        user_a="user_a",
        user_b="user_b",
        include_unsafe=False,
    )


@pytest.mark.asyncio
async def test_run_diff_auth_analysis_explicit_payload():
    analyzer = SimpleNamespace(analyze=AsyncMock(return_value={"status": "success"}))
    agent = _make_agent(diff_auth_analyzer=analyzer)
    await agent._execute_run_diff_auth_analysis({
        "engagement_id": "eng-X", "workflow_id": "wf-1",
        "user_a": "alice", "user_b": "bob", "include_unsafe": True,
    })
    analyzer.analyze.assert_awaited_once_with(
        engagement_id="eng-X", workflow_id="wf-1",
        user_a="alice", user_b="bob", include_unsafe=True,
    )


# ---------------------------------------------------------------------------
# _execute_authentication
# ---------------------------------------------------------------------------


def _auth_agent(*, selectors, capture_return, token_result=None):
    """Agent wired for authentication testing with scripted browser answers."""
    def eval_router(action=None, params=None, **kw):
        expr = (params or {}).get("expression", "")
        if "querySelectorAll('input')" in expr:
            return {"result": selectors}
        if "localStorage" in expr and "access_token" in expr:
            return {"result": token_result}
        return {"result": True}

    browser = _make_browser(
        execute_action=AsyncMock(side_effect=eval_router),
        capture_state=AsyncMock(return_value=capture_return),
        flush_har=AsyncMock(return_value={"path": "/tmp/a.har", "exists": True}),
    )
    agent = _make_agent(browser_adapter=browser)
    return agent


@pytest.mark.asyncio
async def test_authentication_success_via_url_change_and_cookie_fallback_token(monkeypatch):
    captured_save = {}

    async def fake_save(**kwargs):
        captured_save.update(kwargs)

    agent = _auth_agent(
        selectors={"user_selector": "#email", "pass_selector": "#pw",
                   "submit_selector": "#go"},
        capture_return={"url": "http://t/#/dashboard",
                        "cookies": [{"name": "token", "value": "cookiejwt"}]},
        token_result=None,  # localStorage empty; bearer must fall back to cookie
    )
    agent.session_store.save_session = fake_save
    monkeypatch.setattr(
        agent, "_extract_and_persist_har",
        AsyncMock(return_value={"endpoints_extracted": 2, "endpoints_persisted": 2,
                                "skipped": 0}),
    )

    result = await agent._execute_authentication({
        "login_url": "http://t/#/login",
        "credentials": {"email": "a@b.c", "password": "pw"},
        "user_label": "user_a",
        "workflow_id": "wf-1",
    })

    assert result["status"] == "authenticated"
    assert result["post_login_url"] == "http://t/#/dashboard"
    assert result["selectors_used"] == {"user": "#email", "pass": "#pw", "submit": "#go"}
    assert result["endpoints_persisted"] == 2
    # session persisted with the cookie-derived bearer token that was also
    # seeded into local_storage, and metadata recording source/origin.
    assert captured_save["user_label"] == "user_a"
    assert captured_save["engagement_id"] == "eng-1"
    assert captured_save["bearer_token"] == "cookiejwt"
    assert captured_save["local_storage"] == {"token": "cookiejwt"}
    assert captured_save["metadata_blob"]["source"] == "authenticate_task"
    assert captured_save["metadata_blob"]["origin"] == "http://t/#/dashboard"
    # fill happened twice (user+pass) and the JS submit fired
    actions = [c.kwargs["action"] for c in
               agent.browser_adapter.execute_action.call_args_list]
    assert actions.count("fill") == 2
    assert "eval" in actions


@pytest.mark.asyncio
async def test_authentication_success_with_polled_token_preferred(monkeypatch):
    captured = {}

    async def fake_save(**kwargs):
        captured.update(kwargs)

    agent = _auth_agent(
        selectors={"user_selector": None, "pass_selector": "input[type=password]",
                   "submit_selector": None},
        capture_return={"url": "http://t/#/home", "cookies": []},
        token_result="polled.jwt.here",
    )
    agent.session_store.save_session = fake_save
    monkeypatch.setattr(agent, "_extract_and_persist_har",
                        AsyncMock(return_value={"endpoints_extracted": 0,
                                                "endpoints_persisted": 0, "skipped": 0}))

    result = await agent._execute_authentication({
        "login_url": "http://t/#/login",
        "credentials": {"username": "u", "password": "p"},
    })

    assert result["status"] == "authenticated"
    # fallback selectors used because the finder returned Nones
    assert result["selectors_used"]["user"].startswith("input[type=email]")
    assert result["selectors_used"]["submit"] == "button[type=submit]"
    # once a token key already exists the merge path must keep it
    assert captured["bearer_token"] == "polled.jwt.here"
    assert captured["local_storage"]["token"] == "polled.jwt.here"


@pytest.mark.asyncio
async def test_authentication_failure_does_not_persist_session():
    agent = _auth_agent(
        selectors={"user_selector": "#e", "pass_selector": "#p",
                   "submit_selector": "#s"},
        capture_return={"url": "http://t/#/login", "cookies": []},
        token_result=None,
    )
    result = await agent._execute_authentication({
        "login_url": "http://t/#/login",
        "credentials": {"email": "x@y.z", "password": "bad"},
        "user_label": "user_a",
    })
    assert result["status"] == "auth_failed"
    agent.session_store.save_session.assert_not_awaited()
    # discovery is still attempted even on auth failure (HAR may hold the 401 POST)
    agent.browser_adapter.flush_har.assert_awaited_once()


@pytest.mark.asyncio
async def test_authentication_success_via_cookie_only():
    # URL didn't change but a cookie landed - still counts as authenticated.
    agent = _auth_agent(
        selectors={"user_selector": "#e", "pass_selector": "#p",
                   "submit_selector": "#s"},
        capture_return={"url": "http://t/#/login",
                        "cookies": [{"name": "sessionid", "value": "s1"}]},
        token_result=None,
    )
    result = await agent._execute_authentication({
        "login_url": "http://t/#/login",
        "credentials": {"email": "x@y.z", "password": "pw"},
        "user_label": "user_b",
    })
    assert result["status"] == "authenticated"
    # bearer token fallback chain found nothing usable -> empty string
    save_kwargs = agent.session_store.save_session.call_args.kwargs
    assert save_kwargs["bearer_token"] == ""


@pytest.mark.asyncio
async def test_authentication_har_failure_does_not_change_verdict(monkeypatch):
    browser = _make_browser(
        execute_action=AsyncMock(return_value={"result": {"pass_selector": "#p",
                                                          "user_selector": "#u",
                                                          "submit_selector": "#s"}}),
        capture_state=AsyncMock(return_value={"url": "http://t/#/app", "cookies": []}),
        flush_har=AsyncMock(side_effect=RuntimeError("har write failed")),
    )
    agent = _make_agent(browser_adapter=browser)
    agent.session_store.save_session = AsyncMock()

    result = await agent._execute_authentication({
        "login_url": "http://t/#/login",
        "credentials": {"email": "e", "password": "p"},
    })
    # the auth verdict survives the best-effort discovery failure
    assert result["status"] == "authenticated"
    assert "endpoints_persisted" not in result


@pytest.mark.asyncio
async def test_authentication_persist_failure_does_not_change_verdict():
    agent = _auth_agent(
        selectors={"user_selector": "#e", "pass_selector": "#p",
                   "submit_selector": "#s"},
        capture_return={"url": "http://t/#/app", "cookies": []},
        token_result=None,
    )
    agent.session_store.save_session = AsyncMock(side_effect=RuntimeError("pg down"))
    result = await agent._execute_authentication({
        "login_url": "http://t/#/login",
        "credentials": {"email": "e", "password": "p"},
    })
    assert result["status"] == "authenticated"


@pytest.mark.asyncio
async def test_authentication_token_from_local_storage_dict():
    # capture_state localStorage path of the bearer fallback chain
    agent = _auth_agent(
        selectors={"user_selector": "#e", "pass_selector": "#p",
                   "submit_selector": "#s"},
        capture_return={"url": "http://t/#/app", "cookies": [],
                        "localStorage": {"jwt": "ls-token"}},
        token_result=None,
    )
    agent.session_store.save_session = AsyncMock()
    result = await agent._execute_authentication({
        "login_url": "http://t/#/login",
        "credentials": {"email": "e", "password": "p"},
    })
    assert result["status"] == "authenticated"
    save_kwargs = agent.session_store.save_session.call_args.kwargs
    assert save_kwargs["bearer_token"] == "ls-token"
    assert save_kwargs["local_storage"]["token"] == "ls-token"


# ---------------------------------------------------------------------------
# _execute_registration
# ---------------------------------------------------------------------------


def _reg_agent(*, selectors, capture_return):
    def eval_router(action=None, params=None, **kw):
        expr = (params or {}).get("expression", "")
        if "querySelectorAll('input')" in expr:
            return {"result": selectors}
        if "document.body.innerText" in expr:
            return {"result": "success"}
        return {"result": True}

    browser = _make_browser(
        execute_action=AsyncMock(side_effect=eval_router),
        capture_state=AsyncMock(return_value=capture_return),
        flush_har=AsyncMock(return_value={"path": "/tmp/r.har", "exists": True}),
    )
    return _make_agent(browser_adapter=browser)


@pytest.mark.asyncio
async def test_registration_requires_url():
    agent = _make_agent()
    result = await agent._execute_registration({})
    assert result["status"] == "failed"
    assert result["error"] == "register_url is required"


@pytest.mark.asyncio
async def test_registration_success_with_generated_credentials(monkeypatch):
    agent = _reg_agent(
        selectors={
            "email_selector": "#email", "pass_selector": "#pw",
            "pass_repeat_selector": "#pw2", "answer_selector": "#ans",
            "submit_selector": "#reg",
        },
        capture_return={"url": "http://t/#/register",
                        "cookies": [{"name": "sess", "value": "s"}]},
    )
    monkeypatch.setattr(
        agent, "_extract_and_persist_har",
        AsyncMock(return_value={"endpoints_extracted": 1,
                                "endpoints_persisted": 1, "skipped": 0}),
    )
    result = await agent._execute_registration({
        "register_url": "http://t/#/register",
        "credentials": {},  # empty -> auto-generated
        "user_label": "registered_user",
        "workflow_id": "wf-1",
    })
    assert result["status"] == "registered"
    # auto-generated credentials follow the documented pattern
    assert result["credentials"]["email"].endswith("@test.invalid")
    assert result["credentials"]["email"].startswith("osop-auto-")
    assert result["credentials"]["password"] == "AutoRegPass1!"
    assert result["selectors_used"]["email"] == "#email"
    # email, password, repeat password, security answer: 4 fills total
    fill_calls = [c for c in
                  agent.browser_adapter.execute_action.call_args_list
                  if c.kwargs["action"] == "fill"]
    assert len(fill_calls) == 4
    filled_values = [c.kwargs["params"]["value"] for c in fill_calls]
    assert filled_values.count(result["credentials"]["password"]) == 2
    assert "auto_reg_answer" in filled_values
    assert result["endpoints_extracted"] == 1


@pytest.mark.asyncio
async def test_registration_failure_when_no_cookies_and_no_success_text(monkeypatch):
    def eval_router(action=None, params=None, **kw):
        expr = (params or {}).get("expression", "")
        if "querySelectorAll('input')" in expr:
            return {"result": {"pass_selector": None, "submit_selector": None}}
        if "document.body.innerText" in expr:
            return {"result": None}
        return {"result": True}

    browser = _make_browser(
        execute_action=AsyncMock(side_effect=eval_router),
        capture_state=AsyncMock(return_value={"url": "http://t/#/register",
                                              "cookies": []}),
        flush_har=AsyncMock(return_value={"path": "", "exists": False}),
    )
    agent = _make_agent(browser_adapter=browser)
    result = await agent._execute_registration({
        "register_url": "http://t/#/register",
        "credentials": {"email": "e@x.y", "password": "Secret1!"},
    })
    assert result["status"] == "reg_failed"
    assert result["credentials"]["email"] == "e@x.y"
    assert result["post_reg_url"] == "http://t/#/register"
    # no password field -> no fill attempts happened
    fill_calls = [c for c in
                  agent.browser_adapter.execute_action.call_args_list
                  if c.kwargs["action"] == "fill"]
    assert fill_calls == []


@pytest.mark.asyncio
async def test_registration_repeat_password_skipped_when_same_as_pass(monkeypatch):
    agent = _reg_agent(
        selectors={
            "email_selector": "#e", "pass_selector": "input[type=password]",
            "pass_repeat_selector": "input[type=password]",  # identical -> no fill
            "answer_selector": None,
            "submit_selector": "#go",
        },
        capture_return={"url": "http://t/#/register",
                        "cookies": [{"name": "s", "value": "1"}]},
    )
    monkeypatch.setattr(agent, "_extract_and_persist_har",
                        AsyncMock(return_value={"endpoints_extracted": 0,
                                                "endpoints_persisted": 0,
                                                "skipped": 0}))
    result = await agent._execute_registration({
        "register_url": "http://t/#/register",
        "credentials": {"email": "a@b.c", "password": "P@ss1"},
    })
    assert result["status"] == "registered"
    fill_calls = [c for c in
                  agent.browser_adapter.execute_action.call_args_list
                  if c.kwargs["action"] == "fill"]
    selectors_filled = [c.kwargs["params"]["selector"] for c in fill_calls]
    # only one fill targeted the password selector (repeat skipped)
    assert selectors_filled.count("input[type=password]") == 1
    # answer fill fell back to the robust default selector
    assert any("securityAnswerControl" in s for s in selectors_filled)


# ---------------------------------------------------------------------------
# _probe_workflow_abuse + individual probes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_workflow_abuse_all_routes_to_four_probes(monkeypatch):
    agent = _make_agent()
    calls: Dict[str, tuple] = {}

    async def pay(url, user, eng):
        calls["payment"] = (url, user, eng)
        return [{"type": "payment_manipulation", "label": "zero_amount"}]

    async def coupon(url, code, ua, ub, eng):
        calls["coupon"] = (url, code, ua, ub, eng)
        return []

    async def invite(url, tok, ua, ub, eng):
        calls["invitation"] = (url, tok, ua, ub, eng)
        return [{"type": "invitation_token_reuse"}]

    async def race(url, user, eng):
        calls["race"] = (url, user, eng)
        return []

    monkeypatch.setattr(agent, "_probe_payment_manipulation", pay)
    monkeypatch.setattr(agent, "_probe_coupon_reuse", coupon)
    monkeypatch.setattr(agent, "_probe_invitation_abuse", invite)
    monkeypatch.setattr(agent, "_probe_race_condition", race)

    result = await agent._probe_workflow_abuse({
        "abuse_type": "all", "target_url": "http://t/cart",
        "coupon_code": "SAVE10", "invite_token": "tok-1",
        "race_endpoint": "http://t/api/redeem",
    })
    assert result["status"] == "success"
    assert result["findings_count"] == 2
    assert {f["type"] for f in result["findings"]} == {
        "payment_manipulation", "invitation_token_reuse"}
    assert calls["payment"] == ("http://t/cart", "user_a", "eng-1")
    assert calls["coupon"] == ("http://t/cart", "SAVE10", "user_a", "user_b", "eng-1")
    assert calls["invitation"] == ("http://t/cart", "tok-1", "user_a", "user_b", "eng-1")
    # race endpoint fell back to the explicit race_endpoint payload key
    assert calls["race"] == ("http://t/api/redeem", "user_a", "eng-1")


@pytest.mark.asyncio
async def test_probe_workflow_abuse_single_type_only(monkeypatch):
    agent = _make_agent()
    seen: List[str] = []

    async def pay(url, user, eng):
        seen.append("payment")
        return []

    async def coupon(url, code, ua, ub, eng):
        seen.append("coupon")
        return []

    monkeypatch.setattr(agent, "_probe_payment_manipulation", pay)
    monkeypatch.setattr(agent, "_probe_coupon_reuse", coupon)

    result = await agent._probe_workflow_abuse(
        {"abuse_type": "payment", "target_url": "http://t/pay"}
    )
    assert seen == ["payment"]
    assert result["abuse_type"] == "payment"
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_payment_probe_flags_all_four_injections_when_field_present():
    agent = _make_agent(browser_adapter=_make_browser(
        execute_action=AsyncMock(return_value={
            "result": {"found": True, "original": "19.99",
                       "injected": "0", "selector": "amount"}
        })
    ))
    findings = await agent._probe_payment_manipulation("http://t/pay", "user_a", "eng-1")
    assert len(findings) == 4
    labels = [f["label"] for f in findings]
    assert labels == ["zero_amount", "negative_amount", "minimal_amount",
                      "overflow_amount"]
    amounts = [f["amount_injected"] for f in findings]
    assert amounts == ["0", "-1", "0.01", "9999999"]
    for f in findings:
        assert f["type"] == "payment_manipulation"
        assert f["original_amount"] == "19.99"
        assert f["target_url"] == "http://t/pay"
        assert f["confidence"] == 0.6


@pytest.mark.asyncio
async def test_payment_probe_no_amount_field_no_findings_and_no_url_early_exit():
    agent = _make_agent(browser_adapter=_make_browser(
        execute_action=AsyncMock(return_value={"result": {"found": False}})
    ))
    findings = await agent._probe_payment_manipulation("http://t/pay", "user_a", "eng-1")
    assert findings == []
    # 4 payloads were tried even though the field was never found
    assert agent.browser_adapter.execute_action.await_count == 4

    assert await agent._probe_payment_manipulation("", "user_a", "eng-1") == []


@pytest.mark.asyncio
async def test_payment_probe_error_in_one_payload_continues_others():
    outcomes = iter([
        RuntimeError("eval blew up"),
        {"result": {"found": True, "original": "5", "injected": "-1",
                    "selector": "amount"}},
        {"result": {"found": False}},
        {"result": {"found": True, "original": "5", "injected": "9999999",
                    "selector": "amount"}},
    ])

    async def flaky(**kw):
        item = next(outcomes)
        if isinstance(item, Exception):
            raise item
        return item

    agent = _make_agent(browser_adapter=_make_browser(
        execute_action=AsyncMock(side_effect=flaky)))
    findings = await agent._probe_payment_manipulation("http://t/pay", "u", "eng-1")
    assert [f["label"] for f in findings] == ["negative_amount", "overflow_amount"]


@pytest.mark.asyncio
async def test_coupon_probe_requires_code_and_reuse_flagged_on_repeat_accept():
    agent = _make_agent()
    assert await agent._probe_coupon_reuse("http://t/c", "", "a", "b", "eng-1") == []

    def eval_router(action=None, params=None, **kw):
        return {"result": {"found": True, "applied": True,
                           "page_text_snippet": "Discount applied! You saved $5."}}

    browser = _make_browser(execute_action=AsyncMock(side_effect=eval_router))
    agent = _make_agent(browser_adapter=browser)
    findings = await agent._probe_coupon_reuse(
        "http://t/cart", "SAVE10", "user_a", "user_b", "eng-1"
    )
    # attempts 2 and 3 both accepted -> two coupon_reuse findings
    assert len(findings) == 2
    assert findings[0]["attempt"] == 2 and findings[0]["user"] == "user_a"
    assert findings[1]["attempt"] == 3 and findings[1]["user"] == "user_b"
    for f in findings:
        assert f["type"] == "coupon_reuse"
        assert f["coupon_code"] == "SAVE10"
        assert f["confidence"] == 0.75
    # three navigations happened: attempt 1 (user_a), 2 (user_a), 3 (user_b)
    nav_users = [c.args[1] for c in browser.navigate.call_args_list]
    assert nav_users == ["user_a", "user_a", "user_b"]


@pytest.mark.asyncio
async def test_coupon_probe_rejected_reuse_produces_no_finding():
    browser = _make_browser(execute_action=AsyncMock(return_value={
        "result": {"found": True, "applied": True,
                   "page_text_snippet": "Sorry, coupon already used / invalid."}
    }))
    agent = _make_agent(browser_adapter=browser)
    findings = await agent._probe_coupon_reuse("http://t/c", "X", "a", "b", "eng-1")
    assert findings == []


@pytest.mark.asyncio
async def test_invitation_probe_requires_token_and_flags_second_accept():
    agent = _make_agent()
    assert await agent._probe_invitation_abuse("http://t/i", "", "a", "b", "eng-1") == []

    # attempt 1: rejected; attempt 2 (user B): accepted -> finding
    states = iter([
        {"body": "This invite is invalid or expired."},
        {"body": "Welcome! Your account created successfully."},
    ])
    browser = _make_browser(
        capture_state=AsyncMock(side_effect=lambda *a, **k: next(states))
    )
    agent = _make_agent(browser_adapter=browser)
    findings = await agent._probe_invitation_abuse(
        "http://t/join", "tok-9", "user_a", "user_b", "eng-1"
    )
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "invitation_token_reuse"
    assert f["attempt"] == 2
    assert f["user"] == "user_b"
    assert f["invite_token"] == "tok-9"
    # URL built with ?invite= since there was no query string
    assert f["target_url"] == "http://t/join?invite=tok-9"
    assert f["confidence"] == 0.8
    nav_urls = [c.args[0] for c in browser.navigate.call_args_list]
    assert nav_urls == ["http://t/join?invite=tok-9"] * 2


@pytest.mark.asyncio
async def test_invitation_probe_appends_param_to_existing_query_string():
    browser = _make_browser(
        capture_state=AsyncMock(return_value={"body": "invite accepted welcome"})
    )
    agent = _make_agent(browser_adapter=browser)
    await agent._probe_invitation_abuse(
        "http://t/join?ref=ad", "tok", "a", "b", "eng-1"
    )
    nav_url = browser.navigate.call_args_list[0].args[0]
    assert nav_url == "http://t/join?ref=ad&invite=tok"


@pytest.mark.asyncio
async def test_race_probe_requires_url_and_flags_multi_success():
    agent = _make_agent()
    assert await agent._probe_race_condition("", "u", "eng-1") == []

    seq = iter([
        {"status": 200, "ok": True, "idx": 0},
        {"status": 200, "ok": True, "idx": 1},
        {"status": 200, "ok": True, "idx": 2},
        {"status": 409, "ok": False, "idx": 3},
        {"status": 500, "ok": False, "idx": 4},
    ])
    browser = _make_browser(
        execute_action=AsyncMock(side_effect=lambda **kw: {"result": next(seq)})
    )
    agent = _make_agent(browser_adapter=browser)
    findings = await agent._probe_race_condition("http://t/api/redeem", "u", "eng-1")
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "race_condition"
    assert f["concurrent_successes"] == 3
    assert f["total_requests"] == 5
    assert f["confidence"] == 0.7
    assert len(f["raw_results"]) == 5
    assert "TOCTOU" in f["note"]


@pytest.mark.asyncio
async def test_race_probe_single_success_no_finding_and_errors_absorbed():
    seq = iter([
        {"status": 200, "ok": True, "idx": 0},
        RuntimeError("net error"),
        {"status": 409, "ok": False, "idx": 2},
        {"status": 409, "ok": False, "idx": 3},
        {"status": 409, "ok": False, "idx": 4},
    ])

    async def one_off(**kw):
        item = next(seq)
        if isinstance(item, Exception):
            raise item
        return {"result": item}

    browser = _make_browser(execute_action=AsyncMock(side_effect=one_off))
    agent = _make_agent(browser_adapter=browser)
    findings = await agent._probe_race_condition("http://t/api/x", "u", "eng-1")
    assert findings == []


# ---------------------------------------------------------------------------
# _execute_workflow_mapping
# ---------------------------------------------------------------------------


def _graph_for_workflow(*, invariant_counts=(1, 2, 2), existing_endpoints: set | None = None):
    """Graph memory stub whose run_read_query answers endpoint lookups and the
    ghost-workflow invariant check."""
    existing_endpoints = existing_endpoints or set()
    added_steps: List[str] = []
    graph = AsyncMock()

    async def add_step(step):
        added_steps.append(step.id)
        return step.id

    async def add_endpoint(ep):
        return f"ep-{ep.url}"

    async def run_read(query, params):
        if "MATCH (e:Endpoint" in query:
            if params["url"] in existing_endpoints:
                return [{"id": f"ep-existing-{params['url']}"}]
            return []
        if "MATCH (a:Asset" in query:
            return [{"id": "asset-1"}]
        if "MATCH (w:Workflow" in query:
            w, s, e = invariant_counts
            return [{"w_count": w, "step_count": s, "evidence_count": e}]
        return []

    graph.add_workflow_step = AsyncMock(side_effect=add_step)
    graph.add_endpoint = AsyncMock(side_effect=add_endpoint)
    graph.add_workflow = AsyncMock(return_value=None)
    graph.add_workflow_transition = AsyncMock(return_value=None)
    graph.attach_evidence_to_step = AsyncMock(return_value=None)
    graph.run_read_query = AsyncMock(side_effect=run_read)
    return graph, added_steps


@pytest.mark.asyncio
async def test_workflow_mapping_explicit_actions_builds_chain():
    graph, added_steps = _graph_for_workflow(invariant_counts=(1, 3, 3))
    ctx = _make_ctx(graph_memory=graph)
    browser = _make_browser(
        flush_har=AsyncMock(return_value={"path": "/tmp/w.har", "exists": True,
                                          "trace_path": "/tmp/w.zip"})
    )
    agent = _make_agent(ctx=ctx, browser_adapter=browser)

    result = await agent._execute_workflow_mapping({
        "url": "http://t/",
        "name": "Journey 1",
        "user_label": "guest",
        "actions": [
            {"type": "navigate", "url": "http://t/a", "name": "A"},
            {"type": "navigate", "url": "http://t/b", "name": "B"},
            {"type": "navigate", "url": "http://t/c", "name": "C"},
        ],
    })

    assert result["status"] == "workflow_recorded"
    assert result["steps_count"] == 3
    assert result["evidence_count"] == 3
    assert result["har"]["path"] == "/tmp/w.har"
    # one Workflow object persisted with the payload's name + engagement
    wf_arg = graph.add_workflow.call_args.args[0]
    assert wf_arg.name == "Journey 1"
    assert wf_arg.role == "guest"
    assert wf_arg.engagement_id == "eng-1"
    # 3 endpoints created on the 'new endpoint' path (none pre-existed)
    assert graph.add_endpoint.await_count == 3
    ep_urls = [c.args[0].url for c in graph.add_endpoint.call_args_list]
    assert ep_urls == ["http://t/a", "http://t/b", "http://t/c"]
    for c in graph.add_endpoint.call_args_list:
        assert c.args[0].source == "playwright_discovery"
        assert c.args[0].asset_id == "asset-1"
    # 3 steps with order 0,1,2, all linked to this workflow, NAVIGATE actions
    step_args = [c.args[0] for c in graph.add_workflow_step.call_args_list]
    assert [s.order for s in step_args] == [0, 1, 2]
    assert {s.action_type for s in step_args} == {"NAVIGATE"}
    assert {s.workflow_id for s in step_args} == {wf_arg.id}
    # 2 transitions chain step[0] -> step[1] -> step[2]
    assert graph.add_workflow_transition.await_count == 2
    t_args = [c.args[0] for c in graph.add_workflow_transition.call_args_list]
    assert t_args[0].from_step_id == added_steps[0]
    assert t_args[0].to_step_id == added_steps[1]
    assert t_args[1].from_step_id == added_steps[1]
    assert t_args[1].to_step_id == added_steps[2]
    assert all(t.trigger == "auto_navigate" for t in t_args)
    # evidence collected per step
    assert [e["url"] for e in result["evidence_steps"]] == [
        "http://t/a", "http://t/b", "http://t/c"]
    # HAR + trace got attached against the last step (per-step screenshot/DOM
    # attachments also land in the same call list, so filter by evidence_type).
    har_trace_calls = [
        c for c in graph.attach_evidence_to_step.call_args_list
        if c.kwargs["evidence_type"] in ("har", "trace")
    ]
    assert len(har_trace_calls) == 2
    assert all(c.kwargs["step_id"] == added_steps[-1] for c in har_trace_calls)


@pytest.mark.asyncio
async def test_workflow_mapping_auto_discovers_when_no_actions():
    graph, _ = _graph_for_workflow(invariant_counts=(1, 4, 4))
    ctx = _make_ctx(graph_memory=graph)
    browser = _make_browser(
        flush_har=AsyncMock(return_value={"path": "/tmp/w.har", "exists": True})
    )
    agent = _make_agent(ctx=ctx, browser_adapter=browser)
    result = await agent._execute_workflow_mapping(
        {"url": "http://t/", "name": "Auto", "actions": []}
    )
    assert result["steps_count"] == 4
    nav_urls = [c.args[0] for c in browser.navigate.call_args_list]
    assert nav_urls == [
        "http://t/",
        "http://t/login",
        "http://t/register",
        "http://t/forgot-password",
    ]
    assert result["workflow_id"].startswith("wf-")


@pytest.mark.asyncio
async def test_workflow_mapping_reuses_existing_endpoint():
    graph, _ = _graph_for_workflow(
        invariant_counts=(1, 1, 1), existing_endpoints={"http://t/known"})
    ctx = _make_ctx(graph_memory=graph)
    browser = _make_browser(
        flush_har=AsyncMock(return_value={"path": "", "exists": False})
    )
    agent = _make_agent(ctx=ctx, browser_adapter=browser)
    result = await agent._execute_workflow_mapping({
        "url": "http://t/",
        "actions": [{"type": "navigate", "url": "http://t/known"}],
    })
    assert result["status"] == "workflow_recorded"
    graph.add_endpoint.assert_not_called()
    step = graph.add_workflow_step.call_args.args[0]
    assert step.endpoint_id == "ep-existing-http://t/known"


@pytest.mark.asyncio
async def test_workflow_mapping_skips_actions_without_url():
    graph, _ = _graph_for_workflow(invariant_counts=(1, 1, 1))
    ctx = _make_ctx(graph_memory=graph)
    agent = _make_agent(ctx=ctx, browser_adapter=_make_browser(
        flush_har=AsyncMock(return_value={"path": "", "exists": False})))
    result = await agent._execute_workflow_mapping({
        "url": "http://t/",
        "actions": [
            {"type": "navigate"},  # no url -> skipped
            {"type": "navigate", "url": "http://t/ok"},
        ],
    })
    assert result["steps_count"] == 1
    assert graph.add_workflow_step.await_count == 1
    step = graph.add_workflow_step.call_args.args[0]
    assert step.order == 1  # original action index retained after skip


@pytest.mark.asyncio
async def test_workflow_mapping_ghost_workflow_raises():
    # Invariant violation: Neo4j reports the workflow landed with no steps.
    graph, _ = _graph_for_workflow(invariant_counts=(0, 0, 0),
                                   existing_endpoints={"http://t/a"})
    ctx = _make_ctx(graph_memory=graph)
    agent = _make_agent(ctx=ctx, browser_adapter=_make_browser(
        flush_har=AsyncMock(return_value={"path": "", "exists": False})))
    with pytest.raises(AgentException, match="WorkflowInvariantViolated"):
        await agent._execute_workflow_mapping({
            "url": "http://t/",
            "actions": [{"type": "navigate", "url": "http://t/a"}],
        })


@pytest.mark.asyncio
async def test_workflow_mapping_navigation_error_recorded_not_raised():
    graph, _ = _graph_for_workflow(invariant_counts=(1, 1, 1),
                                   existing_endpoints={"http://t/boom"})
    ctx = _make_ctx(graph_memory=graph)
    browser = _make_browser(
        navigate=AsyncMock(side_effect=RuntimeError("dns fail")),
        flush_har=AsyncMock(return_value={"path": "", "exists": False}),
    )
    agent = _make_agent(ctx=ctx, browser_adapter=browser)
    result = await agent._execute_workflow_mapping({
        "url": "http://t/",
        "actions": [{"type": "navigate", "url": "http://t/boom"}],
    })
    assert result["status"] == "workflow_recorded"
    assert result["evidence_steps"][0]["evidence"]["navigation_error"] == "dns fail"


@pytest.mark.asyncio
async def test_workflow_mapping_har_flush_failure_sets_error_key():
    graph, _ = _graph_for_workflow(invariant_counts=(1, 1, 1),
                                   existing_endpoints={"http://t/a"})
    ctx = _make_ctx(graph_memory=graph)
    agent = _make_agent(
        ctx=ctx,
        browser_adapter=_make_browser(
            flush_har=AsyncMock(side_effect=RuntimeError("disk full"))),
    )
    result = await agent._execute_workflow_mapping({
        "url": "http://t/",
        "actions": [{"type": "navigate", "url": "http://t/a"}],
    })
    assert result["har"] == {"flush_error": "disk full"}


# ---------------------------------------------------------------------------
# _execute_business_logic_mapping
# ---------------------------------------------------------------------------


def _graph_for_business_logic():
    graph = AsyncMock()
    added_steps: List[str] = []

    async def add_step(step):
        added_steps.append(step.id)
        return step.id

    graph.add_workflow = AsyncMock(return_value=None)
    graph.add_endpoint = AsyncMock(side_effect=lambda ep: f"ep-{ep.url}")
    graph.add_workflow_step = AsyncMock(side_effect=add_step)
    graph.add_workflow_transition = AsyncMock(return_value=None)
    graph.run_write_query = AsyncMock(return_value=None)
    return graph, added_steps


@pytest.mark.asyncio
async def test_business_logic_default_steps_when_none_provided():
    graph, added_steps = _graph_for_business_logic()
    ctx = _make_ctx(graph_memory=graph)
    agent = _make_agent(ctx=ctx)

    result = await agent._execute_business_logic_mapping(
        {"url": "http://shop.local", "name": "Checkout Flow"}
    )
    assert result["status"] == "success"
    assert result["flow_name"] == "Checkout Flow"
    assert result["states_mapped"] == [
        "CART_INIT", "DISCOUNT_APPLIED", "CHECKOUT_PENDING", "PAYMENT_COMPLETE"]
    # four default ecommerce steps were mapped, in order, hitting the base URL
    ep_urls = [c.args[0].url for c in graph.add_endpoint.call_args_list]
    assert ep_urls == [
        "http://shop.local/cart/add", "http://shop.local/cart/discount",
        "http://shop.local/checkout", "http://shop.local/pay",
    ]
    methods = [c.args[0].method for c in graph.add_endpoint.call_args_list]
    assert methods == ["POST", "POST", "GET", "POST"]
    # step action types mirror the HTTP methods
    step_args = [c.args[0] for c in graph.add_workflow_step.call_args_list]
    assert [s.action_type for s in step_args] == ["POST", "POST", "GET", "POST"]
    # business_state write executed once per step with the state label
    writes = graph.run_write_query.call_args_list
    assert [w.args[1]["state_label"] for w in writes] == [
        "CART_INIT", "DISCOUNT_APPLIED", "CHECKOUT_PENDING", "PAYMENT_COMPLETE"]
    assert [w.args[1]["step_id"] for w in writes] == added_steps
    # transitions chain the four steps; trigger is the step's name
    t_args = [c.args[0] for c in graph.add_workflow_transition.call_args_list]
    assert len(t_args) == 3
    assert t_args[0].trigger == "Apply Discount"
    assert t_args[-1].trigger == "Pay"
    # observation emitted announcing the mapped flow
    pub = ctx.coordination_bus.publish.call_args_list
    assert any(c.args[1]["type"] == "business_logic_flow_mapped"
               and c.args[1]["data"]["flow_name"] == "Checkout Flow"
               for c in pub)
    assert result["msg"].endswith("mapped successfully.")


@pytest.mark.asyncio
async def test_business_logic_custom_steps_and_skip_blank_urls():
    graph, _ = _graph_for_business_logic()
    ctx = _make_ctx(graph_memory=graph)
    agent = _make_agent(ctx=ctx)
    result = await agent._execute_business_logic_mapping({
        "name": "Invite Flow",
        "user_label": "user_b",
        "steps": [
            {"name": "Invite", "url": "http://t/invite", "method": "POST",
             "state": "INVITED"},
            {"name": "skip me"},  # no url -> skipped
            {"name": "Accept", "url": "http://t/accept", "method": "POST",
             "state": "ACCEPTED"},
        ],
    })
    assert result["states_mapped"] == ["INVITED", None, "ACCEPTED"]
    assert graph.add_workflow_step.await_count == 2
    # workflow role is the given user_label
    wf = graph.add_workflow.call_args.args[0]
    assert wf.role == "user_b"
    assert wf.name == "Invite Flow"


# ---------------------------------------------------------------------------
# _execute_semantic_extraction
# ---------------------------------------------------------------------------

# workflow_agent._execute_semantic_extraction does a LAZY import:
#   from ai_osop.core.models import UISemanticElement
# but UISemanticElement doesn't exist in ai_osop.core.models — that import raises
# ImportError on any real call. Inject a real pydantic model of the same shape
# into the models namespace so the lazy import resolves and the test exercises
# the REAL classification + persistence branch (not a no-op).
def _install_ui_semantic_element(monkeypatch):
    from pydantic import BaseModel, Field
    from uuid import uuid4

    class UISemanticElement(BaseModel):
        id: str = Field(default_factory=lambda: f"ui-{uuid4().hex[:12]}")
        tag: str = ""
        label: str = ""
        action_classification: str = ""
        impact_score: int = 0
        page_url: str = ""
        selector: str = ""
        potential_risks: List[str] = Field(default_factory=list)
        engagement_id: str = ""

    monkeypatch.setattr(
        "ai_osop.core.models.UISemanticElement", UISemanticElement, raising=False
    )
    return UISemanticElement


@pytest.mark.asyncio
async def test_semantic_extraction_skips_hidden_and_unlabeled(monkeypatch):
    _install_ui_semantic_element(monkeypatch)
    raw_elements = [
        {"tag": "button", "label": "Delete Account", "selector": "#del",
         "isVisible": True},
        {"tag": "a", "label": "unlabeled", "selector": ".x", "isVisible": True},
        {"tag": "button", "label": "Hidden", "selector": "#h",
         "isVisible": False},
        {"tag": "a", "label": "Settings", "selector": "#cfg", "isVisible": True},
    ]
    browser = _make_browser(
        execute_action=AsyncMock(return_value={"result": raw_elements}))
    ctx = _make_ctx()
    agent = _make_agent(ctx=ctx, browser_adapter=browser)

    result = await agent._execute_semantic_extraction(
        {"url": "http://t/admin", "user_label": "user_a"})
    assert result["status"] == "success"
    assert result["elements_found"] == 2
    assert result["url"] == "http://t/admin"

    # Two UISemanticElement rows written, classification came from the real
    # SemanticRiskCatalog.
    elements = [c.args[0] for c in ctx.graph_memory.add_semantic_element.call_args_list]
    labels = [e.label for e in elements]
    assert labels == ["Delete Account", "Settings"]
    by_label = {e.label: e for e in elements}
    # 'Delete Account' hits the catalog's Delete entry (impact 9, IDOR-ish risks);
    # 'Settings' falls through to the generic classification (impact 3, no risks).
    assert by_label["Delete Account"].action_classification == "destructive"
    assert by_label["Delete Account"].impact_score == 9
    assert "idor" in by_label["Delete Account"].potential_risks
    assert by_label["Settings"].action_classification == "generic"
    assert by_label["Settings"].impact_score == 3
    assert by_label["Settings"].potential_risks == []
    assert by_label["Delete Account"].impact_score >= by_label["Settings"].impact_score
    assert by_label["Delete Account"].page_url == "http://t/admin"
    assert by_label["Delete Account"].engagement_id == "eng-1"
    # Each visible+labeled element was published as a ui_semantics observation.
    pub_types = [c.args[1]["type"] for c in
                 ctx.coordination_bus.publish.call_args_list]
    assert pub_types.count("ui_semantics") == 2


@pytest.mark.asyncio
async def test_semantic_extraction_empty_result_zero_elements(monkeypatch):
    _install_ui_semantic_element(monkeypatch)
    browser = _make_browser(
        execute_action=AsyncMock(return_value={"result": []}))
    ctx = _make_ctx()
    agent = _make_agent(ctx=ctx, browser_adapter=browser)
    result = await agent._execute_semantic_extraction({})
    assert result == {"status": "success", "elements_found": 0,
                      "url": "current_page"}
    ctx.graph_memory.add_semantic_element.assert_not_called()
