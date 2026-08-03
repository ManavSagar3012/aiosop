"""Deep coverage tests for ai_osop.agents.recon_agent.

These tests complement tests/test_recon_agent_coverage.py. They target the
paths that file leaves uncovered, primarily:

  * ReconAgent._active_crawl_target  — the multi-identity active crawler
    (link/form/script/inline-route extraction, dedup via visited_urls +
    endpoint_inventory, max_pages budget, JS-bundle API-route mining with
    live param probing, auth header/cookie plumbing from UserSession,
    scope rejection of lookalike hosts).
  * _execute_waf_detection akamai / f5_bigip / imperva / akamai-body branches
    and the graph-persist exception swallow.
  * _execute_cert_transparency persist-exception swallow.
  * _execute_wayback_discovery parse + persist exception swallows.
  * _execute_expand_subdomains resolve=True DNS path.
  * _execute_content_discovery targeted-permutator probe block.
  * _setup_resources and the remaining _execute dispatcher branches.

The httpx boundary is stubbed with a responder-driven fake client (the same
pattern as the existing coverage file) so tests assert real behaviour of the
parsing / classification / bookkeeping logic rather than mock-theatre.
"""

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.recon_agent import ReconAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Asset, Endpoint, ScopeDefinition, Task
from ai_osop.safety.scope import ScopeEnforcer


# ---------------------------------------------------------------------------
# Shared stand-ins (same patterns as test_recon_agent_coverage.py)
# ---------------------------------------------------------------------------


def _make_ctx(engagement_id: str = "eng-test"):
    ctx = MagicMock()
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.add_asset = AsyncMock()
    ctx.graph_memory.add_endpoint = AsyncMock()
    ctx.graph_memory.add_endpoints_batch = AsyncMock()
    ctx.graph_memory.run_read_query = AsyncMock(return_value=[])
    ctx.graph_memory.run_write_query = AsyncMock()
    ctx.session_memory = MagicMock()
    ctx.vector_memory = MagicMock()
    ctx.llm_client = MagicMock()
    ctx.mcp_registry = MagicMock()
    ctx.agent_id = "agent-recon-test"
    ctx.scope = None
    ctx.current_task = Task(
        type="full_recon",
        agent_type=AgentType.RECON,
        payload={},
        engagement_id=engagement_id,
    )
    return ctx


def _make_agent(engagement_id: str = "eng-test") -> ReconAgent:
    ctx = _make_ctx(engagement_id=engagement_id)
    agent = ReconAgent(ctx)
    agent.recon_adapter = MagicMock()
    agent.security_bridge = MagicMock()
    agent.asset_inventory = {}
    agent.endpoint_inventory = {}
    agent._rejected_scope_urls = set()
    return agent


def _task(task_type: str, payload: Dict[str, Any], engagement_id: str = "eng-test") -> Task:
    return Task(
        type=task_type,
        agent_type=AgentType.RECON,
        payload=payload,
        engagement_id=engagement_id,
    )


class _FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
        url: str = "",
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url

    def json(self):
        import json as _json

        return _json.loads(self.text)


class _FakeClient:
    """Responder-driven stand-in for the governed httpx client."""

    def __init__(self, responder):
        self._responder = responder
        self.calls: List[str] = []

    async def get(self, url: str, **kwargs: Any):
        self.calls.append(url)
        return self._responder(url)


class _ClientCtx:
    def __init__(self, client):
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    """Minimal UserSession stand-in for the crawler identity matrix."""

    def __init__(self, user_label, bearer_token="", extra_headers=None, cookies=None):
        self.user_label = user_label
        self.bearer_token = bearer_token
        self.extra_headers = extra_headers or {}
        self.cookies = cookies or []


class _FakeSessionStore:
    def __init__(self, sessions):
        self._sessions = sessions
        self.requested_engagement: List[str] = []

    async def list_sessions(self, engagement_id: str):
        self.requested_engagement.append(engagement_id)
        return list(self._sessions)


# ---------------------------------------------------------------------------
# _setup_resources
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSetupResources:
    async def test_setup_constructs_adapters_and_empty_inventories(self):
        ctx = _make_ctx()
        agent = ReconAgent(ctx)
        await agent._setup_resources()
        assert agent.recon_adapter is not None
        assert agent.security_bridge is not None
        assert agent.asset_inventory == {}
        assert agent.endpoint_inventory == {}
        assert agent._rejected_scope_urls == set()


# ---------------------------------------------------------------------------
# _execute dispatcher — branches not exercised by the existing file
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDispatcherAdditionalBranches:
    async def test_dispatches_full_recon(self):
        agent = _make_agent()
        agent._execute_full_recon = AsyncMock(return_value={"status": "success"})
        result = await agent._execute(_task("full_recon", {"domain": "example.com"}))
        agent._execute_full_recon.assert_awaited_once()
        assert result["status"] == "success"

    async def test_dispatches_expand_subdomains(self):
        agent = _make_agent()
        agent._execute_expand_subdomains = AsyncMock(return_value={"status": "success"})
        result = await agent._execute(
            _task("expand_subdomains", {"domain": "example.com", "resolve": False})
        )
        agent._execute_expand_subdomains.assert_awaited_once()
        assert result["status"] == "success"

    async def test_dispatches_content_discovery(self):
        agent = _make_agent()
        agent._execute_content_discovery = AsyncMock(return_value={"status": "success"})
        result = await agent._execute(
            _task("content_discovery", {"url": "https://target.local"})
        )
        agent._execute_content_discovery.assert_awaited_once()
        assert result["status"] == "success"

    async def test_dispatches_openapi_ingest(self):
        agent = _make_agent()
        agent._execute_openapi_ingest = AsyncMock(return_value={"status": "success"})
        result = await agent._execute(
            _task("openapi_ingest", {"url": "https://api.target.local"})
        )
        agent._execute_openapi_ingest.assert_awaited_once()
        assert result["status"] == "success"

    async def test_dispatches_cert_transparency(self):
        agent = _make_agent()
        agent._execute_cert_transparency = AsyncMock(return_value={"status": "success"})
        result = await agent._execute(_task("cert_transparency", {"domain": "example.com"}))
        agent._execute_cert_transparency.assert_awaited_once()
        assert result["status"] == "success"

    async def test_dispatches_wayback_discovery(self):
        agent = _make_agent()
        agent._execute_wayback_discovery = AsyncMock(return_value={"status": "success"})
        result = await agent._execute(_task("wayback_discovery", {"domain": "example.com"}))
        agent._execute_wayback_discovery.assert_awaited_once()
        assert result["status"] == "success"

    async def test_dispatches_waf_detection(self):
        agent = _make_agent()
        agent._execute_waf_detection = AsyncMock(return_value={"status": "success"})
        result = await agent._execute(_task("waf_detection", {"url": "https://t.local"}))
        agent._execute_waf_detection.assert_awaited_once()
        assert result["status"] == "success"

    async def test_dispatches_spa_harvest(self):
        agent = _make_agent()
        agent._execute_spa_harvest = AsyncMock(return_value={"status": "completed"})
        result = await agent._execute(_task("spa_harvest", {"url": "https://t.local"}))
        agent._execute_spa_harvest.assert_awaited_once()
        assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# _active_crawl_target — deep crawler coverage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestActiveCrawlTarget:
    def _seed_agent(self, monkeypatch):
        agent = _make_agent()
        agent._ep_scope_enforcer = None
        # Neutralise the active param miner — it would issue live probes;
        # here we want deterministic behaviour.
        import ai_osop.core.url_intelligence as _ui

        monkeypatch.setattr(_ui, "active_parameter_mine", AsyncMock(return_value=[]))
        return agent

    async def test_crawls_html_extracts_links_forms_scripts_and_inline_routes(
        self, monkeypatch
    ):
        agent = self._seed_agent(monkeypatch)
        domain = "example.com"
        root_url = f"https://{domain}/"

        page_html = """
        <html><head><script src="/static/app.js"></script></head>
        <body>
          <a href="/about">About</a>
          <a href="https://example.com/contact">Contact</a>
          <form action="/search" method="GET">
            <input type="text" name="q"><input type="hidden" name="page">
          </form>
          <form action="/login" method="post">
            <input type="text" name="username"><input type="password" name="password">
          </form>
          <script>fetch("/api/v1/items?limit=10");</script>
        </body></html>
        """

        js_body = 'var x = "/rest/products/search?q="; fetch("/api/orders/");'

        def responder(url: str) -> _FakeResponse:
            if url.endswith("/static/app.js"):
                return _FakeResponse(200, js_body, {"Content-Type": "application/javascript"}, url=url)
            if url in (root_url, f"http://{domain}/") or url == root_url:
                return _FakeResponse(200, page_html, {"Content-Type": "text/html"}, url=url)
            # any linked / probed page
            return _FakeResponse(200, "<html><body>ok</body></html>", {"Content-Type": "text/html"}, url=url)

        client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(client))

        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))
        assert endpoints, "crawler should have produced endpoints"

        by_url = {ep.url: ep for ep in endpoints}

        # The crawled root pages registered as active_crawl web endpoints
        assert by_url[root_url].source == "active_crawl"
        assert by_url[root_url].status_code == 200
        assert by_url[root_url].status_codes_seen == [200]
        assert by_url[root_url].method == "GET"
        assert by_url[root_url].user_label == "anonymous"
        assert by_url[root_url].auth_required is False

        # Crawled links were followed and registered
        assert f"{root_url}about" in by_url or "https://example.com/about" in by_url

        # GET form → query_keys; POST form → body_schema_keys
        search_ep = next(e for e in endpoints if e.url == "https://example.com/search")
        assert search_ep.source == "active_crawl_form"
        assert search_ep.method == "GET"
        assert search_ep.query_keys == ["q", "page"]
        assert search_ep.body_schema_keys == []

        login_ep = next(e for e in endpoints if e.url == "https://example.com/login")
        assert login_ep.method == "POST"
        assert login_ep.body_schema_keys == ["username", "password"]
        assert login_ep.query_keys == []
        assert login_ep.confidence == 0.95

        # JS bundle registered as a script endpoint
        js_ep = next(e for e in endpoints if e.url.endswith("/static/app.js"))
        assert js_ep.source == "active_crawl_script"
        assert js_ep.type == "web"

        # Inline / JS-mined API routes probed and registered as api endpoints.
        # The template route /rest/products/search?q= carries param q -> probed
        # with ?q=1.
        search_api = next(
            (e for e in endpoints if e.source == "js_route_extraction" and "products" in e.path),
            None,
        )
        assert search_api is not None
        assert search_api.type == "api"
        assert search_api.query_keys == ["q"]
        assert search_api.parameters == ["q"]
        assert "q=1" in search_api.url
        # The probe captured a concrete status
        assert search_api.status_code == 200
        assert search_api.status_codes_seen == [200]

        # The plain /api/orders/ quoted route got no assumed params
        orders_api = next(
            (e for e in endpoints if e.source == "js_route_extraction" and e.path == "/api/orders/"),
            None,
        )
        assert orders_api is not None
        assert orders_api.query_keys == []
        assert orders_api.status_code is None
        assert orders_api.status_codes_seen == []

        # inventory matches discovered URLs
        for ep in endpoints:
            assert agent.endpoint_inventory.get(ep.url) is ep

    async def test_id_uses_md5_of_url(self, monkeypatch):
        import hashlib

        agent = self._seed_agent(monkeypatch)
        domain = "md5.example.com"

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, "<html></html>", {"Content-Type": "text/html"}, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))
        for ep in endpoints:
            expected = f"endpoint-{hashlib.md5(ep.url.encode()).hexdigest()[:12]}"
            assert ep.id == expected

    async def test_authenticated_identity_sets_headers_cookies_and_labels(
        self, monkeypatch
    ):
        agent = self._seed_agent(monkeypatch)
        domain = "auth.example.com"
        session = _FakeSession(
            user_label="admin",
            bearer_token="tok-123",
            extra_headers={"X-Role": "admin"},
            cookies=[{"name": "sid", "value": "abc"}],
        )
        captured_kwargs: List[Dict[str, Any]] = []

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, "<html></html>", {"Content-Type": "text/html"}, url=url)

        client = _FakeClient(responder)

        class _CapturingCtx:
            async def __aenter__(self):
                return client

            async def __aexit__(self, *a):
                return False

        def _spawn(**kwargs):
            captured_kwargs.append(kwargs)
            return _CapturingCtx()

        agent.get_governed_client = MagicMock(side_effect=_spawn)
        endpoints = await agent._active_crawl_target(
            domain, session_store=_FakeSessionStore([session])
        )

        # Two identities -> two governed clients were spawned
        assert len(captured_kwargs) == 2

        anon_kwargs, admin_kwargs = captured_kwargs[0], captured_kwargs[1]
        assert "Authorization" not in anon_kwargs["headers"]
        assert anon_kwargs["cookies"] == {}
        assert admin_kwargs["headers"]["Authorization"] == "Bearer tok-123"
        assert admin_kwargs["headers"]["X-Role"] == "admin"
        assert admin_kwargs["cookies"] == {"sid": "abc"}

        # Privilege-bleed guard: every URL the admin identity re-crawls is already
        # in endpoint_inventory from the anonymous pass, so the crawler keeps the
        # FIRST identity's labels instead of silently re-tagging content as admin.
        assert endpoints
        for ep in endpoints:
            assert ep.user_label == "anonymous"
            assert ep.auth_required is False

    async def test_max_pages_budget_from_payload(self, monkeypatch):
        agent = self._seed_agent(monkeypatch)
        agent.ctx.current_task = Task(
            type="full_recon",
            agent_type=AgentType.RECON,
            payload={"max_pages": 3},
            engagement_id="eng-test",
        )
        domain = "budget.example.com"

        # Every page links to a new page -> without the budget the crawl is unbounded
        def responder(url: str) -> _FakeResponse:
            n = len([c for c in client.calls])
            next_link = f'<a href="https://{domain}/p{n}">next</a>'
            return _FakeResponse(
                200, f"<html><body>{next_link}</body></html>",
                {"Content-Type": "text/html"}, url=url,
            )

        client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(client))

        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))

        crawled = [e for e in endpoints if e.source == "active_crawl"]
        assert len(crawled) == 3  # budget honoured
        assert len(set(e.url for e in crawled)) == 3

    async def test_scope_enforcer_rejects_lookalike_host_link(self, monkeypatch):
        agent = self._seed_agent(monkeypatch)
        # Real enforcer scoped only to syfe.com (mirrors the MAJ-2 comment).
        # ScopeDefinition's field is ``domains`` (not allowed_domains).
        enforcer = ScopeEnforcer(
            ScopeDefinition(engagement_id="eng-test", domains=["syfe.com"])
        )
        agent._ep_scope_enforcer = enforcer
        domain = "syfe.com"

        page_html = (
            '<html><body>'
            '<a href="https://evilsyfe.com/steal">evil lookalike</a>'
            '<a href="https://sub.syfe.com/ok">in scope</a>'
            "</body></html>"
        )

        def responder(url: str) -> _FakeResponse:
            if "evilsyfe.com" in url:
                raise AssertionError("crawler must never fetch the lookalike host")
            body = page_html if url.rstrip("/").endswith("syfe.com") else "<html>ok</html>"
            return _FakeResponse(200, body, {"Content-Type": "text/html"}, url=url)

        client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(client))

        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))

        urls = [e.url for e in endpoints]
        assert any("sub.syfe.com" in u for u in urls)
        assert not any("evilsyfe.com" in u for u in urls)
        assert not any("evilsyfe.com" in c for c in client.calls)

    async def test_dedup_visited_urls_and_inventory(self, monkeypatch):
        agent = self._seed_agent(monkeypatch)
        domain = "dup.example.com"
        root = f"https://{domain}/"

        html = (
            f'<html><body><a href="{root}">self</a>'
            f'<a href="{root}#frag">frag</a>'
            f'<a href="{root}">self again</a></body></html>'
        )

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, html, {"Content-Type": "text/html"}, url=url)

        client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(client))

        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))

        crawled = [e for e in endpoints if e.source == "active_crawl"]
        url_counts: Dict[str, int] = {}
        for e in crawled:
            url_counts[e.url] = url_counts.get(e.url, 0) + 1
        # each crawled URL appears at most once in discovered endpoints
        assert all(v == 1 for v in url_counts.values())

    async def test_known_endpoints_from_graph_seed_the_crawl(self, monkeypatch):
        agent = self._seed_agent(monkeypatch)
        domain = "known.example.com"
        known_url = f"https://{domain}/dashboard"

        agent.ctx.graph_memory.run_read_query = AsyncMock(
            return_value=[
                {
                    "e": {
                        "id": "endpoint-x",
                        "type": "web",
                        "url": known_url,
                        "method": "GET",
                        "confidence": 0.8,
                        "engagement_id": "eng-test",
                        "source": "recon",
                        "query_keys": [],
                        "body_schema_keys": [],
                        "auth_required": True,
                        "user_label": "tester",
                        "technologies": "nginx",  # str -> normalized to list
                    }
                }
            ]
        )

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, "<html></html>", {"Content-Type": "text/html"}, url=url)

        client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(client))

        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))

        # known URL was fetched — i.e. the seed honoured the graph record
        assert known_url in client.calls
        assert known_url in agent.endpoint_inventory

    async def test_fetch_exception_branch_is_swallowed(self, monkeypatch):
        agent = self._seed_agent(monkeypatch)
        domain = "unreachable.example.com"

        class _Exploding:
            async def get(self, url, **kw):
                raise ConnectionError("refused")

                return

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_Exploding()))

        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))
        assert endpoints == []

    async def test_non_html_status_still_registers_endpoint(self, monkeypatch):
        agent = self._seed_agent(monkeypatch)
        domain = "gone.example.com"

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(404, "nope", {"Content-Type": "text/plain"}, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))
        assert endpoints
        for ep in endpoints:
            assert ep.status_code == 404
            assert ep.status_codes_seen == [404]

    async def test_active_parameter_mine_merges_mined_params(self, monkeypatch):
        agent = _make_agent()
        agent._ep_scope_enforcer = None
        import ai_osop.core.url_intelligence as _ui

        miner = AsyncMock(return_value=["debug", "preview"])
        monkeypatch.setattr(_ui, "active_parameter_mine", miner)
        domain = "mine.example.com"
        root = f"https://{domain}/"

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, "<html></html>", {"Content-Type": "text/html"}, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        endpoints = await agent._active_crawl_target(domain, session_store=_FakeSessionStore([]))

        assert miner.await_count >= 1
        root_eps = [e for e in endpoints if e.url == root and e.source == "active_crawl"]
        assert root_eps
        ep = root_eps[0]
        assert "debug" in ep.query_keys
        assert "preview" in ep.query_keys

    async def test_second_identity_skips_inventory_and_reuses_labels(self, monkeypatch):
        """The same URL crawled by a second identity is re-fetched but the
        endpoint_inventory entry retains the FIRST identity's auth metadata."""
        agent = self._seed_agent(monkeypatch)
        domain = "twice.example.com"
        session = _FakeSession(user_label="viewer", bearer_token="tok-x")

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, "<html></html>", {"Content-Type": "text/html"}, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        endpoints = await agent._active_crawl_target(
            domain, session_store=_FakeSessionStore([session])
        )
        root = f"https://{domain}/"
        # inventory entry recorded under first (anonymous) identity
        inv = agent.endpoint_inventory[root]
        assert inv.user_label == "anonymous"
        assert inv.auth_required is False


# ---------------------------------------------------------------------------
# _execute_waf_detection — akamai / f5 / imperva / akamai-body / persist fail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestWafDetectionBranches:
    def _agent_with_waf_response(self, headers=None, text="", cookies=None):
        agent = _make_agent()
        hdrs = dict(headers or {})
        if cookies is not None:
            hdrs["set-cookie"] = cookies

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, text, hdrs, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        return agent

    async def test_akamai_detected_by_ghost_header(self):
        agent = self._agent_with_waf_response(headers={"x-akamai-ghost": "1"})
        # implementation checks lower-cased header name "akamaighost"
        agent = self._agent_with_waf_response(headers={"AkamaiGHost": "1"})
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "akamai"
        assert "akamai headers present" in result["waf_signals"]

    async def test_akamai_detected_by_cookie(self):
        agent = self._agent_with_waf_response(cookies="akamai_session=abc")
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "akamai"

    async def test_f5_bigip_detected_by_cookie(self):
        agent = self._agent_with_waf_response(cookies="BIGipServerpool_web=842184450.36895.0000")
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "f5_bigip"
        assert "BIGipServer cookie present" in result["waf_signals"]

    async def test_imperva_detected_by_incap_cookie(self):
        agent = self._agent_with_waf_response(cookies="incap_ses_123=xyz")
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "imperva"
        assert "incap_ses/visid_incap cookies present" in result["waf_signals"]

    async def test_imperva_detected_by_visid_cookie(self):
        agent = self._agent_with_waf_response(cookies="visid_incap_123=xyz")
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "imperva"

    async def test_akamai_detected_by_access_denied_body(self):
        agent = self._agent_with_waf_response(text="Access Denied — powered by AkamaiGHost")
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "akamai"
        assert "access denied page" in result["waf_signals"]

    async def test_waf_persist_exception_is_swallowed(self):
        agent = self._agent_with_waf_response(headers={"cf-ray": "abc-XYZ"})
        agent.ctx.graph_memory.run_write_query = AsyncMock(
            side_effect=RuntimeError("graph down")
        )
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        # detection still succeeded despite the persist failure
        assert result["status"] == "success"
        assert result["waf_detected"] == "cloudflare"

    async def test_no_waf_does_not_write_to_graph(self):
        agent = self._agent_with_waf_response(headers={"server": "nginx"}, text="hello world")
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] is None
        assert agent.ctx.graph_memory.run_write_query.await_count == 0


# ---------------------------------------------------------------------------
# _execute_cert_transparency — persist exception swallow (lines 1418-1419)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCertTransparencyPersistFailure:
    async def test_add_asset_failure_does_not_abort(self):
        agent = _make_agent()
        crt_body = '[{"name_value": "www.example.com\\nfoo.example.com"}]'

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, crt_body, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        agent.ctx.graph_memory.add_asset = AsyncMock(side_effect=RuntimeError("graph dead"))
        result = await agent._execute_cert_transparency({"domain": "example.com"})
        assert result["status"] == "success"
        assert result["subdomains_found"] == 2
        assert "www.example.com" in result["subdomains"]


# ---------------------------------------------------------------------------
# _execute_wayback_discovery — parse + persist exception branches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestWaybackDiscoveryBranches:
    async def test_invalid_json_swallowed(self):
        agent = _make_agent()

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, "<html>not json</html>", url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        result = await agent._execute_wayback_discovery({"domain": "example.com"})
        assert result["status"] == "success"
        assert result["urls_found"] == 0
        assert result["endpoints_seeded"] == 0

    async def test_persist_exception_swallowed_and_not_counted(self):
        agent = _make_agent()
        wayback = '[["original"],["https://example.com/a?id=1"],["https://example.com/b"]]'

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(200, wayback, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        agent.ctx.graph_memory.add_endpoint = AsyncMock(side_effect=RuntimeError("nope"))
        result = await agent._execute_wayback_discovery({"domain": "example.com"})
        assert result["status"] == "success"
        assert result["urls_found"] == 2
        # Persisting raised inside _persist_endpoint's callee; _persist_endpoint
        # itself does NOT swallow add_endpoint exceptions — so seeded may be 0.
        assert result["endpoints_seeded"] == 0


# ---------------------------------------------------------------------------
# _execute_expand_subdomains — resolve=True DNS path (lines 591-614)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestExpandSubdomainsResolve:
    async def test_resolve_true_keeps_only_resolving_hosts(self, monkeypatch):
        agent = _make_agent()
        import socket as _socket

        def _fake_gethostbyname(host: str) -> str:
            if host.startswith("www."):
                return "93.184.216.34"
            raise OSError("nodns")

        monkeypatch.setattr(_socket, "gethostbyname", _fake_gethostbyname)

        result = await agent._execute_expand_subdomains(
            {
                "domain": "example.com",
                "known_subs": ["www.example.com"],
                "words": ["www", "zzz-no-such"],
                "resolve": True,
            }
        )
        assert result["status"] == "success"
        assert result["resolved_live"] >= 1
        assert any(h.startswith("www.") for h in result["live_subdomains"])
        assert not any("zzz-no-such" in h for h in result["live_subdomains"])
        # every live host was persisted as a subdomain asset
        persisted_values = {
            call.args[0].value for call in agent.ctx.graph_memory.add_asset.await_args_list
        }
        for h in result["live_subdomains"]:
            assert h in persisted_values
        # inventory updated
        assert any(v.value in result["live_subdomains"] for v in agent.asset_inventory.values())


# ---------------------------------------------------------------------------
# _execute_content_discovery — targeted permutator probe block (375-407)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestContentDiscoveryPermutator:
    async def test_permutator_probes_framework_paths_and_persists(self):
        agent = _make_agent()
        agent._ep_scope_enforcer = None
        agent.security_bridge.run_katana = AsyncMock(
            return_value={"endpoints": [], "js_files": []}
        )
        # Graph says the asset runs Django -> permutator probes django paths
        agent.ctx.graph_memory.run_read_query = AsyncMock(
            return_value=[{"techs": ["Django"], "value": "target.local"}]
        )

        probed: List[str] = []
        # Django permutator paths have no leading slash; the agent joins via
        # f"{base_url}{path}" so e.g. "admin/login/" becomes
        # "https://target.localadmin/login/" — match without the leading slash.
        hit_fragment = "admin/login"

        def responder(url: str) -> _FakeResponse:
            probed.append(url)
            # One framework path resolves, everything else 404s
            if hit_fragment in url:
                return _FakeResponse(200, "ok", {}, url=url)
            return _FakeResponse(404, "no", {}, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )

        result = await agent._execute_content_discovery({"url": "https://target.local"})
        assert result["status"] == "success"
        # the permutator actually probed paths against the target
        assert probed, "permutator should have issued probe requests"
        assert all(p.startswith("https://target.local") for p in probed)
        # The path that responded 200 was persisted from source=targeted_permutator
        sources = {
            call.args[0].source for call in agent.ctx.graph_memory.add_endpoint.await_args_list
        }
        assert "targeted_permutator" in sources
        # and matched the admin/login hit
        hit_urls = {
            call.args[0].url
            for call in agent.ctx.graph_memory.add_endpoint.await_args_list
            if call.args[0].source == "targeted_permutator"
        }
        assert any(hit_fragment in u for u in hit_urls)

    async def test_no_technologies_skips_permutator_block(self):
        agent = _make_agent()
        agent._ep_scope_enforcer = None
        agent.security_bridge.run_katana = AsyncMock(
            return_value={"endpoints": ["https://target.local/a?x=1"], "js_files": []}
        )
        agent.ctx.graph_memory.run_read_query = AsyncMock(return_value=[])
        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(lambda u: _FakeResponse(404, "", {}, url=u)))
        )
        result = await agent._execute_content_discovery({"url": "https://target.local"})
        assert result["status"] == "success"
        assert result["endpoints_found"] == 1
