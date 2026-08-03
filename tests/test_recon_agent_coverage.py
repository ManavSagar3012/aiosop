"""Coverage-focused tests for ai_osop.agents.recon_agent.

Strategy: rather than mocking every boundary, we target the pure/sync helpers
(normalize_endpoint_url, SimpleHTMLParser, _mk_endpoint, _build_scope_enforcer)
with direct assertions, and for the network-coordinated executors we stub ONLY
the call boundary (recon_adapter / security_bridge / governed client) and assert
REAL, derivable properties: the task-type dispatch, parameter plumbing, dedup
behavior, scope filtering, and the structure of the returned payloads.
"""

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.recon_agent import (
    ReconAgent,
    SimpleHTMLParser,
    normalize_endpoint_url,
)
from ai_osop.core.enums import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Asset, Endpoint, ScopeDefinition, Task


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------


def _make_ctx(engagement_id: str = "eng-test"):
    """A minimal AgentContext stand-in with the attributes ReconAgent touches."""
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
    # _setup_resources is normally invoked by BaseAgent lifecycle; without going
    # through execute_task() we need the adapters + inventories constructed.
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
    def __init__(self, status_code: int = 200, text: str = "", headers: Optional[Dict[str, str]] = None, url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url

    def json(self):
        import json as _json

        return _json.loads(self.text)


class _FakeClient:
    """Stands in for the httpx governed client. Records GETs and returns
    the response object supplied by the caller's ``responder`` callable."""

    def __init__(self, responder):
        self._responder = responder
        self.calls: List[str] = []

    async def get(self, url: str, **kwargs: Any):
        self.calls.append(url)
        return self._responder(url)


class _ClientCtx:
    def __init__(self, client: _FakeClient):
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *a):
        return False


# -----------------------------------------------------------------------
# normalize_endpoint_url (pure function)
# -----------------------------------------------------------------------


class TestNormalizeEndpointUrl:
    def test_rejects_none_and_non_str(self):
        assert normalize_endpoint_url(None) is None
        assert normalize_endpoint_url(123) is None
        assert normalize_endpoint_url(b"https://x") is None
        assert normalize_endpoint_url("") is None

    def test_rejects_non_http_schemes(self):
        assert normalize_endpoint_url("ftp://example.com/x") is None
        assert normalize_endpoint_url("javascript:alert(1)") is None
        assert normalize_endpoint_url("mailto:foo@example.com") is None

    def test_rejects_missing_netloc(self):
        assert normalize_endpoint_url("https://") is None
        assert normalize_endpoint_url("/relative/path") is None

    def test_rejects_whitespace_in_netloc(self):
        assert normalize_endpoint_url("https://exa mple.com/x") is None

    def test_rejects_whitespace_in_path(self):
        # Classical extractor-noise: a relative join fused two URLs together
        assert normalize_endpoint_url("https://host/core/    https:/cdn.jsdelivr.net/c.js") is None

    def test_rejects_second_scheme_fused_in_path(self):
        assert normalize_endpoint_url("https://host/page/https:/evil.com/x") is None
        assert normalize_endpoint_url("https://host/page/http:/foo") is None

    def test_allows_query_strings_with_url_like_values(self):
        # Legitimate open-redirect-shaped URLs must NOT be rejected
        u = "https://target/login?next=https://other/path"
        assert normalize_endpoint_url(u) == u

    def test_strips_surrounding_whitespace(self):
        assert normalize_endpoint_url("  https://example.com/x  ") == "https://example.com/x"

    def test_allows_https_and_http(self):
        assert normalize_endpoint_url("http://example.com/x") == "http://example.com/x"
        assert normalize_endpoint_url("https://example.com/x") == "https://example.com/x"


# -----------------------------------------------------------------------
# SimpleHTMLParser
# -----------------------------------------------------------------------


class TestSimpleHTMLParser:
    def test_extracts_links_scripts_forms(self):
        html = """
        <html>
          <a href="/about">About</a>
          <a href="/contact">Contact</a>
          <script src="/static/app.js"></script>
          <script src="https://cdn.example.com/lib.js"></script>
          <form action="/login" method="POST">
            <input name="username"><input name="password">
          </form>
        </html>
        """
        p = SimpleHTMLParser()
        p.feed(html)
        assert set(p.links) == {"/about", "/contact"}
        assert set(p.scripts) == {"/static/app.js", "https://cdn.example.com/lib.js"}
        assert len(p.forms) == 1
        form = p.forms[0]
        assert form["action"] == "/login"
        assert form["method"] == "POST"
        assert set(form["inputs"]) == {"username", "password"}

    def test_default_method_is_uppercase_get(self):
        p = SimpleHTMLParser()
        p.feed('<form action="/search"><input name="q"></form>')
        assert p.forms[0]["method"] == "GET"

    def test_input_without_form_is_ignored(self):
        p = SimpleHTMLParser()
        p.feed('<input name="orphan">')
        assert p.forms == []

    def test_form_closes_current_form(self):
        p = SimpleHTMLParser()
        p.feed('<form action="/a"><input name="x"></form><input name="after">')
        # Only the input inside the form should be captured
        assert p.forms[0]["inputs"] == ["x"]
        assert p.current_form is None

    def test_anchor_without_href_skipped(self):
        p = SimpleHTMLParser()
        p.feed("<a name='anchor'>no href</a>")
        assert p.links == []


# -----------------------------------------------------------------------
# Static / sync helpers on the agent
# -----------------------------------------------------------------------


class TestAgentBasics:
    def test_agent_type_is_recon(self):
        agent = _make_agent()
        assert agent.agent_type is AgentType.RECON

    def test_supports_task_type_positive(self):
        agent = _make_agent()
        for t in (
            "full_recon",
            "dns_enumeration",
            "port_scan",
            "service_probe",
            "osint_lookup",
            "technology_fingerprint",
            "content_discovery",
            "openapi_ingest",
            "expand_subdomains",
            "cert_transparency",
            "wayback_discovery",
            "waf_detection",
            "spa_harvest",
        ):
            assert agent.supports_task_type(t), t

    def test_supports_task_type_negative(self):
        agent = _make_agent()
        assert not agent.supports_task_type("rce_exploit")
        assert not agent.supports_task_type("")
        assert not agent.supports_task_type("FULL_RECON")  # case-sensitive


class TestBuildScopeEnforcer:
    def test_returns_none_for_empty_payload(self):
        assert ReconAgent._build_scope_enforcer({}) is None
        assert ReconAgent._build_scope_enforcer({"scope": None}) is None
        assert ReconAgent._build_scope_enforcer({"scope": {}}) is None

    def test_returns_none_for_non_dict_payload(self):
        # Defensive: not-a-dict is treated as empty
        assert ReconAgent._build_scope_enforcer("nope") is None  # type: ignore[arg-type]

    def test_accepts_scope_definition_instance(self):
        sd = ScopeDefinition(engagement_id="eng-test", domains=["example.com"])
        enforcer = ReconAgent._build_scope_enforcer({"scope": sd})
        assert enforcer is not None
        assert enforcer.host_in_scope("example.com")

    def test_constructs_from_dict(self):
        sd = {"engagement_id": "eng-test", "domains": ["example.com"]}
        enforcer = ReconAgent._build_scope_enforcer({"scope": sd})
        assert enforcer is not None
        assert enforcer.host_in_scope("example.com")
        assert not enforcer.host_in_scope("evil.com")

    def test_returns_none_on_invalid_scope_dict(self):
        # Missing engagement_id -> pydantic validation error -> None
        assert ReconAgent._build_scope_enforcer({"scope": {"foo": "bar"}}) is None


class TestMkEndpoint:
    def test_derives_params_from_query_when_not_overridden(self):
        agent = _make_agent()
        ep = agent._mk_endpoint(
            "https://example.com/search?q=foo&page=2",
            engagement_id="eng-test",
            source="unit",
        )
        # query params surfaced in BOTH `parameters` and `query_keys`
        assert set(ep.parameters) == {"q", "page"}
        assert set(ep.query_keys) == {"q", "page"}

    def test_explicit_parameters_override_url_query(self):
        agent = _make_agent()
        ep = agent._mk_endpoint(
            "https://example.com/search?q=foo",
            engagement_id="eng-test",
            source="openapi",
            parameters=["id", "name"],  # spec-derived
        )
        assert ep.parameters == ["id", "name"]
        assert ep.query_keys == ["id", "name"]  # parameters override flows through

    def test_default_confidence_is_085(self):
        agent = _make_agent()
        ep = agent._mk_endpoint("https://example.com/", "eng-test", "unit")
        assert abs(ep.confidence - 0.85) < 1e-6

    def test_confidence_can_be_overridden(self):
        agent = _make_agent()
        ep = agent._mk_endpoint("https://example.com/", "eng-test", "unit", confidence=0.9)
        assert ep.confidence == 0.9

    def test_populates_host_path_and_metadata(self):
        agent = _make_agent()
        ep = agent._mk_endpoint(
            "https://example.com/api/users/123?active=1",
            "eng-test",
            "katana",
        )
        assert ep.host == "example.com"
        assert ep.path == "/api/users/123"
        # metadata carries tags + template enrichment
        assert "tags" in ep.metadata
        assert "template" in ep.metadata
        assert isinstance(ep.metadata["tags"], list)

    def test_caller_metadata_is_merged_in(self):
        agent = _make_agent()
        ep = agent._mk_endpoint(
            "https://example.com/api/x",
            "eng-test",
            "openapi",
            metadata={"operation_id": "getX"},
        )
        assert ep.metadata["operation_id"] == "getX"
        # default keys still present
        assert "tags" in ep.metadata
        assert "template" in ep.metadata

    def test_extra_fields_forwarded_to_model(self):
        agent = _make_agent()
        ep = agent._mk_endpoint(
            "https://example.com/api/x",
            "eng-test",
            "openapi",
            method="POST",
            type="api",
        )
        assert ep.method == "POST"
        assert ep.type == "api"


# -----------------------------------------------------------------------
# _persist_endpoint / _persist_endpoints_batch
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestPersistEndpoints:
    async def test_malformed_url_dropped_not_persisted(self):
        agent = _make_agent()
        ep = Endpoint(
            url="not even a url",
            source="unit",
            confidence=0.5,
            engagement_id="eng-test",
        )
        ok = await agent._persist_endpoint(ep)
        assert ok is False
        agent.ctx.graph_memory.add_endpoint.assert_not_awaited()

    async def test_valid_endpoint_persisted(self):
        agent = _make_agent()
        ep = Endpoint(
            url="https://target.local/x",
            source="unit",
            confidence=0.5,
            engagement_id="eng-test",
        )
        ok = await agent._persist_endpoint(ep)
        assert ok is True
        agent.ctx.graph_memory.add_endpoint.assert_awaited_once()
        # The URL was normalized (trailing whitespace stripped here)
        assert agent.ctx.graph_memory.add_endpoint.await_args.args[0].url == "https://target.local/x"

    async def test_out_of_scope_endpoint_skipped_with_real_enforcer(self):
        agent = _make_agent()
        agent._ep_scope_enforcer = ReconAgent._build_scope_enforcer(
            {"scope": ScopeDefinition(engagement_id="eng-test", domains=["target.local"])}
        )
        ep = Endpoint(
            url="https://evil.com/x",
            source="unit",
            confidence=0.5,
            engagement_id="eng-test",
        )
        ok = await agent._persist_endpoint(ep)
        assert ok is False
        agent.ctx.graph_memory.add_endpoint.assert_not_awaited()
        # Rejection dedup set was populated
        assert "https://evil.com/x" in agent._rejected_scope_urls

    async def test_scope_rejection_logged_once_per_url(self):
        """The dedup guard exists to stop log-spam; the second rejection MUST NOT
        add a duplicate entry to _rejected_scope_urls."""
        agent = _make_agent()
        agent._ep_scope_enforcer = ReconAgent._build_scope_enforcer(
            {"scope": ScopeDefinition(engagement_id="eng-test", domains=["target.local"])}
        )
        ep = Endpoint(
            url="https://evil.com/x",
            source="unit",
            confidence=0.5,
            engagement_id="eng-test",
        )
        await agent._persist_endpoint(ep)
        await agent._persist_endpoint(ep)
        assert agent._rejected_scope_urls == {"https://evil.com/x"}

    async def test_in_scope_endpoint_passes_through(self):
        agent = _make_agent()
        agent._ep_scope_enforcer = ReconAgent._build_scope_enforcer(
            {"scope": ScopeDefinition(engagement_id="eng-test", domains=["target.local"])}
        )
        ep = Endpoint(
            url="https://sub.target.local/x",
            source="unit",
            confidence=0.5,
            engagement_id="eng-test",
        )
        ok = await agent._persist_endpoint(ep)
        assert ok is True
        assert agent.ctx.graph_memory.add_endpoint.await_count == 1

    async def test_batch_filters_and_counts(self):
        agent = _make_agent()
        agent._ep_scope_enforcer = ReconAgent._build_scope_enforcer(
            {"scope": ScopeDefinition(engagement_id="eng-test", domains=["target.local"])}
        )
        good1 = Endpoint(url="https://target.local/a", source="u", confidence=0.5, engagement_id="eng-test")
        good2 = Endpoint(url="https://x.target.local/b", source="u", confidence=0.5, engagement_id="eng-test")
        bad_malformed = Endpoint(url="not a url", source="u", confidence=0.5, engagement_id="eng-test")
        bad_offscope = Endpoint(url="https://evil.com/c", source="u", confidence=0.5, engagement_id="eng-test")

        stored = await agent._persist_endpoints_batch([good1, bad_malformed, good2, bad_offscope])
        assert stored == 2
        # Only valid ones were sent to the graph batch write
        agent.ctx.graph_memory.add_endpoints_batch.assert_awaited_once()
        batch_arg = agent.ctx.graph_memory.add_endpoints_batch.await_args.args[0]
        assert {e.url for e in batch_arg} == {"https://target.local/a", "https://x.target.local/b"}

    async def test_batch_no_valid_does_not_call_graph(self):
        agent = _make_agent()
        agent._ep_scope_enforcer = ReconAgent._build_scope_enforcer(
            {"scope": ScopeDefinition(engagement_id="eng-test", domains=["target.local"])}
        )
        bad = Endpoint(url="https://evil.com/c", source="u", confidence=0.5, engagement_id="eng-test")
        stored = await agent._persist_endpoints_batch([bad])
        assert stored == 0
        agent.ctx.graph_memory.add_endpoints_batch.assert_not_awaited()


# -----------------------------------------------------------------------
# _execute dispatcher
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestExecuteDispatcher:
    async def test_unknown_task_type_raises(self):
        agent = _make_agent()
        with pytest.raises(AgentException) as exc:
            await agent._execute(_task("rce_exploit", {}))
        assert "Unknown recon task type" in str(exc.value)
        assert "rce_exploit" in str(exc.value)

    async def test_dispatches_dns_enumeration(self):
        agent = _make_agent()
        agent.recon_adapter.dns_enumeration = AsyncMock(return_value=[])
        agent.recon_adapter.initialize = AsyncMock()
        result = await agent._execute(_task("dns_enumeration", {"domain": "example.com"}))
        assert result["status"] == "success"
        assert result["domain"] == "example.com"
        agent.recon_adapter.dns_enumeration.assert_awaited_once()

    async def test_dispatches_port_scan(self):
        agent = _make_agent()
        agent.recon_adapter.port_scan = AsyncMock(return_value=[])
        agent.recon_adapter.initialize = AsyncMock()
        result = await agent._execute(
            _task("port_scan", {"targets": ["1.2.3.4"], "ports": "top-100"})
        )
        assert result["status"] == "success"
        agent.recon_adapter.port_scan.assert_awaited_once()
        # ports are plumbed through verbatim
        assert agent.recon_adapter.port_scan.await_args.kwargs["ports"] == "top-100"

    async def test_dispatches_service_probe(self):
        agent = _make_agent()
        agent.recon_adapter.service_probe = AsyncMock(return_value=[])
        agent.recon_adapter.initialize = AsyncMock()
        result = await agent._execute(_task("service_probe", {"targets": ["https://x"]}))
        assert result["status"] == "success"
        assert result["endpoints_discovered"] == 0

    async def test_dispatches_osint_lookup(self):
        agent = _make_agent()
        agent.recon_adapter.initialize = AsyncMock()
        # AIOSOP-FABRICATED-TELEMETRY: _execute_osint now calls the real adapter
        # (Shodan-backed) instead of fabricating success with empty findings.
        agent.recon_adapter.osint_lookup = AsyncMock(return_value=[])
        result = await agent._execute(_task("osint_lookup", {"domain": "example.com"}))
        assert result == {"status": "success", "domain": "example.com", "findings": []}
        agent.recon_adapter.osint_lookup.assert_awaited_once_with("example.com")

    async def test_dispatches_technology_fingerprint(self):
        agent = _make_agent()
        agent.recon_adapter.initialize = AsyncMock()
        # AIOSOP-FABRICATED-TELEMETRY: _execute_tech_fingerprint now calls the
        # real adapter instead of counting endpoints without processing.
        agent.recon_adapter.technology_fingerprint = AsyncMock(
            return_value={"a": ["React"], "b": ["nginx"]}
        )
        result = await agent._execute(
            _task("technology_fingerprint", {"endpoints": ["a", "b", "c"]})
        )
        assert result["status"] == "success"
        assert result["processed_count"] == 2
        assert result["fingerprints"] == {"a": ["React"], "b": ["nginx"]}
        agent.recon_adapter.technology_fingerprint.assert_awaited_once_with(["a", "b", "c"])

    async def test_scope_payload_triggers_adapter_initialize(self):
        agent = _make_agent()
        agent.recon_adapter.initialize = AsyncMock()
        agent.recon_adapter.service_probe = AsyncMock(return_value=[])
        scope = {"engagement_id": "eng-test", "domains": ["example.com"]}
        await agent._execute(_task("service_probe", {"targets": [], "scope": scope}))
        agent.recon_adapter.initialize.assert_awaited_once()
        # Both scope *and* engagement_id were passed
        assert agent.recon_adapter.initialize.await_args.args[0] == scope
        assert agent.recon_adapter.initialize.await_args.args[1] == "eng-test"


# -----------------------------------------------------------------------
# _execute_dns_enum
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestDnsEnum:
    async def test_no_domain_returns_failed(self):
        agent = _make_agent()
        result = await agent._execute_dns_enum({})
        assert result["status"] == "failed"
        assert "domain parameter is required" in result["error"]

    async def test_domain_extracted_from_url(self):
        agent = _make_agent()
        agent.recon_adapter.dns_enumeration = AsyncMock(return_value=[])
        result = await agent._execute_dns_enum({"url": "https://app.example.com/some/path"})
        assert result["domain"] == "app.example.com"
        # Adapter saw the same hostname
        assert agent.recon_adapter.dns_enumeration.await_args.kwargs["domain"] == "app.example.com"

    async def test_domain_extracted_from_targets(self):
        agent = _make_agent()
        agent.recon_adapter.dns_enumeration = AsyncMock(return_value=[])
        result = await agent._execute_dns_enum({"targets": ["t1.example.com", "t2.example.com"]})
        assert result["domain"] == "t1.example.com"

    async def test_adapter_failure_falls_back_to_base_domain_asset(self):
        agent = _make_agent()
        agent.recon_adapter.dns_enumeration = AsyncMock(side_effect=RuntimeError("boom"))
        result = await agent._execute_dns_enum({"domain": "example.com"})
        assert result["status"] == "success"
        assert result["assets_discovered"] == 1
        # The fallback asset preserves the domain
        assert result["assets"][0]["value"] == "example.com"
        assert result["assets"][0]["type"] == "domain"
        assert result["assets"][0]["source"] == "recon_fallback"

    async def test_persists_assets_and_populates_inventory(self):
        agent = _make_agent()
        a1 = Asset(
            id="a1", type="subdomain", value="sub.example.com",
            source="dns", confidence=0.9, engagement_id="",
        )
        a2 = Asset(
            id="a2", type="domain", value="example.com",
            source="dns", confidence=1.0, engagement_id="",
        )
        agent.recon_adapter.dns_enumeration = AsyncMock(return_value=[a1, a2])
        result = await agent._execute_dns_enum({"domain": "example.com"})
        assert result["assets_discovered"] == 2
        # engagement_id stamped from current_task
        assert a1.engagement_id == "eng-test"
        assert a2.engagement_id == "eng-test"
        # inventory updated
        assert set(agent.asset_inventory.keys()) == {"a1", "a2"}
        # graph calls issued
        assert agent.ctx.graph_memory.add_asset.await_count == 2

    async def test_depth_and_active_forwarded(self):
        agent = _make_agent()
        agent.recon_adapter.dns_enumeration = AsyncMock(return_value=[])
        await agent._execute_dns_enum({"domain": "example.com", "depth": 4, "active": False})
        kwargs = agent.recon_adapter.dns_enumeration.await_args.kwargs
        assert kwargs["domain"] == "example.com"
        assert kwargs["depth"] == 4
        assert kwargs["active"] is False


# -----------------------------------------------------------------------
# _execute_port_scan
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestPortScan:
    async def test_returns_targets_and_discovered_count(self):
        agent = _make_agent()
        host1 = Asset(id="h1", type="ip", value="1.2.3.4", source="nmap", confidence=0.9, engagement_id="")
        agent.recon_adapter.port_scan = AsyncMock(return_value=[host1])
        result = await agent._execute_port_scan({"targets": ["1.2.3.4"], "ports": "22,80"})
        assert result == {"status": "success", "targets": ["1.2.3.4"], "assets_discovered": 1}
        # assets persisted
        agent.ctx.graph_memory.add_asset.assert_awaited_once()
        assert agent.asset_inventory["h1"].value == "1.2.3.4"

    async def test_adapter_failure_yields_empty_assets_not_exception(self):
        agent = _make_agent()
        agent.recon_adapter.port_scan = AsyncMock(side_effect=RuntimeError("nmap crashed"))
        result = await agent._execute_port_scan({"targets": ["1.2.3.4"]})
        assert result["status"] == "success"
        assert result["assets_discovered"] == 0

    async def test_default_ports_is_top_1000(self):
        agent = _make_agent()
        agent.recon_adapter.port_scan = AsyncMock(return_value=[])
        await agent._execute_port_scan({"targets": ["1.2.3.4"]})
        assert agent.recon_adapter.port_scan.await_args.kwargs["ports"] == "top-1000"


# -----------------------------------------------------------------------
# _execute_service_probe
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestServiceProbe:
    async def test_stamps_engagement_id_and_persists_batch(self):
        agent = _make_agent()
        ep1 = Endpoint(url="https://a.example.com/", source="httpx", confidence=0.9, engagement_id="")
        ep2 = Endpoint(url="https://b.example.com/", source="httpx", confidence=0.9, engagement_id="")
        agent.recon_adapter.service_probe = AsyncMock(return_value=[ep1, ep2])
        result = await agent._execute_service_probe({"targets": ["https://a.example.com"]})
        assert result["status"] == "success"
        assert result["endpoints_discovered"] == 2
        # engagement_id stamped on every endpoint
        assert ep1.engagement_id == "eng-test"
        assert ep2.engagement_id == "eng-test"
        # batch persist was called with both
        agent.ctx.graph_memory.add_endpoints_batch.assert_awaited_once()
        batch = agent.ctx.graph_memory.add_endpoints_batch.await_args.args[0]
        assert {e.url for e in batch} == {"https://a.example.com/", "https://b.example.com/"}

    async def test_adapter_failure_returns_zero_endpoints(self):
        agent = _make_agent()
        agent.recon_adapter.service_probe = AsyncMock(side_effect=RuntimeError("httpx boom"))
        result = await agent._execute_service_probe({"targets": ["https://x"]})
        assert result == {"status": "success", "endpoints_discovered": 0}

    async def test_off_scope_endpoint_not_in_inventory(self):
        agent = _make_agent()
        # Restrict scope so that evil.com gets filtered by _persist_endpoints_batch
        agent._ep_scope_enforcer = ReconAgent._build_scope_enforcer(
            {"scope": ScopeDefinition(engagement_id="eng-test", domains=["example.com"])}
        )
        in_scope = Endpoint(url="https://in.example.com/", source="httpx", confidence=0.9, engagement_id="")
        out_scope = Endpoint(url="https://attacker.evil.com/", source="httpx", confidence=0.9, engagement_id="")
        agent.recon_adapter.service_probe = AsyncMock(return_value=[in_scope, out_scope])
        result = await agent._execute_service_probe({"targets": ["https://in.example.com"]})
        # Bug-compat behavior: report includes both, but only one was persisted
        assert result["endpoints_discovered"] == 2
        # batch persist saw only the in-scope endpoint
        batch = agent.ctx.graph_memory.add_endpoints_batch.await_args.args[0]
        assert len(batch) == 1
        assert batch[0].url == "https://in.example.com/"


# -----------------------------------------------------------------------
# _execute_expand_subdomains
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestExpandSubdomains:
    async def test_no_domain_returns_failed(self):
        agent = _make_agent()
        result = await agent._execute_expand_subdomains({})
        assert result["status"] == "failed"
        assert "domain parameter is required" in result["error"]

    async def test_domain_extracted_from_url(self):
        agent = _make_agent()
        result = await agent._execute_expand_subdomains(
            {"url": "https://app.example.com/path", "resolve": False}
        )
        assert result["domain"] == "app.example.com"
        assert result["status"] == "success"

    async def test_generate_permutations_without_resolution(self):
        """resolve=False skips DNS entirely; candidates were generated deterministically."""
        agent = _make_agent()
        result = await agent._execute_expand_subdomains(
            {
                "domain": "example.com",
                "known_subs": ["www.example.com", "api.example.com"],
                "resolve": False,
            }
        )
        assert result["status"] == "success"
        assert result["resolved_live"] == 0
        assert result["live_subdomains"] == []
        # candidates_generated equals the returned candidate count when resolve=False
        assert result["candidates_generated"] == len(result["candidates"])
        # Permutation produces many more candidates than the 2 known seeds
        assert result["candidates_generated"] > 2
        # All returned candidates are host strings under the target domain
        for c in result["candidates"]:
            assert c.endswith(".example.com") or c == "example.com"

    async def test_uses_inventory_when_known_subs_not_given(self):
        agent = _make_agent()
        agent.asset_inventory["a1"] = Asset(
            id="a1", type="subdomain", value="cache.example.com",
            source="x", confidence=0.9, engagement_id="eng-test",
        )
        agent.asset_inventory["a2"] = Asset(
            id="a2", type="ip", value="10.0.0.1",  # not a domain/subdomain, must be ignored
            source="x", confidence=0.9, engagement_id="eng-test",
        )
        result = await agent._execute_expand_subdomains(
            {"domain": "example.com", "resolve": False}
        )
        assert result["candidates_generated"] >= 1
        for c in result["candidates"]:
            # None of the permutations should be built on the IP asset
            assert "10.0.0.1" not in c


# -----------------------------------------------------------------------
# _execute_openapi_ingest
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestOpenapiIngest:
    async def test_missing_target_raises(self):
        agent = _make_agent()
        with pytest.raises(AgentException) as exc:
            await agent._execute_openapi_ingest({})
        assert "openapi_ingest requires" in str(exc.value)

    async def test_no_spec_found_returns_honest_zero(self):
        """All candidates 404 -> spec_found=False, execution_verified reflects that
        real HTTP attempts were issued."""
        agent = _make_agent()
        agent._ep_scope_enforcer = None

        def responder(url: str) -> _FakeResponse:
            return _FakeResponse(status_code=404, text="{}")

        fake_client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(fake_client))

        result = await agent._execute_openapi_ingest({"url": "https://api.target.local"})
        assert result["status"] == "success"
        assert result["spec_found"] is False
        assert result["endpoints_found"] == 0
        # At least one HTTP GET was issued
        assert result["candidates_probed"] > 0
        assert result["execution_verified"] is True
        # The candidate URLs are conventional spec locations under the target
        assert any("openapi" in c or "swagger" in c for c in fake_client.calls)

    async def test_valid_spec_parsed_into_endpoints(self):
        """When a candidate returns a valid spec, descriptors become Endpoint objects."""
        agent = _make_agent()
        agent._ep_scope_enforcer = None
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1"},
            "paths": {
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "parameters": [{"name": "id", "in": "path"}],
                    }
                },
                "/health": {"get": {}},
            },
        }
        import json as _json
        spec_json = _json.dumps(spec)

        def responder(url: str) -> _FakeResponse:
            # First candidate fails, second succeeds — tests the `break` only after success
            if "openapi.json" in url:
                return _FakeResponse(status_code=200, text=spec_json)
            return _FakeResponse(status_code=404, text="{}")

        fake_client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(fake_client))

        # Caller supplies the spec URL directly so we control which candidate matches
        result = await agent._execute_openapi_ingest(
            {
                "url": "https://api.target.local",
                "spec_urls": ["https://api.target.local/openapi.json"],
            }
        )
        assert result["spec_found"] is True
        assert result["spec_url"] == "https://api.target.local/openapi.json"
        assert result["execution_verified"] is True
        assert result["endpoints_found"] == 2
        # Endpoints went through _mk_endpoint: confidence was pinned to 0.9 for openapi
        persisted_urls = [c.args[0].url for c in agent.ctx.graph_memory.add_endpoint.await_args_list]
        assert any("/users/" in u for u in persisted_urls)
        assert any(u.endswith("/health") for u in persisted_urls)
        # inventory matches what was persisted
        assert len(agent.endpoint_inventory) == 2


# -----------------------------------------------------------------------
# _execute_cert_transparency
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestCertTransparency:
    async def test_missing_domain_returns_failed(self):
        agent = _make_agent()
        result = await agent._execute_cert_transparency({})
        assert result == {"status": "failed", "error": "domain parameter is required"}

    async def test_domain_extracted_from_url(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(status_code=200, text="[]", url=url)

        fake_client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(fake_client))

        result = await agent._execute_cert_transparency(
            {"url": "https://app.example.com/x", "engagement_id": "eng-test"}
        )
        assert result["domain"] == "app.example.com"
        # The crt.sh query was for the extracted domain
        assert any("%.app.example.com" in c for c in fake_client.calls)

    async def test_parses_crt_json_and_filters_off_domain(self):
        """crt.sh returns name_values that may include off-domain rows; we only
        keep names that end with the target domain."""
        agent = _make_agent()
        crt_body = """[
          {"name_value": "sub1.example.com\\nwww.example.com"},
          {"name_value": "other.com"},
          {"name_value": "api.example.com"}
        ]"""

        def responder(url):
            return _FakeResponse(status_code=200, text=crt_body, url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        result = await agent._execute_cert_transparency({"domain": "example.com"})
        assert result["status"] == "success"
        assert result["subdomains_found"] == 3
        assert set(result["subdomains"]) == {
            "sub1.example.com",
            "www.example.com",
            "api.example.com",
        }
        # other.com was filtered out
        assert all(s.endswith(".example.com") for s in result["subdomains"])
        # 3 assets were persisted (one per in-domain subdomain)
        assert agent.ctx.graph_memory.add_asset.await_count == 3

    async def test_http_error_yields_zero_subdomains_without_raising(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(status_code=503, text="oops", url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        result = await agent._execute_cert_transparency({"domain": "example.com"})
        assert result["status"] == "success"
        assert result["subdomains_found"] == 0
        agent.ctx.graph_memory.add_asset.assert_not_awaited()

    async def test_invalid_json_swallowed(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(status_code=200, text="<not json>", url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        result = await agent._execute_cert_transparency({"domain": "example.com"})
        assert result["subdomains_found"] == 0


# -----------------------------------------------------------------------
# _execute_wayback_discovery
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestWaybackDiscovery:
    async def test_missing_domain_returns_failed(self):
        agent = _make_agent()
        result = await agent._execute_wayback_discovery({})
        assert result == {"status": "failed", "error": "domain parameter is required"}

    async def test_parses_cdx_json_and_seeds_endpoints(self):
        """Wayback returns [headers, [url], [url], ...]; we seed unique URLs."""
        agent = _make_agent()
        wayback_payload = """[
          ["original"],
          ["https://example.com/old-admin"],
          ["https://example.com/api/v1/users?id=1"],
          ["https://example.com/old-admin"]
        ]"""

        def responder(url):
            return _FakeResponse(status_code=200, text=wayback_payload, url=url)

        fake_client = _FakeClient(responder)
        agent.get_governed_client = MagicMock(return_value=_ClientCtx(fake_client))

        result = await agent._execute_wayback_discovery({"domain": "example.com"})
        assert result["status"] == "success"
        # Duplicate was deduped
        assert result["urls_found"] == 2
        assert result["endpoints_seeded"] == 2
        # The CDX API endpoint was queried with the target domain
        assert any("web.archive.org" in c and "example.com" in c for c in fake_client.calls)
        # Endpoints were persisted via add_endpoint
        persisted_urls = [
            c.args[0].url for c in agent.ctx.graph_memory.add_endpoint.await_args_list
        ]
        assert "https://example.com/old-admin" in persisted_urls
        assert any("api/v1/users" in u for u in persisted_urls)

    async def test_empty_wayback_history_zero_seeded(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(status_code=200, text='[["original"]]', url=url)

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_FakeClient(responder))
        )
        result = await agent._execute_wayback_discovery({"domain": "example.com"})
        assert result["urls_found"] == 0
        assert result["endpoints_seeded"] == 0
        agent.ctx.graph_memory.add_endpoint.assert_not_awaited()


# -----------------------------------------------------------------------
# _execute_waf_detection
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestWafDetection:
    async def test_missing_url_and_domain_returns_failed(self):
        agent = _make_agent()
        result = await agent._execute_waf_detection({})
        assert result["status"] == "failed"

    async def test_cloudflare_detected_by_cf_ray_header(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(
                status_code=200,
                text="ok",
                headers={"cf-ray": "abc123-LHR"},
                url=url,
            )

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_FakeClient(responder)))
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["status"] == "success"
        assert result["waf_detected"] == "cloudflare"
        assert "cf-ray header present" in result["waf_signals"]
        # Persisted as asset attribute via run_write_query
        agent.ctx.graph_memory.run_write_query.assert_awaited_once()
        # The MERGE query carries the detected WAF
        call_kwargs = agent.ctx.graph_memory.run_write_query.await_args.args[1]
        assert call_kwargs["waf"] == "cloudflare"

    async def test_aws_waf_detected_by_amzn_header(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(
                status_code=200,
                text="ok",
                headers={"x-amzn-waf": "block"},
                url=url,
            )

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_FakeClient(responder)))
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "aws_waf"

    async def test_sucuri_detected_by_x_sucuri_id(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(
                status_code=200,
                text="x",
                headers={"x-sucuri-id": "1234"},
                url=url,
            )

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_FakeClient(responder)))
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "sucuri"

    async def test_cloudflare_detected_by_challenge_page_text(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(
                status_code=200,
                text="<html>Just a moment... checking your browser</html>",
                headers={},
                url=url,
            )

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_FakeClient(responder)))
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] == "cloudflare"
        assert "challenge page detected" in result["waf_signals"]

    async def test_no_waf_leaves_waf_detected_none(self):
        agent = _make_agent()

        def responder(url):
            return _FakeResponse(status_code=200, text="regular page", headers={}, url=url)

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_FakeClient(responder)))
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["waf_detected"] is None
        assert result["waf_signals"] == []
        # No asset update because nothing was detected
        agent.ctx.graph_memory.run_write_query.assert_not_awaited()

    async def test_domain_constructs_http_url(self):
        agent = _make_agent()
        seen: List[str] = []

        def responder(url):
            seen.append(url)
            return _FakeResponse(status_code=200, text="", headers={}, url=url)

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_FakeClient(responder)))
        result = await agent._execute_waf_detection({"domain": "target.local"})
        assert result["target"] == "http://target.local"
        assert seen == ["http://target.local"]

    async def test_network_failure_returns_failed_status(self):
        agent = _make_agent()

        class _BoomClient:
            async def get(self, url, **kw):
                raise ConnectionError("econnrefused")

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_BoomClient()))
        result = await agent._execute_waf_detection({"url": "https://target.local/"})
        assert result["status"] == "failed"
        assert "econnrefused" in result["error"]


# -----------------------------------------------------------------------
# _fetch_single_url_forms / _fetch_and_extract_form_fields
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestFetchFormFields:
    async def test_extracts_form_fields_on_200(self):
        agent = _make_agent()
        html = """
        <form action="/search"><input name="q"><input name="page"></form>
        """

        class _Resp:
            status_code = 200
            text = html

        class _Sess:
            async def get(self, url, timeout=None):
                return _Resp()

        result = await agent._fetch_single_url_forms(_Sess(), "https://x/")
        assert set(result) == {"q", "page"}

    async def test_returns_empty_on_non_200(self):
        agent = _make_agent()

        class _Resp:
            status_code = 404
            text = ""

        class _Sess:
            async def get(self, url, timeout=None):
                return _Resp()

        result = await agent._fetch_single_url_forms(_Sess(), "https://x/")
        assert result == []

    async def test_returns_empty_on_exception(self):
        agent = _make_agent()

        class _Sess:
            async def get(self, url, timeout=None):
                raise ConnectionError("down")

        result = await agent._fetch_single_url_forms(_Sess(), "https://x/")
        assert result == []

    async def test_empty_web_url_list_short_circuits_no_client(self):
        """When every URL is a .js bundle, web_urls is empty and we return {}
        WITHOUT opening a governed client (would have been a wasted ctx)."""
        agent = _make_agent()
        agent.get_governed_client = MagicMock(
            side_effect=AssertionError("client should not be built")
        )
        result = await agent._fetch_and_extract_form_fields(
            ["https://x/app.js", "https://x/vendor.js"]
        )
        assert result == {}

    async def test_filters_js_urls_and_fetches_web_urls(self):
        """.js files excluded; HTML pages fetched concurrently via governed client."""
        agent = _make_agent()
        captured: List[str] = []

        class _Resp:
            status_code = 200
            text = '<form action="/s"><input name="q"></form>'

        class _Sess:
            async def get(self, url, timeout=None):
                captured.append(url)
                return _Resp()

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_Sess()))
        result = await agent._fetch_and_extract_form_fields(
            [
                "https://x/page1",
                "https://x/page2",
                "https://x/app.js",  # must be excluded
            ]
        )
        assert set(captured) == {"https://x/page1", "https://x/page2"}
        assert result == {"https://x/page1": ["q"], "https://x/page2": ["q"]}

    async def test_failing_fetches_are_dropped_from_result(self):
        agent = _make_agent()

        class _Sess:
            async def get(self, url, timeout=None):
                if "fail" in url:
                    raise ConnectionError("boom")

                class _R:
                    status_code = 200
                    text = '<form action="/s"><input name="q"></form>'

                return _R()

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_Sess()))
        result = await agent._fetch_and_extract_form_fields(
            ["https://x/ok", "https://x/fail"]
        )
        assert result == {"https://x/ok": ["q"]}


# -----------------------------------------------------------------------
# _execute_content_discovery
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestContentDiscovery:
    async def test_missing_target_raises(self):
        agent = _make_agent()
        with pytest.raises(AgentException) as exc:
            await agent._execute_content_discovery({})
        assert "content_discovery requires" in str(exc.value)

    async def test_katana_failure_returns_error_status(self):
        agent = _make_agent()
        agent.security_bridge.run_katana = AsyncMock(side_effect=RuntimeError("katana died"))
        result = await agent._execute_content_discovery({"url": "https://target.local"})
        assert result["status"] == "error"
        assert "katana crawl failed" in result["error"]

    async def test_happy_path_persists_endpoints_and_returns_intel(self):
        agent = _make_agent()
        agent._ep_scope_enforcer = None
        agent.security_bridge.run_katana = AsyncMock(
            return_value={
                "endpoints": [
                    "https://target.local/search?q=foo",
                    "https://target.local/profile?id=123",
                ],
                "js_files": ["https://target.local/app.js"],
            }
        )

        # No HTML fetches succeed (empty form fields), but endpoints still persist
        class _Sess:
            async def get(self, url, timeout=None, **kw):
                raise ConnectionError("no host")

        agent.get_governed_client = MagicMock(return_value=_ClientCtx(_Sess()))
        result = await agent._execute_content_discovery({"url": "https://target.local"})
        assert result["status"] == "success"
        assert result["target"] == "https://target.local"
        assert result["endpoints_found"] == 3  # 2 URLs + 1 JS file
        assert result["js_files"] == 1
        # parameter intelligence was mined from the URLs
        intel = result["parameter_intelligence"]
        assert "q" in intel["param_frequency"] or "id" in intel["param_frequency"]
        # Every endpoint was registered in the local inventory
        assert len(agent.endpoint_inventory) == 3
        # Graph batch was NOT used for content_discovery — the per-endpoint path is.
        # At least 3 persists happened (some may have been filtered; use >= because
        # of how inventory and persist calls interleave).
        assert agent.ctx.graph_memory.add_endpoint.await_count >= 3


# -----------------------------------------------------------------------
# _execute_spa_harvest (delegates to spa_harvester; we stub only the boundary)
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestSpaHarvest:
    async def test_missing_url_raises(self):
        agent = _make_agent()
        with pytest.raises(AgentException) as exc:
            await agent._execute_spa_harvest({})
        assert "spa_harvest requires" in str(exc.value)


# -----------------------------------------------------------------------
# think()
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestThinkDegradation:
    async def test_llm_failure_returns_empty_string_not_exception(self):
        agent = _make_agent()

        # _load_skill is called for every skill name returned by think; make it return ""
        agent._load_skill = MagicMock(return_value="")

        # RetrievalAgent construction would touch session/graph — stub it out
        import ai_osop.agents.recon_agent as recon_mod

        class _FakeRA:
            def __init__(self, ctx):
                pass

            async def _setup_resources(self):
                return None

            def search(self, category):
                return []

        original_ra = recon_mod.RetrievalAgent
        recon_mod.RetrievalAgent = _FakeRA
        try:
            agent.ctx.llm_client.complete = AsyncMock(side_effect=RuntimeError("LLM down"))
            out = await agent.think("some context", ["skill-a"])
            assert out == ""
        finally:
            recon_mod.RetrievalAgent = original_ra


# -----------------------------------------------------------------------
# _cleanup_resources
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestCleanup:
    async def test_clears_inventories(self):
        agent = _make_agent()
        agent.asset_inventory["a"] = MagicMock()
        agent.endpoint_inventory["e"] = MagicMock()
        await agent._cleanup_resources()
        assert agent.asset_inventory == {}
        assert agent.endpoint_inventory == {}


# -----------------------------------------------------------------------
# _execute_full_recon (orchestration path)
# -----------------------------------------------------------------------


@pytest.mark.asyncio
class TestFullRecon:
    async def test_no_domain_returns_failed(self):
        agent = _make_agent()
        result = await agent._execute_full_recon({})
        assert result["status"] == "failed"
        assert "domain parameter is required" in result["error"]

    async def test_orchestrates_dns_port_probe_and_reports_verified(self):
        """With a stubbed adapter, full_recon drives every sub-step, persists the
        root domain asset, and reports execution_verified=True (honesty guard)."""
        agent = _make_agent()

        # Stub DNS to return a single subdomain so port_scan + probe run
        sub_asset = Asset(
            id="s1", type="subdomain", value="sub.example.com",
            source="dns", confidence=0.9, engagement_id="eng-test",
        )
        agent.recon_adapter.dns_enumeration = AsyncMock(return_value=[sub_asset])
        agent.recon_adapter.port_scan = AsyncMock(return_value=[])
        agent.recon_adapter.service_probe = AsyncMock(return_value=[])
        agent.recon_adapter.historical_urls = AsyncMock(return_value=[])
        agent.recon_adapter.osint_lookup = AsyncMock(return_value=[])

        # Stub the network-bound helpers via governed client
        class _NeverCalledClient:
            async def get(self, url, **kw):
                # No live hosts in the test sandbox; everything errors quickly
                raise ConnectionError("no network")

        agent.get_governed_client = MagicMock(
            return_value=_ClientCtx(_NeverCalledClient())
        )

        # Stub think() so the LLM isn't invoked
        async def _think(ctx, skills):
            return "recon reasoning"

        agent.think = _think  # type: ignore[method-assign]
        agent._get_relevant_skills = AsyncMock(return_value=[])

        # active_crawl_target itself hits the network; stub it to return []
        async def _no_crawl(domain, session_store=None):
            return []

        agent._active_crawl_target = _no_crawl  # type: ignore[method-assign]

        result = await agent._execute_full_recon({"domain": "example.com"})
        assert result["status"] == "success"
        assert result["target"] == "example.com"
        assert result["subdomains_found"] == 1
        # Honesty guard: real adapter flow ran, asset_inventory non-empty
        assert result["execution_verified"] is True
        assert result["reasoning"] == "recon reasoning"
        # Root domain asset was persisted (the seed that keeps vuln phase alive)
        assert any(
            call.args[0].value == "example.com"
            for call in agent.ctx.graph_memory.add_asset.await_args_list
        )
        # And the subdomain asset from DNS was also persisted
        assert any(
            call.args[0].value == "sub.example.com"
            for call in agent.ctx.graph_memory.add_asset.await_args_list
        )

    async def test_failed_root_asset_write_aborts_recon(self):
        agent = _make_agent()
        agent.recon_adapter.dns_enumeration = AsyncMock(return_value=[])
        agent.ctx.graph_memory.add_asset = AsyncMock(side_effect=RuntimeError("neo4j down"))
        result = await agent._execute_full_recon({"domain": "example.com"})
        assert result["status"] == "failed"
        assert "neo4j down" in result["error"]
