"""BURP-COMMUNITY-001: end-to-end tests for the Burp Suite Community workflow.

Proves the platform's full scanning pipeline works with the FREE, legally
usable Burp Community edition — active scanning routed to AI-OSOP's own
engines, Community-supported Burp APIs used unchanged, findings/evidence/
validation/dedup/reporting preserved, and graceful degradation everywhere.

A fake Community burp-mcp extension (get_version reports
COMMUNITY_EDITION with every Pro module unavailable; scan_target performs the
HTTP-engine probe fallback) stands in for the real Montoya extension, so no
Burp install or network is needed.

Explicitly NOT tested (and never implemented anywhere): bypassing Burp's
licensing, patching Burp binaries, unlocking paid features, or making Burp
impersonate Pro. Community is used strictly as licensed.
"""

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.adapters.burp_capabilities import (
    BurpCapabilities,
    burp_deep_channel_probe,
    deep_probe_verdict,
    detect_burp_capabilities,
    routing_plan,
)
from ai_osop.adapters.burp_mcp import BurpMCPAdapter
from ai_osop.agents.base import AgentContext
from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import MCPExecuteResponse

# ---------------------------------------------------------------------------
# Fake Community / Pro extension registries
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_va_httpx():
    """Keep the vuln_agent httpx stub from leaking into other test modules."""
    import ai_osop.agents.vuln_agent as _va

    original = _va.httpx
    yield
    _va.httpx = original


class _FakeBurpExtension:
    """In-memory burp-mcp extension answering like the Montoya Java server.

    ``edition`` selects the persona:
      * "community" — COMMUNITY_EDITION, scanner/collaborator/organizer false,
        scan_target answers the HTTP-engine probe fallback.
      * "pro"      — PROFESSIONAL_EDITION, scanner true, scan_target starts
        a real audit.
    Community tools behave exactly like the Java extension's Community path
    (proxy history, sitemap, scope, live traffic, HTTP engine all supported).
    """

    def __init__(self, edition: str = "community"):
        self.edition = edition
        self.calls: List[Dict[str, Any]] = []

    def _respond(
        self, status: str, result: Optional[Dict[str, Any]] = None, error: Optional[str] = None
    ) -> MCPExecuteResponse:
        return MCPExecuteResponse(request_id="req-test", status=status, result=result, error=error)

    async def execute_tool(
        self, server_id: str, tool: str, params: Dict[str, Any], **_: Any
    ) -> MCPExecuteResponse:
        self.calls.append({"tool": tool, "params": params})
        if tool == "get_version":
            is_pro = self.edition == "pro"
            return self._respond(
                "success",
                {
                    "edition": "PROFESSIONAL_EDITION" if is_pro else "COMMUNITY_EDITION",
                    "version": "2026.4",
                    "scanner_available": is_pro,
                    "collaborator_available": is_pro,
                    "organizer_available": is_pro,
                    "websocket_available": True,
                    "live_traffic": True,
                },
            )
        if tool == "scan_target":
            if self.edition == "pro":
                return self._respond("success", {"status": "started", "target": params.get("url")})
            # Community: HTTP-engine probe fallback (Java extension behavior).
            return self._respond(
                "success",
                {
                    "status": "probe_completed",
                    "target": params.get("url"),
                    "status_code": 200,
                    "note": "Burp Scanner (Pro-only) unavailable; performed active probe via Burp HTTP engine.",
                },
            )
        if tool == "get_scan_issues":
            return self._respond("success", {"total": 0, "issues": []})
        if tool == "get_sitemap":
            return self._respond(
                "success",
                {
                    "total": 1,
                    "entries": [
                        {
                            "url": "http://127.0.0.1/login",
                            "method": "GET",
                            "status_code": 200,
                            "host": "127.0.0.1",
                        }
                    ],
                },
            )
        if tool == "get_proxy_history":
            return self._respond("success", {"total": 0, "entries": []})
        if tool == "add_to_scope":
            return self._respond("success", {"status": "success"})
        if tool == "send_http_request":
            return self._respond(
                "success",
                {
                    "status": "success",
                    "status_code": 200,
                    "response_headers": [],
                    "response_body": "benign page",
                },
            )
        if tool == "intruder_attack":
            return self._respond(
                "success", {"status": "success", "message": "Sent to Intruder tab"}
            )
        if tool == "collaborator_payload" and self.edition == "pro":
            return self._respond(
                "success",
                {"status": "success", "collab_id": "collab-1", "payload": "x.oastify.com"},
            )
        if tool == "sync_to_organizer" and self.edition == "pro":
            return self._respond("success", {"status": "success", "message": "Sent to Organizer"})
        # Any Pro-only tool called directly on Community errors like the real
        # extension does (the adapter is expected to never call them blind).
        return self._respond("error", {"error": f"{tool} requires Burp Suite Pro"})


class _FakeRegistry:
    """MCPRegistry stand-in routing burp-mcp to the fake extension."""

    def __init__(self, extension: _FakeBurpExtension):
        self.extension = extension

    async def execute_tool(
        self, server_id: str, tool: str, params: Dict[str, Any], **_: Any
    ) -> MCPExecuteResponse:
        assert server_id == "burp-mcp", f"unexpected server {server_id}"
        return await self.extension.execute_tool(server_id, tool, params)


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------


async def test_detect_community_edition_and_pro_only_gaps():
    ext = _FakeBurpExtension("community")
    caps = await detect_burp_capabilities(_FakeRegistry(ext))
    assert caps.reachable is True
    assert caps.edition_family == "community"
    assert caps.active_scan_available is False
    assert caps.requires_internal_routing is True
    assert caps.collaborator_available is False
    assert caps.organizer_available is False
    # Community-supported modules stay available.
    assert caps.websocket_available is True
    assert caps.live_traffic is True


async def test_detect_pro_edition_uses_native_scanner():
    caps = await detect_burp_capabilities(_FakeRegistry(_FakeBurpExtension("pro")))
    assert caps.edition_family == "pro"
    assert caps.active_scan_available is True
    assert caps.requires_internal_routing is False


async def test_detect_never_raises_on_dead_server():
    class _Dead:
        async def execute_tool(self, *a: Any, **k: Any) -> MCPExecuteResponse:
            raise ConnectionError("burp-mcp down")

    caps = await detect_burp_capabilities(_Dead())  # type: ignore[arg-type]
    assert caps.reachable is False
    assert caps.requires_internal_routing is True  # route internally, never error


async def test_detect_legacy_extension_without_get_version_infers_from_probe():
    """Pre-v0.2.0 extensions lack get_version — fall back to scan_target."""

    class _Legacy:
        async def execute_tool(
            self, _s: str, tool: str, _p: Dict[str, Any], **_: Any
        ) -> MCPExecuteResponse:
            if tool == "get_version":
                return MCPExecuteResponse(
                    request_id="r",
                    status="error",
                    result={"error": "unknown tool: get_version"},
                )
            assert tool == "scan_target"
            return MCPExecuteResponse(
                request_id="r",
                status="success",
                result={"status": "probe_completed", "status_code": 200},
            )

    caps = await detect_burp_capabilities(_Legacy(), probe_url="http://127.0.0.1/")  # type: ignore[arg-type]
    assert caps.reachable is True
    assert caps.edition_family == "community"
    assert caps.active_scan_available is False


# ---------------------------------------------------------------------------
# Routing plan (capability matrix resolution)
# ---------------------------------------------------------------------------


def test_routing_plan_community_reports_every_capability():
    plan = {
        row["capability"]: row
        for row in routing_plan(
            BurpCapabilities(
                reachable=True,
                edition="COMMUNITY_EDITION",
                scanner_available=False,
                collaborator_available=False,
                organizer_available=False,
                websocket_available=True,
                live_traffic=True,
            )
        )
    }
    # Community-supported capabilities stay on Burp.
    for cap in (
        "proxy_history",
        "sitemap",
        "live_traffic",
        "http_engine",
        "scope_sync",
        "repeater_handoff",
        "decoder_handoff",
        "websockets",
        "extension_persistence",
    ):
        assert plan[cap]["provider"] == "burp", f"{cap} must stay on Burp"
    # Pro-only capabilities are routed to AI-OSOP engines with honest notes.
    assert plan["active_scan"]["provider"] == "nuclei-mcp + web_audit differential"
    assert plan["collaborator_oob"]["provider"] == "oast-mcp"
    assert "Neo4j attack graph" in plan["organizer_findings_ui"]["provider"]
    assert "Pro-only" in plan["active_scan"]["note"]


def test_routing_plan_pro_keeps_burp_native():
    plan = {
        row["capability"]: row
        for row in routing_plan(
            BurpCapabilities(
                reachable=True,
                edition="PROFESSIONAL_EDITION",
                scanner_available=True,
                collaborator_available=True,
                organizer_available=True,
            )
        )
    }
    assert plan["active_scan"]["provider"] == "burp"
    assert plan["collaborator_oob"]["provider"] == "burp"
    assert plan["organizer_findings_ui"]["provider"] == "burp"


# ---------------------------------------------------------------------------
# Adapter degradation (never null, never error, never a raise)
# ---------------------------------------------------------------------------


def _adapter(extension: _FakeBurpExtension) -> BurpMCPAdapter:
    return BurpMCPAdapter(_FakeRegistry(extension))


async def test_collaborator_payload_routes_to_oast_on_community():
    """Community: same interface, transparent provider switch to oast-mcp."""

    class _OastRegistry(_FakeRegistry):
        async def execute_tool(self, server_id: str, tool: str, params: Dict[str, Any], **_: Any):
            if server_id == "oast-mcp" and tool == "oast_register":
                return MCPExecuteResponse(
                    request_id="r",
                    status="success",
                    result={"token": "tok-123", "callback_url": "http://cb.oast.example/tok-123"},
                )
            return await super().execute_tool(server_id, tool, params)

    adapter = BurpMCPAdapter(_OastRegistry(_FakeBurpExtension("community")))
    result = await adapter.collaborator_payload(label="test")
    assert result["status"] == "success"
    assert result["provider"] == "aiosop-oast"
    assert result["collab_id"] == "tok-123"
    assert result["payload"].startswith("http://cb.oast.example/")
    # Pro-only Burp tool was never blindly invoked.
    called = {c["tool"] for c in adapter.registry.extension.calls}
    assert "collaborator_payload" not in called


async def test_collaborator_payload_uses_native_collaborator_on_pro():
    adapter = _adapter(_FakeBurpExtension("pro"))
    result = await adapter.collaborator_payload()
    assert result["provider"] == "burp-collaborator"


async def test_collaborator_payload_degrades_when_oast_also_down():
    adapter = _adapter(_FakeBurpExtension("community"))  # oast-mcp absent
    result = await adapter.collaborator_payload()
    # Structured unavailability with reason + remediation, never an exception.
    assert result["status"] == "unavailable"
    assert result["collab_id"] == ""
    assert "oast-mcp" in result["reason"]
    assert "8099" in result["note"]


async def test_collaborator_interactions_polls_oast_tokens_on_community():
    class _OastRegistry(_FakeRegistry):
        async def execute_tool(self, server_id: str, tool: str, params: Dict[str, Any], **_: Any):
            if server_id == "oast-mcp" and tool == "oast_poll":
                return MCPExecuteResponse(
                    request_id="r",
                    status="success",
                    result={"interactions": [{"source_ip": "10.0.0.9"}]},
                )
            return await super().execute_tool(server_id, tool, params)

    adapter = BurpMCPAdapter(_OastRegistry(_FakeBurpExtension("community")))
    hits = await adapter.collaborator_interactions("tok-123")
    assert hits == [{"source_ip": "10.0.0.9"}]


async def test_sync_to_organizer_degrades_gracefully_on_community():
    adapter = _adapter(_FakeBurpExtension("community"))
    response = await adapter.sync_to_organizer("http://127.0.0.1/login")
    assert response.status == "success"  # NOT an error
    assert response.result["status"] == "degraded"
    assert response.result["burp_organizer"] is False
    assert response.result["provider"] == "aiosop-graph-ledger"
    # The pair was still captured through a Community-supported Burp API.
    assert "send_http_request" in {c["tool"] for c in adapter.registry.extension.calls}


async def test_sync_to_organizer_native_on_pro():
    adapter = _adapter(_FakeBurpExtension("pro"))
    response = await adapter.sync_to_organizer("http://127.0.0.1/login")
    assert response.result.get("burp_organizer", True) is not False


async def test_send_http_request_works_on_community():
    """The Community-supported transport used by internal routing."""
    adapter = _adapter(_FakeBurpExtension("community"))
    result = await adapter.send_http_request({"url": "http://127.0.0.1/", "method": "GET"})
    assert result["status_code"] == 200


async def test_capabilities_cached_but_refreshable():
    ext = _FakeBurpExtension("community")
    adapter = _adapter(ext)
    first = await adapter.get_capabilities()
    ext.edition = "pro"  # operator upgrades Burp mid-session
    second = await adapter.get_capabilities()  # cached
    assert second.edition_family == first.edition_family
    third = await adapter.get_capabilities(refresh=True)
    assert third.edition_family == "pro"


# ---------------------------------------------------------------------------
# End-to-end burp_scan task: Community routing
# ---------------------------------------------------------------------------


def _make_vuln_agent(
    extension: _FakeBurpExtension, http_responses: Optional[Dict[str, Any]] = None
) -> VulnAnalysisAgent:
    """Agent wired to the fake Burp extension + mocked memory + canned HTTP.

    ``http_responses`` follows the test_web_audit._patch_http convention
    (substring of the URL-DECODED request -> {"status_code","text"}), and
    also keys the Burp HTTP engine fake so both transports serve the same
    canned pages.
    """
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "vuln-agent-community"
    ctx.agent_type = AgentType.VULN_ANALYSIS
    ctx.session_id = "eng-community"
    ctx.current_task = None
    ctx.llm_client = AsyncMock()
    ctx.llm_client.complete.return_value = "reasoned"
    session = MagicMock()
    session.scope = ScopeDefinition(
        engagement_id="eng-community", domains=["127.0.0.1"], ips=["127.0.0.1"]
    )
    session.session_id = "eng-community"
    ctx.session_memory = MagicMock()
    ctx.session_memory.get_session_state = AsyncMock(return_value=session)
    ctx.session_memory.load_session_state = AsyncMock(return_value=session)
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.add_asset = AsyncMock(return_value=True)
    ctx.graph_memory.add_endpoint = AsyncMock(return_value=True)
    ctx.graph_memory.add_vulnerability = AsyncMock(return_value=True)
    ctx.audit_callback = AsyncMock()

    # Registry: burp tools -> fake extension; security-bridge/nuclei fail so
    # the internal engines degrade honestly (web_audit's own httpx probes still
    # run through the canned HTTP below).
    class _Registry:
        def __init__(self):
            self.burp = extension

        async def initialize_server(
            self, server_id: str, scope: Any = None, credentials: Any = None, session_id: str = ""
        ) -> None:
            self.bound = (server_id, session_id)

        async def execute_tool(self, server_id: str, tool: str, params: Dict[str, Any], **_: Any):
            if server_id == "burp-mcp":
                return await self.burp.execute_tool(server_id, tool, params)
            if server_id == "oast-mcp":
                return MCPExecuteResponse(
                    request_id="r",
                    status="success",
                    result={"token": "", "callback_url": ""},  # OAST off -> honest degrade
                )
            raise RuntimeError(f"{server_id} down")

    ctx.mcp_registry = _Registry()

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = ctx
    agent.findings = {}
    agent.burp_adapter = BurpMCPAdapter(ctx.mcp_registry)

    # Canned HTTP for web_audit / catch-all / intruder internal transports.
    from urllib.parse import unquote_plus

    import ai_osop.agents.vuln_agent as va

    class _Resp:
        def __init__(self, status_code: int, text: str):
            self.status_code = status_code
            self.text = text

        @property
        def content(self) -> bytes:
            return (self.text or "").encode("utf-8")

    class _Client:
        def __init__(self, *a: Any, **k: Any):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a: Any):
            return False

        def _match(self, url: str, data: Any = None) -> _Resp:
            decoded = unquote_plus(url)
            form_part = ""
            if data:
                try:
                    form_part = unquote_plus("&".join(f"{k}={v}" for k, v in data.items()))
                except Exception:  # noqa: BLE001
                    pass
            target_str = form_part if data is not None else decoded
            for key, resp in (http_responses or {}).items():
                if key in target_str:
                    return _Resp(resp["status_code"], resp["text"])
            return _Resp(200, "benign page")

        async def get(self, url: str, headers: Dict[str, str] = None):
            return self._match(url)

        async def post(
            self,
            url: str,
            data: Dict[str, str] = None,
            headers: Dict[str, str] = None,
            content: str = None,
        ):
            if data is not None:
                return self._match(url, data)
            return self._match(url, None)

    # Patch httpx only inside vuln_agent (web_audit/intruder/catch-all probes).
    class _HttpxProxy:
        AsyncClient = staticmethod(_Client)
        Response = _Resp

    va.httpx = _HttpxProxy  # type: ignore[assignment]
    return agent


async def test_burp_scan_end_to_end_on_community_routes_and_succeeds():
    """THE core test: full burp_scan task against Burp Community.

    Expect: Community capabilities detected; scan_target probe fired; nuclei
    + web_audit executed as the internal active-scan engines; Burp passive
    layer (scan issues, sitemap, proxy history) still consumed; SQLi
    differential CONFIRMED through the internal engine with full evidence;
    result reports community routing transparently; no error status.
    """
    ext = _FakeBurpExtension("community")
    agent = _make_vuln_agent(
        ext,
        http_responses={
            "audit_probe_baseline_77": {"status_code": 200, "text": "normal page"},
            "OR '1'='1": {"status_code": 200, "text": "ERROR: sql syntax error near"},
        },
    )

    result = await agent._execute_burp_scan(
        {
            "url": "http://127.0.0.1:8200/search?q=seed",
            "engagement_id": "eng-community",
            "config": {"audit_items": ["sqli", "xss"]},
        }
    )

    # Task succeeded — never blocked, never errored.
    assert result["status"] == "success"
    assert result["scan_mode"] == "community_routed"
    assert result["burp_edition"] == "community"

    # Community did its legal part: probe + scope sync + passive reads.
    burp_tools = [c["tool"] for c in ext.calls]
    assert "scan_target" in burp_tools
    assert "add_to_scope" in burp_tools
    assert "get_scan_issues" in burp_tools
    assert "get_sitemap" in burp_tools
    assert "get_proxy_history" in burp_tools

    # The internal active-scan engines ran: web_audit SUCCEEDED (in
    # internal_components, with its confirmed finding); nuclei-mcp degraded
    # honestly (it is mocked down in this harness — its coverage is proven by
    # tests/test_web_audit.py + the nuclei unit suite).
    providers = {c["provider"] for c in result["internal_components"]}
    assert "web_audit" in providers
    assert {"nuclei-mcp"} <= {c["component"] for c in result["degraded_components"]}

    # The differential engine CONFIRMED the SQLi with honest evidence.
    assert result["findings_count"] >= 1
    finding = result["findings"][0]
    assert finding["cwe"] == "CWE-89"
    assert finding["validated"] is True
    assert finding["tool_source"] == "web_audit"
    assert finding["evidence"][0]["type"] == "web_audit_differential"
    assert finding["evidence"][0]["parameter"] == "q"

    # Finding persisted to the graph + agent ledger (same funnel as Pro).
    agent.ctx.graph_memory.add_vulnerability.assert_awaited()

    # Transparency: routing plan included verbatim.
    routing = {row["capability"]: row for row in result["capability_routing"]}
    assert routing["active_scan"]["provider"] == "nuclei-mcp + web_audit differential"
    assert routing["proxy_history"]["provider"] == "burp"


async def test_burp_scan_on_pro_uses_native_burp_audit():
    """Pro path unchanged: Burp's own scanner runs, no internal routing."""
    ext = _FakeBurpExtension("pro")
    agent = _make_vuln_agent(ext)

    result = await agent._execute_burp_scan(
        {"url": "http://127.0.0.1:8200/", "engagement_id": "eng-community"}
    )

    assert result["status"] == "success"
    assert result["scan_mode"] == "burp_pro_active_audit"
    assert result["burp_error"] is None
    # Internal engines were NOT invoked.
    assert result["internal_components"] == []


async def test_burp_scan_degrades_when_burp_entirely_down():
    """No Burp at all: internal_routed mode still completes the task."""

    class _DeadBurp(_FakeBurpExtension):
        async def execute_tool(
            self, server_id: str, tool: str, params: Dict[str, Any], **_: Any
        ) -> MCPExecuteResponse:
            raise ConnectionError("burp-mcp down")

    agent = _make_vuln_agent(_DeadBurp("community"))

    result = await agent._execute_burp_scan(
        {"url": "http://127.0.0.1:8200/", "engagement_id": "eng-community"}
    )

    assert result["status"] == "success"
    assert result["scan_mode"] == "internal_routed"
    assert result["burp_edition"] == "unreachable"
    assert result["burp_error"]
    # Active scanning still happened through the internal engines: web_audit
    # needs no Burp at all (internal httpx transport), so it completes cleanly;
    # nuclei-mcp degrades with its reason recorded — never an error.
    assert {"nuclei-mcp"} <= {c["component"] for c in result["degraded_components"]}
    assert "web_audit" in {c["provider"] for c in result["internal_components"]}


# ---------------------------------------------------------------------------
# intruder_fuzz on Community: deterministic differential execution
# ---------------------------------------------------------------------------


async def test_intruder_fuzz_community_executes_payloads_deterministically():
    """Intruder execution is Pro-only; Community runs the set through Burp's
    HTTP engine with AI-OSOP differential judgment — and CONFIRMS a finding."""

    class _FuzzBurp(_FakeBurpExtension):
        """HTTP engine that answers the SQLi payload with a DB error."""

        async def execute_tool(
            self, server_id: str, tool: str, params: Dict[str, Any], **_: Any
        ) -> MCPExecuteResponse:
            self.calls.append({"tool": tool, "params": params})
            if tool == "send_http_request":
                body = str(params.get("body") or "") + str(params.get("url") or "")
                if "' OR '1'='1" in body:
                    return self._respond(
                        "success",
                        {
                            "status": "success",
                            "status_code": 200,
                            "response_headers": [],
                            "response_body": "Error: you have an error in your SQL syntax",
                        },
                    )
                return self._respond(
                    "success",
                    {
                        "status": "success",
                        "status_code": 200,
                        "response_headers": [],
                        "response_body": "benign page",
                    },
                )
            return await super().execute_tool(server_id, tool, params)

    ext = _FuzzBurp("community")
    agent = _make_vuln_agent(ext)

    result = await agent._execute_intruder_fuzz(
        {
            "url": "http://127.0.0.1:8200/login",
            "method": "POST",
            "body": "user=§test§",
            "payload_set": ["' OR '1'='1' --"],
            "engagement_id": "eng-community",
        }
    )

    assert result["status"] == "success"
    assert result["attack_mode"] == "aiosop_deterministic"
    assert result["burp_edition"] == "community"
    # UI hand-off still happened (Community-supported).
    assert result["sent_to_intruder_tab"] is True
    assert "intruder_attack" in {c["tool"] for c in ext.calls}
    # Payload executed through Burp's HTTP engine.
    assert "send_http_request" in {c["tool"] for c in ext.calls}
    assert len(result["execution_results"]) == 1
    row = result["execution_results"][0]
    assert row["transport"] == "burp_http_engine"
    assert row.get("confirmed") == "sqli"
    # Differential finding minted + validated + persisted.
    assert result["findings_count"] == 1
    finding = result["findings"][0]
    assert finding["cwe"] == "CWE-89"
    assert finding["validated"] is True
    assert finding["tool_source"] == "intruder_fuzz"
    assert finding["evidence"][0]["burp_intruder_execution"] is False
    agent.ctx.graph_memory.add_vulnerability.assert_awaited()


async def test_intruder_fuzz_pro_uses_native_intruder():
    agent = _make_vuln_agent(_FakeBurpExtension("pro"))
    result = await agent._execute_intruder_fuzz(
        {"url": "http://127.0.0.1:8200/login", "payload_set": ["a"], "engagement_id": "e"}
    )
    assert result["attack_mode"] == "burp_intruder_pro"
    assert "execution_results" not in result


async def test_intruder_fuzz_clean_target_no_false_positive():
    """Deltas absent -> zero findings (honest, no probe noise)."""
    agent = _make_vuln_agent(_FakeBurpExtension("community"))
    result = await agent._execute_intruder_fuzz(
        {
            "url": "http://127.0.0.1:8200/search?q=seed",
            "payload_set": ["' OR '1'='1' --", "{{7*9}}"],
            "engagement_id": "eng-community",
        }
    )
    assert result["status"] == "success"
    assert result["findings_count"] == 0
    assert all("confirmed" not in r for r in result["execution_results"])


# ---------------------------------------------------------------------------
# Health deep probe verdicts
# ---------------------------------------------------------------------------


async def test_deep_probe_verdict_community():
    verdict, detail = deep_probe_verdict(
        http_ok=True,
        edition="COMMUNITY_EDITION",
        scanner_available=False,
        scan_result={"status": "probe_completed", "status_code": 200},
        nuclei_result={"findings": ["missing header"]},
    )
    assert verdict == "community_verified_internal_scanning"
    assert detail["scan_capable"] is False
    assert detail["internal_active_scan"] == "verified"
    assert detail["edition"] == "COMMUNITY_EDITION"


async def test_deep_probe_verdict_pro():
    verdict, detail = deep_probe_verdict(
        http_ok=True,
        edition="PROFESSIONAL_EDITION",
        scanner_available=True,
        scan_result={"status": "started"},
        nuclei_result=None,
    )
    assert verdict == "real_execution_verified"
    assert detail["scan_capable"] is True


async def test_deep_probe_verdict_community_without_internal_coverage():
    verdict, detail = deep_probe_verdict(
        http_ok=True,
        edition="COMMUNITY_EDITION",
        scanner_available=False,
        scan_result={"status": "probe_completed"},
        nuclei_result={"error": "nuclei-mcp down"},
    )
    assert verdict == "scan_unavailable"
    assert detail["internal_active_scan"] == "unverified"


async def test_deep_probe_verdict_http_failure():
    verdict, detail = deep_probe_verdict(
        http_ok=False,
        edition="",
        scanner_available=False,
        scan_result=None,
        nuclei_result=None,
    )
    assert verdict == "failed"
    assert detail["stage"] == "http"


async def test_burp_deep_channel_probe_live_community():
    """Full channel probe against a fake Community extension + nuclei."""

    async def run_tool(base: str, tool: str, params: Dict[str, Any], timeout: float):
        if "8081" in base:  # burp base
            ext = _FakeBurpExtension("community")
            return (await ext.execute_tool("burp-mcp", tool, params)).result
        # nuclei base
        return {"status": "success", "findings": ["x"]}

    verdict, detail = await burp_deep_channel_probe(
        run_tool=run_tool,
        burp_base="http://127.0.0.1:8081",
        nuclei_base="http://127.0.0.1:8084",
        api_port=8200,
    )
    assert verdict == "community_verified_internal_scanning"
    assert detail["internal_active_scan"] == "verified"


# ---------------------------------------------------------------------------
# Documentation-sync guard: the capability matrix doc must stay truthful.
# ---------------------------------------------------------------------------


def test_capability_matrix_doc_lists_every_routed_capability():
    """docs/BURP_COMMUNITY_CAPABILITY_MATRIX.md must cover the routing table
    — keeps the operator-facing matrix from drifting from the code."""
    import os
    import re

    doc = os.path.join(
        os.path.dirname(__file__), "..", "docs", "BURP_COMMUNITY_CAPABILITY_MATRIX.md"
    )
    assert os.path.exists(doc), "capability matrix doc must exist"
    content = open(doc, encoding="utf-8").read()
    from ai_osop.adapters.burp_capabilities import CAPABILITY_ROUTES

    for route in CAPABILITY_ROUTES:
        assert route.capability in content, f"doc must document capability '{route.capability}'"
    assert re.search(r"oast-mcp", content)
    assert re.search(r"web_audit", content)
    # The doc states the licensing posture explicitly.
    assert re.search(r"(?i)no.{0,40}(license|licensing).{0,60}bypass", content) or re.search(
        r"(?i)without bypassing", content
    )
