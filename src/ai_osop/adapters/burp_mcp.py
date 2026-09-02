"""
Burp Suite MCP Adapter
Production-grade adapter for Burp Suite MCP with request/response normalization,
scanner issue correlation, and proxy history management.

BURP-COMMUNITY-001 (2026-08-31): the adapter is edition-aware. Pro-only
capabilities (Collaborator, Organizer) are detected via
``ai_osop.adapters.burp_capabilities`` and degrade gracefully — Collaborator
transparently routes to AI-OSOP's oast-mcp (equivalent OOB detection), and
Organizer requests return a structured degradation response instead of an
error, because every AI-OSOP finding is already persisted to the Neo4j attack
graph + findings ledger. Burp Community APIs (proxy, sitemap, HTTP engine,
scope, repeater, decoder, websockets, persistence) are used unchanged.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ai_osop.adapters.burp_capabilities import BurpCapabilities, detect_burp_capabilities
from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.exceptions import MCPException
from ai_osop.core.models import Endpoint, ScopeDefinition, Vulnerability
from ai_osop.mcp.protocol import MCPExecuteResponse, MCPRegistry


class BurpMCPAdapter:
    """
    High-level adapter for Burp Suite MCP server.

    Provides:
    - Proxy history retrieval with filtering
    - Scanner issue extraction and normalization
    - Repeater request execution
    - Intruder attack orchestration
    - Extension API invocation
    """

    SERVER_ID = "burp-mcp"

    # Capability probe cache TTL. The extension answers get_version from
    # in-memory probes computed at extension load, so a short TTL keeps the
    # adapter honest across extension reloads (edition changes mid-session)
    # without hammering the server on every tool call.
    CAPABILITY_TTL = timedelta(seconds=120)

    def __init__(self, registry: MCPRegistry):
        self.registry = registry
        self._proxy_history_buffer: List[Dict[str, Any]] = []
        self._max_history_size = 10000
        # FIX (scope-gate-2026-08-24): retain scope so every tool call can be
        # client-side validated by the registry gate (defense-in-depth).
        self._scope: Optional[ScopeDefinition] = None
        self._capabilities: Optional[BurpCapabilities] = None
        self._capabilities_at: Optional[datetime] = None

    # ---------------------------------------------------------------- edition / routing

    async def get_capabilities(
        self, refresh: bool = False, probe_url: Optional[str] = None
    ) -> BurpCapabilities:
        """Current Burp capability snapshot (cached; never raises).

        BURP-COMMUNITY-001: this is the single decision point for where active
        scanning is executed. Community (or any edition without a working
        Pro scanner) reports ``requires_internal_routing`` so callers route to
        AI-OSOP's nuclei + web_audit engines instead of failing.
        """
        now = datetime.utcnow()
        if (
            not refresh
            and self._capabilities is not None
            and self._capabilities_at is not None
            and now - self._capabilities_at < self.CAPABILITY_TTL
        ):
            return self._capabilities
        caps = await detect_burp_capabilities(self.registry, probe_url=probe_url)
        self._capabilities = caps
        self._capabilities_at = now
        return caps

    async def edition_info(self) -> Dict[str, Any]:
        """get_version result as a plain dict (empty on unreachable)."""
        response = await self.registry.execute_tool(self.SERVER_ID, "get_version", {})
        if response.status != "success" or not response.result:
            return {}
        return response.result

    @staticmethod
    def _extract_error(response: MCPExecuteResponse) -> str:
        """Surface the *real* server-side error.

        AIOSOP-BURP-ERR-001 (2026-07-03): the Burp Montoya MCP returns its actual
        failure inside ``result`` (e.g. ``result.error`` — a Java exception string
        such as ``Scanner.startAudit(...) is null``), while the protocol's top-level
        ``error`` field stays empty. Reading only ``response.error`` therefore
        collapsed every real Burp failure to the useless string ``"unknown error"``,
        masking the root cause (runtime-proven on scan_target vs the Syfe target).
        Prefer the top-level error, then common nested keys, before giving up.
        """
        if response.error:
            return response.error
        result = response.result or {}
        if isinstance(result, dict):
            for key in ("error", "error_message", "message", "detail", "reason"):
                val = result.get(key)
                if val:
                    return str(val)
        return "unknown error"

    def _check_response(self, response: MCPExecuteResponse, operation: str) -> None:
        """Raise typed exceptions for non-success MCP responses so callers can
        distinguish 'no data' from 'operation failed' (FINDING-011 / FINDING-012)."""
        if response.status == "success":
            return
        from ai_osop.core.exceptions import MCPException, MCPTimeoutError

        if response.status == "timeout":
            raise MCPTimeoutError(f"Burp MCP operation '{operation}' timed out")
        if response.status == "circuit_open":
            raise MCPException(
                f"Burp MCP operation '{operation}' rejected: circuit breaker is open"
            )
        raise MCPException(
            f"Burp MCP operation '{operation}' failed: {self._extract_error(response)}"
        )

    async def initialize(self, scope: ScopeDefinition, session_id: str) -> None:
        """Initialize Burp MCP with scope and auth."""
        credentials = {}
        # FIX (scope-gate-2026-08-24): retain scope so every tool call can be
        # client-side validated by the registry gate (defense-in-depth).
        self._scope: Optional[ScopeDefinition] = scope

        await self.registry.initialize_server(
            self.SERVER_ID,
            scope=scope.model_dump(),
            credentials=credentials,
            session_id=session_id,
        )

    async def scan_target(
        self, url: str, config: Optional[Dict[str, Any]] = None
    ) -> MCPExecuteResponse:
        """Initiate Burp crawl + audit scan on target URL."""
        params = {
            "url": url,
            "config": config
            or {
                "scan_type": "crawl_and_audit",
                "audit_items": ["sqli", "xss", "csrf", "idor", "ssrf"],
                "scan_speed": "normal",
                "max_depth": 10,
            },
        }
        response = await self.registry.execute_tool(
            self.SERVER_ID, "scan_target", params, timeout_override=3600, scope=self._scope
        )
        self._check_response(response, "scan_target")
        return response

    async def get_proxy_history(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve captured proxy traffic with optional filtering."""
        params = {"filters": filters or {}, "limit": 1000, "offset": 0}
        response = await self.registry.execute_tool(self.SERVER_ID, "get_proxy_history", params)

        if response.status == "success" and response.result:
            entries = response.result.get("entries", [])
            self._update_history_buffer(entries)
            return entries
        return []

    async def get_scan_issues(self, target: Optional[str] = None) -> List[Vulnerability]:
        """Retrieve and normalize scanner findings."""
        params = {"target": target} if target else {}
        response = await self.registry.execute_tool(self.SERVER_ID, "get_scan_issues", params)

        if response.status != "success":
            self._check_response(response, "get_scan_issues")
            return []
        if not response.result:
            return []

        raw_issues = response.result.get("issues", [])
        vulnerabilities = []

        for issue in raw_issues:
            vuln = self._normalize_scan_issue(issue)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def send_to_repeater(
        self, request: Dict[str, Any], tab_name: Optional[str] = None
    ) -> MCPExecuteResponse:
        """Send request to Repeater for manual manipulation.

        ``request`` is a flat request dict ({"url","method","body","headers"}) as
        produced by the exploit agent. The Java extension reads url/method/body
        as individual parameters, so flatten here.
        """
        params = {
            "url": request.get("url", ""),
            "method": request.get("method", "GET"),
            "body": request.get("body", ""),
            "tab_name": tab_name or "",
        }
        response = await self.registry.execute_tool(self.SERVER_ID, "send_to_repeater", params)
        self._check_response(response, "send_to_repeater")
        return response

    async def intruder_attack(
        self,
        request: Dict[str, Any],
        payload_positions: List[Dict[str, Any]],
        payload_set: List[str],
        config: Optional[Dict[str, Any]] = None,
    ) -> MCPExecuteResponse:
        """Send a request to Burp's Intruder UI tab (Community) for fuzzing.

        The Java extension's intruder_attack tool accepts url/method/body and an
        optional tab_name; on Community it hands the request to the Intruder tab
        (attack execution is Pro-only). payload_positions/payload_set are accepted
        for API compatibility but the extension does not drive a live attack.
        """
        cfg = config or {}
        params = {
            "url": request.get("url", ""),
            "method": request.get("method", "GET"),
            "body": request.get("body", ""),
            "tab_name": cfg.get("tab_name", "") or "",
        }
        response = await self.registry.execute_tool(
            self.SERVER_ID, "intruder_attack", params, timeout_override=1800
        )
        self._check_response(response, "intruder_attack")
        return response

    async def extension_call(
        self, extension_name: str, method: str, params: Dict[str, Any]
    ) -> MCPExecuteResponse:
        """Placeholder for arbitrary Burp extension invocation.

        The Java extension does not expose a generic extension_call tool (and
        never did — the tool was advertised but unimplemented). Prefer the
        specific tools: extension_data_get/extension_data_set for extension
        persistence, sync_to_organizer, send_to_decoder, etc.
        """
        raise MCPException(
            "Burp extension_call is not implemented by the AI-OSOP extension. "
            "Use the specific tools: extension_data_get/extension_data_set, "
            "sync_to_organizer, send_to_decoder, collaborator_*."
        )

    async def get_sitemap(self, url_prefix: Optional[str] = None) -> List[Endpoint]:
        """Extract site map as normalized endpoints."""
        params = {"url_prefix": url_prefix} if url_prefix else {}
        response = await self.registry.execute_tool(self.SERVER_ID, "get_sitemap", params)

        if response.status != "success" or not response.result:
            return []

        endpoints = []
        for entry in response.result.get("entries", []):
            ep = Endpoint(
                url=entry.get("url"),
                method=entry.get("method", "GET"),
                status_code=entry.get("status_code"),
                title=entry.get("title"),
                technologies=entry.get("technologies", []),
                parameters=entry.get("parameters", []),
                auth_required=entry.get("auth_required", False),
                asset_id=entry.get("asset_id", ""),
                source="burp_sitemap",
                confidence=0.95,
                engagement_id=entry.get("engagement_id", ""),
            )
            endpoints.append(ep)

        return endpoints

    def _normalize_scan_issue(self, issue: Dict[str, Any]) -> Optional[Vulnerability]:
        """Convert Burp scan issue to standardized Vulnerability model."""
        burp_severity = issue.get("severity", "info")
        severity_map = {
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
            "Information": Severity.INFO,
        }

        # Map Burp issue types to CWE/VulnClass
        issue_type = issue.get("type", "")
        vuln_type = self._map_burp_issue_type(issue_type)
        cwe = self._map_burp_to_cwe(issue_type)

        return Vulnerability(
            cwe=cwe,
            vuln_type=vuln_type,
            severity=severity_map.get(burp_severity, Severity.INFO),
            title=issue.get("name", "Unknown Issue"),
            description=issue.get("issue_detail", ""),
            evidence=[
                {
                    "type": "burp_issue",
                    "confidence": issue.get("confidence"),
                    "path": issue.get("path"),
                    "request_response": issue.get("request_response"),
                }
            ],
            tool_source="burp_scanner",
            endpoint_id=issue.get("endpoint_id"),
            confidence=0.9 if issue.get("confidence") == "Certain" else 0.7,
            entry_point=issue.get("entry_point", False),
            requires_auth=issue.get("requires_auth", False),
            exploitability="high" if burp_severity == "High" else "medium",
            engagement_id=issue.get("engagement_id", ""),
        )

    def _map_burp_issue_type(self, issue_type: str) -> VulnClass:
        """Map Burp issue type string to VulnClass enum."""
        mapping = {
            "SQL injection": VulnClass.SQLI,
            "Cross-site scripting": VulnClass.XSS,
            "SSRF": VulnClass.SSRF,
            "XML external entity injection": VulnClass.XXE,
            "OS command injection": VulnClass.RCE,
            "File path traversal": VulnClass.LFI,
            "Insecure deserialization": VulnClass.DESERIALIZATION,
        }

        for key, value in mapping.items():
            if key.lower() in issue_type.lower():
                return value

        # Heuristic fallback
        if "sql" in issue_type.lower():
            return VulnClass.SQLI
        elif "xss" in issue_type.lower() or "scripting" in issue_type.lower():
            return VulnClass.XSS
        elif "ssrf" in issue_type.lower():
            return VulnClass.SSRF
        elif "jwt" in issue_type.lower():
            return VulnClass.JWT_ABUSE
        elif "idor" in issue_type.lower() or "direct" in issue_type.lower():
            return VulnClass.IDOR

        return VulnClass.UNKNOWN

    def _map_burp_to_cwe(self, issue_type: str) -> Optional[str]:
        """Map Burp issue to CWE identifier using substring matching."""
        cwe_map = {
            "SQL injection": "CWE-89",
            "Cross-site scripting": "CWE-79",
            "SSRF": "CWE-918",
            "XML external entity injection": "CWE-611",
            "OS command injection": "CWE-78",
            "File path traversal": "CWE-22",
            "Insecure deserialization": "CWE-502",
        }
        for key, value in cwe_map.items():
            if key.lower() in issue_type.lower():
                return value
        return None

    def _update_history_buffer(self, entries: List[Dict[str, Any]]) -> None:
        """Maintain circular buffer of proxy history."""
        self._proxy_history_buffer.extend(entries)
        if len(self._proxy_history_buffer) > self._max_history_size:
            self._proxy_history_buffer = self._proxy_history_buffer[-self._max_history_size :]

    async def get_request_by_id(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve specific request from proxy history."""
        for entry in self._proxy_history_buffer:
            if entry.get("id") == request_id:
                return entry

        # Fallback to MCP query (the Java extension implements get_request_by_id
        # against the live proxy history by integer id).
        response = await self.registry.execute_tool(
            self.SERVER_ID, "get_request_by_id", {"request_id": request_id}
        )

        if response.status == "success" and response.result:
            return response.result
        return None

    # ---------------------------------------------------------------- new tools (v0.2.0)

    async def get_version(self) -> Dict[str, Any]:
        """Report Burp edition, version, and available capability probes.

        Kept as the raw extension view; prefer get_capabilities()/edition_info()
        for edition-aware routing decisions (they add caching + fail-safe
        inference for pre-v0.2.0 extensions).
        """
        return await self.edition_info()

    async def get_live_traffic(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Traffic observed through Burp's HTTP engine (registered handler)."""
        response = await self.registry.execute_tool(
            self.SERVER_ID, "get_live_traffic", {"limit": limit}
        )
        if response.status != "success" or not response.result:
            return []
        return response.result.get("entries", [])

    async def ws_open(self, url: str) -> Dict[str, Any]:
        """Open a WebSocket client connection through Burp's WebSockets module."""
        response = await self.registry.execute_tool(self.SERVER_ID, "ws_open", {"url": url})
        self._check_response(response, "ws_open")
        return response.result or {}

    async def ws_send(self, ws_id: str, payload: str) -> MCPExecuteResponse:
        """Send a text message over an AI-OSOP-opened WebSocket."""
        response = await self.registry.execute_tool(
            self.SERVER_ID, "ws_send", {"ws_id": ws_id, "payload": payload}
        )
        self._check_response(response, "ws_send")
        return response

    async def ws_read(self, ws_id: str) -> List[Dict[str, Any]]:
        """Drain buffered inbound messages from an AI-OSOP-opened WebSocket."""
        response = await self.registry.execute_tool(self.SERVER_ID, "ws_read", {"ws_id": ws_id})
        if response.status != "success" or not response.result:
            return []
        return response.result.get("messages", [])

    async def ws_close(self, ws_id: str) -> MCPExecuteResponse:
        """Close an AI-OSOP-opened WebSocket."""
        response = await self.registry.execute_tool(self.SERVER_ID, "ws_close", {"ws_id": ws_id})
        self._check_response(response, "ws_close")
        return response

    async def ws_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """WebSocket frames seen by the proxy."""
        response = await self.registry.execute_tool(self.SERVER_ID, "ws_history", {"limit": limit})
        if response.status != "success" or not response.result:
            return []
        return response.result.get("entries", [])

    async def add_to_scope(self, url: str) -> MCPExecuteResponse:
        """Add a URL to Burp's project scope."""
        response = await self.registry.execute_tool(self.SERVER_ID, "add_to_scope", {"url": url})
        self._check_response(response, "add_to_scope")
        return response

    async def remove_from_scope(self, url: str) -> MCPExecuteResponse:
        """Remove a URL from Burp's project scope."""
        response = await self.registry.execute_tool(
            self.SERVER_ID, "remove_from_scope", {"url": url}
        )
        self._check_response(response, "remove_from_scope")
        return response

    async def is_in_scope(self, url: str) -> bool:
        """Check whether a URL is in Burp's project scope."""
        response = await self.registry.execute_tool(self.SERVER_ID, "is_in_scope", {"url": url})
        if response.status != "success" or not response.result:
            return False
        return bool(response.result.get("in_scope", False))

    async def sync_to_organizer(
        self, url: str, method: str = "GET", body: str = ""
    ) -> MCPExecuteResponse:
        """Send a request/response pair to Burp's Organizer (Pro) for the findings UI.

        BURP-COMMUNITY-001: Organizer is Pro-only. On Community this degrades
        gracefully instead of erroring: the pair is still captured through
        Burp's site map (every edition) simply by issuing the request through
        the HTTP engine, and AI-OSOP's findings already persist to the Neo4j
        attack graph + findings ledger — the persistence Organizer would have
        provided. The response reports the degradation explicitly.
        """
        caps = await self.get_capabilities()
        if not (caps.reachable and caps.organizer_available):
            # Degrade transparently: issue the request through Burp's HTTP
            # engine so the pair lands in the site map (Community-supported),
            # keeping the traffic visible in Burp's UI even without Organizer.
            try:
                await self.send_http_request({"url": url, "method": method, "body": body})
                note = (
                    "Burp Organizer is Pro-only; request issued through Burp's "
                    "HTTP engine and captured in the site map. Findings persist "
                    "to the AI-OSOP attack graph + findings ledger."
                )
            except Exception as e:  # noqa: BLE001 - best-effort capture
                note = (
                    f"Burp Organizer is Pro-only and HTTP capture failed: {e}. "
                    "Findings persist to the AI-OSOP attack graph + findings ledger."
                )
            return MCPExecuteResponse(
                request_id=f"organizer-degraded-{url[:40]}",
                status="success",
                result={
                    "status": "degraded",
                    "provider": "aiosop-graph-ledger",
                    "burp_organizer": False,
                    "url": url,
                    "note": note,
                },
            )
        response = await self.registry.execute_tool(
            self.SERVER_ID,
            "sync_to_organizer",
            {"url": url, "method": method, "body": body},
        )
        self._check_response(response, "sync_to_organizer")
        return response

    async def send_http_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send one HTTP request through Burp's engine (every edition).

        Community-supported transport used by AI-OSOP's deterministic fuzzing
        and probe fallbacks. ``request`` is a flat dict ({"url","method","body",
        "headers"}); returns status_code, response headers and body.
        """
        params: Dict[str, Any] = {
            "url": request.get("url", ""),
            "method": request.get("method", "GET"),
        }
        if request.get("body"):
            params["body"] = request["body"]
        if isinstance(request.get("headers"), dict) and request["headers"]:
            params["headers"] = request["headers"]
        response = await self.registry.execute_tool(
            self.SERVER_ID, "send_http_request", params, timeout_override=60
        )
        result = response.result if isinstance(response.result, dict) else {}
        if response.status != "success" or result.get("error"):
            raise MCPException(f"burp send_http_request failed: {self._extract_error(response)}")
        return result

    async def send_to_decoder(self, text: str) -> MCPExecuteResponse:
        """Send a value to Burp's Decoder tab."""
        response = await self.registry.execute_tool(
            self.SERVER_ID, "send_to_decoder", {"text": text}
        )
        self._check_response(response, "send_to_decoder")
        return response

    async def extension_data_get(self, key: str) -> Optional[str]:
        """Read a value from the extension's persistent data store."""
        response = await self.registry.execute_tool(
            self.SERVER_ID, "extension_data_get", {"key": key}
        )
        if response.status != "success" or not response.result:
            return None
        return response.result.get("value")

    async def extension_data_set(self, key: str, value: str) -> MCPExecuteResponse:
        """Write a value to the extension's persistent data store."""
        response = await self.registry.execute_tool(
            self.SERVER_ID, "extension_data_set", {"key": key, "value": value}
        )
        self._check_response(response, "extension_data_set")
        return response

    async def collaborator_payload(
        self, label: str = "burp-collaborator", context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate an OOB callback payload — Burp Collaborator (Pro) or AI-OSOP OAST.

        BURP-COMMUNITY-001: on Community (or whenever Collaborator is
        unavailable), this degrades *gracefully* instead of raising: the same
        interface transparently mints an AI-OSOP oast-mcp token, which is the
        platform's own out-of-band interaction server (equivalent detection,
        no Burp license involved). The response records which provider served
        the request so evidence provenance stays honest. Only when BOTH
        providers fail does it return an explicit "unavailable" payload with
        the reason — never a raise, never null.
        """
        caps = await self.get_capabilities()
        if caps.reachable and caps.collaborator_available:
            response = await self.registry.execute_tool(self.SERVER_ID, "collaborator_payload", {})
            result = response.result if isinstance(response.result, dict) else {}
            if response.status == "success" and result.get("collab_id") and not result.get("error"):
                return {**result, "provider": "burp-collaborator"}
            # Fall through to the OAST route: the caller needs a usable payload.

        try:
            from ai_osop.adapters.oast_mcp import OASTAdapter

            oast = OASTAdapter(self.registry)
            token, callback_url = await oast.register(label=label, context=context or {})
            if token and callback_url:
                return {
                    "status": "success",
                    "provider": "aiosop-oast",
                    "collab_id": token,
                    "payload": callback_url,
                    "note": (
                        "Burp Collaborator is Pro-only; routed to AI-OSOP "
                        "oast-mcp for equivalent out-of-band detection."
                    ),
                }
            oast_error = "oast-mcp returned empty token/callback_url"
        except Exception as e:  # noqa: BLE001 - degrade, never raise
            oast_error = str(e)
        return {
            "status": "unavailable",
            "provider": None,
            "collab_id": "",
            "payload": "",
            "reason": (
                f"Burp Collaborator unavailable (edition={caps.edition_family}) "
                f"and AI-OSOP oast-mcp failed: {oast_error}"
            ),
            "note": "Start oast-mcp (port 8099) to restore out-of-band detection.",
        }

    async def collaborator_interactions(self, collab_id: str = "") -> List[Dict[str, Any]]:
        """Fetch interactions for a generated Collaborator/OAST payload.

        BURP-COMMUNITY-001: payloads minted on Community are oast-mcp tokens,
        so this polls oast-mcp instead of Burp's Pro-only Collaborator API.
        Unknown ids on a Pro install degrade to an empty list (honest
        "no interactions"), never an error.
        """
        caps = await self.get_capabilities()
        # Community: any payload this stack minted is an OAST token — poll it.
        if not (caps.reachable and caps.collaborator_available):
            if not collab_id:
                return []
            try:
                from ai_osop.adapters.oast_mcp import OASTAdapter

                oast = OASTAdapter(self.registry)
                return await oast.poll(collab_id)
            except Exception:  # noqa: BLE001 - unknown token / oast down
                return []

        response = await self.registry.execute_tool(
            self.SERVER_ID, "collaborator_interactions", {"collab_id": collab_id}
        )
        if response.status != "success" or not response.result:
            return []
        return response.result.get("interactions", [])

    async def export_project_options(self) -> Optional[str]:
        """Export Burp project options as JSON (useful for audit trail)."""
        response = await self.registry.execute_tool(self.SERVER_ID, "export_project_options", {})
        if response.status != "success" or not response.result:
            return None
        return response.result.get("project_options")

    async def set_scan_config(self, config: str) -> MCPExecuteResponse:
        """Persist a scanner config for consumption when Burp Scanner is available."""
        response = await self.registry.execute_tool(
            self.SERVER_ID, "set_scan_config", {"config": config}
        )
        self._check_response(response, "set_scan_config")
        return response
