"""Fail-closed Burp MCP adapter; Burp provider data is never source authority.

The optional external :8081 transport is only MCP discovery. Consequential
tools must traverse the original signed FlowMCPActionExecutor PostgreSQL CAS,
not this adapter's legacy convenience methods. Observations additionally need
operator-enrolled provider Ed25519 signatures over exact result bytes.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.core.config import Severity, VulnClass, settings
from ai_osop.core.exceptions import MCPException
from ai_osop.core.models import Endpoint, ScopeDefinition, SessionState, Vulnerability
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import (
    MCPExecuteResponse,
    MCPInitializeResponse,
    MCPRegistry,
    SideEffectClass,
)

_ORIGIN = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z")
_KID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_OBSERVER_DOMAIN = b"ai-osop/burp-observation/v1\x00"
_OBSERVATION_FIELDS = frozenset(
    {
        "version",
        "server_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "request_id",
        "tool_name",
        "result_sha256",
        "issued_at",
        "expires_at",
    }
)
_READ_ONLY = frozenset({"get_proxy_history", "get_scan_issues", "get_sitemap", "get_request_by_id"})
_CONSEQUENTIAL = frozenset(
    {
        "scan_target",
        "send_to_repeater",
        "intruder_attack",
        "extension_call",
    }
)


def _canonical(value: Any, *, limit: int) -> bytes:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise MCPException("Burp provider data malformed; outcome unconfirmed") from None
    if len(raw) > limit:
        raise MCPException("Burp provider data exceeds safe bound; outcome unconfirmed")
    return raw


def _exact_origin(value: Any) -> str:
    if type(value) is not str or not 1 <= len(value) <= 2048:
        raise MCPException("Burp observation requires bounded target origin")
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or not _ORIGIN.fullmatch(parsed.hostname.lower())
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.port == 0
            or (parsed.path not in {"", "/"})
            or parsed.query
        ):
            raise ValueError("Origin only")
        port = parsed.port
    except ValueError:
        raise MCPException("Burp observation requires exact authorized origin") from None
    return f"{parsed.scheme}://{parsed.hostname.lower()}{(':'+str(port)) if port else ''}"


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

    def __init__(self, registry: MCPRegistry):
        self.registry = registry
        self._proxy_history_buffer: List[Dict[str, Any]] = []
        self._max_history_size = 10000
        self._scope: Optional[ScopeDefinition] = None
        self._credential_sha256: Optional[str] = None
        self._manifest_sha256: Optional[str] = None

    async def initialize(self, scope: ScopeDefinition, session_id: str) -> None:
        """Negotiate authenticated *metadata* only, not scan authorization."""
        self._scope = None
        self._credential_sha256 = None
        self._manifest_sha256 = None
        if (
            not isinstance(self.registry, MCPRegistry)
            or not isinstance(scope, ScopeDefinition)
            or not scope.authorization_ref
            or not (scope.domains or scope.ips)
            or type(session_id) is not str
            or not 1 <= len(session_id) <= 128
        ):
            raise MCPException("Burp signed scope or MCP registry unavailable")
        connection = self.registry._servers.get(self.SERVER_ID)
        if (
            connection is None
            or connection.server_id != self.SERVER_ID
            or connection.host != "127.0.0.1"
            or not 1 <= connection.port <= 65535
            or type(connection.auth_token) is not str
            or not 20 <= len(connection.auth_token) <= 512
        ):
            raise MCPException("Burp independent loopback credential unavailable")
        try:
            declaration = await self.registry.initialize_server(
                self.SERVER_ID,
                scope=scope.model_dump(mode="json"),
                credentials={},
                session_id=session_id,
            )
        except Exception:
            raise MCPException("Burp MCP initialization unavailable") from None
        if (
            not isinstance(declaration, MCPInitializeResponse)
            or declaration.status != "ready"
            or declaration.server_id != self.SERVER_ID
            or not declaration.tools
            or len(declaration.tools) != len({tool.name for tool in declaration.tools})
            or not {"mcp_bound_receipts_v1", "burp_signed_observations_v1"}.issubset(
                set(declaration.capabilities)
            )
            or any(
                tool.name not in _READ_ONLY | _CONSEQUENTIAL
                or tool.scope_check is not True
                or tool.requires_approval is not True
                or (
                    tool.name in _CONSEQUENTIAL
                    and tool.side_effect_class == SideEffectClass.READ_ONLY
                )
                for tool in declaration.tools
            )
            or connection._initialized is not True
            or connection._session is None
            or connection._session.closed
        ):
            raise MCPException("Burp independently bound MCP declaration unavailable")
        self._scope = scope.model_copy(deep=True)
        self._credential_sha256 = hashlib.sha256(connection.auth_token.encode("utf-8")).hexdigest()
        self._manifest_sha256 = hashlib.sha256(
            _canonical(
                [tool.model_dump(mode="json") for tool in declaration.tools],
                limit=65536,
            )
        ).hexdigest()

    def _connection(self) -> Any:
        if (
            not isinstance(self.registry, MCPRegistry)
            or self._scope is None
            or self._credential_sha256 is None
            or self._manifest_sha256 is None
        ):
            raise MCPException("Burp authorized provider unavailable")
        connection = self.registry._servers.get(self.SERVER_ID)
        if (
            connection is None
            or connection.server_id != self.SERVER_ID
            or connection.host != "127.0.0.1"
            or type(connection.auth_token) is not str
            or hashlib.sha256(connection.auth_token.encode()).hexdigest() != self._credential_sha256
            or connection._initialized is not True
            or connection._session is None
            or connection._session.closed
            or hashlib.sha256(
                _canonical(
                    [tool.model_dump(mode="json") for tool in connection._tools.values()],
                    limit=65536,
                )
            ).hexdigest()
            != self._manifest_sha256
        ):
            raise MCPException("Burp MCP credential or negotiated manifest changed")
        return connection

    async def _current_authority(self) -> Dict[str, str]:
        """Live source-side signed ROE/owner/Flow fence, not caller metadata."""
        from ai_osop.memory.session_memory import SessionMemory

        self._connection()
        context = RequestContext.get()
        scope = self._scope
        memory = getattr(getattr(self.registry, "_budget_callback", None), "__self__", None)
        if (
            not isinstance(memory, SessionMemory)
            or not callable(self.registry._execution_event_callback)
            or scope is None
            or context.get("engagement_id") != scope.engagement_id
            or not all(context.get(field) for field in ("flow_id", "task_id", "user_id"))
        ):
            raise MCPException("Burp current signed Flow/ROE context unavailable")
        try:
            signed = await memory.assert_signed_authorization(scope.engagement_id)
            session = await memory.load_session_state(scope.engagement_id)
            flow = await memory.load_flow(context["flow_id"])
        except Exception:
            raise MCPException("Burp signed source authority unavailable") from None
        if (
            signed is None
            or not isinstance(session, SessionState)
            or session.scope.engagement_id != scope.engagement_id
            or session.scope.authorization_ref != scope.authorization_ref
            or session.created_by != context["user_id"]
            or getattr(signed, "authorization_id", None) != scope.authorization_ref
            or not getattr(signed, "policy_sha256", None)
            or getattr(flow, "engagement_id", None) != scope.engagement_id
            or getattr(flow, "id", None) != context["flow_id"]
            or getattr(flow, "status", None) not in {"pending", "running"}
        ):
            raise MCPException("Burp signed authorization or Flow ownership changed")
        self._connection()
        return context

    def _scope_origin(self, origin: str) -> str:
        parsed = urlsplit(origin)
        scope = self._scope
        if scope is None:
            raise MCPException("Burp authorized provider unavailable")
        if (
            parsed.hostname not in {value.lower() for value in scope.domains}
            and parsed.hostname not in {value.lower() for value in scope.ips}
        ) or parsed.hostname in {value.lower() for value in scope.exclusions}:
            raise MCPException("Burp observation origin outside exact signed scope")
        return origin

    @staticmethod
    def _signed_observation(response: Any, tool: str, context: Dict[str, str]) -> Dict[str, Any]:
        """Exact signed result SHA, provider identity, scope, and short TTL."""
        if (
            not isinstance(response, MCPExecuteResponse)
            or response.status != "success"
            or response.error is not None
            or type(response.result) is not dict
            or any(
                response.result.get(k) in {True, "error", "unknown", "simulated"}
                for k in ("isError", "error", "status", "simulated")
                if not isinstance(response.result.get(k), (dict, list))
            )
        ):
            raise MCPException("Burp provider action unavailable; outcome UNKNOWN")
        receipt = (
            response.metadata.get("burp_observation") if type(response.metadata) is dict else None
        )
        if type(receipt) is not dict or set(receipt) != {"claims", "kid", "signature"}:
            raise MCPException("Burp independently signed observation unavailable")
        claims = receipt["claims"]
        if type(claims) is not dict or set(claims) != _OBSERVATION_FIELDS:
            raise MCPException("Burp observation binding unavailable")
        now = int(time.time())
        if (
            type(claims.get("version")) is not int
            or claims["version"] != 1
            or any(
                claims.get(k) != expected
                for k, expected in (
                    ("server_id", "burp-mcp"),
                    ("engagement_id", context["engagement_id"]),
                    ("flow_id", context["flow_id"]),
                    ("task_id", context["task_id"]),
                    ("request_id", response.request_id),
                    ("tool_name", tool),
                )
            )
            or type(claims.get("issued_at")) is not int
            or type(claims.get("expires_at")) is not int
            or not now - 5
            <= claims["issued_at"]
            <= now
            < claims["expires_at"]
            <= claims["issued_at"] + 15
            or type(claims.get("result_sha256")) is not str
            or _SHA.fullmatch(claims["result_sha256"]) is None
            or claims["result_sha256"]
            != hashlib.sha256(_canonical(response.result, limit=131072)).hexdigest()
            or type(receipt["kid"]) is not str
            or _KID.fullmatch(receipt["kid"]) is None
            or type(receipt["signature"]) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{86}", receipt["signature"]) is None
        ):
            raise MCPException("Burp observation identity, digest, or freshness invalid")
        try:
            config = json.loads(os.environ.get("OSOP_BURP_MCP_OBSERVATION_TRUST_JSON", ""))
            if type(config) is not dict or not 1 <= len(config) <= 8:
                raise ValueError("Trust unavailable")
            encoded = config[receipt["kid"]]
            if type(encoded) is not str or len(encoded) != 43:
                raise ValueError("Trust key unavailable")
            key = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
            signature = base64.b64decode(receipt["signature"] + "==", altchars=b"-_", validate=True)
            if (
                len(key) != 32
                or len(signature) != 64
                or base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") != encoded
                or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
                != receipt["signature"]
            ):
                raise ValueError("Noncanonical trust")
            Ed25519PublicKey.from_public_bytes(key).verify(
                signature, _OBSERVER_DOMAIN + _canonical(claims, limit=3072)
            )
        except (ValueError, KeyError, TypeError, InvalidSignature, binascii.Error):
            raise MCPException("Burp independently trusted observation unavailable") from None
        return response.result

    async def _observe(self, tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if settings.environment.strip().lower() in {"production", "prod"}:
            # The legacy adapter path knows only a RequestContext, not an
            # independently approved durable original 0027 Action. Even a
            # provider-signed read-only result cannot mint human authority.
            # Operators must use dispatch_prepared_action, whose source
            # authorizes and consumes exactly one approved invocation first.
            raise MCPException("Original reviewed Burp Flow Action required")
        context = await self._current_authority()
        connection = self._connection()
        definition = connection._tools.get(tool)
        if (
            tool not in _READ_ONLY
            or definition is None
            or definition.side_effect_class != SideEffectClass.READ_ONLY
            or definition.requires_approval is not True
        ):
            raise MCPException("Burp read-only tool admission unavailable")
        expected_request_id = "req-" + uuid.uuid4().hex
        try:
            response = await self.registry.execute_tool(
                self.SERVER_ID, tool, params, request_id=expected_request_id
            )
        except Exception:
            raise MCPException("Burp provider transport ambiguous; outcome UNKNOWN") from None
        # An action may have been accepted despite a lost ACK; NO retry.
        if getattr(response, "request_id", None) != expected_request_id:
            raise MCPException("Burp provider response identity mismatch; outcome UNKNOWN")
        await self._current_authority()
        return self._signed_observation(response, tool, context)

    async def dispatch_prepared_action(
        self,
        executor: Any,
        binding: Dict[str, Any],
        operator: Dict[str, Any],
        action_id: str,
        expected_tool: str,
    ) -> Dict[str, Any]:
        """Single governed Burp dispatch entry through current original 0027.

        Read-only signed observations are still *provider testimony*; this
        returns only the durable status, never alleged target-side effects.
        """
        from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor

        self._connection()
        if (
            not isinstance(executor, FlowMCPActionExecutor)
            or executor.registry is not self.registry
            or expected_tool not in _CONSEQUENTIAL | _READ_ONLY
            or type(action_id) is not str
            or re.fullmatch(r"action-[a-f0-9]{32}", action_id) is None
            or type(binding) is not dict
            or type(operator) is not dict
        ):
            raise MCPException("Burp durable signed Action authority unavailable")
        try:
            await executor._authority(binding, operator)
            row = await executor.store.get(binding, operator["sub"], action_id)
        except Exception:
            raise MCPException("Burp signed Action source authority unavailable") from None
        if (
            type(row) is not dict
            or row.get("status") != "prepared"
            or row.get("server_id") != self.SERVER_ID
            or row.get("tool_name") != expected_tool
        ):
            raise MCPException("Burp prepared action identity unavailable")
        try:
            result = await executor.dispatch(binding, operator, action_id)
        except Exception:
            raise MCPException(
                "Burp signed Action outcome UNKNOWN; inspect readback, never retry"
            ) from None
        return {
            "status": "finished" if result.get("status") == "finished" else "unknown",
            "execution_authority": "source_signed_flow_action",
            "independent_target_effect_verified": False,
        }

    @staticmethod
    def _deny_direct_execution() -> None:
        raise MCPException("Burp direct execution denied; use signed prepared Flow Action")

    async def scan_target(
        self, url: str, config: Optional[Dict[str, Any]] = None
    ) -> MCPExecuteResponse:
        """Direct scans have no signed Action claim; never execute them."""
        self._deny_direct_execution()

    async def get_proxy_history(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve captured proxy traffic with optional filtering."""
        if type(filters) is not dict or set(filters) != {"origin"}:
            raise MCPException("Burp history authorization unavailable: exact origin required")
        origin = self._scope_origin(_exact_origin(filters["origin"]))
        result = await self._observe(
            "get_proxy_history", {"filters": {"origin": origin}, "limit": 1000, "offset": 0}
        )
        entries = result.get("entries")
        if (
            not isinstance(entries, list)
            or len(entries) > 1000
            or any(
                type(entry) is not dict or not self._same_origin(entry.get("url"), origin)
                for entry in entries
            )
        ):
            raise MCPException("Burp proxy history observation is malformed")
        # Proxy bodies, headers, and cookies are private cross-user data, even
        # if provider-signed. Only bounded exact-origin request metadata exits.
        safe = [
            {
                "id": e["id"],
                "url": e["url"],
                "method": e["method"],
                "status_code": e.get("status_code"),
            }
            for e in entries
            if type(e.get("id")) is str
            and len(e["id"]) <= 128
            and e.get("method") in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
            and type(e.get("url")) is str
            and len(e["url"]) <= 2048
        ]
        if len(safe) != len(entries):
            raise MCPException("Burp history metadata invalid")
        self._update_history_buffer(safe)
        return safe

    async def get_scan_issues(self, target: Optional[str] = None) -> List[Vulnerability]:
        """Retrieve and normalize scanner findings."""
        origin = self._scope_origin(_exact_origin(target))
        result = await self._observe("get_scan_issues", {"target": origin})
        raw_issues = result.get("issues")
        if (
            not isinstance(raw_issues, list)
            or len(raw_issues) > 500
            or any(
                type(issue) is not dict or not self._same_origin(issue.get("url"), origin)
                for issue in raw_issues
            )
        ):
            raise MCPException("Burp scan issue observation is malformed")
        vulnerabilities = []

        for issue in raw_issues:
            vuln = self._normalize_scan_issue(issue)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def send_to_repeater(
        self, request: Dict[str, Any], tab_name: Optional[str] = None
    ) -> MCPExecuteResponse:
        """Requires independent persisted approval, not adapter caller input."""
        self._deny_direct_execution()

    async def intruder_attack(
        self,
        request: Dict[str, Any],
        payload_positions: List[Dict[str, Any]],
        payload_set: List[str],
        config: Optional[Dict[str, Any]] = None,
    ) -> MCPExecuteResponse:
        """No direct Intruder; use durable signed one-shot Flow Action."""
        self._deny_direct_execution()

    async def extension_call(
        self, extension_name: str, method: str, params: Dict[str, Any]
    ) -> MCPExecuteResponse:
        """Never launch caller-selected extension via this adapter."""
        self._deny_direct_execution()

    async def get_sitemap(self, url_prefix: Optional[str] = None) -> List[Endpoint]:
        """Extract site map as normalized endpoints."""
        if self._scope is None:
            raise MCPException("Burp authorized provider unavailable")
        origin = self._scope_origin(_exact_origin(url_prefix))
        result = await self._observe("get_sitemap", {"url_prefix": origin})
        endpoints = []
        rows = result.get("entries")
        if (
            not isinstance(rows, list)
            or len(rows) > 1000
            or any(
                type(entry) is not dict or not self._same_origin(entry.get("url"), origin)
                for entry in rows
            )
        ):
            raise MCPException("Burp sitemap observation is malformed")
        for entry in rows:
            ep = Endpoint(
                url=entry.get("url"),
                method=entry.get("method", "GET"),
                status_code=entry.get("status_code"),
                title=entry.get("title"),
                technologies=entry.get("technologies", []),
                parameters=entry.get("parameters", []),
                auth_required=entry.get("auth_required", False),
                asset_id=entry.get("asset_id", ""),
                source="burp_sitemap_provider_reported",
                confidence=0.3,
                engagement_id=self._scope.engagement_id,
            )
            endpoints.append(ep)

        return endpoints

    @staticmethod
    def _same_origin(value: Any, origin: str) -> bool:
        if type(value) is not str or len(value) > 2048:
            return False
        try:
            parsed = urlsplit(value)
            base = urlsplit(origin)
            return (
                parsed.scheme == base.scheme
                and parsed.hostname == base.hostname
                and (parsed.port or (443 if parsed.scheme == "https" else 80))
                == (base.port or (443 if base.scheme == "https" else 80))
                and parsed.username is None
                and parsed.password is None
                and not parsed.fragment
            )
        except ValueError:
            return False

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
            title=str(issue.get("name", "Unverified Burp candidate"))[:160],
            description="Provider-reported candidate; independent target effect unverified",
            evidence=[
                {
                    "type": "provider_reported_candidate",
                    "independent_target_effect_verified": False,
                }
            ],
            tool_source="burp_scanner_unverified",
            endpoint_id=None,
            confidence=0.3,
            entry_point=False,
            requires_auth=False,
            exploitability="high" if burp_severity == "High" else "medium",
            engagement_id=self._scope.engagement_id,
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

        return VulnClass.RCE  # Default to most restrictive handling

    def _map_burp_to_cwe(self, issue_type: str) -> Optional[str]:
        """Map Burp issue to CWE identifier."""
        cwe_map = {
            "SQL injection": "CWE-89",
            "Cross-site scripting": "CWE-79",
            "SSRF": "CWE-918",
            "XML external entity injection": "CWE-611",
            "OS command injection": "CWE-78",
            "File path traversal": "CWE-22",
            "Insecure deserialization": "CWE-502",
        }
        return cwe_map.get(issue_type)

    def _update_history_buffer(self, entries: List[Dict[str, Any]]) -> None:
        """Maintain circular buffer of proxy history."""
        self._proxy_history_buffer.extend(entries)
        if len(self._proxy_history_buffer) > self._max_history_size:
            self._proxy_history_buffer = self._proxy_history_buffer[-self._max_history_size :]

    async def get_request_by_id(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve specific request from proxy history."""
        if type(request_id) is not str or not 1 <= len(request_id) <= 128:
            raise MCPException("Burp request identity unavailable")
        for entry in self._proxy_history_buffer:
            if entry.get("id") == request_id:
                await self._current_authority()
                return dict(entry)
        # Never retrieve arbitrary private cross-tenant request bodies by ID.
        raise MCPException("Burp request not in signed origin-scoped history")
