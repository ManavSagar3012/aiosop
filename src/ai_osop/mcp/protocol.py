"""
MCP Protocol Implementation
Standardized Model Context Protocol for tool integration.
Implements the core MCP spec with async support and structured I/O.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import aiohttp
import structlog
import websockets
from pydantic import BaseModel, Field

from ai_osop.core.config import settings
from ai_osop.core.exceptions import (
    MCPApprovalRequired,
    MCPConnectionError,
    MCPException,
    MCPScopeDenied,
)
from ai_osop.core.telemetry import add_mcp_latency
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger(__name__)


class MCPExecutionGate:
    """Client-side enforcement of a tool's declared ``requires_approval`` /
    ``scope_check`` flags (W3 — declared-but-not-enforced -> real fail-closed gate).

    The Go MCP servers already validate scope *server-side* against the scope
    they received at ``initialize``; this is defense-in-depth ON THE CLIENT so
    the request never leaves the platform process when the target is out of
    scope, and so a high-impact tool flagged ``requires_approval=True`` cannot
    fire without a valid approval wired in. ``None`` gate = no gate configured:
    fail-closed for approval-flagged tools (safer than silently allowing), but
    for ``scope_check`` the server-side check still holds, so we do NOT block
    scope-flagged tools when no client gate is wired (that would break every
    adapter today, where scope is enforced server-side not client-side).

    Override the gate per-call with ``trust_server_scope=True`` for read-only
    tools whose scope is already enforced by the server (e.g. recon listings).
    """

    def __init__(
        self,
        *,
        host_in_scope: Optional[Callable[[str], bool]] = None,
        is_approved: Optional[Callable[[str, str, Dict[str, Any]], bool]] = None,
    ) -> None:
        self._host_in_scope = host_in_scope
        self._is_approved = is_approved

    def check_scope(self, server_id: str, tool_name: str, parameters: Dict[str, Any]) -> None:
        """Raise MCPScopeDenied if the target host of this call is out of scope."""
        if self._host_in_scope is None:
            return  # no client-side scope wired -> rely on server-side check
        host = _extract_target_host(parameters)
        if host is None:
            return  # no target host to check (e.g. a payload-generation call)
        if not self._host_in_scope(host):
            logger.warning(
                "mcp_scope_denied",
                server_id=server_id,
                tool_name=tool_name,
                host=host,
            )
            raise MCPScopeDenied(
                f"MCP tool {server_id}/{tool_name} target host {host!r} is out of scope"
            )

    def check_approval(self, server_id: str, tool_name: str, parameters: Dict[str, Any]) -> None:
        """Raise MCPApprovalRequired if an approval-flagged tool lacks approval."""
        if self._is_approved is None or not self._is_approved(server_id, tool_name, parameters):
            logger.warning(
                "mcp_approval_required",
                server_id=server_id,
                tool_name=tool_name,
            )
            raise MCPApprovalRequired(
                f"MCP tool {server_id}/{tool_name} requires operator approval "
                "and none is wired in (fail-closed)"
            )

    _ALLOWED_PARAMS: Dict[str, set] = {
        "scan_endpoint": {"url", "method", "payload", "headers", "endpoint", "target"},
        "capture_session": {
            "target_host",
            "username",
            "password",
            "register_url",
            "login_url",
            "credentials",
            "user_label",
            "scope_hosts",
            "headers",
        },
        "fetch_page": {"url", "timeout_s", "headers", "params"},
        "write_report": {"title", "body", "findings"},
        "spa_harvest": {
            "target",
            "url",
            "scope_hosts",
            "engagement_id",
            "js_route_limit",
            "max_bundle_fetches",
        },
    }

    _ALLOWED_TYPES: Dict[str, tuple] = {
        "url": (str,),
        "method": (str,),
        "endpoint": (str,),
        "target": (str,),
        "target_host": (str,),
        "register_url": (str,),
        "login_url": (str,),
        "username": (str,),
        "user_label": (str,),
        "title": (str,),
        "body": (str,),
        "headers": (dict,),
        "credentials": (dict,),
        "payload": (dict,),
        "findings": (list,),
        "timeout_s": (int,),
        "scope_hosts": (list,),
        "js_route_limit": (int,),
        "max_bundle_fetches": (int,),
        "engagement_id": (str,),
    }

    def register_tool_schema(self, tool: str, schema: Dict[str, type]) -> None:
        """Merge an adapter-declared schema into the allowed-params map.

        ``schema`` maps arg name -> allowed python type (or tuple of types).
        """
        self._ALLOWED_PARAMS[tool] = set(schema.keys())
        for arg, allowed_t in schema.items():
            self._ALLOWED_TYPES[arg] = (
                tuple(allowed_t) if isinstance(allowed_t, (tuple, list)) else (allowed_t,)
            )

    def check_params(self, tool_name: str, params: Dict[str, Any]) -> None:
        """Fail-closed: every executed tool must have a registered schema."""
        from ai_osop.core.exceptions import ScopeValidationError

        allowed = self._ALLOWED_PARAMS.get(tool_name)
        if allowed is None:
            raise ScopeValidationError(
                f"MCP tool '{tool_name}' has no registered schema; refusing params"
            )
        for k, v in params.items():
            if k not in allowed:
                raise ScopeValidationError(f"Unknown MCP arg '{k}' for tool {tool_name}")
            expected = self._ALLOWED_TYPES.get(k)
            if expected is None:
                continue
            if not isinstance(v, expected):
                raise ScopeValidationError(f"MCP arg '{k}' should be {expected} got {type(v)}")

        for urlk in ("url", "target", "endpoint", "register_url", "login_url", "target_host"):
            u = params.get(urlk)
            if not isinstance(u, str):
                continue
            if ".." in u:
                raise ValueError(f"MCP param '{urlk}' contains traversal (..)")
            if ";" in u:
                raise ValueError(f"MCP param '{urlk}' contains ;")
            if "'" in u or '"' in u:
                raise ValueError(f"MCP param '{urlk}' contains quote character")


def _extract_target_host(parameters: Dict[str, Any]) -> Optional[str]:
    """Best-effort pull of a target host from common MCP parameter shapes.

    MCP tools pass targets in a few keys (url, target, host, domain, endpoint);
    return the hostname for scope comparison, or None when no host is present.
    """
    from urllib.parse import urlparse

    for key in ("url", "target", "endpoint"):
        val = parameters.get(key)
        if isinstance(val, str) and "://" in val:
            parsed = urlparse(val)
            if parsed.hostname:
                return parsed.hostname
        if isinstance(val, str) and val and "://" not in val and "." in val:
            # bare host/domain
            return val.split("/")[0].split(":")[0]
    for key in ("host", "domain"):
        val = parameters.get(key)
        if isinstance(val, str) and val:
            return val.split("/")[0].split(":")[0]
    return None


class MCPToolParameter(BaseModel):
    name: str
    type: str
    # Tolerate third-party MCP servers that omit per-parameter descriptions
    # (reporting-mcp, attack-graph-mcp). Previously strict-required, which made
    # those servers fail init at boot ("4 validation errors for
    # MCPInitializeResponse") and left them permanently unregistered.
    description: Optional[str] = ""
    required: bool = True
    default: Optional[Any] = None
    enum: Optional[List[Any]] = None


class MCPToolDefinition(BaseModel):
    name: str
    description: str
    parameters: List[MCPToolParameter]
    returns: Dict[str, Any]
    timeout_seconds: int = 30
    requires_approval: bool = False
    scope_check: bool = True


class MCPInitializeRequest(BaseModel):
    scope: Dict[str, Any]
    auth_credentials: Dict[str, Any] = Field(default_factory=dict)
    session_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MCPInitializeResponse(BaseModel):
    server_id: str
    # PATCH (REL-002, 2026-06-15): Defaulting `version` so that a partial MCP
    # response missing this field still parses. Real-time verification on
    # 2026-06-15 showed all current servers (recon/payload/shodan/threat-intel/
    # burp/browser/etc.) DO return a version, so this is defense-in-depth only.
    # The actual reason those four MCPs appear "uninitialized" in
    # /system/health/full is that no agent has invoked them yet — initialize
    # is called lazily by each adapter's .initialize() the first time it runs.
    version: str = "unknown"
    capabilities: List[str]
    tools: List[MCPToolDefinition]
    status: str = "ready"


class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Dict[str, Any]
    request_id: str = Field(default_factory=lambda: f"req-{datetime.utcnow().timestamp()}")
    timeout_override: Optional[int] = None


class MCPExecuteResponse(BaseModel):
    request_id: str
    status: str  # success, error, timeout, cancelled
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time_ms: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MCPStateResponse(BaseModel):
    server_id: str
    status: str
    active_requests: int
    queued_requests: int
    uptime_seconds: int
    memory_usage_mb: float
    last_health_check: datetime


@dataclass
class MCPConnection:
    """Managed connection to an MCP server with circuit breaker v2 (half-open support)."""

    server_id: str
    host: str
    port: int
    auth_token: Optional[str] = None
    _session: Optional[aiohttp.ClientSession] = None
    _ws: Optional[websockets.WebSocketClientProtocol] = None
    _initialized: bool = False
    _capabilities: List[str] = field(default_factory=list)
    _tools: Dict[str, MCPToolDefinition] = field(default_factory=dict)
    # Circuit breaker state v2 (Sprint 7)
    _failure_count: int = field(default=0)
    _success_count: int = field(default=0)
    _circuit_open: bool = field(default=False)
    _circuit_opened_at: Optional[datetime] = field(default=None)
    _half_open: bool = field(default=False)
    _recovery_attempts: int = field(default=0)
    _last_success_at: Optional[datetime] = field(default=None)
    _last_failure_at: Optional[datetime] = field(default=None)
    _consecutive_successes: int = field(default=0)
    CIRCUIT_THRESHOLD: int = field(default=5)
    CIRCUIT_RECOVERY_SECONDS: int = field(default=30)
    CIRCUIT_HALF_OPEN_MAX_ATTEMPTS: int = field(default=3)
    CIRCUIT_HALF_OPEN_SUCCESS_REQUIRED: int = field(default=2)
    # MCP Telemetry fields
    started_at: Optional[datetime] = field(default=None)
    reconnect_count: int = field(default=0)
    handshake_latency_ms: Optional[float] = field(default=None)
    _latency_samples: List[float] = field(default_factory=list)
    _max_latency_samples: int = field(default=1000)

    def _circuit_breaker_check(self) -> None:
        """Check circuit state and transition OPEN -> HALF-OPEN if recovery time elapsed."""
        if not self._circuit_open and not self._half_open:
            return
        # If we're in half-open, let the next call through as a probe
        if self._half_open:
            return
        # OPEN state: check if recovery time has elapsed
        if self._circuit_opened_at is None:
            self._circuit_open = False
            return
        elapsed = (datetime.utcnow() - self._circuit_opened_at).total_seconds()
        if elapsed >= self.CIRCUIT_RECOVERY_SECONDS:
            # Transition to HALF-OPEN for probing
            self._circuit_open = False
            self._half_open = True
            self._recovery_attempts += 1
            self._consecutive_successes = 0

    def _record_success(self) -> None:
        """Record a successful call and update circuit state."""
        old_state = self.get_circuit_state()
        self._success_count += 1
        self._last_success_at = datetime.utcnow()
        if self._half_open:
            self._consecutive_successes += 1
            if self._consecutive_successes >= self.CIRCUIT_HALF_OPEN_SUCCESS_REQUIRED:
                # Transition back to CLOSED
                self._half_open = False
                self._failure_count = 0
                self._consecutive_successes = 0
                self._circuit_opened_at = None
        else:
            self._failure_count = 0
        new_state = self.get_circuit_state()
        if old_state != new_state:
            from ai_osop.core.observability import record_circuit_breaker_state

            record_circuit_breaker_state(self.server_id, is_open=(new_state == "open"))

    def _record_failure(self) -> None:
        """Record a failed call and update circuit state."""
        old_state = self.get_circuit_state()
        self._failure_count += 1
        self._last_failure_at = datetime.utcnow()
        if self._half_open:
            # Any failure in half-open goes back to OPEN
            self._half_open = False
            self._circuit_open = True
            self._circuit_opened_at = datetime.utcnow()
            self._consecutive_successes = 0
            # P0-007: cap half-open attempts so a flapping server cannot loop forever
            if self._recovery_attempts >= self.CIRCUIT_HALF_OPEN_MAX_ATTEMPTS:
                # Permanent failure: transition to a terminal state that blocks further probes
                self._circuit_open = True
                self._circuit_opened_at = None  # disables recovery via _circuit_breaker_check
                logger = structlog.get_logger("ai_osop.mcp")
                logger.error(
                    "mcp_circuit_permanent_failure",
                    server_id=self.server_id,
                    recovery_attempts=self._recovery_attempts,
                )
        elif self._failure_count >= self.CIRCUIT_THRESHOLD:
            self._circuit_open = True
            self._circuit_opened_at = datetime.utcnow()
        new_state = self.get_circuit_state()
        if old_state != new_state:
            from ai_osop.core.observability import record_circuit_breaker_state

            record_circuit_breaker_state(self.server_id, is_open=(new_state == "open"))

    def get_circuit_state(self) -> str:
        """Return current circuit state as a string: closed, open, or half_open."""
        if self._circuit_open:
            return "open"
        if self._half_open:
            return "half_open"
        return "closed"

    async def connect(self, max_retries: int = 5) -> None:
        """Establish HTTP and WebSocket connections.

        max_retries controls backoff attempts. Startup warm-up passes 0 (single
        fast attempt) so an unreachable optional server does not block API
        startup ~31s; the connection is still stored for lazy reconnect on first
        real use, which uses the full retry budget.
        """
        # Track reconnect attempts
        if self.started_at is not None:
            self.reconnect_count += 1
        self.started_at = self.started_at or datetime.utcnow()

        self._circuit_breaker_check()
        if self._circuit_open and not self._half_open:
            raise MCPConnectionError(f"MCP server {self.server_id} circuit breaker is open")
        from ai_osop.reliability.retry import retry_with_backoff

        async def _do_connect() -> None:
            if self._session and not self._session.closed:
                await self._session.close()
            self._session = aiohttp.ClientSession(
                headers={"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
            )
            session = self._session
            if session is None:
                raise MCPConnectionError(f"MCP server {self.server_id} has no HTTP session")
            async with session.get(
                f"http://{self.host}:{self.port}/health", timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status != 200:
                    raise MCPConnectionError(f"Health check failed: {resp.status}")

        try:
            await retry_with_backoff(
                _do_connect,
                max_retries=max_retries,
                base_delay=1,
                retry_name=f"mcp_connect_{self.server_id}",
            )
            self._record_success()
        except Exception as e:
            self._record_failure()
            await self.close()
            raise MCPConnectionError(f"Failed to connect to MCP server {self.server_id}: {e}")

    async def initialize(self, request: MCPInitializeRequest) -> MCPInitializeResponse:
        """Initialize server with scope and credentials."""
        self._circuit_breaker_check()
        if self._circuit_open and not self._half_open:
            raise MCPConnectionError(f"MCP server {self.server_id} circuit breaker is open")
        if not self._session or self._session.closed:
            await self.connect()
        session = self._session
        if session is None:
            raise MCPConnectionError(f"MCP server {self.server_id} has no HTTP session")

        import time as _time

        _t0 = _time.monotonic()
        try:
            async with session.post(
                f"http://{self.host}:{self.port}/mcp/initialize",
                json=request.model_dump(),
                timeout=aiohttp.ClientTimeout(total=settings.mcp_initialize_timeout),
            ) as resp:
                _elapsed = (_time.monotonic() - _t0) * 1000
                self.handshake_latency_ms = _elapsed
                data = await resp.json()
                response = MCPInitializeResponse(**data)
                self._capabilities = response.capabilities
                self._tools = {t.name: t for t in response.tools}
                self._initialized = True
                self._record_success()
                return response
        except Exception as e:
            self._record_failure()
            await self.close()
            raise MCPConnectionError(f"MCP server {self.server_id} initialize failed: {e}")

    async def execute(self, request: MCPExecuteRequest) -> MCPExecuteResponse:
        """Execute a tool with timeout, error handling, circuit breaker, and tracing."""
        self._circuit_breaker_check()
        if self._circuit_open and not self._half_open:
            return MCPExecuteResponse(
                request_id=request.request_id,
                status="circuit_open",
                error=f"MCP server {self.server_id} circuit breaker is open",
            )
        if not self._initialized:
            raise MCPException(f"MCP server {self.server_id} not initialized")
        if self._session is None or self._session.closed:
            raise MCPConnectionError(f"MCP server {self.server_id} session is closed")

        tool = self._tools.get(request.tool_name)
        if not tool:
            raise MCPException(f"Tool {request.tool_name} not available on server {self.server_id}")

        timeout = request.timeout_override or tool.timeout_seconds

        with trace_span(
            f"mcp.{self.server_id}.{request.tool_name}",
            attributes={
                "ai_osop.mcp.server_id": self.server_id,
                "ai_osop.mcp.tool_name": request.tool_name,
                "ai_osop.mcp.host": self.host,
                "ai_osop.mcp.port": self.port,
            },
        ):
            try:
                start = datetime.utcnow()
                async with self._session.post(
                    f"http://{self.host}:{self.port}/mcp/execute",
                    json=request.model_dump(),
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    data = await resp.json()
                    elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
                    add_mcp_latency(float(elapsed))
                    # Record latency sample for telemetry histogram
                    if len(self._latency_samples) < self._max_latency_samples:
                        self._latency_samples.append(float(elapsed))
                    response = MCPExecuteResponse(**data)
                    response.execution_time_ms = elapsed
                    self._record_success()
                    return response
            except asyncio.TimeoutError:
                self._record_failure()
                return MCPExecuteResponse(
                    request_id=request.request_id,
                    status="timeout",
                    error=f"Tool {request.tool_name} exceeded {timeout}s timeout",
                )
            except Exception as e:
                self._record_failure()
                return MCPExecuteResponse(
                    request_id=request.request_id, status="error", error=str(e)
                )

    async def get_state(self) -> MCPStateResponse:
        """Get current server state."""
        session = self._session
        if session is None or session.closed:
            raise MCPConnectionError(f"MCP server {self.server_id} session is closed")
        async with session.get(
            f"http://{self.host}:{self.port}/mcp/state",
            timeout=aiohttp.ClientTimeout(total=settings.mcp_initialize_timeout),
        ) as resp:
            data = await resp.json()
            return MCPStateResponse(**data)

    async def list_tools(self) -> List[MCPToolDefinition]:
        """List available tools."""
        return list(self._tools.values())

    def get_telemetry(self) -> Dict[str, Any]:
        """Return live telemetry snapshot for this MCP connection.

        Includes startup time, reconnect count, handshake latency,
        and latency histogram (p50, p95, p99).
        """
        now = datetime.utcnow()
        uptime = (now - self.started_at).total_seconds() if self.started_at else 0.0

        # Compute latency histogram
        samples = self._latency_samples
        hist: Dict[str, float] = {}
        if samples:
            sorted_s = sorted(samples)
            n = len(sorted_s)
            hist = {
                "p50_ms": sorted_s[int(n * 0.50)],
                "p95_ms": sorted_s[int(n * 0.95)],
                "p99_ms": sorted_s[int(n * 0.99)],
                "min_ms": sorted_s[0],
                "max_ms": sorted_s[-1],
                "mean_ms": round(sum(sorted_s) / n, 2),
                "sample_count": n,
            }

        # Total calls and timeout count
        total_calls = len(self._latency_samples) + self._failure_count
        timeout_count = sum(
            1 for s in self._latency_samples if s > 5000
        )  # >5s is timeout territory

        return {
            "server_id": self.server_id,
            "status": self.get_circuit_state(),
            "initialized": self._initialized,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "uptime_seconds": round(uptime, 1),
            "reconnect_count": self.reconnect_count,
            "handshake_latency_ms": (
                round(self.handshake_latency_ms, 2) if self.handshake_latency_ms else None
            ),
            "tool_count": len(self._tools),
            "latency_histogram": hist,
            "total_calls": total_calls,
            "failure_count": self._failure_count,
            "timeout_count": timeout_count,
            "health_status": (
                "healthy"
                if self._initialized and not self._circuit_open
                else "degraded" if self._half_open else "unhealthy"
            ),
        }

    async def close(self) -> None:
        """Clean up connections."""
        if self._session:
            await self._session.close()
        if self._ws:
            await self._ws.close()
        self._initialized = False


class MCPRegistry:
    """Central registry for all MCP server connections."""

    def __init__(self) -> None:
        self._servers: Dict[str, MCPConnection] = {}
        self._event_handlers: Dict[str, List[Callable]] = {}
        self.call_counts: Dict[str, int] = {}
        self.coordination_bus: Optional[Any] = None
        # W3: client-side execution gate enforcing each tool's declared
        # requires_approval / scope_check flags (fail-closed). Set by the
        # orchestrator at startup; None means no gate is wired (approval-
        # flagged tools then fail-closed rather than silently executing).
        self.execution_gate: Optional[MCPExecutionGate] = None

    async def register_server(
        self,
        server_id: str,
        host: str,
        port: int,
        auth_token: Optional[str] = None,
        connect_retries: int = 5,
    ) -> MCPConnection:
        """Register and connect to a new MCP server.

        connect_retries=0 (single attempt) is used for non-blocking startup
        warm-up; the connection is stored regardless so lazy init can retry.
        """
        conn = MCPConnection(server_id=server_id, host=host, port=port, auth_token=auth_token)
        try:
            await conn.connect(max_retries=connect_retries)
            self._servers[server_id] = conn
            import logging

            logging.getLogger("ai_osop.mcp").info(f"Registered server: {server_id}")
        except Exception as e:
            import logging

            logging.getLogger("ai_osop.mcp").warning(
                f"MCP server {server_id} at {host}:{port} unavailable: {e}. Will retry on demand."
            )
            # Store connection anyway so lazy init can retry later
            self._servers[server_id] = conn
        return conn

    async def initialize_server(
        self, server_id: str, scope: Any, credentials: Dict[str, Any], session_id: str
    ) -> MCPInitializeResponse:
        """Initialize a registered server."""
        conn = self._servers.get(server_id)
        if not conn:
            raise MCPConnectionError(f"Server {server_id} not registered")

        # AIOSOP-MCP-SCOPE-001 (2026-07-03): accept either a plain dict or a pydantic
        # scope model. SessionState.scope is a ScopeDefinition, and several vuln_agent
        # call sites passed it RAW (burp/sqli/xss/stored-xss/race/ssrf scans) — which
        # failed MCPInitializeRequest(scope: Dict[str, Any]) validation and silently
        # broke scope initialization for those scans (browser-confirmed XSS in
        # particular always degraded to reflection). Coerce here so every caller works.
        if hasattr(scope, "model_dump"):
            scope = scope.model_dump()

        request = MCPInitializeRequest(
            scope=scope, auth_credentials=credentials, session_id=session_id
        )
        return await conn.initialize(request)

    async def execute_tool(
        self,
        server_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        timeout_override: Optional[int] = None,
        *,
        trust_server_scope: bool = False,
    ) -> MCPExecuteResponse:
        """Execute a tool on a specific server with tracing.

        W3: enforces the tool's declared ``requires_approval`` / ``scope_check``
        flags through the client-side execution gate (fail-closed) BEFORE the
        request leaves the process. ``trust_server_scope=True`` skips the
        client-side scope check for a call whose scope is already enforced by
        the server (read-only recon listings) — approval is NEVER skippable.
        """
        with trace_span(
            f"mcp_registry.execute_tool",
            attributes={
                "ai_osop.mcp.server_id": server_id,
                "ai_osop.mcp.tool_name": tool_name,
            },
        ):
            conn = self._servers.get(server_id)
            if not conn:
                raise MCPConnectionError(f"Server {server_id} not registered")

            _outcome = "allowed"

            def _track(outcome: str) -> None:
                try:
                    from ai_osop.core import metrics_a2

                    metrics_a2.tool_call(tool_name, outcome)
                except Exception:  # noqa: BLE001 - metrics must never block enforcement
                    pass

            tool = conn._tools.get(tool_name)
            if tool is not None and self.execution_gate is not None:
                # Approval is non-negotiable: a tool that declared
                # requires_approval=True must not fire without a wired approval.
                if getattr(tool, "requires_approval", False):
                    try:
                        self.execution_gate.check_approval(server_id, tool_name, parameters)
                    except Exception:
                        _track("denied_approval")
                        raise
                # Scope is defense-in-depth on top of the server-side check, so a
                # caller may opt out per-call when the server already enforces it.
                if getattr(tool, "scope_check", False) and not trust_server_scope:
                    try:
                        self.execution_gate.check_scope(server_id, tool_name, parameters)
                    except Exception:
                        _track("denied_scope")
                        raise

            self.call_counts[server_id] = self.call_counts.get(server_id, 0) + 1
            request = MCPExecuteRequest(
                tool_name=tool_name, parameters=parameters, timeout_override=timeout_override
            )
            try:
                resp = await conn.execute(request)
            except Exception:
                _track("error")
                raise
            _track("allowed")
            return resp

    async def broadcast_execute(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        server_filter: Optional[Callable[[MCPConnection], bool]] = None,
    ) -> Dict[str, MCPExecuteResponse]:
        """Execute a tool across multiple servers with tracing."""
        with trace_span(
            f"mcp_registry.broadcast_execute",
            attributes={
                "ai_osop.mcp.tool_name": tool_name,
            },
        ):
            results = {}
            tasks = []

            for server_id, conn in self._servers.items():
                if server_filter and not server_filter(conn):
                    continue
                if tool_name in conn._tools:
                    task = conn.execute(
                        MCPExecuteRequest(tool_name=tool_name, parameters=parameters)
                    )
                    tasks.append((server_id, task))

            for server_id, task in tasks:
                try:
                    results[server_id] = await task
                except Exception as e:
                    results[server_id] = MCPExecuteResponse(
                        request_id="broadcast", status="error", error=str(e)
                    )

            return results

    def get_server(self, server_id: str) -> Optional[MCPConnection]:
        return self._servers.get(server_id)

    def check_tool_requirements(self, requirements: List[Tuple[str, str]]) -> List[Dict[str, str]]:
        """Return the availability state for required MCP tools without I/O.

        ``unknown`` deliberately does not reject a task: a connection that was
        unavailable during the short non-blocking startup warm-up can still
        reconnect lazily in its adapter.  Conversely, a server that successfully
        initialized but did not advertise a required tool is deterministic
        configuration drift and must be rejected before dispatch.
        """
        statuses: List[Dict[str, str]] = []
        for server_id, tool_name in requirements:
            conn = self._servers.get(server_id)
            if conn is None:
                state = "server_missing"
            elif not conn._initialized:
                state = "unknown"
            elif tool_name not in conn._tools:
                state = "tool_missing"
            else:
                state = "available"
            statuses.append({"server_id": server_id, "tool_name": tool_name, "state": state})
        return statuses

    async def health_check_all(self) -> Dict[str, bool]:
        """Check health of all registered servers."""
        results = {}
        for server_id, conn in self._servers.items():
            try:
                state = await conn.get_state()
                results[server_id] = state.status == "ready"
            except Exception:
                results[server_id] = False
        return results

    # ── Continuous Health Publishing ────────────────────────────────────────

    _health_task: Optional[asyncio.Task] = None
    _last_telemetry_snapshot: Dict[str, Dict[str, Any]] = {}

    def start_health_publisher(self, interval_seconds: int = 30) -> None:
        """Start a background loop that collects and caches telemetry from
        every registered MCP connection at a fixed interval.

        The latest snapshot is accessible via :meth:`get_latest_telemetry` and
        is also published through the coordination bus as ``mcp.health`` events
        so the dashboard, observatory API, and alerting pipeline can consume it
        without polling individual connections.

        Only one publisher runs at a time (start is idempotent).
        """
        if self._health_task is not None and not self._health_task.done():
            return  # already running

        async def _publish_loop() -> None:
            while True:
                try:
                    snapshot: Dict[str, Dict[str, Any]] = {}
                    for server_id, conn in self._servers.items():
                        try:
                            snapshot[server_id] = conn.get_telemetry()
                        except Exception:
                            snapshot[server_id] = {
                                "server_id": server_id,
                                "status": "unknown",
                                "error": "telemetry_collection_failed",
                            }
                    self._last_telemetry_snapshot = snapshot

                    # Publish each server's telemetry as a coordination bus event
                    # so the dashboard and alerting layer see live health.
                    bus = self.coordination_bus
                    for sid, tel in snapshot.items():
                        if bus is None:
                            break
                        try:
                            await bus.publish(
                                "mcp.health",
                                {
                                    "server_id": sid,
                                    "status": tel.get("status"),
                                    "health_status": tel.get("health_status"),
                                    "uptime_seconds": tel.get("uptime_seconds"),
                                    "reconnect_count": tel.get("reconnect_count"),
                                    "latency_p50_ms": tel.get("latency_histogram", {}).get(
                                        "p50_ms"
                                    ),
                                },
                                "mcp_registry",
                            )
                        except Exception:
                            pass
                except Exception:
                    pass
                await asyncio.sleep(interval_seconds)

        self._health_task = asyncio.create_task(_publish_loop())

    async def stop_health_publisher(self) -> None:
        """Cancel the background health publishing loop."""
        if self._health_task is not None and not self._health_task.done():
            self._health_task.cancel()
            try:
                await self._health_task
            except (asyncio.CancelledError, Exception):
                pass
            self._health_task = None

    def get_latest_telemetry(self) -> Dict[str, Dict[str, Any]]:
        """Return the most recent telemetry snapshot for all MCP servers.

        Returns an empty dict if the publisher has never run.
        """
        return self._last_telemetry_snapshot

    async def close_all(self) -> None:
        """Close all connections."""
        await self.stop_health_publisher()
        await asyncio.gather(
            *[conn.close() for conn in self._servers.values()], return_exceptions=True
        )
        self._servers.clear()
