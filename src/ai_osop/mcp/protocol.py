"""
MCP Protocol Implementation
Standardized Model Context Protocol for tool integration.
Implements the core MCP spec with async support and structured I/O.
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

import aiohttp
import websockets
from pydantic import BaseModel, Field

from ai_osop.core.exceptions import MCPConnectionError, MCPException, MCPTimeoutError
from ai_osop.core.models import AuditEvent
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import trace_span, trace_span_with_parent


class MCPToolParameter(BaseModel):
    name: str
    type: str
    description: str
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

    async def connect(self) -> None:
        """Establish HTTP and WebSocket connections."""
        self._circuit_breaker_check()
        if self._circuit_open and not self._half_open:
            raise MCPConnectionError(f"MCP server {self.server_id} circuit breaker is open")
        from ai_osop.reliability.retry import retry_with_backoff
        async def _do_connect():
            self._session = aiohttp.ClientSession(
                headers={"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
            )
            async with self._session.get(
                f"http://{self.host}:{self.port}/health", timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status != 200:
                    raise MCPConnectionError(f"Health check failed: {resp.status}")
        
        try:
            await retry_with_backoff(
                _do_connect,
                max_retries=5,
                base_delay=1,
                retry_name=f"mcp_connect_{self.server_id}"
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
        if not self._session:
            await self.connect()

        try:
            async with self._session.post(
                f"http://{self.host}:{self.port}/mcp/initialize", json=request.model_dump()
            ) as resp:
                data = await resp.json()
                response = MCPInitializeResponse(**data)
                self._capabilities = response.capabilities
                self._tools = {t.name: t for t in response.tools}
                self._initialized = True
                self._record_success()
                return response
        except Exception as e:
            self._record_failure()
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
                return MCPExecuteResponse(request_id=request.request_id, status="error", error=str(e))

    async def get_state(self) -> MCPStateResponse:
        """Get current server state."""
        async with self._session.get(f"http://{self.host}:{self.port}/mcp/state") as resp:
            data = await resp.json()
            return MCPStateResponse(**data)

    async def list_tools(self) -> List[MCPToolDefinition]:
        """List available tools."""
        return list(self._tools.values())

    async def close(self) -> None:
        """Clean up connections."""
        if self._session:
            await self._session.close()
        if self._ws:
            await self._ws.close()


class MCPRegistry:
    """Central registry for all MCP server connections."""

    def __init__(self):
        self._servers: Dict[str, MCPConnection] = {}
        self._event_handlers: Dict[str, List[Callable]] = {}
        self.call_counts: Dict[str, int] = {}

    async def register_server(
        self, server_id: str, host: str, port: int, auth_token: Optional[str] = None
    ) -> MCPConnection:
        """Register and connect to a new MCP server."""
        conn = MCPConnection(server_id=server_id, host=host, port=port, auth_token=auth_token)
        await conn.connect()
        self._servers[server_id] = conn
        import logging
        logging.getLogger("ai_osop.mcp").info(f"Registered server: {server_id}")
        return conn

    async def initialize_server(
        self, server_id: str, scope: Dict[str, Any], credentials: Dict[str, Any], session_id: str
    ) -> MCPInitializeResponse:
        """Initialize a registered server."""
        conn = self._servers.get(server_id)
        if not conn:
            raise MCPConnectionError(f"Server {server_id} not registered")

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
    ) -> MCPExecuteResponse:
        """Execute a tool on a specific server with tracing."""
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

            self.call_counts[server_id] = self.call_counts.get(server_id, 0) + 1
            request = MCPExecuteRequest(
                tool_name=tool_name, parameters=parameters, timeout_override=timeout_override
            )
            return await conn.execute(request)

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
                    task = conn.execute(MCPExecuteRequest(tool_name=tool_name, parameters=parameters))
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

    async def close_all(self) -> None:
        """Close all connections."""
        await asyncio.gather(
            *[conn.close() for conn in self._servers.values()], return_exceptions=True
        )
        self._servers.clear()
