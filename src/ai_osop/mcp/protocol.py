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
    version: str
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
    """Managed connection to an MCP server."""

    server_id: str
    host: str
    port: int
    auth_token: Optional[str] = None
    _session: Optional[aiohttp.ClientSession] = None
    _ws: Optional[websockets.WebSocketClientProtocol] = None
    _initialized: bool = False
    _capabilities: List[str] = field(default_factory=list)
    _tools: Dict[str, MCPToolDefinition] = field(default_factory=dict)

    async def connect(self) -> None:
        """Establish HTTP and WebSocket connections."""
        try:
            self._session = aiohttp.ClientSession(
                headers={"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
            )
            # Test connection with health check
            async with self._session.get(
                f"http://{self.host}:{self.port}/health", timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status != 200:
                    raise MCPConnectionError(
                        f"MCP server {self.server_id} health check failed: {resp.status}"
                    )
        except asyncio.TimeoutError:
            await self.close()
            raise MCPTimeoutError(f"MCP server {self.server_id} connection timed out")
        except Exception as e:
            await self.close()
            raise MCPConnectionError(f"Failed to connect to MCP server {self.server_id}: {e}")

    async def initialize(self, request: MCPInitializeRequest) -> MCPInitializeResponse:
        """Initialize server with scope and credentials."""
        if not self._session:
            await self.connect()

        async with self._session.post(
            f"http://{self.host}:{self.port}/mcp/initialize", json=request.dict()
        ) as resp:
            data = await resp.json()
            response = MCPInitializeResponse(**data)
            self._capabilities = response.capabilities
            self._tools = {t.name: t for t in response.tools}
            self._initialized = True
            return response

    async def execute(self, request: MCPExecuteRequest) -> MCPExecuteResponse:
        """Execute a tool with timeout and error handling."""
        if not self._initialized:
            raise MCPException(f"MCP server {self.server_id} not initialized")

        tool = self._tools.get(request.tool_name)
        if not tool:
            raise MCPException(f"Tool {request.tool_name} not available on server {self.server_id}")

        timeout = request.timeout_override or tool.timeout_seconds

        try:
            start = datetime.utcnow()
            async with self._session.post(
                f"http://{self.host}:{self.port}/mcp/execute",
                json=request.dict(),
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                data = await resp.json()
                elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
                response = MCPExecuteResponse(**data)
                response.execution_time_ms = elapsed
                return response
        except asyncio.TimeoutError:
            return MCPExecuteResponse(
                request_id=request.request_id,
                status="timeout",
                error=f"Tool {request.tool_name} exceeded {timeout}s timeout",
            )
        except Exception as e:
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

    async def register_server(
        self, server_id: str, host: str, port: int, auth_token: Optional[str] = None
    ) -> MCPConnection:
        """Register and connect to a new MCP server."""
        conn = MCPConnection(server_id=server_id, host=host, port=port, auth_token=auth_token)
        await conn.connect()
        self._servers[server_id] = conn
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
        """Execute a tool on a specific server."""
        conn = self._servers.get(server_id)
        if not conn:
            raise MCPConnectionError(f"Server {server_id} not registered")

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
        """Execute a tool across multiple servers."""
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
