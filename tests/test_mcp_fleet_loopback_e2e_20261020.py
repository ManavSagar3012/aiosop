"""REAL HTTP loopback-only MCP transport/fleet qualification.

Each server binds an OS-allocated ephemeral port on 127.0.0.1 and runs in the
pytest event loop. No app/API lifespan, Redis/PostgreSQL, configured provider,
target, payment service, Docker, or production MCP endpoint is ever started.

Scope note: initialization returns the advertised tool manifest, and
MCPConnection.list_tools() reads that in-memory manifest. This protocol does
not use an independent GET/POST tools/list endpoint.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest
from aiohttp import web

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import MCPConnectionError
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry


@dataclass
class DisposableMCP:
    """One genuine HTTP server; never a production MCP adapter or tool target."""

    server_id: str
    auth_token: str | None = None
    health_code: int = 200
    initialization_mode: str = "ready"
    execution_mode: str = "echo"
    delay_seconds: float = 1.2
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    runner: web.AppRunner | None = None
    port: int = 0
    execute_entered: asyncio.Event = field(default_factory=asyncio.Event)
    unblock: asyncio.Event = field(default_factory=asyncio.Event)

    async def start(self) -> "DisposableMCP":
        app = web.Application()
        app.router.add_get("/health", self.health)
        app.router.add_post("/mcp/initialize", self.initialize)
        app.router.add_post("/mcp/execute", self.execute)
        app.router.add_get("/mcp/state", self.state)
        app.router.add_post("/mcp/request/status", self.status)
        app.router.add_post("/mcp/cancel", self.cancel)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        assert site._server is not None
        sockets = site._server.sockets
        assert len(sockets) == 1
        assert sockets[0].getsockname()[0] == "127.0.0.1"
        self.port = sockets[0].getsockname()[1]
        assert 1 <= self.port <= 65535
        return self

    def _authorized(self, request: web.Request) -> bool:
        return self.auth_token is None or (
            request.headers.get("Authorization") == f"Bearer {self.auth_token}"
        )

    def _record(self, name: str, data: dict[str, Any]) -> None:
        self.calls.append((name, data))

    async def health(self, request: web.Request) -> web.Response:
        self._record("health", {})
        if not self._authorized(request):
            return web.Response(status=401)
        return web.json_response({"status": "healthy"}, status=self.health_code)

    async def initialize(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return web.Response(status=401)
        body = await request.json()
        self._record("initialize", body)
        if self.initialization_mode == "malformed":
            return web.Response(text="{broken", content_type="application/json")
        if self.initialization_mode == "http500":
            return web.Response(status=500, text="temporary local failure")
        payload = {
            "server_id": (
                "foreign-unregistered-mcp"
                if self.initialization_mode == "wrong_identity"
                else self.server_id
            ),
            "version": "local-disposable-only",
            "capabilities": ["mcp_request_status_v1", "mcp_cancel_request_v1"],
            "status": "ready",
            "tools": [
                {
                    "name": "get_echo",
                    "description": "Return a local inert payload",
                    "parameters": [
                        {
                            "name": "message",
                            "type": "string",
                            "description": "Inert local string",
                            "required": True,
                        }
                    ],
                    "returns": {"type": "object"},
                    "scope_check": True,
                    "requires_approval": False,
                    "side_effect_class": "READ_ONLY",
                    "timeout_seconds": 1,
                },
                {
                    "name": "scan_target",
                    "description": "Intentionally DENIED active operation",
                    "parameters": [],
                    "returns": {},
                    "scope_check": True,
                    "requires_approval": True,
                    "side_effect_class": "RECON_ACTIVE",
                    "timeout_seconds": 1,
                },
            ],
        }
        if self.initialization_mode == "http500_valid":
            return web.json_response(payload, status=500)
        return web.json_response(payload)

    async def execute(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return web.Response(status=401)
        body = await request.json()
        self._record("execute", body)
        self.execute_entered.set()
        mode = self.execution_mode
        if mode == "wait":
            await asyncio.wait_for(self.unblock.wait(), timeout=4)
        if mode == "slow":
            await asyncio.sleep(self.delay_seconds)
        if mode == "http500":
            return web.Response(status=500, text="inert local HTTP failure")
        if mode == "bad_json":
            return web.Response(text="{not-valid-json", content_type="application/json")
        if mode == "wrong_request":
            return web.json_response(
                {
                    "request_id": "req-foreign",
                    "status": "success",
                    "result": {"echo": "wrong identity"},
                }
            )
        if mode == "http500_forged_success":
            return web.json_response(
                {
                    "request_id": body["request_id"],
                    "status": "success",
                    "result": {"echo": "untrusted 500"},
                },
                status=500,
            )
        return web.json_response(
            {
                "request_id": body["request_id"],
                "status": "success",
                "result": {"echo": body.get("parameters", {}).get("message", "")},
            }
        )

    async def state(self, request: web.Request) -> web.Response:
        self._record("state", {})
        return web.json_response(
            {
                "server_id": self.server_id,
                "status": "ready",
                "active_requests": 0,
                "queued_requests": 0,
                "uptime_seconds": 1,
                "memory_usage_mb": 1.0,
                "last_health_check": "2026-10-20T00:00:00+00:00",
            }
        )

    async def status(self, request: web.Request) -> web.Response:
        body = await request.json()
        self._record("status", body)
        return web.json_response(
            {
                "request_id": body.get("request_id"),
                "status": "completed",
                "verified": False,
            }
        )

    async def cancel(self, request: web.Request) -> web.Response:
        body = await request.json()
        self._record("cancel", body)
        return web.json_response(
            {
                "request_id": body.get("request_id"),
                "status": "cancelled",
                "verified": False,
                "stopped": False,
            }
        )

    async def close(self) -> None:
        self.unblock.set()
        if self.runner is not None:
            await self.runner.cleanup()

    def called(self, name: str) -> int:
        return sum(event == name for event, _ in self.calls)


@pytest.fixture
async def local_fleet():
    servers: list[DisposableMCP] = []
    registries: list[MCPRegistry] = []

    async def serve(server_id: str, **options: Any) -> DisposableMCP:
        server = await DisposableMCP(server_id, **options).start()
        servers.append(server)
        return server

    def registry() -> MCPRegistry:
        item = MCPRegistry()
        registries.append(item)
        return item

    yield serve, registry
    # Release TCP clients BEFORE the disposable listening socket, even on failures.
    for item in registries:
        await asyncio.wait_for(item.close_all(), timeout=5)
    for server in servers:
        await asyncio.wait_for(server.close(), timeout=5)
    RequestContext.clear()


async def connected(
    registry: MCPRegistry, server: DisposableMCP, *, token: str | None = None
) -> MCPConnection:
    conn = await registry.register_server(
        server.server_id,
        "127.0.0.1",
        server.port,
        auth_token=token,
    )
    initialized = await registry.initialize_server(
        server.server_id,
        {},
        {},
        "local-ephemeral-only",
    )
    assert initialized.server_id == server.server_id
    assert initialized.status == "ready"
    return conn


async def local_budget(engagement: str, tool: str, agent: str | None) -> bool:
    """Allow only this synthetic engagement; no application DB or provider."""
    return engagement == "eng-local-fleet" and bool(tool) and agent is not None


class InertAuthority:
    """Pure in-memory ROE/Task inputs, not a production storage adapter or HTTP mock.

    The actual authorization/verification functions still run unpatched.
    Only the real HTTP transport is asserted end-to-end; this model cannot
    demonstrate PostgreSQL-backed signed approval persistence.
    """

    def __init__(self) -> None:
        self.session = SessionState(
            session_id="eng-local-fleet",
            phase="reconnaissance",
            scope=ScopeDefinition(
                engagement_id="eng-local-fleet",
                domains=["disposable.test"],
                authorization_ref="fixture-local-only",
            ),
        )
        self.task = Task(
            id="task-local-fleet",
            type="inert",
            agent_type=AgentType.RECON,
            engagement_id="eng-local-fleet",
            status="running",
        )

    async def load_session_state(self, engagement_id: str) -> SessionState | None:
        return self.session if engagement_id == self.session.session_id else None

    async def load_task(self, task_id: str) -> Task | None:
        return self.task if task_id == self.task.id else None

    async def is_task_approved(
        self,
        task_id: str,
        engagement_id: str,
        approval_id: str,
    ) -> bool:
        return False

    async def consume_mcp_tool_budget(
        self,
        engagement_id: str,
        tool: str,
        agent: str | None,
    ) -> bool:
        return engagement_id == "eng-local-fleet"


def request_context() -> None:
    RequestContext.clear()
    RequestContext.bind(
        engagement_id="eng-local-fleet",
        task_id="task-local-fleet",
        flow_id="flow-local-fleet",
        subtask_id="subtask-local-fleet",
    )


@pytest.mark.asyncio
async def test_multi_server_real_health_initialize_cached_list_and_safe_echo(local_fleet):
    serve, new_registry = local_fleet
    one = await serve("loopback-a")
    two = await serve("loopback-b")
    registry = new_registry()
    registry.set_budget_callback(local_budget)
    request_context()
    first = await connected(registry, one)
    second = await connected(registry, two)

    assert one.called("health") == two.called("health") == 1
    assert one.called("initialize") == two.called("initialize") == 1
    assert one.calls[1][1]["session_id"] == "local-ephemeral-only"
    tools = await first.list_tools()
    assert {tool.name for tool in tools} == {"get_echo", "scan_target"}
    assert (
        next(tool for tool in tools if tool.name == "get_echo").side_effect_class.value
        == "READ_ONLY"
    )
    assert {manifest.tool_name for manifest in registry.get_server_manifests("loopback-a")} == {
        "get_echo",
        "scan_target",
    }
    assert registry.get_server("loopback-b") is second
    assert first._initialized and second._initialized
    result = await registry.execute_tool(
        "loopback-a",
        "get_echo",
        {"message": "harmless local fixture"},
        request_id="req-local-success-1",
    )
    other = await registry.execute_tool(
        "loopback-b",
        "get_echo",
        {"message": "different local port"},
        request_id="req-local-success-2",
    )
    assert result.status == other.status == "success"
    assert result.result == {"echo": "harmless local fixture"}
    assert other.result == {"echo": "different local port"}
    assert one.called("execute") == two.called("execute") == 1
    assert first._session is not None and not first._session.closed
    assert (await registry.ping_server("loopback-a"))["status"] == "healthy"
    assert await registry.health_check_all() == {"loopback-a": True, "loopback-b": True}


@pytest.mark.asyncio
async def test_disposable_fleet_common_transport_for_all_declared_adapter_names(local_fleet):
    """Qualifies the common MCP network contract, NOT live adapter functionality."""
    serve, new_registry = local_fleet
    names = (
        "burp-mcp",
        "recon-mcp",
        "payload-mcp",
        "nuclei-mcp",
        "shodan-mcp",
        "threat-intel-mcp",
        "security-bridge",
        "browser-mcp",
        "source-map-mcp",
        "cloud-mcp",
        "turbo-intruder-mcp",
    )
    assert len(names) == len(set(names))
    instances = [await serve(name) for name in names]
    registry = new_registry()
    registry.set_budget_callback(local_budget)
    request_context()
    for server in instances:
        conn = await connected(registry, server)
        assert len(await conn.list_tools()) == 2
    assert set(registry.get_all_manifests()) == set(names)
    for server in instances:
        result = await registry.execute_tool(
            server.server_id,
            "get_echo",
            {"message": server.server_id},
            request_id=f"req-fleet-{server.server_id}",
        )
        assert result.status == "success"
        assert result.result == {"echo": server.server_id}
        assert server.called("execute") == 1
        assert server.called("initialize") == 1
        assert server.called("health") == 1
    assert registry.call_counts == {name: 1 for name in names}


@pytest.mark.asyncio
async def test_real_auth_header_and_unauthenticated_health_fail_closed(local_fleet):
    serve, new_registry = local_fleet
    server = await serve("loopback-private", auth_token="only-fixture-local")
    registry = new_registry()
    with pytest.raises(MCPConnectionError):
        await registry.register_server(server.server_id, "127.0.0.1", server.port)
    assert server.called("initialize") == server.called("execute") == 0
    assert registry.get_server(server.server_id) is None
    await connected(registry, server, token="only-fixture-local")
    assert server.called("initialize") == 1
    assert server.called("execute") == 0


@pytest.mark.asyncio
async def test_initialize_malformed_http500_and_health500_are_not_ready(local_fleet):
    serve, new_registry = local_fleet
    for mode in ("malformed", "http500", "http500_valid", "wrong_identity"):
        server = await serve(f"loopback-init-{mode}", initialization_mode=mode)
        registry = new_registry()
        conn = await registry.register_server(server.server_id, "127.0.0.1", server.port)
        with pytest.raises(MCPConnectionError):
            await registry.initialize_server(server.server_id, {}, {}, "init-denied")
        assert not conn._initialized
        assert not await conn.list_tools()
        assert server.called("execute") == 0
    bad = await serve("loopback-health500", health_code=500)
    registry = new_registry()
    with pytest.raises(MCPConnectionError):
        await registry.register_server(bad.server_id, "127.0.0.1", bad.port)
    assert bad.called("initialize") == bad.called("execute") == 0


@pytest.mark.asyncio
async def test_uninitialized_or_unregistered_or_undeclared_action_never_reaches_http(local_fleet):
    serve, new_registry = local_fleet
    server = await serve("loopback-uninitialized")
    registry = new_registry()
    registry.set_budget_callback(local_budget)
    request_context()
    await registry.register_server(server.server_id, "127.0.0.1", server.port)
    with pytest.raises(Exception, match="not initialized"):
        await registry.execute_tool(
            server.server_id,
            "get_echo",
            {"message": "inert"},
            request_id="req-uninitialized",
        )
    assert server.called("execute") == 0
    await registry.initialize_server(server.server_id, {}, {}, "init-safe")
    with pytest.raises(Exception, match="not available"):
        await registry.execute_tool(
            server.server_id,
            "never_declared",
            {},
            request_id="req-undeclared",
        )
    assert server.called("execute") == 0
    with pytest.raises(MCPConnectionError):
        await registry.execute_tool("nonexistent", "get_echo", {}, request_id="req-missing")
    assert server.called("execute") == 0


@pytest.mark.asyncio
async def test_active_or_target_bearing_calls_denied_without_authority_before_http(local_fleet):
    serve, new_registry = local_fleet
    server = await serve("loopback-safety")
    registry = new_registry()
    await connected(registry, server)
    RequestContext.clear()
    active = await registry.execute_tool(
        server.server_id,
        "scan_target",
        {},
        request_id="req-no-target",
    )
    assert active.status == "scope_denied"
    target = await registry.execute_tool(
        server.server_id,
        "get_echo",
        {"target": "https://outside.invalid"},
        request_id="req-unapproved-target",
    )
    assert target.status in {"scope_context_missing", "scope_unavailable", "scope_denied"}
    assert server.called("execute") == 0


@pytest.mark.asyncio
async def test_budget_exhaustion_is_denied_before_http_and_never_retried(local_fleet):
    serve, new_registry = local_fleet
    server = await serve("loopback-no-budget")
    registry = new_registry()
    await connected(registry, server)
    request_context()

    async def exhausted(engagement: str, tool: str, agent: str | None) -> bool:
        return False

    registry.set_budget_callback(exhausted)
    result = await registry.execute_tool(
        server.server_id,
        "get_echo",
        {"message": "blocked"},
        request_id="req-exhausted",
    )
    assert result.status == "quota_exceeded"
    assert server.called("execute") == 0

    async def broken(engagement: str, tool: str, agent: str | None) -> bool:
        raise OSError("secret local callback detail must not escape")

    registry.set_budget_callback(broken)
    unknown = await registry.execute_tool(
        server.server_id,
        "get_echo",
        {},
        request_id="req-quota-unavailable",
    )
    assert unknown.status == "quota_unavailable"
    assert "secret local" not in str(unknown.model_dump())
    assert server.called("execute") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["http500", "bad_json", "slow"])
async def test_execute_transport_500_malformed_and_timeout_stay_unknown(local_fleet, mode):
    serve, new_registry = local_fleet
    server = await serve(f"loopback-fault-{mode}", execution_mode=mode)
    registry = new_registry()
    registry.set_budget_callback(local_budget)
    request_context()
    conn = await connected(registry, server)
    rid = f"req-fault-{mode}"
    response = await asyncio.wait_for(
        registry.execute_tool(
            server.server_id, "get_echo", {"message": "local only"}, request_id=rid
        ),
        timeout=4,
    )
    assert response.status == "unknown"
    assert response.request_id == rid
    assert server.called("execute") == 1
    assert conn._executions[rid].outcome == "unknown"
    replay = await registry.execute_tool(
        server.server_id,
        "get_echo",
        {"message": "local only"},
        request_id=rid,
    )
    assert replay.status == "duplicate_request"
    assert server.called("execute") == 1


@pytest.mark.asyncio
async def test_real_http_provider_result_is_not_signed_completion_or_target_proof(local_fleet):
    serve, new_registry = local_fleet
    server = await serve("loopback-unverified-status")
    registry = new_registry()
    authority = InertAuthority()
    registry.set_budget_callback(authority.consume_mcp_tool_budget)
    request_context()
    await connected(registry, server)
    response = await registry.execute_tool(
        server.server_id,
        "get_echo",
        {"message": "inert"},
        request_id="req-unverified-result",
    )
    assert response.status == "success"  # A provider HTTP/tool acknowledgment ONLY.
    reported = await registry.reconcile_execution(
        server.server_id,
        "req-unverified-result",
        "eng-local-fleet",
        "task-local-fleet",
    )
    assert reported["status"] == "unknown"
    assert server.called("status") == 1
    assert server.called("execute") == 1


@pytest.mark.asyncio
async def test_foreign_cancel_or_unverified_stop_is_not_remote_confirmation(local_fleet):
    serve, new_registry = local_fleet
    server = await serve("loopback-unverified-stop")
    registry = new_registry()
    authority = InertAuthority()
    registry.set_budget_callback(authority.consume_mcp_tool_budget)
    request_context()
    await connected(registry, server)
    await registry.execute_tool(
        server.server_id,
        "get_echo",
        {"message": "inert"},
        request_id="req-stop-fixture",
    )
    foreign = await registry.request_cancellation(
        server.server_id,
        "req-stop-fixture",
        "eng-foreign",
        "task-local-fleet",
    )
    assert foreign["status"] in {"denied", "unknown"}
    assert server.called("cancel") == 0
    local = await registry.request_cancellation(
        server.server_id,
        "req-stop-fixture",
        "eng-local-fleet",
        "task-local-fleet",
    )
    assert local["status"] == "unknown"
    assert server.called("cancel") == 1
    assert server.called("execute") == 1


@pytest.mark.asyncio
async def test_cancelled_in_flight_http_remains_unknown_and_request_id_unreplayable(local_fleet):
    serve, new_registry = local_fleet
    server = await serve("loopback-in-flight", execution_mode="wait")
    registry = new_registry()
    registry.set_budget_callback(local_budget)
    request_context()
    conn = await connected(registry, server)
    task = asyncio.create_task(
        registry.execute_tool(
            server.server_id,
            "get_echo",
            {"message": "inert"},
            request_id="req-cancel-inflight",
        )
    )
    await asyncio.wait_for(server.execute_entered.wait(), timeout=3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert conn._executions["req-cancel-inflight"].outcome == "unknown"
    result = await registry.execute_tool(
        server.server_id,
        "get_echo",
        {"message": "inert"},
        request_id="req-cancel-inflight",
    )
    assert result.status == "duplicate_request"
    assert server.called("execute") == 1


@pytest.mark.asyncio
async def test_concurrent_same_request_id_dispatches_once_over_real_http(local_fleet):
    serve, new_registry = local_fleet
    server = await serve("loopback-duplicate", execution_mode="wait")
    registry = new_registry()
    registry.set_budget_callback(local_budget)
    request_context()
    await connected(registry, server)
    first = asyncio.create_task(
        registry.execute_tool(
            server.server_id,
            "get_echo",
            {"message": "local"},
            request_id="req-parallel-same-id",
        )
    )
    await asyncio.wait_for(server.execute_entered.wait(), timeout=3)
    duplicate = await registry.execute_tool(
        server.server_id,
        "get_echo",
        {"message": "local"},
        request_id="req-parallel-same-id",
    )
    assert duplicate.status == "duplicate_request"
    assert server.called("execute") == 1
    server.unblock.set()
    finished = await asyncio.wait_for(first, timeout=3)
    assert finished.status == "success"
    assert server.called("execute") == 1


@pytest.mark.asyncio
async def test_http500_valid_success_envelope_must_not_claim_success(local_fleet):
    """HTTP 500 cannot forge success even with an otherwise valid JSON envelope."""
    serve, new_registry = local_fleet
    server = await serve("loopback-500-envelope", execution_mode="http500_forged_success")
    registry = new_registry()
    registry.set_budget_callback(local_budget)
    request_context()
    await connected(registry, server)
    response = await registry.execute_tool(
        server.server_id,
        "get_echo",
        {"message": "inert"},
        request_id="req-forged-http500",
    )
    assert (
        response.status == "unknown"
    ), "A 500 response body must never certify success, regardless of its JSON content"
