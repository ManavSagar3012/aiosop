"""Qualify MCP remote cancellation over actual disposable loopback HTTP.

The in-process aiohttp provider only runs a long-lived, inert ``get_status``
call. Durable persistence, authority and provider stop receipts are simulated;
this does not qualify a deployed MCP adapter or a real target operation.
"""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest, MCPInitializeRequest

ENGAGEMENT_ID = "eng-local-cancel"
TASK_ID = "task-local-cancel"
REQUEST_ID = "req-local-long-running"


class FakeAuthority:
    """Bound budget callback exposing fake persisted engagement/task reads."""

    def __init__(self):
        self.session = SessionState(
            session_id=ENGAGEMENT_ID,
            phase="reconnaissance",
            scope=ScopeDefinition(
                engagement_id=ENGAGEMENT_ID,
                domains=["example.test"],
                authorization_ref="fixture-authorization-only",
            ),
        )
        self.task = Task(
            id=TASK_ID,
            type="local_inert_health",
            agent_type=AgentType.RECON,
            engagement_id=ENGAGEMENT_ID,
            status="running",
        )
        self.budget_charges = []

    async def load_session_state(self, session_id: str):
        return self.session if session_id == ENGAGEMENT_ID else None

    async def load_task(self, task_id: str):
        return self.task if task_id == TASK_ID else None

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
        qualified_name: str,
        agent_id: str,
    ) -> bool:
        self.budget_charges.append((engagement_id, qualified_name, agent_id))
        return engagement_id == ENGAGEMENT_ID


class InertMCPProvider:
    """Only get_status is executable; counters expose all HTTP side effects."""

    def __init__(self):
        self.port = 0
        self.capabilities = ["mcp_cancel_request_v1", "mcp_request_status_v1"]
        self.cancel_mode = "verified"
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.stopped = False
        self.execute_ids = []
        self.cancel_ids = []
        self.status_ids = []
        self.target_side_calls = 0
        self.initialize_count = 0

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "healthy"})

    async def initialize(self, request: web.Request) -> web.Response:
        body = await request.json()
        assert body["session_id"] == ENGAGEMENT_ID
        self.initialize_count += 1
        return web.json_response(
            {
                "server_id": "local-qualification",
                "version": "test-only",
                "status": "ready",
                "capabilities": self.capabilities,
                "tools": [
                    {
                        "name": "get_status",
                        "description": "Local inert, long-running status query",
                        "parameters": [],
                        "returns": {},
                        "timeout_seconds": 8,
                        "requires_approval": False,
                        "scope_check": True,
                        "side_effect_class": "READ_ONLY",
                    }
                ],
            }
        )

    async def execute(self, request: web.Request) -> web.Response:
        body = await request.json()
        if body["tool_name"] != "get_status" or body["parameters"]:
            self.target_side_calls += 1
            return web.json_response({"error": "inert tools only"}, status=403)
        request_id = body["request_id"]
        self.execute_ids.append(request_id)
        self.started.set()
        await self.release.wait()
        return web.json_response(
            {
                "request_id": request_id,
                "status": "cancelled" if self.stopped else "success",
                "result": {"stopped": self.stopped},
            }
        )

    async def cancel(self, request: web.Request) -> web.Response:
        request_id = (await request.json())["request_id"]
        self.cancel_ids.append(request_id)
        if self.cancel_mode == "verified":
            self.confirm_stop()
            return web.json_response(
                {
                    "request_id": request_id,
                    "status": "cancelled",
                    "verified": True,
                    "stopped": True,
                }
            )
        if self.cancel_mode == "wrong-id":
            return web.json_response(
                {
                    "request_id": "req-foreign",
                    "status": "cancelled",
                    "verified": True,
                    "stopped": True,
                }
            )
        return web.json_response(
            {
                "request_id": request_id,
                "status": "accepted",
                "verified": False,
                "stopped": False,
            }
        )

    async def request_status(self, request: web.Request) -> web.Response:
        request_id = (await request.json())["request_id"]
        self.status_ids.append(request_id)
        return web.json_response(
            {
                "request_id": request_id,
                "verified": True,
                "status": "cancelled" if self.stopped else "running",
                "stopped": self.stopped,
            }
        )

    def confirm_stop(self) -> None:
        self.stopped = True
        self.release.set()


@pytest.fixture(autouse=True)
def clear_request_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


@pytest.fixture
async def local_server():
    provider = InertMCPProvider()
    app = web.Application()
    app.router.add_get("/health", provider.health)
    app.router.add_post("/mcp/initialize", provider.initialize)
    app.router.add_post("/mcp/execute", provider.execute)
    app.router.add_post("/mcp/cancel", provider.cancel)
    app.router.add_post("/mcp/request/status", provider.request_status)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    provider.port = site._server.sockets[0].getsockname()[1]
    try:
        yield provider
    finally:
        provider.release.set()
        await runner.cleanup()


@asynccontextmanager
async def connected(provider: InertMCPProvider):
    authority = FakeAuthority()
    events = AsyncMock(return_value=True)
    connection = MCPConnection("local-qualification", "127.0.0.1", provider.port)
    connection.set_budget_callback(authority.consume_mcp_tool_budget)
    connection.set_execution_event_callback(events)
    RequestContext.bind(engagement_id=ENGAGEMENT_ID, task_id=TASK_ID)
    await connection.connect()
    try:
        response = await connection.initialize(
            MCPInitializeRequest(
                scope={},
                session_id=ENGAGEMENT_ID,
            )
        )
        assert response.capabilities == provider.capabilities
        assert provider.initialize_count == 1
        yield connection, authority, events
    finally:
        await connection.close()


async def begin_inert_execution(connection: MCPConnection, provider: InertMCPProvider):
    pending = asyncio.create_task(
        connection.execute(
            MCPExecuteRequest(
                request_id=REQUEST_ID,
                tool_name="get_status",
                parameters={},
            )
        )
    )
    await asyncio.wait_for(provider.started.wait(), timeout=4)
    assert not pending.done()
    assert provider.execute_ids == [REQUEST_ID]
    return pending


@pytest.mark.asyncio
async def test_real_http_matching_remote_id_confirms_stop_once(local_server):
    async with connected(local_server) as (conn, authority, events):
        pending = await begin_inert_execution(conn, local_server)
        wrong_owner = await conn.request_cancellation(
            REQUEST_ID,
            "eng-another",
            TASK_ID,
        )
        wrong_task = await conn.request_cancellation(
            REQUEST_ID,
            ENGAGEMENT_ID,
            "task-another",
        )
        assert wrong_owner["status"] == wrong_task["status"] == "unknown"
        assert not local_server.cancel_ids

        first, duplicate = await asyncio.gather(
            conn.request_cancellation(REQUEST_ID, ENGAGEMENT_ID, TASK_ID),
            conn.request_cancellation(REQUEST_ID, ENGAGEMENT_ID, TASK_ID),
        )
        result = await asyncio.wait_for(pending, timeout=4)
        assert first == duplicate
        assert first["status"] == "confirmed_stopped"
        assert first["request_id"] == REQUEST_ID
        assert result.request_id == REQUEST_ID and result.status == "cancelled"
        assert local_server.cancel_ids == [REQUEST_ID]
        assert local_server.target_side_calls == 0
        assert authority.budget_charges == [
            (ENGAGEMENT_ID, "local-qualification.get_status", "agent-unspecified"),
        ]
        assert [call.args[2] for call in events.await_args_list] == [
            "dispatch_accepted",
            "execution_started",
            "cancellation_requested",
            "cancellation_result",
            "execution_unknown",
        ]
        assert events.await_args_list[3].args[3]["status"] == "confirmed_stopped"

        # Cached receipt cannot be read by another owner after confirmation.
        denied = await conn.request_cancellation(REQUEST_ID, "eng-another", TASK_ID)
        assert denied["status"] == "denied"
        assert local_server.cancel_ids == [REQUEST_ID]


@pytest.mark.asyncio
async def test_http_accepted_cancel_stays_unknown_until_verified_remote_status(local_server):
    local_server.cancel_mode = "accepted"
    async with connected(local_server) as (conn, _, events):
        pending = await begin_inert_execution(conn, local_server)
        unknown = await conn.request_cancellation(REQUEST_ID, ENGAGEMENT_ID, TASK_ID)
        still_running = await conn.reconcile_execution(REQUEST_ID, ENGAGEMENT_ID, TASK_ID)
        assert unknown["status"] == "unknown"
        assert still_running["status"] == "running"
        assert not pending.done()
        assert local_server.cancel_ids == [REQUEST_ID]
        assert local_server.status_ids == [REQUEST_ID]

        # An actual subsequent provider stop gives the status endpoint proof.
        local_server.confirm_stop()
        stopped = await conn.reconcile_execution(REQUEST_ID, ENGAGEMENT_ID, TASK_ID)
        assert stopped["status"] == "confirmed_stopped"
        assert conn._cancel_receipts[REQUEST_ID]["status"] == "confirmed_stopped"
        duplicate = await conn.request_cancellation(REQUEST_ID, ENGAGEMENT_ID, TASK_ID)
        assert duplicate["status"] == "confirmed_stopped"
        assert local_server.cancel_ids == [REQUEST_ID]
        assert local_server.status_ids == [REQUEST_ID, REQUEST_ID]
        assert local_server.target_side_calls == 0
        assert (await asyncio.wait_for(pending, timeout=4)).status == "cancelled"
        assert "reconciliation_result" in [call.args[2] for call in events.await_args_list]


@pytest.mark.asyncio
async def test_http_wrong_request_receipt_is_never_verified(local_server):
    local_server.cancel_mode = "wrong-id"
    async with connected(local_server) as (conn, _, _):
        pending = await begin_inert_execution(conn, local_server)
        answer = await conn.request_cancellation(REQUEST_ID, ENGAGEMENT_ID, TASK_ID)
        assert answer["status"] == "unknown"
        assert not pending.done()
        assert local_server.cancel_ids == [REQUEST_ID]
        local_server.release.set()
        assert (await asyncio.wait_for(pending, timeout=4)).status == "success"


@pytest.mark.asyncio
async def test_http_unadvertised_capabilities_never_invoke_cancel_or_status(local_server):
    local_server.capabilities = []
    async with connected(local_server) as (conn, _, events):
        pending = await begin_inert_execution(conn, local_server)
        unsupported = await conn.request_cancellation(REQUEST_ID, ENGAGEMENT_ID, TASK_ID)
        unreconcilable = await conn.reconcile_execution(REQUEST_ID, ENGAGEMENT_ID, TASK_ID)
        assert unsupported["status"] == unreconcilable["status"] == "not_supported"
        assert local_server.cancel_ids == local_server.status_ids == []
        assert local_server.target_side_calls == 0
        assert [call.args[2] for call in events.await_args_list] == [
            "dispatch_accepted",
            "execution_started",
        ]
        local_server.release.set()
        assert (await asyncio.wait_for(pending, timeout=4)).status == "success"


@pytest.mark.asyncio
async def test_durable_event_failure_blocks_http_cancellation(local_server):
    async with connected(local_server) as (conn, _, events):
        pending = await begin_inert_execution(conn, local_server)

        async def fail_cancellation_event(engagement_id, task_id, kind, metadata):
            return kind != "cancellation_requested"

        events.side_effect = fail_cancellation_event
        receipt = await conn.request_cancellation(REQUEST_ID, ENGAGEMENT_ID, TASK_ID)
        assert receipt["status"] == "unknown"
        assert receipt["reason"] == "audit_unavailable"
        assert local_server.cancel_ids == []
        assert local_server.target_side_calls == 0
        local_server.release.set()
        assert (await asyncio.wait_for(pending, timeout=4)).status == "success"
