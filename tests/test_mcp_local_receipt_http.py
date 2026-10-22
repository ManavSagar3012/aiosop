"""Loopback HTTP qualification of provider-native status and stop receipts.

No scanning tool, application database, paid provider, or real target is used.
"""

from unittest.mock import AsyncMock

import aiohttp
from aiohttp import web
import pytest

from ai_osop.mcp.protocol import MCPExecuteRequest
from tests.test_remote_execution_receipts import known_execution, remote_connection


@pytest.fixture
async def local_receipt_server():
    calls = []
    response_state = {
        "task_id": "task-allowed", "verified": True,
        "stopped": True, "use_original_dispatch": False,
    }
    dispatched = {}

    async def execute(request):
        payload = await request.json()
        calls.append(("execute", payload))
        if isinstance(payload.get("execution_binding"), dict):
            dispatched[payload["request_id"]] = payload["execution_binding"]
        return web.json_response({
            "request_id": payload["request_id"], "status": "success", "result": {},
        })

    async def cancel(request):
        payload = await request.json()
        calls.append(("cancel", payload))
        return web.json_response({
            **payload, "status": "cancelled", "verified": response_state["verified"],
            "stopped": response_state["stopped"], "task_id": response_state["task_id"],
        })

    async def status(request):
        payload = await request.json()
        calls.append(("status", payload))
        bound = (
            dispatched.get(payload["request_id"], {})
            if response_state["use_original_dispatch"] else payload
        )
        return web.json_response({
            **bound, "status": "completed", "verified": response_state["verified"],
            "request_id": payload["request_id"],
            "task_id": (
                bound.get("task_id") if response_state["use_original_dispatch"]
                else response_state["task_id"]
            ),
        })

    app = web.Application()
    app.router.add_post("/mcp/execute", execute)
    app.router.add_post("/mcp/cancel", cancel)
    app.router.add_post("/mcp/request/status", status)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        port = site._server.sockets[0].getsockname()[1]
        yield port, calls, response_state
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_loopback_stop_ack_requires_durable_event_and_complete_identity(
    local_receipt_server,
):
    port, calls, state = local_receipt_server
    conn = await known_execution(remote_connection(
        capabilities=["mcp_cancel_request_v1", "mcp_bound_receipts_v1"],
    ))
    conn.host, conn.port = "127.0.0.1", port
    conn._requires_bound_provider_receipt = lambda: True
    recorded = []

    async def event(engagement, task, kind, metadata):
        recorded.append((engagement, task, kind))
        return True

    conn.set_execution_event_callback(event)
    async with aiohttp.ClientSession() as client:
        conn._session = client
        outcome = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
        repeated = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert outcome["status"] == repeated["status"] == "confirmed_stopped"
    assert calls == [("cancel", {
        "request_id": "req-remote", "engagement_id": "eng-live",
        "task_id": "task-allowed", "server_id": "scanner",
    })]
    assert [event[2] for event in recorded] == [
        "cancellation_requested", "cancellation_result",
    ]
    assert conn._executions["req-remote"].active is False


@pytest.mark.asyncio
async def test_loopback_foreign_task_status_never_confirms_completion(
    local_receipt_server,
):
    port, calls, state = local_receipt_server
    state["task_id"] = "task-foreign"
    conn = await known_execution(remote_connection(
        capabilities=["mcp_request_status_v1", "mcp_bound_receipts_v1"],
    ))
    conn.host, conn.port = "127.0.0.1", port
    conn._requires_bound_provider_receipt = lambda: True
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    async with aiohttp.ClientSession() as client:
        conn._session = client
        result = await conn.reconcile_execution("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "unknown"
    assert [kind for kind, _ in calls] == ["status"]
    assert conn._executions["req-remote"].outcome == "unknown"


@pytest.mark.asyncio
async def test_loopback_execute_binds_receipt_to_original_provider_dispatch(
    local_receipt_server,
):
    port, calls, state = local_receipt_server
    state["use_original_dispatch"] = True
    conn = remote_connection(
        capabilities=["mcp_request_status_v1", "mcp_bound_receipts_v1"],
    )
    conn.host, conn.port = "127.0.0.1", port
    conn._requires_bound_provider_receipt = lambda: True
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    async with aiohttp.ClientSession() as client:
        conn._session = client
        initial = await conn.execute(MCPExecuteRequest(
            request_id="req-remote", tool_name="scan_target",
            parameters={"url": "https://example.com/inert"},
        ))
        verified = await conn.reconcile_execution(
            "req-remote", "eng-live", "task-allowed",
        )
    assert initial.status == "success"
    assert verified["status"] == "confirmed_finished"
    assert [kind for kind, _ in calls] == ["execute", "status"]
    assert calls[0][1]["execution_binding"] == {
        "request_id": "req-remote", "engagement_id": "eng-live",
        "task_id": "task-allowed", "server_id": "scanner",
    }


@pytest.mark.asyncio
async def test_loopback_remote_stopped_without_committed_receipt_stays_unknown(
    local_receipt_server,
):
    port, calls, state = local_receipt_server
    conn = await known_execution(remote_connection(
        capabilities=["mcp_cancel_request_v1", "mcp_bound_receipts_v1"],
    ))
    conn.host, conn.port = "127.0.0.1", port
    conn._requires_bound_provider_receipt = lambda: True

    async def event(engagement, task, kind, metadata):
        return kind != "cancellation_result"

    conn.set_execution_event_callback(event)
    async with aiohttp.ClientSession() as client:
        conn._session = client
        result = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "unknown"
    assert len(calls) == 1
    assert conn._executions["req-remote"].outcome == "unknown"
