"""One-shot durable remote stop after restart; no original action retry."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import aiohttp
import pytest
from aiohttp import web
from fastapi.testclient import TestClient

from ai_osop.api.routers import supervision
from ai_osop.memory.supervision_store import (
    SupervisionConflict,
    SupervisionStore,
)
from ai_osop.orchestrator.orchestrator import Orchestrator
from tests.test_supervision_api import harness
from tests.test_mcp_signed_provider_receipts import signer
from tests.test_remote_execution_receipts import remote_connection

SID, TID, SERVER, RID = "eng-1", "task-1", "mock-local", "req-original"


def claim(status="outcome_unknown"):
    return {
        "engagement_id": SID,
        "task_id": TID,
        "server_id": SERVER,
        "request_id": RID,
        "tool_name": "get_health",
        "authorization_version": 1,
        "status": status,
    }


@pytest.mark.asyncio
async def test_orchestrator_postrestart_stop_only_after_transactional_claim():
    events = []
    store = SimpleNamespace(
        get_mcp_dispatch=AsyncMock(
            side_effect=[claim(), claim("cancel_requested"), claim("confirmed_stopped")]
        ),
        claim_mcp_cancellation_once=AsyncMock(return_value=True),
    )

    async def stop(original):
        assert original["status"] == "cancel_requested"
        assert store.claim_mcp_cancellation_once.await_count == 1
        events.append("signed-provider-stop")
        return {
            "status": "confirmed_stopped",
            "server_id": SERVER,
            "request_id": RID,
        }

    server = SimpleNamespace(cancel_persisted_execution=AsyncMock(side_effect=stop))
    orch = SimpleNamespace(
        supervision_store=store,
        mcp_registry=SimpleNamespace(get_server=lambda _: server),
    )
    result = await Orchestrator.cancel_persisted_mcp_dispatch(
        orch,
        SID,
        TID,
        SERVER,
        RID,
        actor_id="alice",
        reason="End authorized assessment",
        expected_authorization_version=1,
    )
    assert events == ["signed-provider-stop"]
    assert result["status"] == "confirmed_stopped"
    assert result["provider_reported_stop"] is True
    assert result["remote_stopped"] is False
    assert result["external_effect_status"] == "unknown"
    assert result["safe_to_retry"] is False
    store.claim_mcp_cancellation_once.assert_awaited_once_with(
        SID,
        TID,
        SERVER,
        RID,
        actor_id="alice",
        reason="End authorized assessment",
        expected_authorization_version=1,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("admitted", [False, None])
async def test_duplicate_global_stop_claim_never_calls_provider(admitted):
    store = SimpleNamespace(
        get_mcp_dispatch=AsyncMock(return_value=claim()),
        claim_mcp_cancellation_once=AsyncMock(return_value=admitted),
    )
    server = SimpleNamespace(cancel_persisted_execution=AsyncMock())
    orch = SimpleNamespace(
        supervision_store=store,
        mcp_registry=SimpleNamespace(get_server=lambda _: server),
    )
    receipt = await Orchestrator.cancel_persisted_mcp_dispatch(
        orch,
        SID,
        TID,
        SERVER,
        RID,
        actor_id="alice",
        reason="Stop under incident response",
        expected_authorization_version=1,
    )
    assert receipt["status"] == "unknown"
    assert receipt["safe_to_retry"] is False
    server.cancel_persisted_execution.assert_not_awaited()


@pytest.mark.asyncio
async def test_network_lost_after_durable_stop_claim_stays_unknown():
    store = SimpleNamespace(
        get_mcp_dispatch=AsyncMock(
            side_effect=[
                claim(),
                claim("cancel_requested"),
                claim("cancel_requested"),
            ]
        ),
        claim_mcp_cancellation_once=AsyncMock(return_value=True),
    )
    server = SimpleNamespace(
        cancel_persisted_execution=AsyncMock(side_effect=TimeoutError("Bearer SECRET"))
    )
    orch = SimpleNamespace(
        supervision_store=store,
        mcp_registry=SimpleNamespace(get_server=lambda _: server),
    )
    result = await Orchestrator.cancel_persisted_mcp_dispatch(
        orch,
        SID,
        TID,
        SERVER,
        RID,
        actor_id="alice",
        reason="Stop and quarantine unknown",
        expected_authorization_version=1,
    )
    assert result["status"] == "unknown"
    assert result["persisted_status"] == "cancel_requested"
    assert "SECRET" not in str(result)
    server.cancel_persisted_execution.assert_awaited_once()


def test_stop_route_is_senior_only_and_requires_original_version(harness):
    client, app, store, orch = harness
    orch.cancel_persisted_mcp_dispatch = AsyncMock(
        return_value={
            "status": "unknown",
            "persisted_status": "cancel_requested",
        }
    )
    path = f"/supervision/engagements/{SID}/tasks/{TID}/mcp/cancel-persisted"
    valid = {
        "server_id": SERVER,
        "request_id": RID,
        "expected_authorization_version": 1,
        "reason": "Stop for authorized incident response",
    }
    assert client.post(path, json=valid).status_code == 403
    from ai_osop.api.deps import verify_token

    app.dependency_overrides[verify_token] = lambda: {
        "sub": "alice",
        "role": "senior_operator",
    }
    assert client.post(path, json=valid).status_code == 200
    result = client.post(path, json=valid).json()
    assert result["status"] == "unknown"
    assert result["safe_to_retry"] is False
    assert result["remote_stopped"] is False
    assert result["external_effect_status"] == "unknown"
    orch.cancel_persisted_mcp_dispatch.assert_awaited()
    for invalid in (
        {**valid, "expected_authorization_version": 5},
        {**valid, "reason": "no"},
        {**valid, "server_id": "../foreign"},
        {**valid, "expected_authorization_version": True},
    ):
        reply = client.post(path, json=invalid)
        assert reply.status_code in {409, 422}


class _Reply:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Transaction:
    def __init__(self, dispatch):
        self.dispatch = dispatch
        self.committed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        yield
        self.committed = True

    async def execute(self, _statement):
        return _Reply(self.dispatch)


@pytest.mark.asyncio
async def test_sql_claim_is_fenced_and_emits_exactly_one_outbox_intent(monkeypatch):
    entity = SimpleNamespace(**claim())
    entity.updated_at = None
    tx = _Transaction(entity)
    store = SupervisionStore(SimpleNamespace())
    store._sessions = lambda: tx
    store._guard = AsyncMock(
        return_value=(
            SimpleNamespace(),
            SimpleNamespace(payload={"_authorization_version": 1}),
        )
    )
    store._append_event = AsyncMock(return_value=SimpleNamespace(id="evt-stop-intent"))
    asserted = await store.claim_mcp_cancellation_once(
        SID,
        TID,
        SERVER,
        RID,
        actor_id="alice",
        reason="Emergency one-time signed stop",
        expected_authorization_version=1,
    )
    assert asserted is True
    assert tx.committed is True
    assert entity.status == "cancel_requested"
    assert store._append_event.await_count == 1
    # New worker/process sees the durable previous intent and cannot resend.
    asserted_again = await store.claim_mcp_cancellation_once(
        SID,
        TID,
        SERVER,
        RID,
        actor_id="alice",
        reason="Emergency one-time signed stop",
        expected_authorization_version=1,
    )
    assert asserted_again is False
    assert store._append_event.await_count == 1


@pytest.mark.asyncio
async def test_revoked_owner_and_stale_version_cannot_send_stop(monkeypatch):
    entity = SimpleNamespace(**claim())
    tx = _Transaction(entity)
    store = SupervisionStore(SimpleNamespace())
    store._sessions = lambda: tx
    store._guard = AsyncMock(
        return_value=(
            SimpleNamespace(),
            SimpleNamespace(payload={"_authorization_version": 2}),
        )
    )
    store._append_event = AsyncMock()
    with pytest.raises(SupervisionConflict, match="signer"):
        await store.claim_mcp_cancellation_once(
            SID,
            TID,
            SERVER,
            RID,
            actor_id="alice",
            reason="Stop after authorization drift",
            expected_authorization_version=1,
        )
    assert entity.status == "outcome_unknown"
    store._append_event.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("trusted", [True, False])
async def test_disposable_loopback_provider_persisted_cancel_requires_pinned_signed_receipt(
    signer,
    trusted,
):
    """Actual loopback HTTP I/O, original identity only, no scan or real target."""
    calls = []
    original = {
        "server_id": "scanner",
        "engagement_id": "eng-live",
        "task_id": "task-allowed",
        "request_id": "req-remote",
        "authorization_version": 3,
        "tool_name": "inert",
        "status": "cancel_requested",
    }

    async def cancel(request):
        posted = await request.json()
        calls.append(posted)
        if trusted:
            return web.json_response(signer(status="cancelled", stopped=True))
        return web.json_response(
            {
                "request_id": "req-remote",
                "engagement_id": "eng-live",
                "task_id": "task-allowed",
                "server_id": "scanner",
                "status": "cancelled",
                "verified": True,
                "stopped": True,
            }
        )

    app = web.Application()
    app.router.add_post("/mcp/cancel", cancel)
    runner = web.AppRunner(app)
    await runner.setup()
    listener = web.TCPSite(runner, "127.0.0.1", 0)
    await listener.start()
    port = listener._server.sockets[0].getsockname()[1]
    try:
        conn = remote_connection(
            capabilities=["mcp_cancel_request_v1", "mcp_bound_receipts_v1"],
        )
        conn.host, conn.port = "127.0.0.1", port
        events = AsyncMock(return_value=True)
        conn.set_execution_event_callback(events)
        async with aiohttp.ClientSession() as client:
            conn._session = client
            receipt = await conn.cancel_persisted_execution(original)
        assert receipt["status"] == ("confirmed_stopped" if trusted else "unknown")
        assert len(calls) == 1
        assert calls[0] == {
            "request_id": "req-remote",
            "engagement_id": "eng-live",
            "task_id": "task-allowed",
            "server_id": "scanner",
        }
        assert all(call.args[2] == "cancellation_result" for call in events.await_args_list)
        evidence = events.await_args.args[3]["attested_receipt"]
        assert (evidence is not None) is trusted
    finally:
        await runner.cleanup()
