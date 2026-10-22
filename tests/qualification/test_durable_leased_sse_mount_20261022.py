"""Actual registered 0040 leased SSE route and safe publication contract.

Default tests use isolated local synthetic subscribers and NEVER touch app DB.
Opt-in final test uses existing disposable nonroot PG16 mounted fixture.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from ai_osop.api import main
from ai_osop.api.routers import durable_leased_sse_20261022 as module
from ai_osop.memory.durable_supervision_subscriptions import (
    DurableSupervisionSubscriptions,
    SubscriberPrincipal,
    SubscriptionDenied,
)
from tests.qualification.test_durable_subscriptions_mounted_actual_pg_20261021 import (
    ENG_A,
    TASK_A,
    mounted_real as mounted_real,
    private_pg as private_pg,
    post,
)

ENG = "eng-leased-sse-test"
TASK = "task-leased-sse-test"
SUB = "subscr-" + "c" * 32


def _event(sequence: int) -> dict:
    return {
        "sequence": sequence,
        "id": f"evt-{sequence}",
        "engagement_id": ENG,
        "task_id": TASK,
        "kind": "agent.message",
        "actor_id": "local-test",
        "payload": {"value": f"signed-test-{sequence}"},
        "created_at": datetime.now(timezone.utc),
    }


@pytest.fixture
def local(monkeypatch):
    principal = SubscriberPrincipal(
        engagement_id=ENG,
        subscriber_id=SUB,
        issuer="fixture-issuer",
        subject="local-test",
        role="operator",
        expires_at=int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        authorization_version=1,
        authorization_sha256="f" * 64,
        task_id=TASK,
    )
    state = {
        "cursor": 0,
        "revoked": False,
        "disconnect": False,
        "rows": [_event(11), _event(19)],
        "polls": 0,
    }
    store = object.__new__(DurableSupervisionSubscriptions)

    @asynccontextmanager
    async def transaction(current):
        if state["revoked"]:
            raise SubscriptionDenied("synthetic revoked signer")
        yield SimpleNamespace()

    async def active(db, current, lease):
        if state["revoked"]:
            raise SubscriptionDenied("synthetic revoked lease")
        return {"cursor_sequence": state["cursor"]}

    async def batch(current, lease, *, limit=50):
        state["polls"] += 1
        if state["revoked"] or state["cursor"] != lease.cursor:
            raise SubscriptionDenied("synthetic stale cursor")
        return state["rows"][:limit]

    async def current(*args):
        if state["revoked"]:
            raise SubscriptionDenied("synthetic signed principal revoked")
        return principal, store

    store._transaction = transaction
    store._active = active
    store.read_batch = batch
    monkeypatch.setattr(module, "_context", current)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(
        {"type": "http", "method": "POST", "path": "/", "headers": []}, receive=receive
    )

    async def disconnected():
        return state["disconnect"]

    request.is_disconnected = disconnected
    body = module.LeasedStreamRequest(
        replica_id="replica-only-local",
        lease_id="lease-" + "b" * 32,
        generation=1,
        cursor=0,
        task_id=TASK,
        limit=10,
        wait_seconds=1,
    )
    return state, request, body


def test_route_actually_mounted_with_distinct_existing_nonleased_sse():
    paths = {getattr(r, "path", "") for r in main.app.routes}
    assert (
        "/supervision/engagements/{engagement_id}/subscriptions/{subscriber_id}/leased-stream"
        in paths
    )
    assert "/supervision/engagements/{engagement_id}/events/stream" in paths


@pytest.mark.asyncio
async def test_local_owned_snapshot_yields_bounded_real_sse_frames_not_acks(local):
    state, request, body = local
    response = await module.leased_stream(
        request, Response(), body, ENG, SUB, {"sub": "local-test"}
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    frames = [frame async for frame in response.body_iterator]
    assert len(frames) == 3
    assert frames[0].startswith("id: 11\nevent: supervision\ndata: ")
    assert frames[1].startswith("id: 19\nevent: supervision\ndata: ")
    assert "signed-test-11" in frames[0]
    assert frames[2] == module._COMPLETE
    assert '"acknowledged":true' not in frames[0] + frames[1]
    assert '"client_receipt_verified":true' not in frames[0] + frames[1]
    assert state["cursor"] == 0 and state["polls"] == 1


@pytest.mark.asyncio
async def test_revocation_between_two_committed_rows_stops_publication(local):
    state, request, body = local
    response = await module.leased_stream(request, Response(), body, ENG, SUB, {})
    iterator = response.body_iterator
    first = await iterator.__anext__()
    assert "id: 11" in first
    state["revoked"] = True
    with pytest.raises(StopAsyncIteration):
        await iterator.__anext__()


@pytest.mark.asyncio
async def test_initial_stale_lease_and_host_disconnect_deny_before_http_200(local):
    state, request, body = local
    state["cursor"] = 11
    with pytest.raises(HTTPException) as stale:
        await module.leased_stream(request, Response(), body, ENG, SUB, {})
    assert stale.value.status_code == 409
    state["cursor"] = 0
    state["disconnect"] = True
    with pytest.raises(HTTPException) as disconnected:
        await module.leased_stream(request, Response(), body, ENG, SUB, {})
    assert disconnected.value.status_code == 409


@pytest.mark.asyncio
async def test_empty_poll_revocation_and_bound_wait(local):
    state, request, body = local
    state["rows"] = []
    response = await module.leased_stream(request, Response(), body, ENG, SUB, {})
    frames = [frame async for frame in response.body_iterator]
    assert frames == [module._COMPLETE] and state["polls"] >= 2
    state["rows"] = []
    state["polls"] = 0
    response = await module.leased_stream(request, Response(), body, ENG, SUB, {})
    iterator = response.body_iterator
    state["revoked"] = True
    with pytest.raises(StopAsyncIteration):
        await iterator.__anext__()


@pytest.mark.asyncio
async def test_mounted_raw_preparse_limits_unauthenticated_without_db():
    path = f"/supervision/engagements/{ENG}/subscriptions/{SUB}/leased-stream"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app, raise_app_exceptions=False),
        base_url="http://isolated.invalid",
        timeout=5,
    ) as client:
        too_big = await client.post(
            path,
            content=b"{" + b" " * 5000 + b"}",
            headers={"Content-Type": "application/json"},
        )
        assert too_big.status_code == 413
        bad_content_type = await client.post(
            path, content=b"{}", headers={"Content-Type": "text/plain"}
        )
        assert bad_content_type.status_code == 415
        missing_auth = await client.post(path, json={"replica_id": "replica-local"})
        assert missing_auth.status_code in {401, 403, 422}


@pytest.fixture
def optional_private_pg(request):
    if os.getenv("OSOP_DURABLE_MOUNTED_ACTUAL_PG16") != "1":
        pytest.skip("No private nonroot PG16 opt-in; never app DB")
    return request.getfixturevalue("mounted_real")


@pytest.mark.asyncio
async def test_optional_real_mounted_nonroot_pg16_stream_and_revocation(optional_private_pg):
    world = optional_private_pg
    subscriber = "subscr-" + uuid.uuid4().hex
    opened = await post(
        world,
        "acquire",
        {"replica_id": "replica-real-stream", "task_id": TASK_A},
        subscriber=subscriber,
    )
    assert opened.status_code == 200, opened.text[:250]
    lease = opened.json()["lease"]
    body = {key: lease[key] for key in ("replica_id", "lease_id", "generation", "cursor")}
    body.update({"task_id": TASK_A, "wait_seconds": 1, "limit": 10})
    path = f"/supervision/engagements/{ENG_A}/subscriptions/{subscriber}/leased-stream"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app, raise_app_exceptions=False),
        base_url="http://owned-private.invalid",
        timeout=12,
    ) as client:
        got = await client.post(
            path, json=body, headers={"Authorization": "Bearer " + world["alice"]}
        )
        assert got.status_code == 200, got.text[:300]
        assert "id: 11\nevent: supervision" in got.text
        assert "id: 19\nevent: supervision" in got.text
        assert "id: 12" not in got.text
        assert got.text.endswith(module._COMPLETE)
        # Streaming changes NO PG cursor and cannot prove HTTP client receipt.
        committed = await post(
            world,
            "cursor-readback",
            body={
                key: body[key]
                for key in ("replica_id", "lease_id", "generation", "cursor", "task_id")
            },
            subscriber=subscriber,
        )
        assert committed.status_code == 200
        assert committed.json()["lease"]["cursor"] == 0
        assert committed.json()["acknowledgement_delivered_to_client_verified"] is False
        again = await client.post(
            path, json={**body, "cursor": 12}, headers={"Authorization": "Bearer " + world["alice"]}
        )
        assert again.status_code == 409
        # A genuinely committed monotonic ACK makes the previous streaming
        # cursor stale; NO automatic resend/replay follows a lost HTTP ACK.
        ack = await post(
            world,
            "ack",
            {
                **{
                    key: body[key]
                    for key in ("replica_id", "lease_id", "generation", "cursor", "task_id")
                },
                "expected_cursor": 0,
                "next_sequence": 11,
            },
            subscriber=subscriber,
        )
        assert ack.status_code == 200, ack.text[:240]
        stale = await client.post(
            path, json=body, headers={"Authorization": "Bearer " + world["alice"]}
        )
        assert stale.status_code == 409
        latest = await post(
            world,
            "cursor-readback",
            {
                key: body[key]
                for key in ("replica_id", "lease_id", "generation", "cursor", "task_id")
            },
            subscriber=subscriber,
        )
        assert latest.status_code == 200
        assert latest.json()["lease"]["cursor"] == 11
        revoked = await post(world, "revoke", {"task_id": TASK_A}, subscriber=subscriber)
        assert revoked.status_code == 200
        no_more = await client.post(
            path, json={**body, "cursor": 11}, headers={"Authorization": "Bearer " + world["alice"]}
        )
        assert no_more.status_code == 409
