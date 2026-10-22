"""0040 reusable publication guard contract + mounted API boundary.

Default test doubles do NOT certify PostgreSQL or independently signed ROE.
Separate explicit OSOP_DURABLE_MOUNTED_ACTUAL_PG16=1 test uses already-owned
private nonroot PG16 fixture, never application DB/Docker/external target.
"""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from ai_osop.api.durable_subscription_publication_guard_20261022 import (
    DurableSubscriptionPublicationGuard,
    PublicationCallbacks,
    PublicationFence,
    PublicationRejected,
    PublicationUnknown,
)
from ai_osop.memory.durable_supervision_subscriptions import (
    DurableSupervisionSubscriptions,
    SubscriberLease,
    SubscriberPrincipal,
    SubscriptionDenied,
)
from tests.qualification.test_durable_subscriptions_mounted_actual_pg_20261021 import (
    ENG_A,
    TASK_A,
    mounted_real,  # pytest discovers this opt-in existing fixture; only requested below
    post,
    private_pg,  # transitive fixture required by mounted_real
    sql,
)

ENG = "eng-publication-fixture"
TASK = "task-publication-fixture"
SUB = "subscr-" + "a" * 32
REPLICA = "replica-publication-fixture"
LEASE_ID = "lease-" + "b" * 32


@pytest.fixture
def optional_pg_world(request: pytest.FixtureRequest):
    import os

    if os.getenv("OSOP_DURABLE_MOUNTED_ACTUAL_PG16") != "1":
        pytest.skip("Optional private nonroot PG16 unset; no app DB accessed")
    # Resolve asyncgen fixtures BEFORE entering pytest-asyncio test loop.
    return request.getfixturevalue("mounted_real")


def event(sequence=12, engagement=ENG, task=TASK, payload=None):
    return {
        "sequence": sequence,
        "id": "evt-" + str(sequence),
        "engagement_id": engagement,
        "task_id": task,
        "kind": "agent.message",
        "actor_id": "operator-publication",
        "payload": {"text": "test-only committed event"} if payload is None else payload,
        "created_at": datetime.now(timezone.utc),
    }


@pytest.fixture
def world():
    principal = SubscriberPrincipal(
        engagement_id=ENG,
        subscriber_id=SUB,
        issuer="signed-fixture-issuer",
        subject="operator-publication",
        role="operator",
        expires_at=int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp()),
        authorization_version=4,
        authorization_sha256="a" * 64,
        task_id=TASK,
    )
    lease = SubscriberLease(
        engagement_id=ENG,
        subscriber_id=SUB,
        replica_id=REPLICA,
        lease_id=LEASE_ID,
        generation=3,
        cursor=11,
        lease_until=datetime.now(timezone.utc) + timedelta(seconds=60),
    )
    state = {
        "principal": principal,
        "lease": lease,
        "cursor": 11,
        "revoked": False,
        "disconnect": False,
        "calls": [],
        "block_current": False,
        "disconnect_value": "use-state",
        "cancel_current": False,
        "active_error": False,
    }
    # A subclass instance ensures exactly the production store TYPE is used
    # for the final _transaction/_active dispatch. Both funcs are deliberately
    # synthetic to keep default tests completely isolated.
    store = object.__new__(DurableSupervisionSubscriptions)

    @asynccontextmanager
    async def transaction(principal_arg):
        state["calls"].append("transaction")
        if state["revoked"]:
            raise SubscriptionDenied("fixture simulated signed ROE revoked")
        yield SimpleNamespace(fixture_only=True)
        state["calls"].append("transaction-commit")

    async def active(db, principal_arg, lease_arg):
        state["calls"].append("active")
        if state["active_error"] or lease_arg != state["lease"]:
            raise SubscriptionDenied("fixture stale replica lease")
        return {"cursor_sequence": state["cursor"]}

    async def context():
        state["calls"].append("current-context")
        if state["block_current"]:
            await asyncio.Event().wait()
        if state["cancel_current"]:
            raise asyncio.CancelledError
        return state["principal"], store

    async def disconnected():
        state["calls"].append("disconnect")
        return (
            state["disconnect"]
            if state["disconnect_value"] == "use-state"
            else state["disconnect_value"]
        )

    store._transaction = transaction
    store._active = active
    guard = DurableSubscriptionPublicationGuard(
        PublicationCallbacks(current_context=context, is_disconnected=disconnected)
    )
    return state, guard, PublicationFence(principal, lease, 11)


@pytest.mark.asyncio
async def test_read_returns_bounded_snapshot_only_after_current_owner_and_lease(world):
    state, guard, fence = world
    original = event()
    result = await guard.read(fence, [original])
    assert result.mode == "read"
    assert result.body["cursor"] == 11
    assert result.body["acknowledged"] is False
    assert result.body["delivery_semantics"] == "at_least_once"
    assert result.client_receipt_verified is False and result.safe_to_retry_unknown_ack is False
    assert state["calls"] == [
        "current-context",
        "transaction",
        "active",
        "transaction-commit",
        "disconnect",
    ]
    original["payload"]["text"] = "modified after returned snapshot"
    assert result.body["events"][0]["payload"]["text"] == "test-only committed event"


@pytest.mark.asyncio
async def test_revoked_or_changed_issuer_role_and_signed_roe_denied(world):
    state, guard, fence = world
    state["revoked"] = True
    with pytest.raises(PublicationRejected):
        await guard.read(fence, [event()])
    state["revoked"] = False
    for key, replacement in (
        ("issuer", "other-issuer"),
        ("role", "senior_operator"),
        ("authorization_version", 99),
        ("subject", "other-signed-subject"),
        ("task_id", None),
    ):
        from dataclasses import replace

        state["principal"] = replace(fence.principal, **{key: replacement})
        with pytest.raises(PublicationRejected):
            await guard.read(fence, [event()])
    assert "disconnect" not in state["calls"]


@pytest.mark.asyncio
async def test_stale_replica_lease_and_cursor_denied_even_after_context(world):
    state, guard, fence = world
    state["active_error"] = True
    with pytest.raises(PublicationRejected):
        await guard.read(fence, [])
    state["active_error"] = False
    state["cursor"] = 12  # committed ACK after stale batch SELECT
    with pytest.raises(PublicationRejected):
        await guard.read(fence, [event()])
    state["cursor"] = 11
    from dataclasses import replace

    state["lease"] = replace(fence.lease, generation=4, lease_id="lease-" + "e" * 32)
    with pytest.raises(PublicationRejected):
        await guard.read(fence, [event()])


@pytest.mark.asyncio
async def test_disconnect_and_uncertain_disconnect_are_not_publication(world):
    state, guard, fence = world
    state["disconnect"] = True
    with pytest.raises(PublicationRejected):
        await guard.read(fence, [event()])
    state["disconnect"] = False
    for returned in (None, "false", 0, 1):
        state["disconnect_value"] = returned
        with pytest.raises(PublicationUnknown):
            await guard.read(fence, [event()])
    assert state["calls"].count("active") >= 5


@pytest.mark.asyncio
async def test_timeout_unknown_and_task_cancel_propagates_without_result(world):
    state, _guard, fence = world
    guard = DurableSubscriptionPublicationGuard(
        _guard.callbacks, context_deadline_seconds=0.1, disconnect_deadline_seconds=0.05
    )
    state["block_current"] = True
    with pytest.raises(PublicationUnknown):
        await guard.read(fence, [event()])
    state["block_current"] = False
    state["cancel_current"] = True
    with pytest.raises(asyncio.CancelledError):
        await guard.read(fence, [event()])
    assert "active" not in state["calls"]


@pytest.mark.asyncio
async def test_bad_row_tenant_order_payload_size_nan_batch_and_cursor_denied_before_pg(world):
    state, guard, fence = world
    invalid = [
        [event(12, engagement="eng-foreign")],
        [event(12, task="task-foreign")],
        [event(11)],
        [event(12, payload={"number": float("nan")})],
        [event(12, payload={"excess": "x" * 9000})],
        [event(12), event(12)],
        [event(12)] * 101,
    ]
    for events in invalid:
        with pytest.raises(PublicationRejected):
            await guard.read(fence, events)
    from dataclasses import replace

    with pytest.raises(PublicationRejected):
        await guard.read(replace(fence, expected_cursor=True), [event()])
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_committed_cursor_readback_never_confirms_client_ack_or_auto_retry(world):
    state, guard, fence = world
    from dataclasses import replace

    committed = replace(fence.lease, cursor=11)
    result = await guard.cursor_readback(fence, committed)
    assert result.body["cursor_readback"] == "committed_database_state_only"
    assert result.body["acknowledgement_delivered_to_client_verified"] is False
    assert result.body["safe_to_retry_unknown_ack"] is False
    assert result.body["target_effect_verified"] is False
    assert result.client_receipt_verified is False
    with pytest.raises(PublicationRejected):
        await guard.cursor_readback(fence, replace(committed, generation=2))
    with pytest.raises(PublicationRejected):
        await guard.cursor_readback(fence, replace(committed, cursor=12))
    assert state["calls"].count("active") == 1


@pytest.mark.asyncio
async def test_leased_sse_checks_each_row_and_never_acks(world):
    state, guard, fence = world
    allowed = await guard.leased_sse(fence, event(12))
    assert allowed.mode == "leased-sse"
    assert allowed.frame.startswith("id: 12\nevent: supervision\ndata: ")
    assert allowed.frame.endswith("\n\n")
    assert allowed.body is None and allowed.client_receipt_verified is False
    state["revoked"] = True
    with pytest.raises(PublicationRejected):
        await guard.leased_sse(fence, event(13))
    assert state["calls"].count("active") == 1


def test_mounted_main_routes_and_sse_are_distinct_and_guard_has_no_auto_mount():
    from ai_osop.api.main import app

    route_paths = {getattr(route, "path", "") for route in app.routes}
    base = "/supervision/engagements/{engagement_id}/subscriptions/{subscriber_id}"
    assert {
        base + "/" + suffix
        for suffix in ("read", "ack", "cursor-readback", "acquire", "renew", "release", "revoke")
    }.issubset(route_paths)
    assert "/supervision/engagements/{engagement_id}/events/stream" in route_paths
    # Standalone 0040 publication helper is intentionally NOT globally mounted.
    assert not any("publication-guard" in item for item in route_paths)


@pytest.mark.asyncio
async def test_optional_genuine_mounted_private_pg16_read_and_revoke(
    optional_pg_world,
):
    from starlette.requests import Request
    from ai_osop.api.routers import durable_supervision_subscriptions as router
    from dataclasses import replace

    world = optional_pg_world
    subscriber = "subscr-" + uuid.uuid4().hex
    opened = await post(
        world,
        "acquire",
        {"replica_id": "replica-private-publication", "task_id": TASK_A},
        subscriber=subscriber,
    )
    assert opened.status_code == 200, opened.text[:250]
    payload = opened.json()["lease"]

    async def receive():
        # The original Starlette host request is fully consumed; no client
        # body/JSON claim is used as a trusted disconnect signal.
        return {"type": "http.request", "body": b"", "more_body": False}

    host_request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/supervision/",
            "headers": [(b"authorization", ("Bearer " + world["alice"]).encode("ascii"))],
        },
        receive=receive,
    )
    operator = await router._verified_bearer(world["alice"])

    async def signed_context():
        return await router._context(ENG_A, subscriber, TASK_A, host_request, operator)

    principal, store = await signed_context()
    original_lease = router._lease(
        ENG_A,
        subscriber,
        router.LeaseBinding(
            replica_id=payload["replica_id"],
            lease_id=payload["lease_id"],
            generation=payload["generation"],
            cursor=payload["cursor"],
            task_id=TASK_A,
        ),
    )
    rows = await store.read_batch(principal, original_lease)
    assert rows and rows[0]["sequence"] == 11
    guard = DurableSubscriptionPublicationGuard(
        PublicationCallbacks(
            current_context=signed_context,
            is_disconnected=host_request.is_disconnected,
        ),
        context_deadline_seconds=5,
    )
    fence = PublicationFence(principal, original_lease, payload["cursor"])
    allowed = await guard.read(fence, rows)
    assert [e["sequence"] for e in allowed.body["events"]] == [11, 19]
    assert allowed.body["acknowledged"] is False
    assert allowed.client_receipt_verified is False
    committed = replace(original_lease, cursor=0)
    readback = await guard.cursor_readback(fence, committed)
    assert readback.body["safe_to_retry_unknown_ack"] is False
    await sql(
        world["memory"],
        "UPDATE signed_authorizations SET status='revoked', "
        "revoked_at=clock_timestamp() WHERE session_id=:sid",
        sid=ENG_A,
    )
    with pytest.raises((PublicationRejected, PublicationUnknown)):
        await guard.read(fence, rows)
