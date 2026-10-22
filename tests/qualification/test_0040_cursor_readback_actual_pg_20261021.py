"""Real mounted 0040 durable cursor readback after an ambiguous client ACK.

Opt-in uses the existing independently disposable nonroot WSL PostgreSQL16
Unix-socket fixture; no app DB, target, Docker, provider or external network.
The locally signed operator JWT and ROE are fixture keys, not deployed PKI.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.qualification.test_durable_subscriptions_mounted_actual_pg_20261021 import (
    ENG_A,
    TASK_A,
    lease_body,
    mounted_real,
    post,
    private_pg,
    sql,
)


def test_main_has_one_real_bounded_cursor_readback_route() -> None:
    from ai_osop.api.main import app

    route = "/supervision/engagements/{engagement_id}/subscriptions/{subscriber_id}/cursor-readback"
    matched = [r for r in app.routes if getattr(r, "path", None) == route]
    assert len(matched) == 1
    assert matched[0].methods == {"POST"}


@pytest.mark.asyncio
async def test_actual_pg16_mounted_current_cursor_readback_never_retries_ambiguous_ack(
    mounted_real: dict[str, Any],
) -> None:
    world = mounted_real
    subscriber = "subscr-" + uuid.uuid4().hex
    acquired = await post(
        world,
        "acquire",
        {"replica_id": "replica-cursor-readback", "task_id": TASK_A},
        subscriber=subscriber,
    )
    assert acquired.status_code == 200, acquired.text[:180]
    stale_observed_lease = lease_body(acquired.json())
    assert stale_observed_lease["cursor"] == 0

    committed = await post(
        world,
        "ack",
        {**stale_observed_lease, "expected_cursor": 0, "next_sequence": 11},
        subscriber=subscriber,
    )
    assert committed.status_code == 200, committed.text[:180]
    # The caller intentionally discards the HTTP success-shaped ACK and can
    # later only present the old, signed lease identity. This is NOT exactly
    # once delivery: cursor 11 is durable PG state, not a client receipt.
    recovered = await post(world, "cursor-readback", stale_observed_lease, subscriber=subscriber)
    assert recovered.status_code == 200, recovered.text[:180]
    projected = recovered.json()
    assert projected["lease"]["cursor"] == 11
    assert projected["lease"]["generation"] == acquired.json()["lease"]["generation"]
    assert projected["cursor_readback"] == "committed_database_state_only"
    assert projected["acknowledgement_delivered_to_client_verified"] is False
    assert projected["safe_to_retry_unknown_ack"] is False
    assert projected["target_effect_verified"] is False

    # Readback MUST NOT apply another original ACK, increment the cursor or
    # change the durable lease generation. Subsequent duplicate ACK still 409.
    duplicate = await post(
        world,
        "ack",
        {**stale_observed_lease, "expected_cursor": 0, "next_sequence": 11},
        subscriber=subscriber,
    )
    assert duplicate.status_code == 409
    read_cursor = await sql(
        world["memory"],
        "SELECT cursor_sequence,lease_generation FROM supervision_durable_subscriptions "
        "WHERE engagement_id=:engagement AND subscriber_id=:subscriber",
        engagement=ENG_A,
        subscriber=subscriber,
    )
    assert read_cursor == [
        {"cursor_sequence": 11, "lease_generation": projected["lease"]["generation"]}
    ]

    # Different signed bearer, changed replica and forged lease ID all fail
    # without disclosing the signed subscription's persisted cursor.
    foreign = await post(
        world, "cursor-readback", stale_observed_lease, subject="bob", subscriber=subscriber
    )
    assert foreign.status_code == 403
    other_replica = await post(
        world,
        "cursor-readback",
        {**stale_observed_lease, "replica_id": "replica-not-owner"},
        subscriber=subscriber,
    )
    assert other_replica.status_code == 409
    other_lease = await post(
        world,
        "cursor-readback",
        {**stale_observed_lease, "lease_id": "lease-" + uuid.uuid4().hex},
        subscriber=subscriber,
    )
    assert other_lease.status_code == 409

    await sql(
        world["memory"],
        "UPDATE signed_authorizations SET status='revoked',"
        "revoked_at=clock_timestamp() WHERE session_id=:sid",
        sid=ENG_A,
    )
    revoked = await post(world, "cursor-readback", stale_observed_lease, subscriber=subscriber)
    assert revoked.status_code == 409
    assert "lease" not in revoked.json()
