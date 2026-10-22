"""Actual private nonroot PG16 read-cursor/lease final-publication fence.

Uses only explicit opt-in fixture from mounted 0040 qualification. No app DB.
Original source/ROE are synthetic test fixtures, never deployed authority.
"""

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
)


@pytest.mark.asyncio
async def test_mounted_private_pg_read_rejects_stale_cursor_after_ack_and_manual_readback(
    mounted_real: dict[str, Any],
) -> None:
    subscriber = "subscr-" + uuid.uuid4().hex
    opened = await post(
        mounted_real,
        "acquire",
        {"replica_id": "replica-original-owner", "task_id": TASK_A},
        subscriber=subscriber,
    )
    assert opened.status_code == 200, opened.text[:150]
    first = lease_body(opened.json())
    assert first["cursor"] == 0

    acked = await post(
        mounted_real,
        "ack",
        {**first, "expected_cursor": 0, "next_sequence": 11},
        subscriber=subscriber,
    )
    assert acked.status_code == 200, acked.text[:150]
    # Previously the store looked up events after the NEW committed cursor,
    # but the API labelled the projection with the OLD client cursor zero.
    # This now rejects instead of silently publishing a mislabeled batch.
    stale_read = await post(mounted_real, "read", {**first, "limit": 10}, subscriber=subscriber)
    assert stale_read.status_code == 409
    assert "events" not in stale_read.json()

    # An ACK lost at the socket must NOT be repeated. Read back actual PG.
    readback = await post(mounted_real, "cursor-readback", first, subscriber=subscriber)
    assert readback.status_code == 200, readback.text[:150]
    body = readback.json()
    assert body["lease"]["cursor"] == 11
    assert body["acknowledgement_delivered_to_client_verified"] is False
    assert body["safe_to_retry_unknown_ack"] is False

    current = lease_body(body)
    readable = await post(mounted_real, "read", {**current, "limit": 10}, subscriber=subscriber)
    assert readable.status_code == 200, readable.text[:150]
    assert readable.json()["cursor"] == 11
    assert readable.json()["acknowledged"] is False
    # Other committed fixture events may follow sequence 11; never infer the
    # archive is empty from a valid current cursor/read, only strict monotonic
    # tenant-bounded event sequences after the acknowledged position.
    assert all(
        event["sequence"] > 11 and event["engagement_id"] == ENG_A
        for event in readable.json()["events"]
    )
