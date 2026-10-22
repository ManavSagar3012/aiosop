"""Current host-only ACK disconnect recheck, after transactional auth and SQL.

The store uses its actual production SQL against an explicitly simulated PG
executor; this does NOT prove a real network disconnect or deployed PG rollback.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

import pytest

from ai_osop.api.routers import durable_supervision_subscriptions as api
from tests.test_durable_supervision_subscriptions_20261021 import (
    SimulatedPostgres,
    SubscriptionDenied,
    adapter,
    principal,
)
from tests.test_durable_supervision_subscriptions_api_20261021 import (
    _binding,
    _call,
    env as env,
)

__all__ = ["env"]


@pytest.mark.asyncio
async def test_host_probe_detects_queued_disconnect_after_nonblocking_starlette_miss():
    class HostRequest:
        async def is_disconnected(self):
            # Models Starlette's immediate CancelScope, which can miss a
            # pending ASGI receive channel that suspends before returning.
            return False

        async def receive(self):
            await asyncio.sleep(0)
            return {"type": "http.disconnect"}

    assert await api._host_ack_disconnected(HostRequest()) is True


@pytest.mark.asyncio
async def test_host_probe_rejects_unexpected_second_request_after_body_consumption():
    class HostRequest:
        async def is_disconnected(self):
            return False

        async def receive(self):
            return {"type": "http.request", "body": b"ignored", "more_body": False}

    # The separately imported API module uses the installed production class;
    # the isolated fake-store loader deliberately uses its own module identity.
    with pytest.raises(api.SubscriptionDenied, match="transport state ambiguous"):
        await api._host_ack_disconnected(HostRequest())


@pytest.mark.asyncio
async def test_rolled_back_when_server_observes_disconnect_after_update():
    pg = SimulatedPostgres()
    subject = principal(task="task-a")
    store = adapter(pg)
    lease = await store.acquire(subject, "replica-host")
    sequence: list[str] = []
    original_auth = store._authorize
    original_fence = store._fence_revocation_insert

    async def auth(db, owner):
        sequence.append("authorize")
        return await original_auth(db, owner)

    async def fence(db):
        sequence.append("fence")
        return await original_fence(db)

    async def disconnected():
        sequence.append("disconnect")
        assert pg.rows[(subject.engagement_id, subject.subscriber_id)]["cursor_sequence"] == 12
        return True

    store._authorize = auth
    store._fence_revocation_insert = fence
    with pytest.raises(SubscriptionDenied, match="connection lost"):
        await store.acknowledge(
            subject,
            lease,
            expected_cursor=0,
            next_sequence=12,
            precommit_disconnect=disconnected,
        )
    assert sequence == ["authorize", "fence", "authorize", "disconnect"]
    assert pg.rows[(subject.engagement_id, subject.subscriber_id)]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_incomplete_or_failed_host_check_never_commits_cursor():
    pg = SimulatedPostgres()
    subject = principal(task="task-a")
    store = adapter(pg)
    lease = await store.acquire(subject, "replica-host")

    async def nonboolean():
        return "connected"

    async def broken():
        raise OSError("ASGI receive unavailable")

    async def never():
        await asyncio.sleep(30)
        return False

    for guard in (nonboolean, broken, never):
        with pytest.raises(SubscriptionDenied):
            await store.acknowledge(
                subject,
                lease,
                expected_cursor=0,
                next_sequence=12,
                precommit_disconnect=guard,
            )
        assert pg.rows[(subject.engagement_id, subject.subscriber_id)]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_mounted_ack_uses_current_host_request_not_body(
    env: Dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acquired = await _call(env, "/acquire", {"replica_id": "replica-host", "task_id": "task-a"})
    assert acquired.status_code == 200
    lease = acquired.json()["lease"]
    checks: list[bool] = []

    async def disconnected(_request):
        checks.append(True)
        return True

    monkeypatch.setattr(api.Request, "is_disconnected", disconnected)
    result = await _call(
        env, "/ack", {**_binding(lease), "expected_cursor": 0, "next_sequence": 12}
    )
    assert result.status_code == 409
    assert result.json() == {"detail": "Durable supervision subscription denied or unavailable"}
    assert checks == [True]
    assert env["pg"].rows[("eng-a", lease["subscriber_id"])]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_original_live_connected_host_preserves_monotonic_single_ack():
    pg = SimulatedPostgres()
    subject = principal(task="task-a")
    store = adapter(pg)
    lease = await store.acquire(subject, "replica-host")
    calls: list[bool] = []

    async def still_connected():
        calls.append(True)
        return False

    result = await store.acknowledge(
        subject,
        lease,
        expected_cursor=0,
        next_sequence=12,
        precommit_disconnect=still_connected,
    )
    assert result.cursor == 12
    assert calls == [True]
    with pytest.raises(SubscriptionDenied):
        await store.acknowledge(
            subject,
            lease,
            expected_cursor=0,
            next_sequence=12,
            precommit_disconnect=still_connected,
        )
    assert pg.rows[(subject.engagement_id, subject.subscriber_id)]["cursor_sequence"] == 12
