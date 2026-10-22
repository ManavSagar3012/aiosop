"""Signed owner revocation and committed tenant identity at the live SSE boundary.

The PostgreSQL session and FastAPI authentication checks are deterministic
fakes: no application database, remote target or actual event is contacted.
"""

import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.routers import supervision


def _event(sequence=1, engagement_id="eng-owned", task_id="task-owned", payload=None):
    return {
        "id": f"evt-{sequence}",
        "sequence": sequence,
        "engagement_id": engagement_id,
        "task_id": task_id,
        "kind": "task.observed",
        "actor_id": "operator-test",
        "payload": {"status": "unknown"} if payload is None else payload,
        "created_at": datetime(2026, 10, 21),
    }


def test_committed_event_boundary_rejects_other_tenant_task_and_invalid_cursor():
    candidate = _event()
    checked = supervision._sse_committed_event(
        candidate, engagement_id="eng-owned", task_id="task-owned", after_sequence=0
    )
    assert checked is not None and checked[0] == 1
    assert '"status":"unknown"' in checked[1]
    assert (
        supervision._sse_committed_event(
            candidate, engagement_id="eng-owned", task_id="task-owned", after_sequence=1
        )
        is None
    )
    for poison in (
        _event(engagement_id="eng-foreign"),
        _event(task_id="task-foreign"),
        _event(sequence=True),
        _event(sequence=2**63),
        _event(sequence=-1),
        _event(payload={"large": "x" * 8192}),
        _event(payload={"nonfinite": float("nan")}),
    ):
        with pytest.raises((ValueError, TypeError)):
            supervision._sse_committed_event(
                poison, engagement_id="eng-owned", task_id="task-owned", after_sequence=0
            )


class _Request:
    headers = {"last-event-id": "0"}

    async def is_disconnected(self):
        return False


@pytest.mark.asyncio
async def test_revoked_after_batch_select_cannot_publish_second_cached_event(monkeypatch):
    store = SimpleNamespace(list_events_after=AsyncMock(return_value=[_event(1), _event(2)]))
    calls = 0

    async def current(_request, _operator, _engagement_id, _task_id):
        nonlocal calls
        calls += 1
        if calls == 4:
            raise HTTPException(403, "Owner revoked after first event")
        return store

    monkeypatch.setattr(supervision, "_stream_revalidate", current)
    response = await supervision.stream_events(
        "eng-owned", _Request(), 0, "task-owned", {"sub": "operator-test", "role": "operator"}
    )
    stream = response.body_iterator
    # The strengthened post-serialization fence is the fourth check, so the
    # newly revoked owner loses the FIRST candidate frame, not merely the
    # second. Neither originally selected cached row may leak to the client.
    first = await anext(stream)
    assert first == "event: auth_required\ndata: {}\n\n"
    with pytest.raises(StopAsyncIteration):
        await anext(stream)
    assert calls == 4
    store.list_events_after.assert_awaited_once_with("eng-owned", 0, "task-owned", 100)


@pytest.mark.asyncio
async def test_unexpected_foreign_pg_row_fails_closed_after_authorization(monkeypatch):
    store = SimpleNamespace(
        list_events_after=AsyncMock(return_value=[_event(engagement_id="eng-foreign")])
    )
    auth = AsyncMock(return_value=store)
    monkeypatch.setattr(supervision, "_stream_revalidate", auth)
    response = await supervision.stream_events(
        "eng-owned", _Request(), 0, "task-owned", {"sub": "operator-test", "role": "operator"}
    )
    stream = response.body_iterator
    assert await anext(stream) == "event: unavailable\ndata: {}\n\n"
    with pytest.raises(StopAsyncIteration):
        await anext(stream)
    assert auth.await_count == 3  # route admission, batch read, final publish fence


@pytest.mark.asyncio
async def test_sse_duplicate_sequence_cannot_replay_existing_cursor(monkeypatch):
    store = SimpleNamespace(list_events_after=AsyncMock(return_value=[_event(3), _event(3)]))
    auth = AsyncMock(return_value=store)
    monkeypatch.setattr(supervision, "_stream_revalidate", auth)
    monkeypatch.setattr(supervision.asyncio, "sleep", AsyncMock())

    # Let the first batch finish: a duplicate cannot become a second frame.
    class _OnePoll(_Request):
        count = 0

        async def is_disconnected(self):
            self.count += 1
            # One extra disconnect check now runs immediately before sending
            # the first frame. Keep this stream connected for that frame and
            # disconnect before the second batch poll.
            return self.count > 2

    response = await supervision.stream_events(
        "eng-owned", _OnePoll(), 0, "task-owned", {"sub": "operator-test", "role": "operator"}
    )
    stream = response.body_iterator
    assert "id: 3\n" in await anext(stream)
    with pytest.raises(StopAsyncIteration):
        await anext(stream)
    assert auth.await_count == 5
