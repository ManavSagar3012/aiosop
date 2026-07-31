"""Unit tests for the retry re-queue fix (Phase-1 issue #6).

Previously ``_maybe_retry`` re-dispatched via ``_assign_task`` directly,
keeping the task ONLY in the in-memory ``_tasks`` dict. If the orchestrator
restarted between the retry dispatch and execution, the task was lost —
``recover_state`` only restores from the Redis queue.

The fix re-queues the task to the Redis priority queue FIRST (so it is durable
across a restart), then attempts immediate assignment. If assignment fails the
task stays queued and the scheduler loop picks it up on the next tick.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.task_scheduler import TaskScheduler


def _make_task(*, retry_count: int = 0, max_retries: int = 3) -> Task:
    return Task(
        type="burp_scan",
        agent_type=AgentType.VULN_ANALYSIS,
        engagement_id="eng-test",
        retry_count=retry_count,
        max_retries=max_retries,
        timeout_seconds=5,
    )


def _orch():
    """Build a stub orchestrator with only the attrs _maybe_retry touches."""
    orch = MagicMock()
    orch._audit_log = AsyncMock()
    orch._assign_task = AsyncMock()
    orch._retry_sleep = AsyncMock()

    sm = MagicMock()
    sm.push_task_queue = AsyncMock(return_value=None)
    sm.store_task = AsyncMock(return_value=None)  # a94e1c03: retry now persists to warm store
    orch.session_memory = sm

    gm = MagicMock()
    gm.upsert_task = AsyncMock(return_value=None)
    orch.graph_memory = gm

    dlq = MagicMock()
    dlq.enqueue = AsyncMock(return_value=None)
    orch.dlq = dlq

    return orch


@pytest.mark.asyncio
async def test_retry_pushes_task_to_redis_queue_before_assign():
    """A retry must push the task to the Redis queue so it survives a restart
    that happens between the retry dispatch and execution."""
    orch = _orch()
    ts = TaskScheduler(orch, MagicMock())
    task = _make_task()

    ok = await ts._maybe_retry(task, {"error": "transient timeout"})

    assert ok is True
    # The task was pushed to the durable Redis queue.
    orch.session_memory.push_task_queue.assert_awaited_once()
    queue_name, payload = orch.session_memory.push_task_queue.await_args.args
    assert queue_name == "tasks:eng-test"
    assert payload["id"] == task.id
    assert payload["status"] == "pending"
    # AND immediate assignment was attempted (fast-path).
    orch._assign_task.assert_awaited_once_with(task)


@pytest.mark.asyncio
async def test_retry_queue_push_precedes_assign():
    """The Redis push MUST happen before _assign_task so the task is durable
    the instant the retry fires."""
    orch = _orch()
    order: list[str] = []

    async def track_push(queue, payload):
        order.append("push")

    async def track_assign(task):
        order.append("assign")

    orch.session_memory.push_task_queue = AsyncMock(side_effect=track_push)
    orch._assign_task = AsyncMock(side_effect=track_assign)

    ts = TaskScheduler(orch, MagicMock())
    task = _make_task()

    await ts._maybe_retry(task, {"error": "x"})

    assert order == ["push", "assign"]


@pytest.mark.asyncio
async def test_retry_swallows_redis_push_failure_and_still_assigns():
    """If the Redis push raises, the retry must still attempt assignment —
    a Redis blip must not strand a task that has retry budget left."""
    orch = _orch()
    orch.session_memory.push_task_queue = AsyncMock(side_effect=RuntimeError("redis down"))

    ts = TaskScheduler(orch, MagicMock())
    task = _make_task()

    ok = await ts._maybe_retry(task, {"error": "x"})

    assert ok is True  # retry still succeeded
    orch._assign_task.assert_awaited_once_with(task)  # assignment still attempted


@pytest.mark.asyncio
async def test_retry_still_dlqs_on_budget_exhaustion():
    """The Redis-queue fix is in the retry path only; budget exhaustion must
    still route to the DLQ and NOT push to Redis."""
    orch = _orch()
    ts = TaskScheduler(orch, MagicMock())
    # Task at its retry budget — next retry must DLQ, not re-queue.
    task = _make_task(retry_count=3, max_retries=3)

    ok = await ts._maybe_retry(task, {"error": "x"})

    assert ok is False
    orch.dlq.enqueue.assert_awaited_once()
    # No Redis push on the exhaustion path.
    orch.session_memory.push_task_queue.assert_not_awaited()
    orch._assign_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_retry_still_dlqs_on_non_retryable_error():
    """Deterministic / non-retryable errors short-circuit to the DLQ without
    pushing to Redis (the task is intentionally terminal)."""
    orch = _orch()
    ts = TaskScheduler(orch, MagicMock())
    task = _make_task()

    ok = await ts._maybe_retry(
        task, {"error": "Tool run_sqlmap not available on server security-bridge"}
    )

    assert ok is False
    orch.dlq.enqueue.assert_awaited_once()
    orch.session_memory.push_task_queue.assert_not_awaited()
