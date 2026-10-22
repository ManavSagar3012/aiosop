"""Callback workers must not keep issuing effects after losing their SQL fence."""

from types import SimpleNamespace
from unittest.mock import AsyncMock
import asyncio

import pytest

from ai_osop.orchestrator.terminal_dispatcher import TerminalCallbackDispatcher


def _worker():
    store = AsyncMock()
    store.renew_callback_lease.return_value = True
    store.claim_callbacks.return_value = [
        {"id": "cb-1", "lease_id": "lease-1", "engagement_id": "eng-1", "task_id": "task-1"}
    ]
    orch = SimpleNamespace(
        terminal_store=store,
        _tasks={},
        _sync_subtask_result=AsyncMock(),
        graph_memory=AsyncMock(),
        _refine_completed_flow_subtask=AsyncMock(),
        _trigger_downstream_tasks=AsyncMock(),
        _chain_authenticated_surface=AsyncMock(),
        adaptive_planner=AsyncMock(),
    )
    worker = TerminalCallbackDispatcher(orch)
    worker._load_authorized_task = AsyncMock(return_value=SimpleNamespace(
        id="task-1", engagement_id="eng-1", status="completed",
        result={"status": "completed"}
    ))
    return worker, store, orch


@pytest.mark.asyncio
async def test_lost_callback_lease_stops_before_followup_and_marks_unknown():
    worker, store, orch = _worker()
    # The first outer ownership check passes; the nested projection check
    # fails before even synchronizing task lineage.
    store.renew_callback_lease.side_effect = [True, False]
    assert await worker.flush_once() == 0
    orch._sync_subtask_result.assert_not_awaited()
    orch.graph_memory.upsert_task.assert_not_awaited()
    orch._trigger_downstream_tasks.assert_not_awaited()
    store.finish_callback.assert_awaited_once_with(
        "cb-1", "lease-1", status="unknown"
    )


@pytest.mark.asyncio
async def test_callback_lease_fences_all_followup_boundaries():
    worker, store, orch = _worker()
    assert await worker.flush_once() == 1
    assert store.renew_callback_lease.await_count >= 7
    orch._trigger_downstream_tasks.assert_awaited_once()
    orch._chain_authenticated_surface.assert_awaited_once()
    store.finish_callback.assert_awaited_once_with("cb-1", "lease-1")


@pytest.mark.asyncio
async def test_missing_durable_effect_plan_prevents_all_downstream_calls():
    worker, store, orch = _worker()
    store.plan_callback_effects.return_value = False
    assert await worker.flush_once() == 0
    orch._sync_subtask_result.assert_not_awaited()
    orch.graph_memory.upsert_task.assert_not_awaited()
    store.start_callback_effect.assert_not_awaited()
    store.finish_callback.assert_awaited_once_with(
        "cb-1", "lease-1", status="unknown"
    )


@pytest.mark.asyncio
async def test_lost_receipt_prevents_later_consequential_effects():
    worker, store, orch = _worker()
    store.confirm_callback_effect.return_value = False
    assert await worker.flush_once() == 0
    orch._sync_subtask_result.assert_awaited_once()
    orch.graph_memory.upsert_task.assert_not_awaited()
    orch._trigger_downstream_tasks.assert_not_awaited()
    store.start_callback_effect.assert_awaited_once()
    store.finish_callback.assert_awaited_once_with(
        "cb-1", "lease-1", status="unknown"
    )


@pytest.mark.asyncio
async def test_heartbeat_loss_interrupts_blocked_callback_without_replay(monkeypatch):
    from ai_osop.orchestrator import terminal_dispatcher

    worker, store, orch = _worker()
    original_sleep = asyncio.sleep
    entered = asyncio.Event()
    stopped = asyncio.Event()

    async def blocked_projection(_item):
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            stopped.set()
            raise

    async def fast_sleep(_seconds):
        await entered.wait()
        await original_sleep(0)

    worker._project = blocked_projection
    store.renew_callback_lease.side_effect = [True, False]
    monkeypatch.setattr(terminal_dispatcher.asyncio, "sleep", fast_sleep)
    assert await asyncio.wait_for(worker.flush_once(), 1) == 0
    assert stopped.is_set()
    store.finish_callback.assert_awaited_once_with(
        "cb-1", "lease-1", status="unknown"
    )
    orch._trigger_downstream_tasks.assert_not_awaited()
