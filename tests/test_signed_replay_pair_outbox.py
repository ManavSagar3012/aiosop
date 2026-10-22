"""Committed paired GET intents: redacted, restart-safe queue-only recovery."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.supervision_outbox import SupervisionOutboxDispatcher


def pair_event():
    return {
        "id": "out-pair-1",
        "event_id": "evt-pair-1",
        "lease_id": "lease-pair-1",
        "engagement_id": "eng-pair-1",
        "topic": "replay.pair_admitted",
        "payload": {
            "event_id": "evt-pair-1",
            "engagement_id": "eng-pair-1",
            "task_id": "task-parent-1",
            "kind": "replay.pair_admitted",
            "metadata": {
                "source_task_id": "task-source-1",
                "target_task_id": "task-target-1",
                "url": "https://private.example/secret?token=never-publish",
                "headers": {"Authorization": "sensitive bearer"},
            },
        },
    }


@pytest.mark.asyncio
async def test_pair_outbox_redacts_and_requires_reconciled_delivery_before_ack():
    store, bus, queue = AsyncMock(), AsyncMock(), AsyncMock()
    store.claim_outbox.return_value = [pair_event()]
    store.ack_outbox.return_value = True
    dispatcher = SupervisionOutboxDispatcher(
        store, bus, enqueue_signed_replay_pair=queue,
    )
    assert await dispatcher.flush_once() == 1
    queue.assert_awaited_once_with("task-source-1", "task-target-1")
    assert store.ack_outbox.await_count == 1
    event = bus.publish.await_args.args[1]
    assert event["kind"] == "replay.pair_admitted"
    assert event["source_task_id"] == "task-source-1"
    assert event["target_task_id"] == "task-target-1"
    assert "secret" not in str(event) and "Authorization" not in str(event)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["missing_callback", "queue_error", "forged_pair"])
async def test_pair_outbox_unknown_and_forged_intents_never_ack(mode):
    store, bus, queue = AsyncMock(), AsyncMock(), AsyncMock()
    item = pair_event()
    if mode == "forged_pair":
        item["payload"]["metadata"]["target_task_id"] = "task-source-1"
    if mode == "queue_error":
        queue.side_effect = OSError("Redis delivery UNKNOWN")
    store.claim_outbox.return_value = [item]
    dispatcher = SupervisionOutboxDispatcher(
        store, bus, enqueue_signed_replay_pair=(
            None if mode == "missing_callback" else queue
        ),
    )
    assert await dispatcher.flush_once() == 0
    store.ack_outbox.assert_not_awaited()
    if mode != "queue_error":
        queue.assert_not_awaited()


def _recovery():
    memory = SessionMemory.__new__(SessionMemory)
    parent = Task(
        id="task-parent-1", engagement_id="eng-pair-1",
        type="replay_for_diff_auth", agent_type=AgentType.WORKFLOW,
        status="completed", flow_id="flow-pair-1", parent_task_id="task-map-1",
        payload={"approval_id": "apr-human-1", "operator_approved": True},
    )
    children = []
    for role, label in (("source", "alice"), ("target", "bob")):
        children.append(Task(
            id=f"task-{role}-1", engagement_id="eng-pair-1",
            type="navigate", agent_type=AgentType.WORKFLOW,
            parent_task_id=parent.id, flow_id=parent.flow_id,
            status="pending", approval_required=True,
            payload={
                "_comparison_role": role, "user_label": label,
                "url": "https://authorized.example/owned", "method": "GET",
            },
        ))
    tasks = {task.id: task for task in [parent, *children]}
    memory.load_task_authoritative = AsyncMock(side_effect=lambda tid: tasks.get(tid))
    memory.admit_signed_replay_observation_pair = AsyncMock(return_value=[])
    memory.push_task_queue = AsyncMock()
    orchestrator = Orchestrator.__new__(Orchestrator)
    orchestrator.session_memory = memory
    return SimpleNamespace(orch=orchestrator, memory=memory, source=children[0], target=children[1])


@pytest.mark.asyncio
async def test_replacement_dispatcher_only_requeues_pg_pending_children():
    fx = _recovery()
    assert await fx.orch.reconcile_signed_replay_pair_intent(fx.source.id, fx.target.id)
    assert fx.memory.push_task_queue.await_count == 2
    call = fx.memory.admit_signed_replay_observation_pair.await_args
    assert call.kwargs == {"existing_only": True}
    assert all(task.status == "pending" for task in call.args[1])
    fx.memory.push_task_queue.reset_mock()
    fx.source.status = "dispatch_unknown"
    fx.target.status = "awaiting_approval"
    fx.target.payload["approval_id"] = "apr-target-1"
    fx.target.payload["operator_approved"] = True
    assert await fx.orch.reconcile_signed_replay_pair_intent(fx.source.id, fx.target.id)
    fx.memory.push_task_queue.assert_not_awaited()
    second = fx.memory.admit_signed_replay_observation_pair.await_args.args[1]
    assert second[0].status == "pending"
    assert "approval_id" not in second[1].payload
    assert "operator_approved" not in second[1].payload


@pytest.mark.asyncio
async def test_missing_peer_and_revoked_authority_fail_closed_without_redis_delivery():
    fx = _recovery()
    fx.memory.load_task_authoritative.side_effect = lambda tid: (
        None if tid == fx.target.id else fx.source if tid == fx.source.id else Task(
            id="task-parent-1", engagement_id="eng-pair-1",
            type="replay_for_diff_auth", agent_type=AgentType.WORKFLOW,
        )
    )
    with pytest.raises(Exception):
        await fx.orch.reconcile_signed_replay_pair_intent(fx.source.id, fx.target.id)
    fx.memory.push_task_queue.assert_not_awaited()
    fx = _recovery()
    fx.memory.admit_signed_replay_observation_pair.side_effect = PermissionError("revoked")
    with pytest.raises(Exception):
        await fx.orch.reconcile_signed_replay_pair_intent(fx.source.id, fx.target.id)
    fx.memory.push_task_queue.assert_not_awaited()
