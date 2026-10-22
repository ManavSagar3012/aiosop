"""New durable task/Flow atomic admission contract; no app DB or target calls."""

from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.api.routers import flows
from ai_osop.memory import adaptive_dispatch as admission
from tests.test_adaptive_target_binding import (
    DbSession, claim_args, durable as old_durable_fixture,
    api_adaptive_step as old_api_adaptive_step_fixture,
)
from tests.test_execution_flows_api import _create_flow_and_task, flow_client


@pytest.fixture
def durable_atomic(old_durable_fixture, monkeypatch):
    """Extend the earlier immutable-lineage fake with a transactional TaskORM."""
    state, store = old_durable_fixture
    state.reserved_tasks = {}

    class AtomicSession(DbSession):
        @asynccontextmanager
        async def begin(self):
            async with self.state.lock:
                snapshot = deepcopy((
                    self.state.flow, self.state.step,
                    self.state.events, self.state.reserved_tasks,
                ))
                try:
                    yield
                except BaseException:
                    (
                        self.state.flow, self.state.step,
                        self.state.events, self.state.reserved_tasks,
                    ) = snapshot
                    raise

        def add(self, row):
            if row.__tablename__ != "tasks" or row.id in self.state.reserved_tasks:
                raise RuntimeError("Duplicate or unexpected execution TaskORM")
            self.state.reserved_tasks[row.id] = row

        async def flush(self):
            return None

        async def execute(self, statement):
            sql = str(statement)
            if sql.startswith("UPDATE execution_subtasks"):
                if self.state.step.status != "pending" or self.state.step.execution_task_id is not None:
                    from tests.test_adaptive_target_binding import Result
                    return Result(None)
                params = statement.compile().params
                self.state.step.status = "dispatched"
                self.state.step.execution_task_id = params["execution_task_id"]
                from tests.test_adaptive_target_binding import Result
                return Result(self.state.step.id)
            return await super().execute(statement)

    store._sessions = lambda: AtomicSession(state)
    return state, store


def signed_task(state, *, target="example.com", priority=5):
    return admission.build_adaptive_execution_task(
        flow=state.flow_model(), subtask=state.subtask_model(),
        target=target, priority=priority,
    )


@pytest.mark.asyncio
async def test_pg_atomic_claim_persists_task_subtask_binding_flow_and_outbox(durable_atomic):
    state, _ = durable_atomic
    task = signed_task(state)
    assert task.approval_required is True and task.status == "pending"
    assert task.payload == {"target": "example.com"}
    receipt = await admission.claim_confirmed_adaptive_subtask(
        object(), **claim_args(state, execution_task=task),
    )
    assert receipt == {
        "status": "pending", "task_id": task.id,
        "subtask_id": state.step.id, "flow_revision": 11,
        "approval_required": True, "execution_started": False,
    }
    assert state.flow.revision == 11
    assert state.step.status == "dispatched"
    assert state.step.execution_task_id == task.id
    assert len(state.reserved_tasks) == len(state.events) == 1
    persisted = state.reserved_tasks[task.id]
    assert persisted.status == "pending" and persisted.approval_required is True
    assert persisted.payload == {"target": "example.com", "_authorization_version": 4}
    assert persisted.parent_task_id == state.objective_id
    assert persisted.subtask_id == state.step.id
    assert state.events[0][0] == "planner.adaptive_dispatch_intent"
    assert state.events[0][2] == task.id


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["outbox", "flow_cas", "bad_target", "bad_actor", "foreign_task"])
async def test_failed_admission_rolls_back_task_step_revision_and_intent(durable_atomic, failure):
    state, _ = durable_atomic
    task = signed_task(state)
    params = claim_args(state, execution_task=task)
    if failure == "outbox":
        state.fail_event = True
    elif failure == "flow_cas":
        state.fail_cas = True
    elif failure == "bad_target":
        params["payload"] = {"target": "sub.example.com"}
    elif failure == "bad_actor":
        params["actor_id"] = "other-senior"
    elif failure == "foreign_task":
        task.id = "task-foreign"
    with pytest.raises((admission.AdaptiveDispatchDenied, admission.AdaptiveDispatchUnavailable)):
        await admission.claim_confirmed_adaptive_subtask(object(), **params)
    assert state.step.status == "pending"
    assert state.step.execution_task_id is None
    assert state.flow.revision == 10
    assert state.reserved_tasks == {}
    assert not state.events


@pytest.mark.asyncio
async def test_two_replicas_can_reserve_at_most_one_identical_execution_task(durable_atomic):
    import asyncio
    state, _ = durable_atomic
    snapshots = claim_args(state, execution_task=signed_task(state))
    results = await asyncio.gather(
        admission.claim_confirmed_adaptive_subtask(object(), **snapshots),
        admission.claim_confirmed_adaptive_subtask(object(), **snapshots),
        return_exceptions=True,
    )
    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(isinstance(result, admission.AdaptiveDispatchDenied) for result in results) == 1
    assert len(state.reserved_tasks) == 1
    assert len(state.events) == 1
    assert state.step.execution_task_id == next(iter(state.reserved_tasks))


def test_production_manual_flow_reserves_task_in_pg_then_only_enqueues(flow_client, monkeypatch):
    client, _, orchestrator, memory = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(f"/flows/{flow_id}/subtasks", json={
        "task_id": task_id, "title": "Existing manual workflow",
    }).json()
    # Force only this isolated fake through the production branch; real app
    # uses the genuine SessionMemory type, never an arbitrary fake fallback.
    monkeypatch.setattr(flows, "SessionMemory", type(memory))
    original = memory.claim_subtask
    received = []

    async def tracked_claim(*args, **kwargs):
        assert kwargs.get("execution_task") is not None
        task = kwargs["execution_task"]
        assert task.payload == {"target": "example.com"}
        received.append(task.id)
        return await original(*args, **{k: v for k, v in kwargs.items() if k != "execution_task"})

    memory.claim_subtask = tracked_claim
    orchestrator.enqueue_registered_task = AsyncMock(return_value=SimpleNamespace(status="awaiting_approval"))
    orchestrator.schedule_task = AsyncMock(side_effect=AssertionError("No re-upsert scheduling"))
    response = client.post(f"/flows/{flow_id}/subtasks/{step['id']}/dispatch", json={
        "expected_revision": memory.flows[flow_id].revision,
        "payload": {"target": "example.com"},
    })
    assert response.status_code == 200, response.text
    assert response.json()["task_id"] == received[0]
    assert response.json()["execution_started"] is False
    orchestrator.enqueue_registered_task.assert_awaited_once_with(received[0])
    orchestrator.schedule_task.assert_not_awaited()


def test_production_manual_flow_no_hydration_method_fails_before_claim(flow_client, monkeypatch):
    client, _, orchestrator, memory = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(f"/flows/{flow_id}/subtasks", json={
        "task_id": task_id, "title": "No hydration enqueue",
    }).json()
    monkeypatch.setattr(flows, "SessionMemory", type(memory))
    memory.claim_subtask = AsyncMock(side_effect=AssertionError("No claim without hydration"))
    response = client.post(f"/flows/{flow_id}/subtasks/{step['id']}/dispatch", json={
        "expected_revision": memory.flows[flow_id].revision,
        "payload": {"target": "example.com"},
    })
    assert response.status_code == 503
    memory.claim_subtask.assert_not_awaited()
    assert not orchestrator.scheduled


def test_production_adaptive_flow_routes_only_reserved_task_id_through_enqueue(
    old_api_adaptive_step_fixture, monkeypatch,
):
    client, _, orchestrator, memory, flow_id, subtask_id, claim = old_api_adaptive_step_fixture
    monkeypatch.setattr(flows, "SessionMemory", type(memory))
    received = []
    revision = memory.flows[flow_id].revision

    async def signed_claim(*args, **kwargs):
        task = kwargs["execution_task"]
        assert task.status == "pending"
        assert task.approval_required is True
        assert task.payload == {"target": "example.com"}
        assert kwargs["actor_role"] == "senior_operator"
        assert kwargs["actor_id"] == "alice"
        received.append(task.id)
        return {
            "task_id": task.id, "status": "pending",
            "flow_revision": revision + 1,
            "approval_required": True, "execution_started": False,
        }

    claim.side_effect = signed_claim
    orchestrator.enqueue_registered_task = AsyncMock(return_value=SimpleNamespace(status="pending"))
    orchestrator.schedule_task = AsyncMock(side_effect=AssertionError("Unsafe duplicate task UPSERT"))
    response = client.post(f"/flows/{flow_id}/subtasks/{subtask_id}/dispatch", json={
        "expected_revision": revision,
        "payload": {"target": "example.com"},
    })
    assert response.status_code == 200, response.text
    assert response.json() == {
        "subtask_id": subtask_id,
        "task_id": received[0],
        "status": "registered", "approval_required": True,
        "approval_state": "awaiting_scheduler_review", "execution_started": False,
    }
    orchestrator.enqueue_registered_task.assert_awaited_once_with(received[0])
    orchestrator.schedule_task.assert_not_awaited()


def test_adaptive_production_without_enqueue_method_refuses_before_claim(
    old_api_adaptive_step_fixture, monkeypatch,
):
    client, _, orchestrator, memory, flow_id, subtask_id, claim = old_api_adaptive_step_fixture
    monkeypatch.setattr(flows, "SessionMemory", type(memory))
    response = client.post(f"/flows/{flow_id}/subtasks/{subtask_id}/dispatch", json={
        "expected_revision": memory.flows[flow_id].revision,
        "payload": {"target": "example.com"},
    })
    assert response.status_code == 503
    assert not orchestrator.scheduled
    claim.assert_not_awaited()


def test_production_unknown_queue_result_never_retries_or_resets_claim(flow_client, monkeypatch):
    client, _, orchestrator, memory = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(f"/flows/{flow_id}/subtasks", json={
        "task_id": task_id, "title": "Queue may already have started",
    }).json()
    monkeypatch.setattr(flows, "SessionMemory", type(memory))
    original_claim = memory.claim_subtask
    async def tracked_claim(*a, **kw):
        return await original_claim(
            *a, **{k: v for k, v in kw.items() if k != "execution_task"},
        )
    memory.claim_subtask = AsyncMock(side_effect=tracked_claim)
    orchestrator.enqueue_registered_task = AsyncMock(side_effect=OSError("Queue unverified"))
    orchestrator.schedule_task = AsyncMock(side_effect=AssertionError("No duplicate scheduling"))
    response = client.post(f"/flows/{flow_id}/subtasks/{step['id']}/dispatch", json={
        "expected_revision": memory.flows[flow_id].revision,
        "payload": {"target": "example.com"},
    })
    assert response.status_code == 503
    assert "unknown" in response.json()["detail"].lower()
    assert memory.subtasks[step["id"]].status == "dispatched"
    assert memory.flows[flow_id].revision > 0
    orchestrator.schedule_task.assert_not_awaited()
