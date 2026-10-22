"""Hard-kill callback checkpoint qualification without application databases.

The persisted manifest gates each effect. Only committed 'done' checkpoints
and untouched 'pending' suffixes are recoverable; unknown remote effects are
quarantined. Fake transactional sessions simulate PostgreSQL row ownership.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.terminal_lifecycle import (
    TerminalCallbackORM,
    TerminalLifecycleStore,
    _expired_callback_disposition,
)
from ai_osop.orchestrator.terminal_dispatcher import TerminalCallbackDispatcher


def manifest(*states):
    order = ["sync_subtask", "graph_upsert", "downstream_schedule"][:len(states)]
    return {"order": order, "states": dict(zip(order, states))}


@pytest.mark.parametrize(
    "plan,attempts,wanted",
    [
        (None, 1, "requeue"),
        (None, 3, "unknown"),
        (manifest("pending", "pending"), 1, "requeue"),
        (manifest("done", "pending"), 1, "requeue"),
        (manifest("done", "done", "pending"), 2, "requeue"),
        (manifest("done", "done"), 1, "done"),
        (manifest("started", "pending"), 1, "unknown"),
        (manifest("done", "started"), 1, "unknown"),
        (manifest("unknown", "pending"), 1, "unknown"),
        (manifest("pending", "done"), 1, "unknown"),
        (manifest("done", "pending"), 3, "unknown"),
        ({"order": ["graph_upsert"], "states": {}}, 1, "unknown"),
        ({"order": ["unknown-effect"], "states": {"unknown-effect": "pending"}}, 1, "unknown"),
    ],
)
def test_expired_callback_recovery_only_for_durable_untouched_suffix(plan, attempts, wanted):
    assert _expired_callback_disposition(plan, attempts) == wanted


class Result:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class FakePostgres:
    def __init__(self, records):
        self.records = records
        self.writes = []
        self.queries = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def begin(self):
        return self

    async def execute(self, query):
        sql = str(query.compile(compile_kwargs={"literal_binds": True}))
        self.queries.append(sql)
        if "status = 'leased'" in sql:
            expired = [
                row for row in self.records
                if row.status == "leased" and row.leased_until <= datetime.utcnow()
            ]
            return Result(expired)
        if "status = 'pending'" in sql:
            return Result([row for row in self.records if row.status == "pending"])
        raise AssertionError("Unexpected database operation: " + sql)


def callback(task_id, plan, attempts=1):
    return SimpleNamespace(
        id="cb-" + task_id,
        task_id=task_id,
        engagement_id="eng-test",
        attempt_id="attempt-" + task_id,
        outcome="succeeded",
        status="leased",
        worker_id="worker-crashed",
        lease_id="lease-crashed",
        leased_until=datetime.utcnow() - timedelta(seconds=10),
        attempts=attempts,
        effect_steps=plan,
        receipt={"result_code": "agent_completed"},
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        completed_at=None,
    )


@pytest.mark.asyncio
async def test_postgres_reclaims_hard_kill_before_manifest_without_reexecuting_completed_task():
    row = callback("task-initial", None)
    db = FakePostgres([row])
    store = TerminalLifecycleStore.__new__(TerminalLifecycleStore)
    store._sessions = lambda: db
    store._append_event = AsyncMock()

    claimed = await store.claim_callbacks("worker-replacement", limit=2)
    assert len(claimed) == 1
    assert row.status == "leased"
    assert row.worker_id == "worker-replacement"
    assert row.attempts == 2
    assert claimed[0]["lease_id"] != "lease-crashed"
    assert row.effect_steps is None
    assert store._append_event.await_args_list[0].args[3] == "agent.callback_requeued"
    assert "LIMIT 8" in db.queries[0].upper()


@pytest.mark.asyncio
async def test_postgres_reclaims_done_graph_checkpoint_without_repeating_it():
    plan = manifest("done", "done", "pending")
    row = callback("task-graph", plan)
    db = FakePostgres([row])
    store = TerminalLifecycleStore.__new__(TerminalLifecycleStore)
    store._sessions = lambda: db
    store._append_event = AsyncMock()

    claimed = await store.claim_callbacks("worker-next", limit=1)
    assert len(claimed) == 1
    assert claimed[0]["effect_steps"] == plan
    assert row.effect_steps == plan
    assert row.worker_id == "worker-next"
    assert row.status == "leased"
    assert row.attempts == 2


@pytest.mark.asyncio
async def test_hard_kill_while_graph_effect_started_does_not_retry_effect_or_outbox():
    row = callback("task-uncertain", manifest("done", "started", "pending"))
    db = FakePostgres([row])
    store = TerminalLifecycleStore.__new__(TerminalLifecycleStore)
    store._sessions = lambda: db
    store._append_event = AsyncMock()

    claimed = await store.claim_callbacks("worker-next")
    assert claimed == []
    assert row.status == "unknown"
    assert row.effect_steps["states"]["graph_upsert"] == "unknown"
    assert row.effect_steps["states"]["downstream_schedule"] == "pending"
    assert store._append_event.await_args.args[3] == "agent.callback_unknown"


@pytest.mark.asyncio
async def test_final_callback_ack_outage_preserves_done_checkpoints_for_pg_reaper():
    """A failed ACK after all returns must not quarantine completed graph work."""
    plan = manifest("done", "done", "done")
    row = callback("task-ack", plan)
    row.leased_until = datetime.utcnow() + timedelta(seconds=30)
    dispatcher = TerminalCallbackDispatcher.__new__(TerminalCallbackDispatcher)
    dispatcher.worker_id = "worker-original"
    dispatcher._comparison_cursor = None
    dispatcher.store = SimpleNamespace(
        claim_callbacks=AsyncMock(return_value=[{
            "id": row.id, "task_id": row.task_id,
            "engagement_id": row.engagement_id,
            "lease_id": row.lease_id,
        }]),
        finish_callback=AsyncMock(side_effect=OSError("final ACK connection lost")),
    )
    dispatcher._project_with_owner_monitor = AsyncMock()
    dispatcher._check_callback_owner = AsyncMock()
    assert await dispatcher.flush_once() == 0
    assert dispatcher.store.finish_callback.await_count == 1
    assert dispatcher.store.finish_callback.await_args.kwargs == {}
    assert row.status == "leased"
    # Simulate lease expiry/replacement: only the final ACK is recovered.
    row.leased_until = datetime.utcnow() - timedelta(seconds=1)
    db = FakePostgres([row])
    reaper = TerminalLifecycleStore.__new__(TerminalLifecycleStore)
    reaper._sessions = lambda: db
    reaper._append_event = AsyncMock()
    assert await reaper.claim_callbacks("worker-replacement") == []
    assert row.status == "done"
    assert row.effect_steps == plan
    assert reaper._append_event.await_args.args[3] == "agent.callback_done"
    dispatcher._project_with_owner_monitor.assert_awaited_once()


@pytest.mark.asyncio
async def test_restarted_dispatcher_uses_committed_manifest_when_registry_changes(monkeypatch):
    """An acknowledged graph checkpoint stays done; only pending suffix runs."""
    task = Task(
        id="task-source",
        engagement_id="eng-test",
        type="recon",
        status="completed",
        agent_type=AgentType.RECON,
        result={"status": "success"},
    )
    plan = {
        "order": [
            "sync_subtask", "graph_upsert", "flow_refinement",
            "downstream_schedule", "surface_continuation", "adaptive_planner",
        ],
        "states": {
            "sync_subtask": "done",
            "graph_upsert": "done",
            "flow_refinement": "done",
            "downstream_schedule": "pending",
            "surface_continuation": "pending",
            "adaptive_planner": "pending",
        },
    }
    orch = SimpleNamespace(
        _tasks={},
        adaptive_planner=SimpleNamespace(on_task_completed=AsyncMock()),
        _sync_subtask_result=AsyncMock(),
        graph_memory=SimpleNamespace(upsert_task=AsyncMock()),
        _refine_completed_flow_subtask=AsyncMock(),
        _trigger_downstream_tasks=AsyncMock(),
        _chain_authenticated_surface=AsyncMock(),
    )
    store = SimpleNamespace(plan_callback_effects=AsyncMock(return_value=True))
    dispatcher = TerminalCallbackDispatcher.__new__(TerminalCallbackDispatcher)
    dispatcher.store = store
    dispatcher.orch = orch
    dispatcher.worker_id = "worker-new"
    dispatcher._check_callback_owner = AsyncMock()
    dispatcher._load_authorized_task = AsyncMock(return_value=task)
    invoked = []

    async def apply(item, effect, callback):
        invoked.append(effect)
        if plan["states"][effect] == "pending":
            await callback()

    dispatcher._apply_effect = apply
    monkeypatch.setattr(
        "ai_osop.memory.graph_research_context.research_enabled", lambda: False
    )
    await dispatcher._project({
        "id": "cb-task-source", "lease_id": "lease-next",
        "engagement_id": "eng-test", "task_id": task.id, "effect_steps": plan,
    })
    assert store.plan_callback_effects.await_args.args[3] == plan["order"]
    assert invoked == plan["order"]
    orch.graph_memory.upsert_task.assert_not_awaited()
    orch._sync_subtask_result.assert_not_awaited()
    orch._refine_completed_flow_subtask.assert_not_awaited()
    orch._trigger_downstream_tasks.assert_awaited_once()
    orch._chain_authenticated_surface.assert_awaited_once()
    orch.adaptive_planner.on_task_completed.assert_awaited_once()


@pytest.mark.asyncio
async def test_restarted_callback_cannot_skip_mandatory_signed_comparison_step(monkeypatch):
    task = Task(
        id="task-signed", engagement_id="eng-test", flow_id="flow-test",
        type="navigate", agent_type=AgentType.WORKFLOW, status="completed",
        payload={"_authorization_version": 4, "_comparison_role": "target"},
        result={
            "status": "success", "verification_status": "provider_testimony_only",
            "authorization_violation_verified": False,
        },
    )
    dispatcher = TerminalCallbackDispatcher.__new__(TerminalCallbackDispatcher)
    dispatcher._check_callback_owner = AsyncMock()
    dispatcher._load_authorized_task = AsyncMock(return_value=task)
    dispatcher._apply_effect = AsyncMock()
    dispatcher.store = SimpleNamespace(plan_callback_effects=AsyncMock())
    dispatcher.orch = SimpleNamespace(_tasks={}, adaptive_planner=None)
    dispatcher.worker_id = "worker-next"
    monkeypatch.setattr(
        "ai_osop.memory.graph_research_context.research_enabled", lambda: False
    )
    with pytest.raises(RuntimeError, match="manifest"):
        await dispatcher._project({
            "id": "cb-signed", "lease_id": "lease-next",
            "engagement_id": "eng-test", "task_id": task.id,
            "effect_steps": {
                "order": ["sync_subtask", "graph_upsert"],
                "states": {"sync_subtask": "done", "graph_upsert": "pending"},
            },
        })
    dispatcher.store.plan_callback_effects.assert_not_awaited()
    dispatcher._apply_effect.assert_not_awaited()
