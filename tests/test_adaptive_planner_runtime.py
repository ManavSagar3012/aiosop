"""Regression tests for bounded planning, recovery, and execution lineage."""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.context_manager_agent import ContextManagerAgent
from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.exceptions import OutOfScopeError, WorkflowException
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, SubtaskRecord, Task
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.core.telemetry import RequestContext
from ai_osop.orchestrator.orchestrator import Orchestrator


def make_orchestrator(*, max_iterations=2, adaptive=True):
    sm = AsyncMock()
    cached = {}

    async def read_hot(key):
        return cached.get(key)

    async def write_hot(key, data, ttl=3600):
        cached[key] = data

    sm.retrieve_hot.side_effect = read_hot
    sm.store_hot.side_effect = write_hot
    sm.load_flow.return_value = None
    gm = AsyncMock()
    gm.run_read_query.return_value = []
    gm.get_graph_stats.return_value = {"endpoints": 0, "vulnerabilities": 0}
    orch = Orchestrator(sm, gm, AsyncMock(), AsyncMock())
    session = SessionState(
        session_id="eng-test",
        scope=ScopeDefinition(
            engagement_id="eng-test",
            domains=["example.com"],
            authorization_ref="signed-test-roe",
        ),
        phase=EngagementPhase.RECONNAISSANCE.value,
        roe={
            "adaptive_planning_enabled": adaptive,
            "adaptive_max_iterations": max_iterations,
        },
    )
    orch._sessions["eng-test"] = session

    async def schedule(task):
        orch._tasks[task.id] = task
        return task

    orch.schedule_task = AsyncMock(side_effect=schedule)
    orch._audit_log = AsyncMock()
    return orch, sm, gm, cached


def completed_recon(task_id):
    return Task(
        id=task_id,
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-test",
        payload={"domain": "example.com"},
        status="completed",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "refusal",
    [
        ModelBudgetExceeded("No signed budget"),
        ModelOutcomeUncertain("Unconfirmed provider result"),
    ],
)
async def test_strategic_planner_never_uses_heuristic_after_provider_safety_refusal(
    refusal
):
    orch, _, _, _ = make_orchestrator()
    orch.llm_client = AsyncMock()
    orch.llm_client.complete.side_effect = refusal
    planner = orch.adaptive_planner
    planner.build_engagement_state_summary = AsyncMock(return_value={})
    planner._heuristic_fallback_plan = AsyncMock()
    with pytest.raises(type(refusal)):
        await planner.evaluate_and_plan_next_step("eng-test")
    planner._heuristic_fallback_plan.assert_not_awaited()


@pytest.mark.asyncio
async def test_completed_task_refinement_does_not_swallow_uncertain_provider_outcome():
    orch, _, _, _ = make_orchestrator()
    task = completed_recon("task-durable-refinement")
    task.flow_id = "flow-refine"
    task.subtask_id = "subtask-refine"
    orch.flow_refiner.on_subtask_completed = AsyncMock(
        side_effect=ModelOutcomeUncertain("Unknown downstream model outcome")
    )
    with pytest.raises(ModelOutcomeUncertain):
        await orch._refine_completed_flow_subtask(task, {"status": "success"})


@pytest.mark.asyncio
async def test_adaptive_planner_requires_consent_and_caps_iterations():
    orch, sm, _, cached = make_orchestrator(max_iterations=1)
    planner = orch.adaptive_planner
    planner.evaluate_and_plan_next_step = AsyncMock(
        return_value={
            "action": "request_sub_recon",
            "parameters": {"target": "example.com"},
            "provenance": "test",
        }
    )
    parent = completed_recon("task-parent-a")
    orch._tasks[parent.id] = parent

    dispatched = await planner.on_task_completed(parent)
    assert dispatched == {
        "status": "human_confirmation_required",
        "action": "request_sub_recon",
        "target": "example.com",
        "source_task_id": parent.id,
        "flow_id": planner._flow_id("eng-test"),
        "execution_started": False,
        "proposal_only": True,
    }
    # Even an offline heuristic has no authority to queue target-side work.
    sm.store_subtask.assert_not_awaited()

    assert (await planner.on_task_completed(parent))["status"] == "already_processed"
    other = completed_recon("task-parent-b")
    assert (await planner.on_task_completed(other))["status"] == "iteration_budget_exhausted"
    orch.schedule_task.assert_not_awaited()
    assert cached["adaptive_plan:eng-test"]["iterations"] == 1
    # Adaptive progress must not use an unconditional Flow upsert. That can
    # revert operator pause/cancel state and a newer replica's revision.
    sm.store_flow.assert_not_awaited()
    assert sm.create_flow_if_absent.await_count >= 1


@pytest.mark.asyncio
async def test_adaptive_planner_cannot_override_operator_paused_flow():
    orch, sm, _, _ = make_orchestrator()
    flow = FlowRecord(
        id=orch.adaptive_planner._flow_id("eng-test"),
        engagement_id="eng-test",
        objective="Approved reconnaissance",
        status="paused",
        revision=4,
    )
    sm.load_flow.return_value = flow
    parent = completed_recon("task-after-pause")
    orch._tasks[parent.id] = parent
    orch.adaptive_planner.evaluate_and_plan_next_step = AsyncMock(
        return_value={"action": "request_sub_recon", "parameters": {"target": "example.com"}}
    )

    result = await orch.adaptive_planner.on_task_completed(parent)

    assert result == {"status": "flow_inactive"}
    orch.adaptive_planner.evaluate_and_plan_next_step.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()
    sm.store_flow.assert_not_awaited()
    sm.transition_flow_status.assert_not_awaited()


@pytest.mark.asyncio
async def test_adaptive_completion_is_revision_guarded_and_never_reopens_closed_flow():
    orch, sm, _, _ = make_orchestrator(max_iterations=1)
    planner = orch.adaptive_planner
    flow_id = planner._flow_id("eng-test")
    sm.load_flow.return_value = FlowRecord(
        id=flow_id, engagement_id="eng-test", objective="Review", status="running", revision=8
    )
    await planner._save_plan(
        "eng-test",
        {"overall_goal": "Review", "iterations": 1, "max_iterations": 1},
    )
    sm.transition_flow_status.assert_awaited_once_with(
        flow_id, "eng-test", 8, ["running"], "completed"
    )
    assert sm.create_flow_if_absent.await_count == 1
    sm.store_flow.assert_not_awaited()

    sm.transition_flow_status.reset_mock()
    sm.load_flow.return_value = FlowRecord(
        id=flow_id, engagement_id="eng-test", objective="Review", status="cancelled", revision=9
    )
    await planner._save_plan(
        "eng-test",
        {"overall_goal": "Review", "iterations": 1, "max_iterations": 1},
    )
    sm.transition_flow_status.assert_not_awaited()


@pytest.mark.asyncio
async def test_adaptive_planner_disabled_by_default():
    orch, _, _, _ = make_orchestrator(adaptive=False)
    assert (await orch.adaptive_planner.on_task_completed(completed_recon("task-1"))) == {
        "status": "disabled"
    }
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_adaptive_planner_rejects_out_of_scope_and_unsafe_decisions():
    orch, _, _, _ = make_orchestrator()
    planner = orch.adaptive_planner
    parent = completed_recon("task-parent")
    with pytest.raises(OutOfScopeError):
        await planner.execute_strategic_action(
            "eng-test", {"action": "request_sub_recon", "parameters": {"target": "other.net"}},
            parent_task=parent,
        )
    blocked = await planner.execute_strategic_action(
        "eng-test", {"action": "execute_attack_chain", "parameters": {"path_id": "path"}},
        parent_task=parent,
    )
    assert blocked["status"] == "blocked"
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_adaptive_planner_summarizes_every_second_iteration():
    orch, sm, _, _ = make_orchestrator(max_iterations=2)
    planner = orch.adaptive_planner
    planner.evaluate_and_plan_next_step = AsyncMock(
        return_value={"action": "create_hypothesis", "parameters": {"statement": "Review header"}}
    )
    agent = AsyncMock()
    agent.ctx.agent_type = AgentType.CONTEXT_MANAGER
    orch._agents["context-1"] = agent

    for i in range(2):
        await planner.on_task_completed(completed_recon(f"task-recon-{i}"))
    sm.create_checkpoint.assert_awaited_once()
    sm.persist_session_state.assert_awaited_once()
    scheduled = orch.schedule_task.await_args.args[0]
    assert scheduled.type == "summarize_context"
    assert scheduled.dependencies == ["task-recon-1"]


@pytest.mark.asyncio
async def test_temporal_schedule_never_bypasses_approval_or_scope():
    orch, sm, _, _ = make_orchestrator()
    orch.temporal_enabled = True
    orch.temporal_scheduler = AsyncMock()
    # Exercise the actual entry point instead of the fake plan test scheduler.
    orch.schedule_task = Orchestrator.schedule_task.__get__(orch, Orchestrator)
    orch.approval_coordinator._raise_approval = AsyncMock()
    task = Task(
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-test",
        approval_required=True,
        payload={"domain": "example.com"},
    )
    await orch.schedule_task(task)
    assert task.status == "awaiting_approval"
    orch.approval_coordinator._raise_approval.assert_awaited_once()
    orch.temporal_scheduler.start_task_workflow.assert_not_awaited()
    outside = task.model_copy(update={"id": "task-outside", "payload": {"domain": "other.net"}})
    with pytest.raises(OutOfScopeError):
        await orch.schedule_task(outside)
    assert orch.temporal_scheduler.start_task_workflow.await_count == 0
    assert sm.store_task.await_count >= 1


@pytest.mark.asyncio
async def test_recovery_hydrates_sessions_and_only_queues_eligible_tasks():
    orch, sm, _, _ = make_orchestrator()
    session = orch._sessions.pop("eng-test")
    sm.list_all_sessions.return_value = [session]
    awaiting = Task(
        id="task-approval", type="full_recon", agent_type=AgentType.RECON,
        engagement_id="eng-test", approval_required=True, status="awaiting_approval",
    )
    pending = completed_recon("task-pending")
    pending.status = "running"
    eligible = completed_recon("task-safe-pending")
    eligible.status = "pending"
    finished = completed_recon("task-finished")
    sm.list_all_tasks.return_value = [awaiting, pending, eligible, finished]

    state = await orch.recovery_service.recover_state()
    assert state["engagements"] == 1
    assert orch._sessions["eng-test"].session_id == "eng-test"
    assert orch._tasks[pending.id].status == "running"
    assert orch._tasks[awaiting.id].status == "awaiting_approval"
    assert sm.push_task_queue.await_count == 1
    assert sm.push_task_queue.await_args.args[1]["id"] == eligible.id
    assert state["unresolved"] == 1
    sm.store_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_recovery_refuses_pending_work_from_paused_flow():
    orch, sm, _, _ = make_orchestrator()
    session = orch._sessions.pop("eng-test")
    sm.list_all_sessions.return_value = [session]
    queued = completed_recon("task-paused")
    queued.status = "pending"
    queued.flow_id = "flow-paused"
    sm.load_flow.return_value = FlowRecord(
        id="flow-paused",
        engagement_id="eng-test",
        objective="Paused",
        status="paused",
    )
    sm.list_all_tasks.return_value = [queued]
    summary = await orch.recovery_service.recover_state()
    assert summary["tasks"] == 0
    assert summary["skipped"] == 1
    sm.push_task_queue.assert_not_awaited()


@pytest.mark.asyncio
async def test_recovery_refuses_pending_work_after_scope_window_expiry():
    orch, sm, _, _ = make_orchestrator()
    session = orch._sessions.pop("eng-test")
    session.scope.testing_window_end = datetime.utcnow() - timedelta(minutes=1)
    sm.list_all_sessions.return_value = [session]
    queued = completed_recon("task-window-expired")
    queued.status = "pending"
    sm.list_all_tasks.return_value = [queued]
    summary = await orch.recovery_service.recover_state()
    assert summary["skipped"] == 1
    sm.push_task_queue.assert_not_awaited()


@pytest.mark.asyncio
async def test_reaper_never_retries_unresolved_external_execution():
    orch, sm, gm, _ = make_orchestrator()
    task = completed_recon("task-external-outcome-unknown")
    task.status = "running"
    task.started_at = datetime.utcnow() - timedelta(hours=1)
    task.timeout_seconds = 5
    orch._tasks[task.id] = task
    orch._audit_log = AsyncMock()
    orch.task_scheduler._maybe_retry = AsyncMock()
    assert await orch._reap_stuck_tasks() == 0
    assert await orch._reap_stuck_tasks() == 0
    assert task.status == "running"
    orch.task_scheduler._maybe_retry.assert_not_awaited()
    sm.store_task.assert_not_awaited()
    gm.upsert_task.assert_not_awaited()
    orch._audit_log.assert_awaited_once()
    assert orch._audit_log.await_args.args[0].action["outcome"] == "external_outcome_unknown"


@pytest.mark.asyncio
async def test_task_completion_updates_subtask_and_preserves_other_engagements():
    orch, sm, _, _ = make_orchestrator()
    flow_id = "flow-test"
    subtask = SubtaskRecord(
        id="subtask-test", engagement_id="eng-test", flow_id=flow_id,
        task_id="task-root", title="Recon", execution_task_id="task-exec",
    )
    sm.list_subtasks.return_value = [subtask]
    task = completed_recon("task-exec")
    task.flow_id = flow_id
    task.subtask_id = subtask.id
    await orch._sync_subtask_result(task, "completed", {"status": "success"})
    assert subtask.status == "completed"
    assert subtask.result_summary == '{"status": "success"}'
    sm.store_subtask.assert_awaited_once_with(subtask)

    sm.store_subtask.reset_mock()
    subtask.engagement_id = "eng-other"
    await orch._sync_subtask_result(task, "failed", {"error": "failed"})
    sm.store_subtask.assert_not_awaited()


@pytest.mark.asyncio
async def test_context_snapshots_available_to_other_agents():
    sm = AsyncMock()
    sm.retrieve_hot.return_value = {"summary": "Known endpoint /health is public"}
    llm = AsyncMock()
    llm.complete.return_value = "Next reasoning"
    ctx = AgentContext(
        agent_id="context-test", agent_type=AgentType.CONTEXT_MANAGER,
        session_id="eng-test", session_memory=sm, graph_memory=AsyncMock(),
        vector_memory=AsyncMock(), llm_client=llm, mcp_registry=AsyncMock(),
        rate_limiter=AsyncMock(), threat_intel_adapter=AsyncMock(),
        audit_callback=AsyncMock(), coordination_bus=AsyncMock(),
    )
    agent = ContextManagerAgent(ctx)
    output = await agent.think("What next?", [])
    assert output == "Next reasoning"
    messages = llm.complete.await_args.args[0]
    assert "Known endpoint /health is public" in messages[1]["content"]


@pytest.mark.asyncio
async def test_checkpoint_restore_refuses_active_tasks_before_mutating_state():
    orch, sm, _, cached = make_orchestrator()
    cached["checkpoint:chk-example"] = {"session_id": "eng-test"}
    active = completed_recon("task-running")
    active.status = "running"
    orch._tasks[active.id] = active
    with pytest.raises(WorkflowException, match="tasks are running"):
        await orch.restore_engagement_checkpoint("chk-example")
    sm.restore_checkpoint.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("unresolved_status", ["scheduled", "dispatching", "dispatch_unknown"])
async def test_checkpoint_restore_refuses_unresolved_external_execution(unresolved_status):
    orch, sm, _, cached = make_orchestrator()
    cached["checkpoint:chk-unresolved"] = {"session_id": "eng-test"}
    task = completed_recon("task-unresolved")
    task.status = unresolved_status
    orch._tasks[task.id] = task
    with pytest.raises(WorkflowException, match="unresolved"):
        await orch.restore_engagement_checkpoint("chk-unresolved")
    sm.restore_checkpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_restart_does_not_reset_running_tasks_owned_by_other_replicas():
    orch, sm, gm, _ = make_orchestrator()
    gm.find_incomplete_chains.return_value = []
    result = await orch.recover_state()
    gm.reset_interrupted_tasks.assert_not_awaited()
    gm.find_incomplete_chains.assert_awaited_once()
    assert result["interrupted_reset"] == 0
    assert result["redispatched"] == 0
    sm.store_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_restart_refuses_unverified_graph_chain_parent():
    orch, sm, gm, _ = make_orchestrator()
    gm.find_incomplete_chains.return_value = [
        {"id": "task-graph-parent", "engagement_id": "eng-test", "status": "completed"}
    ]
    parent = completed_recon("task-graph-parent")
    parent.status = "running"
    sm.load_task.return_value = parent
    orch._resume_chain_link = AsyncMock()
    result = await orch.recover_state()
    assert result["chains_resumed"] == 0
    orch._resume_chain_link.assert_not_awaited()
    gm.reset_interrupted_tasks.assert_not_awaited()


@pytest.mark.asyncio
async def test_executor_only_releases_dependency_when_parent_succeeded():
    orch, _, _, _ = make_orchestrator()
    parent = completed_recon("task-parent")
    child = completed_recon("task-child")
    child.status = "pending"
    child.dependencies = [parent.id]
    orch._tasks[parent.id] = parent
    orch._tasks[child.id] = child
    orch.task_scheduler._assign_task = AsyncMock()
    await orch.task_scheduler._trigger_downstream_tasks(parent)
    orch.task_scheduler._assign_task.assert_awaited_once_with(child)
    orch.task_scheduler._assign_task.reset_mock()
    parent.status = "failed"
    await orch.task_scheduler._trigger_downstream_tasks(parent)
    orch.task_scheduler._assign_task.assert_not_awaited()


def test_request_context_carries_and_clears_execution_lineage():
    try:
        RequestContext.bind(
            engagement_id="eng-test", task_id="task-x",
            flow_id="flow-a", subtask_id="subtask-a",
        )
        observed = RequestContext.get()
        assert observed["flow_id"] == "flow-a"
        assert observed["subtask_id"] == "subtask-a"
        RequestContext.bind(flow_id="", subtask_id="")
        assert RequestContext.get()["flow_id"] == ""
        assert RequestContext.get()["subtask_id"] == ""
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
async def test_orchestrator_shutdown_drains_provenance_before_memory_close():
    orch, sm, _, _ = make_orchestrator()
    order = []

    async def mcp_drain():
        order.append("mcp")

    async def llm_drain():
        order.append("llm")

    async def close_storage():
        order.append("storage")

    orch.mcp_registry.drain_provenance.side_effect = mcp_drain
    orch.llm_client.drain_provenance.side_effect = llm_drain
    sm.close.side_effect = close_storage
    await orch.shutdown()
    assert order == ["mcp", "llm", "storage"]
