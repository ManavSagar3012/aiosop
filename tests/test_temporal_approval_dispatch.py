"""Approval and dependency gates for the real Temporal scheduling routes."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.exceptions import OutOfScopeError, WorkflowException
from ai_osop.core.models import ApprovalRequest, ScopeDefinition, SessionState, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.orchestrator.orchestrator import Orchestrator


def make_temporal_orchestrator():
    """Capture write ordering while keeping all infrastructure in memory."""
    store = AsyncMock()
    graph = AsyncMock()
    orch = Orchestrator(store, graph, AsyncMock(), AsyncMock())
    orch.temporal_enabled = True
    orch.temporal_scheduler = AsyncMock()
    orch._audit_log = AsyncMock()
    orch.rate_limiter = AsyncMock()
    orch._sessions["eng-test"] = SessionState(
        session_id="eng-test",
        scope=ScopeDefinition(
            engagement_id="eng-test",
            domains=["example.com"],
            authorization_ref="signed-fixture-roe",
        ),
        phase=EngagementPhase.RECONNAISSANCE.value,
    )
    approvals = {}
    operations = []
    launch_context = []

    async def store_approval(request):
        operations.append(("approval_persisted", request.id, request.status))
        approvals[request.id] = request.model_copy(deep=True)

    async def store_task(task):
        operations.append(("task_persisted", task.id, task.status, task.payload.get("approval_id")))

    async def load_approval(request_id):
        return approvals.get(request_id)

    async def register_approval(request):
        orch._approval_requests[request.id] = request
        await store.store_approval_request(request)

    async def start_workflow(task_data):
        approval_id = task_data["payload"].get("approval_id")
        if task_data["approval_required"]:
            # A workflow may never be started against an uncommitted decision.
            assert approvals[approval_id].status == "approved"
            assert task_data["payload"]["operator_approved"] is True
        operations.append(("workflow_start", task_data["id"], approval_id))
        launch_context.append(RequestContext.get())
        await asyncio.sleep(0)
        return f"ai-osop-{task_data['id']}"

    store.store_approval_request.side_effect = store_approval
    store.load_approval_request.side_effect = load_approval
    store.store_task.side_effect = store_task
    orch.approval_coordinator._raise_approval = AsyncMock(side_effect=register_approval)
    orch.temporal_scheduler.start_task_workflow.side_effect = start_workflow
    return orch, store, approvals, operations, launch_context


def scoped_task(*, dependencies=None, approval_required=True):
    return Task(
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-test",
        payload={"domain": "example.com"},
        dependencies=dependencies or [],
        approval_required=approval_required,
        flow_id="flow-demo",
        subtask_id="subtask-demo",
    )


@pytest.mark.parametrize("scheduler_route", ["orchestrator", "task_scheduler"])
@pytest.mark.parametrize("resolver_route", ["orchestrator", "approval_coordinator"])
@pytest.mark.asyncio
async def test_temporal_approval_dispatches_once_after_persisted_decision(
    scheduler_route, resolver_route
):
    orch, store, approvals, operations, launch_context = make_temporal_orchestrator()
    task = scoped_task()
    schedule = (
        orch.schedule_task
        if scheduler_route == "orchestrator"
        else orch.task_scheduler.schedule_task
    )
    resolve = (
        orch.resolve_approval
        if resolver_route == "orchestrator"
        else orch.approval_coordinator.resolve_approval
    )
    try:
        await schedule(task)
        assert task.status == "awaiting_approval"
        assert len(orch._approval_requests) == 1
        assert orch.temporal_scheduler.start_task_workflow.await_count == 0
        request = next(iter(orch._approval_requests.values()))
        assert approvals[request.id].status == "pending"

        # Verify the context of the actual workflow-start callback rather than
        # inherited context from scheduling or the HTTP approval request.
        RequestContext.bind(flow_id="flow-old", subtask_id="subtask-old")
        approved = await resolve(request.id, "approved", "operator-7")
        assert approved.status == "approved"
        assert task.status == "scheduled"
        assert task.result["workflow_id"] == f"ai-osop-{task.id}"
        assert orch.temporal_scheduler.start_task_workflow.await_count == 1
        start_position = next(
            i for i, op in enumerate(operations) if op[0] == "workflow_start"
        )
        assert any(
            op[:3] == ("approval_persisted", request.id, "approved")
            for op in operations[:start_position]
        )
        assert any(
            op == ("task_persisted", task.id, "awaiting_approval", request.id)
            for op in operations[:start_position]
        )
        assert launch_context == [
            {
                **launch_context[0],
                "engagement_id": task.engagement_id,
                "task_id": task.id,
                "flow_id": task.flow_id,
                "subtask_id": task.subtask_id,
            }
        ]

        # A repeated API decision or racing queue callbacks cannot start again.
        await resolve(request.id, "approved", "operator-7")
        await asyncio.gather(
            orch._assign_task(task),
            orch.task_scheduler._assign_task(task),
        )
        orch.temporal_scheduler.start_task_workflow.assert_awaited_once()
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
async def test_temporal_approval_waits_until_all_parent_tasks_complete():
    orch, store, approvals, _, _ = make_temporal_orchestrator()
    parent = scoped_task(approval_required=False)
    parent.id = "task-parent"
    parent.status = "pending"
    child = scoped_task(dependencies=[parent.id])
    orch._tasks[parent.id] = parent

    await orch.schedule_task(child)
    assert child.status == "pending"
    assert not orch._approval_requests
    assert orch.temporal_scheduler.start_task_workflow.await_count == 0

    parent.status = "completed"
    await orch._assign_task(child)
    assert child.status == "awaiting_approval"
    request = next(iter(orch._approval_requests.values()))

    # The parent becomes incomplete before the operator clicks Approve.
    parent.status = "pending"
    await orch.approval_coordinator.resolve_approval(
        request.id, "approved", "operator-7"
    )
    assert approvals[request.id].status == "approved"
    assert child.status == "pending"
    assert orch.temporal_scheduler.start_task_workflow.await_count == 0

    parent.status = "completed"
    await orch._trigger_downstream_tasks(parent)
    assert child.status == "scheduled"
    orch.temporal_scheduler.start_task_workflow.assert_awaited_once()
    await orch._trigger_downstream_tasks(parent)
    orch.temporal_scheduler.start_task_workflow.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_non_approval_task_waits_for_completed_dependency():
    orch, _, _, _, _ = make_temporal_orchestrator()
    parent = scoped_task(approval_required=False)
    parent.status = "pending"
    child = scoped_task(dependencies=[parent.id], approval_required=False)
    orch._tasks[parent.id] = parent
    await orch.task_scheduler.schedule_task(child)
    assert child.status == "pending"
    orch.temporal_scheduler.start_task_workflow.assert_not_awaited()
    parent.status = "failed"
    await orch.task_scheduler._assign_task(child)
    orch.temporal_scheduler.start_task_workflow.assert_not_awaited()
    parent.status = "completed"
    await orch.task_scheduler._assign_task(child)
    assert child.status == "scheduled"
    orch.temporal_scheduler.start_task_workflow.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_rejects_forged_approval_payload():
    orch, _, _, _, _ = make_temporal_orchestrator()
    task = scoped_task()
    task.payload.update({"operator_approved": True, "approval_id": "apr-forged"})
    orch._tasks[task.id] = task
    await orch._assign_task(task)
    assert task.status == "awaiting_approval"
    assert "operator_approved" not in task.payload
    orch.temporal_scheduler.start_task_workflow.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_rechecks_scope_at_approval_time():
    orch, _, _, _, _ = make_temporal_orchestrator()
    task = scoped_task()
    await orch.schedule_task(task)
    request = next(iter(orch._approval_requests.values()))
    orch._sessions["eng-test"].scope.domains = ["safe.other.net"]
    with pytest.raises(OutOfScopeError):
        await orch.resolve_approval(request.id, "approved", "operator-7")
    assert orch.temporal_scheduler.start_task_workflow.await_count == 0


@pytest.mark.asyncio
async def test_temporal_denial_never_starts_workflow():
    orch, _, _, _, _ = make_temporal_orchestrator()
    task = scoped_task()
    await orch.schedule_task(task)
    request = next(iter(orch._approval_requests.values()))
    await orch.approval_coordinator.resolve_approval(
        request.id, "rejected", "operator-7"
    )
    assert task.status == "awaiting_approval"
    orch.temporal_scheduler.start_task_workflow.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_child_restores_completed_parent_from_database():
    orch, store, _, _, _ = make_temporal_orchestrator()
    parent = scoped_task(approval_required=False)
    parent.id = "task-persisted-parent"
    parent.status = "completed"
    store.load_task.return_value = parent
    child = scoped_task(
        dependencies=[parent.id],
        approval_required=False,
    )
    assert parent.id not in orch._tasks
    await orch.task_scheduler.schedule_task(child)
    store.load_task.assert_awaited_once_with(parent.id)
    assert orch._tasks[parent.id].status == "completed"
    assert child.status == "scheduled"
    orch.temporal_scheduler.start_task_workflow.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_never_accepts_parent_from_another_engagement():
    orch, store, _, _, _ = make_temporal_orchestrator()
    parent = scoped_task(approval_required=False)
    parent.id = "task-other-engagement"
    parent.status = "completed"
    parent.engagement_id = "eng-foreign"
    store.load_task.return_value = parent
    child = scoped_task(
        dependencies=[parent.id],
        approval_required=False,
    )
    await orch.task_scheduler.schedule_task(child)
    assert child.status == "pending"
    assert parent.id not in orch._tasks
    orch.temporal_scheduler.start_task_workflow.assert_not_awaited()


@pytest.mark.parametrize("durable_executor", ["orchestrator", "task_scheduler"])
@pytest.mark.asyncio
async def test_temporal_durable_executor_rebinds_flow_and_subtask(
    durable_executor,
):
    orch, _, _, _, _ = make_temporal_orchestrator()
    agent = AsyncMock()
    agent.ctx.agent_id = "agent-test"
    observed = []

    async def execute_task(task):
        observed.append(RequestContext.get())
        return {"status": "success"}

    agent.execute_task.side_effect = execute_task
    executor = (
        orch if durable_executor == "orchestrator" else orch.task_scheduler
    )
    executor._find_available_agent = AsyncMock(return_value=agent)
    executor._release_agent = lambda _id: None
    task = scoped_task(approval_required=False)
    try:
        RequestContext.bind(flow_id="old-flow", subtask_id="old-subtask")
        result = await executor._execute_task_durable(task)
        assert result["status"] == "success"
        assert observed[0]["flow_id"] == task.flow_id
        assert observed[0]["subtask_id"] == task.subtask_id
        assert observed[0]["engagement_id"] == task.engagement_id
        assert observed[0]["task_id"] == task.id
    finally:
        RequestContext.clear()
