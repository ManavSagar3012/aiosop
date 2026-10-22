"""Generic approval endpoints must never turn planner identities into agent work."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ApprovalRequest, ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import Orchestrator


@pytest.fixture
def planner_approval():
    memory = AsyncMock()
    orchestrator = Orchestrator(memory, AsyncMock(), AsyncMock(), AsyncMock())
    orchestrator._audit_log = AsyncMock()
    orchestrator._assign_task = AsyncMock()
    orchestrator.task_scheduler._assign_task = AsyncMock()
    engagement_id = "eng-planner-approval"
    orchestrator._sessions[engagement_id] = SessionState(
        session_id=engagement_id,
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id=engagement_id, domains=["example.com"], authorization_ref="signed",
        ),
    )
    task = Task(
        id="task-planner-internal", engagement_id=engagement_id,
        type="planner_inference", agent_type=AgentType.CONTEXT_MANAGER,
        status="awaiting_approval", approval_required=True,
    )
    request = ApprovalRequest(
        id="apr-planner-internal", task_id=task.id, engagement_id=engagement_id,
        agent_id="planner-runtime", action_type="planner_inference", target="none",
        payload_summary="bounded inference", risk_assessment="requires approval",
    )
    orchestrator._tasks[task.id] = task
    orchestrator._approval_requests[request.id] = request
    return orchestrator, task, request, memory


@pytest.mark.parametrize("resolver", ["orchestrator", "coordinator"])
@pytest.mark.asyncio
async def test_internal_planner_cannot_be_dispatched_as_external_agent(
    planner_approval, resolver
):
    orch, task, request, memory = planner_approval
    method = (orch.resolve_approval if resolver == "orchestrator"
              else orch.approval_coordinator.resolve_approval)
    with pytest.raises(WorkflowException, match="Internal planner approval"):
        await method(request.id, "approved", "senior-verified")
    assert request.status == "pending"
    assert "operator_approved" not in task.payload
    memory.store_approval_request.assert_not_awaited()
    orch._assign_task.assert_not_awaited()
    orch.task_scheduler._assign_task.assert_not_awaited()


@pytest.mark.parametrize("resolver", ["orchestrator", "coordinator"])
@pytest.mark.asyncio
async def test_nonexistent_decision_is_not_written_or_dispatched(planner_approval, resolver):
    orch, task, request, memory = planner_approval
    task.type = "recon"
    method = (orch.resolve_approval if resolver == "orchestrator"
              else orch.approval_coordinator.resolve_approval)
    with pytest.raises(WorkflowException, match="Invalid approval decision"):
        await method(request.id, "granted-by-client", "senior-verified")
    assert request.status == "pending"
    memory.store_approval_request.assert_not_awaited()
    orch._assign_task.assert_not_awaited()
    orch.task_scheduler._assign_task.assert_not_awaited()


@pytest.mark.parametrize("resolver", ["orchestrator", "coordinator"])
@pytest.mark.asyncio
async def test_stale_approved_task_is_not_restarted(planner_approval, resolver):
    orch, task, request, memory = planner_approval
    task.type = "recon"
    task.status = "running"
    method = (orch.resolve_approval if resolver == "orchestrator"
              else orch.approval_coordinator.resolve_approval)
    with pytest.raises(WorkflowException, match="not awaiting"):
        await method(request.id, "approved", "senior-verified")
    assert request.status == "pending"
    memory.store_approval_request.assert_not_awaited()
    orch._assign_task.assert_not_awaited()
    orch.task_scheduler._assign_task.assert_not_awaited()


@pytest.mark.parametrize("resolver", ["orchestrator", "coordinator"])
@pytest.mark.asyncio
async def test_failed_approval_commit_does_not_expose_phantom_grant(planner_approval, resolver):
    orch, task, request, memory = planner_approval
    task.type = "recon"
    memory.store_approval_request.side_effect = OSError("database write rejected")
    method = (orch.resolve_approval if resolver == "orchestrator"
              else orch.approval_coordinator.resolve_approval)
    with pytest.raises(OSError, match="database write rejected"):
        await method(request.id, "approved", "verified-senior")
    assert request.status == "pending"
    assert request.operator_id is None
    assert request.responded_at is None
    assert "operator_approved" not in task.payload
    orch._assign_task.assert_not_awaited()
    orch.task_scheduler._assign_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_two_local_approval_entry_points_serialize_one_decision(planner_approval):
    orch, task, request, memory = planner_approval
    task.type = "recon"
    commits = []

    async def delayed_persist(pending):
        await asyncio.sleep(0.01)
        commits.append(pending.model_copy(deep=True))

    memory.store_approval_request.side_effect = delayed_persist
    first, second = await asyncio.gather(
        orch.resolve_approval(request.id, "approved", "senior-one"),
        orch.approval_coordinator.resolve_approval(request.id, "rejected", "senior-two"),
    )
    assert first.status == second.status == "approved"
    assert request.operator_id == "senior-one"
    assert len(commits) == 1
    assert commits[0].status == "approved"
    assert orch._assign_task.await_count + orch.task_scheduler._assign_task.await_count == 1
