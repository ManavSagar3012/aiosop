"""Emergency halt cannot be reversed by an approval submitted from a stale tab."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ApprovalRequest, ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import Orchestrator


def _context():
    memory = AsyncMock()
    orch = Orchestrator(
        session_memory=memory,
        graph_memory=AsyncMock(),
        mcp_registry=MagicMock(),
        llm_client=AsyncMock(),
    )
    orch.temporal_enabled = False
    session = SessionState(
        session_id="eng-race",
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id="eng-race",
            domains=["example.com"],
            authorization_ref="signed-roe",
        ),
    )
    task = Task(
        id="task-race",
        engagement_id="eng-race",
        type="recon",
        agent_type=AgentType.RECON,
        status="awaiting_approval",
        approval_required=True,
    )
    request = ApprovalRequest(
        id="apr-race",
        task_id=task.id,
        agent_id="",
        action_type=task.type,
        target="example.com",
        payload_summary="redacted",
        risk_assessment="high",
        engagement_id=task.engagement_id,
    )
    orch._sessions[session.session_id] = session
    orch._tasks[task.id] = task
    orch._approval_requests[request.id] = request
    orch._assign_task = AsyncMock()
    orch.task_scheduler._assign_task = AsyncMock()
    return orch, task, request, memory


@pytest.mark.parametrize("resolver", ["orchestrator", "coordinator"])
@pytest.mark.asyncio
async def test_stale_pending_grant_after_halt_is_rejected(resolver) -> None:
    orch, task, request, _ = _context()
    orch._sessions[task.engagement_id].phase = "halted"
    resolving = (
        orch.resolve_approval
        if resolver == "orchestrator"
        else orch.approval_coordinator.resolve_approval
    )
    with pytest.raises(WorkflowException, match="inactive"):
        await resolving(request.id, "approved", "senior-operator")
    assert request.status == "pending"
    orch._assign_task.assert_not_awaited()
    orch.task_scheduler._assign_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_halt_rejects_pending_grant_and_cancels_awaiting_task() -> None:
    orch, task, request, memory = _context()
    await orch.halt_engagement("eng-race", "operator emergency stop")
    assert task.status == "cancelled"
    assert request.status == "rejected"
    assert request.operator_notes == "Engagement halted"
    memory.store_approval_request.assert_awaited_once_with(request)
    result = await orch.resolve_approval(request.id, "approved", "senior-operator")
    assert result.status == "rejected"
    orch._assign_task.assert_not_awaited()
