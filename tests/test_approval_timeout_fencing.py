"""An approval timer must not forge a failed task before persistence wins."""

from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ApprovalRequest, ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import Orchestrator


def _case():
    memory = AsyncMock()
    orch = Orchestrator(memory, AsyncMock(), AsyncMock(), AsyncMock())
    orch._on_task_failure = AsyncMock()
    orch.task_scheduler._on_task_failure = AsyncMock()
    task = Task(
        id="task-timeout", engagement_id="eng-timeout", type="full_recon",
        agent_type=AgentType.RECON, status="awaiting_approval", approval_required=True,
    )
    req = ApprovalRequest(
        id="apr-timeout", engagement_id="eng-timeout", task_id=task.id,
        agent_id="agent-recon", action_type="full_recon", target="example.com",
        payload_summary="operator review", risk_assessment="high",
    )
    orch._tasks[task.id] = task
    orch._approval_requests[req.id] = req
    orch._sessions[task.engagement_id] = SessionState(
        session_id=task.engagement_id, phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id=task.engagement_id, domains=["example.com"],
            authorization_ref="signed-test",
        ),
    )
    return orch, memory, task, req


@pytest.mark.asyncio
async def test_failed_timeout_write_cannot_change_a_pending_approval():
    orch, memory, task, req = _case()
    memory.store_approval_request.side_effect = OSError("PostgreSQL unavailable")
    with pytest.raises(OSError, match="PostgreSQL unavailable"):
        await orch._expire_pending_approval(req.id)
    assert req.status == "pending"
    assert req.responded_at is None
    assert task.status == "awaiting_approval"
    orch._on_task_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_timeout_cannot_overwrite_local_committed_approval():
    orch, memory, task, req = _case()
    req.status = "approved"
    req.operator_id = "senior-verified"
    observed, fail_task = await orch._expire_pending_approval(req.id)
    assert observed.status == "approved"
    assert not fail_task
    memory.store_approval_request.assert_not_awaited()
    assert task.status == "awaiting_approval"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["orchestrator", "coordinator"])
async def test_timeout_waiter_does_not_fail_task_when_database_commit_fails(path, monkeypatch):
    orch, memory, task, req = _case()
    memory.store_approval_request.side_effect = OSError("storage offline")
    monkeypatch.setattr("ai_osop.orchestrator.orchestrator.settings.approval_timeout_seconds", 0.001)
    if path == "orchestrator":
        await orch._await_approval_outcome(req.id)
    else:
        await orch.approval_coordinator._await_approval_outcome(req.id)
    assert req.status == "pending"
    assert task.status == "awaiting_approval"
    orch._on_task_failure.assert_not_awaited()
    orch.task_scheduler._on_task_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_mock_timeout_records_before_failing_local_parked_task():
    orch, memory, task, req = _case()
    recorded = []

    async def write(snapshot):
        recorded.append(snapshot.status)
        assert task.status == "awaiting_approval"

    memory.store_approval_request.side_effect = write
    result, should_fail = await orch._expire_pending_approval(req.id)
    assert should_fail
    assert recorded == ["timeout"]
    assert result.status == "timeout"
    assert result.responded_at is not None


@pytest.mark.parametrize("route", ["orchestrator", "coordinator"])
@pytest.mark.asyncio
async def test_failed_registration_has_no_process_local_approval(route):
    orch, memory, task, req = _case()
    orch._approval_requests.clear()
    memory.store_approval_request.side_effect = OSError("commit rejected")
    register = (
        orch._register_approval
        if route == "orchestrator"
        else orch.approval_coordinator._register_approval
    )
    with pytest.raises(OSError, match="commit rejected"):
        await register(req)
    assert req.id not in orch._approval_requests
