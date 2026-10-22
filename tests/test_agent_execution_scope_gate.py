"""The shared agent entry point must reject stale or unauthorized task state."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import ApprovalDeniedError, ScopeValidationError, WorkflowException
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, Task


class _GuardAgent(BaseAgent):
    @property
    def agent_type(self) -> AgentType:
        return AgentType.RECON

    async def _execute(self, task: Task):
        return {"status": "success"}

    async def _setup_resources(self) -> None:
        return None

    async def _cleanup_resources(self) -> None:
        return None


def _guard(*, phase="reconnaissance", end=None):
    session = SessionState(
        session_id="eng-guard",
        phase=phase,
        scope=ScopeDefinition(
            engagement_id="eng-guard",
            domains=["example.com"],
            authorization_ref="test-roe",
            testing_window_end=end,
        ),
    )
    memory = SimpleNamespace(
        load_session_state=AsyncMock(return_value=session),
        load_flow=AsyncMock(return_value=None),
        load_task=AsyncMock(return_value=None),
        is_task_approved=AsyncMock(return_value=False),
    )
    agent = _GuardAgent(SimpleNamespace(session_memory=memory))
    task = Task(
        id="task-guard",
        engagement_id=session.session_id,
        agent_type=AgentType.RECON,
        type="full_recon",
        payload={"target": "https://example.com"},
    )
    return agent, task, memory


@pytest.mark.asyncio
async def test_agent_gate_allows_authorized_live_task() -> None:
    agent, task, memory = _guard()
    await agent._validate_task(task)
    memory.is_task_approved.assert_not_awaited()


@pytest.mark.asyncio
async def test_agent_gate_rejects_missing_persisted_scope() -> None:
    agent, task, memory = _guard()
    memory.load_session_state.return_value = None
    with pytest.raises(ScopeValidationError, match="persisted authorized engagement"):
        await agent._validate_task(task)


@pytest.mark.asyncio
async def test_agent_gate_rejects_halted_engagement() -> None:
    agent, task, _ = _guard(phase="halted")
    with pytest.raises(WorkflowException, match="inactive"):
        await agent._validate_task(task)


@pytest.mark.asyncio
async def test_agent_gate_rejects_expired_testing_window() -> None:
    agent, task, _ = _guard(end=datetime.utcnow() - timedelta(seconds=1))
    with pytest.raises(Exception, match="Testing window has ended"):
        await agent._validate_task(task)


@pytest.mark.asyncio
async def test_agent_gate_rejects_offset_aware_expired_window() -> None:
    agent, task, _ = _guard(
        end=datetime.now(timezone.utc) - timedelta(seconds=1)
    )
    with pytest.raises(Exception, match="Testing window has ended"):
        await agent._validate_task(task)


@pytest.mark.asyncio
async def test_agent_gate_rejects_secondary_out_of_scope_target() -> None:
    agent, task, _ = _guard()
    task.payload["target_url"] = "https://unauthorized.invalid"
    with pytest.raises(Exception, match="not in scope"):
        await agent._validate_task(task)


@pytest.mark.asyncio
async def test_agent_gate_rejects_forged_operator_flag() -> None:
    agent, task, memory = _guard()
    task.approval_required = True
    task.payload.update({"operator_approved": True, "approval_id": "apr-fake"})
    with pytest.raises(ApprovalDeniedError, match="Approval not valid"):
        await agent._validate_task(task)
    memory.is_task_approved.assert_awaited_once_with(
        task.id, task.engagement_id, "apr-fake"
    )


@pytest.mark.asyncio
async def test_agent_gate_checks_persisted_dependency_ownership() -> None:
    agent, task, memory = _guard()
    task.dependencies = ["task-parent"]
    memory.load_task.return_value = Task(
        id="task-parent",
        type="recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-other",
        status="completed",
    )
    with pytest.raises(WorkflowException, match="dependency"):
        await agent._validate_task(task)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["paused", "cancelled", "completed"])
async def test_agent_gate_rejects_stopped_flow_even_if_engagement_is_active(status) -> None:
    agent, task, memory = _guard()
    task.flow_id = "flow-guard"
    memory.load_flow.return_value = FlowRecord(
        id=task.flow_id,
        engagement_id=task.engagement_id,
        objective="Authorized scope",
        status=status,
        revision=2,
    )
    with pytest.raises(WorkflowException, match="Flow is paused, closed"):
        await agent._validate_task(task)
    memory.is_task_approved.assert_not_awaited()


@pytest.mark.asyncio
async def test_agent_gate_rejects_missing_or_foreign_flow() -> None:
    agent, task, memory = _guard()
    task.flow_id = "flow-guard"
    with pytest.raises(WorkflowException, match="unavailable"):
        await agent._validate_task(task)
    memory.load_flow.return_value = FlowRecord(
        id=task.flow_id, engagement_id="eng-foreign", objective="Unrelated"
    )
    with pytest.raises(WorkflowException, match="unavailable"):
        await agent._validate_task(task)


@pytest.mark.asyncio
async def test_agent_gate_allows_current_owned_mutable_flow() -> None:
    agent, task, memory = _guard()
    task.flow_id = "flow-guard"
    memory.load_flow.return_value = FlowRecord(
        id=task.flow_id, engagement_id=task.engagement_id, objective="Authorized"
    )
    await agent._validate_task(task)


@pytest.mark.asyncio
async def test_agent_audit_does_not_copy_sensitive_target_or_raw_model_output() -> None:
    agent, task, _ = _guard()
    callback = AsyncMock()
    agent.ctx.agent_id = "agent-guard"
    agent.ctx.agent_type = AgentType.RECON
    agent.ctx.session_id = task.engagement_id
    agent.ctx.audit_callback = callback
    task.payload["target"] = "https://example.com/?token=never-persist"
    task.started_at = datetime.utcnow() - timedelta(seconds=1)
    task.completed_at = datetime.utcnow()
    task.status = "completed"

    await agent._log_task_completion(
        task, {"status": "success", "reasoning": "never-persist private response"}
    )
    await agent._log_task_failure(
        task, RuntimeError("never-persist credential in database error")
    )

    assert callback.await_count == 2
    for call in callback.await_args_list:
        audit = call.args[0]
        assert "never-persist" not in str(audit.model_dump())
        assert audit.engagement_id == task.engagement_id
