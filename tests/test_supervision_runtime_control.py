"""Supervisor controls must not overstate local or remote cancellation."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import Orchestrator


def _fixture():
    sm = AsyncMock()
    gm = AsyncMock()
    mcp = AsyncMock()
    orchestrator = Orchestrator(sm, gm, mcp, AsyncMock())
    orchestrator._supervision_store = AsyncMock()
    engagement = SessionState(
        session_id="eng-control",
        scope=ScopeDefinition(
            engagement_id="eng-control",
            authorization_ref="signed-roe",
            domains=["example.test"],
        ),
    )
    task = Task(
        id="task-control",
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id=engagement.session_id,
        status="running",
    )
    sm.load_session_state.return_value = engagement
    sm.load_task.return_value = task
    return orchestrator, sm, mcp, task


@pytest.mark.asyncio
async def test_remote_cancel_unsupported_remains_unconfirmed():
    orchestrator, _, mcp, task = _fixture()
    mcp.cancel_task_execution.return_value = {"status": "not_supported"}
    result = await orchestrator.request_task_control(
        task.engagement_id, task.id, "cancel", "ctrl-1"
    )
    assert result["status"] == "unknown"
    assert result["execution_stopped"] is False
    assert result["receipts"]["mcp"]["status"] == "not_supported"
    orchestrator.supervision_store.resolve_control.assert_awaited_once_with(
        "ctrl-1", "unknown", result
    )


@pytest.mark.asyncio
async def test_cancel_local_coroutine_does_not_claim_remote_stopped():
    orchestrator, _, mcp, task = _fixture()
    mcp.cancel_task_execution.return_value = {"status": "unknown"}
    started = asyncio.Event()

    async def long_running():
        started.set()
        await asyncio.Event().wait()

    handle = asyncio.create_task(long_running())
    orchestrator._inflight_tasks[task.id] = handle
    await started.wait()
    result = await orchestrator.request_task_control(
        task.engagement_id, task.id, "cancel", "ctrl-2"
    )
    assert handle.cancelled()
    assert result["status"] == "unknown"
    assert result["execution_stopped"] is False


@pytest.mark.asyncio
async def test_live_pause_returns_unsupported_without_mutating_task():
    orchestrator, sm, mcp, task = _fixture()
    result = await orchestrator.request_task_control(
        task.engagement_id, task.id, "pause", "ctrl-3"
    )
    assert result["reason"] == "distributed_suspend_resume_not_supported"
    assert result["status"] == "unknown"
    assert task.status == "running"
    sm.store_task.assert_not_awaited()
    mcp.cancel_task_execution.assert_not_awaited()


@pytest.mark.asyncio
async def test_supervisor_cannot_control_foreign_task():
    orchestrator, sm, mcp, task = _fixture()
    sm.load_task.return_value = task.model_copy(update={"engagement_id": "eng-other"})
    with pytest.raises(Exception, match="persisted engagement ownership"):
        await orchestrator.request_task_control(
            task.engagement_id, task.id, "cancel", "ctrl-4"
        )
    mcp.cancel_task_execution.assert_not_awaited()
    orchestrator.supervision_store.resolve_control.assert_not_awaited()


@pytest.mark.asyncio
async def test_supervision_claim_rejects_duplicate_before_agent_invocation():
    orchestrator, _, _, task = _fixture()
    orchestrator._supervision_active = True
    orchestrator.supervision_store.start_attempt.return_value = {
        "id": "run-existing", "created": False, "revision": 1
    }
    agent = AsyncMock()
    result = await orchestrator._execute_supervised_agent(agent, task)
    assert result["status"] == "execution_unknown"
    agent.execute_task.assert_not_awaited()
    orchestrator.supervision_store.update_attempt.assert_not_awaited()


@pytest.mark.asyncio
async def test_supervision_storage_failure_denies_execution():
    orchestrator, _, _, task = _fixture()
    orchestrator._supervision_active = True
    orchestrator.supervision_store.start_attempt.side_effect = RuntimeError("database unavailable")
    agent = AsyncMock()
    outcome = await orchestrator._execute_supervised_agent(agent, task)
    assert outcome["status"] == "execution_unknown"
    agent.execute_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_supervised_agent_stores_sanitized_receipt_after_execution():
    orchestrator, _, _, task = _fixture()
    orchestrator._supervision_active = True
    orchestrator._terminal_store = SimpleNamespace(
        commit_terminal=AsyncMock(return_value={"created": True, "status": "pending"})
    )
    orchestrator.supervision_store.start_attempt.return_value = {
        "id": "run-new", "created": True, "revision": 0
    }
    agent = AsyncMock()
    agent.execute_task.return_value = {
        "status": "success",
        "reasoning": "confidential credential should never enter a receipt",
    }
    outcome = await orchestrator._execute_supervised_agent(agent, task)
    assert outcome["status"] == "terminal_committed"
    orchestrator._terminal_store.commit_terminal.assert_awaited_once_with(
        task.engagement_id, task.id, "run-new", 0, "succeeded",
        receipt_code="agent_completed",
        continuation={
            "status": "success",
            "reasoning": "confidential credential should never enter a receipt",
        },
    )
    from ai_osop.memory.terminal_lifecycle import _continuation_metadata

    # The function receives the in-process result only to parse the narrow
    # allowlist; PostgreSQL receipts and outbox never persist reasoning text.
    stored = _continuation_metadata(
        task.type,
        orchestrator._terminal_store.commit_terminal.await_args.kwargs["continuation"],
    )
    assert "confidential" not in str(stored)
    orchestrator.supervision_store.update_attempt.assert_not_awaited()


@pytest.mark.asyncio
async def test_supervised_attempt_cas_loss_never_claims_success():
    orchestrator, _, _, task = _fixture()
    orchestrator._supervision_active = True
    orchestrator._terminal_store = SimpleNamespace(
        commit_terminal=AsyncMock(return_value=None)
    )
    orchestrator.supervision_store.start_attempt.return_value = {
        "id": "run-new", "created": True, "revision": 0
    }
    agent = AsyncMock()
    agent.execute_task.return_value = {"status": "success"}
    result = await orchestrator._execute_supervised_agent(agent, task)
    assert result["status"] == "execution_unknown"


@pytest.mark.asyncio
async def test_timeout_outcome_never_finishes_as_success_or_auto_retries():
    orchestrator, _, _, task = _fixture()
    orchestrator._supervision_active = True
    orchestrator.supervision_store.start_attempt.return_value = {
        "id": "run-timeout", "created": True, "revision": 0,
    }
    orchestrator.supervision_store.update_attempt.return_value = {
        "id": "run-timeout", "status": "unknown", "revision": 1,
    }
    agent = AsyncMock()
    agent.execute_task.return_value = {"status": "execution_unknown", "error_type": "TimeoutError"}
    response = await orchestrator._execute_supervised_agent(agent, task)
    assert response["status"] == "execution_unknown"
    orchestrator.supervision_store.update_attempt.assert_awaited_once_with(
        "run-timeout", 0, "unknown",
        receipt={"result_code": "remote_outcome_unverified"},
    )
