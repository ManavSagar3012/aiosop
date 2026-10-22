"""An already-committed terminal state never enters legacy retry/callback paths."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.task_scheduler import TaskScheduler
from ai_osop.memory.terminal_lifecycle import _continuation_metadata


def _fixture():
    orch = Orchestrator(AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock())
    orch._execute_supervised_agent = AsyncMock(
        return_value={"status": "terminal_committed", "task_id": "task-terminal"}
    )
    orch._maybe_retry = AsyncMock(return_value=False)
    orch._on_task_success = AsyncMock()
    orch._on_task_failure = AsyncMock()
    orch._terminal_dispatcher = SimpleNamespace(
        flush_once=AsyncMock(side_effect=RuntimeError("callback backend offline"))
    )
    agent = SimpleNamespace(ctx=SimpleNamespace(agent_id="agent-test", agent_type=AgentType.RECON))
    task = Task(
        id="task-terminal",
        engagement_id="eng-terminal",
        type="recon",
        agent_type=AgentType.RECON,
        status="running",
    )
    return orch, agent, task


@pytest.mark.asyncio
async def test_main_worker_returns_after_commit_even_if_callback_backend_unavailable():
    orch, agent, task = _fixture()
    await orch._execute_via_agent(agent, task)
    assert task.status == "completed"
    orch._execute_supervised_agent.assert_awaited_once()
    orch._terminal_dispatcher.flush_once.assert_not_awaited()
    orch._maybe_retry.assert_not_awaited()
    orch._on_task_failure.assert_not_awaited()
    orch._on_task_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_extracted_scheduler_avoids_duplicate_callbacks_and_unsafe_retry():
    orch, agent, task = _fixture()
    scheduler = TaskScheduler(orch)
    scheduler._on_task_success = AsyncMock()
    scheduler._on_task_failure = AsyncMock()
    scheduler._maybe_retry = AsyncMock()
    await scheduler._execute_via_agent(agent, task)
    assert task.status == "completed"
    scheduler._on_task_success.assert_not_awaited()
    scheduler._on_task_failure.assert_not_awaited()
    scheduler._maybe_retry.assert_not_awaited()
    orch._terminal_dispatcher.flush_once.assert_not_awaited()


def test_continuation_allowlist_rejects_path_traversal_or_model_secrets():
    assert (
        _continuation_metadata(
            "capture_authenticated_surface",
            {
                "har_path": "../../private/secret.har",
                "raw_tool_response": "SENSITIVE",
            },
        )
        == {}
    )
    assert _continuation_metadata(
        "map_workflow",
        {"workflow_id": "wf-valid-01", "model_reasoning": "SENSITIVE"},
    ) == {"workflow_id": "wf-valid-01"}
