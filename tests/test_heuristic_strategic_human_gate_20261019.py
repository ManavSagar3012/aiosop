"""Offline heuristic proposals never bypass signed Flow human dispatch admission."""

from unittest.mock import AsyncMock

import pytest

from tests.test_adaptive_planner_runtime import completed_recon, make_orchestrator


@pytest.mark.asyncio
async def test_direct_heuristic_scoped_recon_is_only_an_unexecuted_proposal():
    orch, session_memory, graph_memory, _ = make_orchestrator()
    planner = orch.adaptive_planner
    task = completed_recon("task-source-offline")
    result = await planner.execute_strategic_action(
        "eng-test",
        {
            "action": "request_sub_recon",
            "parameters": {"target": "example.com"},
            "provenance": "deterministic_planner",
        },
        parent_task=task,
    )
    assert result == {
        "status": "human_confirmation_required",
        "action": "request_sub_recon",
        "target": "example.com",
        "source_task_id": task.id,
        "flow_id": planner._flow_id("eng-test"),
        "execution_started": False,
        "proposal_only": True,
    }
    orch.schedule_task.assert_not_awaited()
    session_memory.store_subtask.assert_not_awaited()
    assert not orch._tasks
    assert not graph_memory.link_task_dependency.await_args_list


@pytest.mark.asyncio
async def test_heuristic_proposal_remains_inert_even_if_legacy_scheduler_would_fail():
    orch, session_memory, _, _ = make_orchestrator()
    orch.schedule_task = AsyncMock(side_effect=RuntimeError("should never dispatch"))
    session_memory.store_subtask.side_effect = RuntimeError("should never persist dispatched")
    result = await orch.adaptive_planner.execute_strategic_action(
        "eng-test",
        {"action": "request_sub_recon", "parameters": {"target": "example.com"}},
        parent_task=completed_recon("task-source-halted-scheduler"),
    )
    assert result["proposal_only"] is True
    orch.schedule_task.assert_not_awaited()
    session_memory.store_subtask.assert_not_awaited()
