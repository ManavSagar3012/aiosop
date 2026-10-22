"""A signed model decision cannot silently launch the legacy scheduler."""

from unittest.mock import AsyncMock

import pytest

from ai_osop.core.models import FlowRecord
from tests.test_adaptive_planner_runtime import completed_recon, make_orchestrator


@pytest.mark.asyncio
async def test_signed_planner_completion_does_not_call_unsafe_direct_agent_scheduler():
    orch, memory, _, cached = make_orchestrator()
    planner = orch.adaptive_planner
    cached["adaptive_plan:eng-test"] = {
        "engagement_id": "eng-test", "overall_goal": "Signed review",
        "iterations": 0, "max_iterations": 2, "processed_task_ids": [],
        "last_action": None,
    }
    flow_id = planner._flow_id("eng-test")
    before = FlowRecord(
        id=flow_id, engagement_id="eng-test", objective="Authorized recon",
        status="running", revision=7,
    )
    after = before.model_copy(update={"revision": 8})
    memory.load_flow.side_effect = [before, after]
    planner.evaluate_and_plan_next_step = AsyncMock(return_value={
        "action": "request_sub_recon",
        "parameters": {"target": "example.com"},
        "_planner_flow_revision": 8,
        "provenance": "LLM",
    })
    planner.execute_strategic_action = AsyncMock(
        side_effect=AssertionError("Signed model output must not schedule an agent")
    )
    outcome = await planner.on_task_completed(completed_recon("task-parent-done"))
    assert outcome == {
        "status": "human_confirmation_required",
        "action": "request_sub_recon",
        "execution_started": False,
    }
    planner.execute_strategic_action.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_planner_pause_race_returns_conflict_without_execution():
    orch, memory, _, cached = make_orchestrator()
    planner = orch.adaptive_planner
    cached["adaptive_plan:eng-test"] = {
        "engagement_id": "eng-test", "overall_goal": "Signed review",
        "iterations": 0, "max_iterations": 2, "processed_task_ids": [],
        "last_action": None,
    }
    flow_id = planner._flow_id("eng-test")
    before = FlowRecord(
        id=flow_id, engagement_id="eng-test", objective="Authorized recon",
        status="running", revision=7,
    )
    after = before.model_copy(update={"status": "paused", "revision": 8})
    memory.load_flow.side_effect = [before, after]
    planner.evaluate_and_plan_next_step = AsyncMock(return_value={
        "action": "request_sub_recon",
        "parameters": {"target": "example.com"},
        "_planner_flow_revision": 8,
        "provenance": "LLM",
    })
    planner.execute_strategic_action = AsyncMock()
    outcome = await planner.on_task_completed(completed_recon("task-parent-done"))
    assert outcome == {"status": "flow_changed_during_planning"}
    planner.execute_strategic_action.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()
