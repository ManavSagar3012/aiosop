"""StrategicPlannerAgent wiring tests (2026-08-29).

Covers the planning-loop wiring that was previously dead code:
- The agent is instantiable (was abstract-uninstantiable before the fix).
- The default goal tree initializes with 4 goals.
- Goal completion/gap logic works.
- The safety wiring functions (stagnation/effort/effectiveness/pools) are
  callable and attach their components to the orchestrator.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.agents.strategic_planner_agent import (
    GoalPriority,
    GoalStatus,
    IntelligenceGap,
    StrategicGoal,
    StrategicPlannerAgent,
)


def _planner() -> StrategicPlannerAgent:
    return StrategicPlannerAgent(agent_id="sp-test", redis_url="redis://localhost:6379/0")


def test_planner_instantiable():
    """The planner is now instantiable (was an abstract class before)."""
    p = _planner()
    assert p.agent_id == "sp-test"
    assert p.agent_type == "strategic_planner"


def test_default_goals_initialized():
    """4 default goals: recon, auth bypass, RCE, data exfil."""
    p = _planner()
    assert len(p.goals) == 4
    ids = set(p.goals.keys())
    assert {
        "goal_recon_complete",
        "goal_auth_bypass",
        "goal_rce",
        "goal_data_exfil",
    } == ids


def test_goal_completion():
    """A goal is complete when all required findings are present."""
    goal = StrategicGoal(
        id="g1",
        name="test",
        description="d",
        priority=GoalPriority.HIGH,
        required_findings={"a", "b"},
        completed_findings={"a", "b"},
    )
    assert goal.is_complete()
    assert goal.get_missing_findings() == set()


def test_goal_missing_findings():
    """get_missing_findings returns the unmet requirements."""
    goal = StrategicGoal(
        id="g1",
        name="test",
        description="d",
        priority=GoalPriority.HIGH,
        required_findings={"a", "b", "c"},
        completed_findings={"a"},
    )
    assert not goal.is_complete()
    assert goal.get_missing_findings() == {"b", "c"}


@pytest.mark.asyncio
async def test_publish_task_requests_uses_bus():
    """The planner publishes gap-driven task requests via the bus (not raw events)."""
    p = _planner()
    p.publish = AsyncMock()  # the CognitiveSwarmAgent.publish method
    # Seed a high-priority gap
    p.intelligence_gaps = [
        IntelligenceGap(
            goal_id="goal_rce",
            gap_type="vulnerability_scanning",
            target="target",
            description="Need vulnerable_service to achieve: Achieve Remote Code Execution",
            priority=GoalPriority.CRITICAL,
        )
    ]
    await p._publish_task_requests()
    assert p.publish.await_count == 1
    topic = p.publish.call_args.kwargs.get("topic")
    assert topic == "strategic.task_request"
    payload = p.publish.call_args.kwargs.get("payload", {})
    assert payload["task_type"] == "vulnerability_scanning"
    assert payload["priority"] == "CRITICAL"


@pytest.mark.asyncio
async def test_start_launches_background_run():
    """start() spawns the background run loop without blocking."""
    p = _planner()
    p.run = AsyncMock()
    p.run.return_value = None
    with patch("ai_osop.agents.strategic_planner_agent.asyncio.create_task") as mock_ct:
        mock_ct.return_value = MagicMock()
        await p.start()
        mock_ct.assert_called_once()
        assert hasattr(p, "_run_task")


def test_get_goal_status_shape():
    """Observability snapshot returns expected keys."""
    p = _planner()
    status = p.get_goal_status()
    assert status["total_goals"] == 4
    assert "completed" in status
    assert "intelligence_gaps" in status
    assert len(status["goals"]) == 4


# --------------------------------------------------------------------------- #
# Safety wiring functions are now callable
# --------------------------------------------------------------------------- #
def test_safety_wiring_functions_are_callable():
    """The wire_* functions in __init_safety_wiring attach real components."""
    from ai_osop.safety import __init_safety_wiring as wiring

    assert callable(wiring.wire_stagnation_detector)
    assert callable(wiring.wire_effort_tracker)
    assert callable(wiring.wire_effectiveness_tracker)
    assert callable(wiring.wire_agent_pools)
    assert callable(wiring.wire_tool_call_validator)
    assert callable(wiring.run_startup_self_tests)


@pytest.mark.asyncio
async def test_wire_stagnation_detector_attaches():
    """wire_stagnation_detector attaches a real StagnationDetector to the orchestrator."""
    from ai_osop.orchestrator.orchestrator import Orchestrator
    from ai_osop.safety.__init_safety_wiring import wire_stagnation_detector

    orch = Orchestrator(AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock())
    detector = wire_stagnation_detector(orch)
    assert orch._stagnation_detector is detector
    assert hasattr(detector, "record_observation")
    assert hasattr(detector, "check_stagnation")


@pytest.mark.asyncio
async def test_wire_effectiveness_tracker_attaches():
    """wire_effectiveness_tracker attaches an EffectivenessTracker to the orchestrator."""
    from ai_osop.orchestrator.orchestrator import Orchestrator
    from ai_osop.safety.__init_safety_wiring import wire_effectiveness_tracker

    orch = Orchestrator(AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock())
    tracker = wire_effectiveness_tracker(orch)
    assert orch._effectiveness_tracker is tracker
    assert hasattr(tracker, "record_execution")
    assert hasattr(tracker, "get_effectiveness")
