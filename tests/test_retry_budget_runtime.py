"""AIOSOP-PROMPT-001: runtime enforcement of retry budgets (base.py).

The production system prompt (§8) tells the model "max 3 attempts per tool call"
and "mark a host DEGRADED after 5 consecutive failures." These tests verify the
LOOP enforces those ceilings mechanically — a runaway LLM returning the same call
cannot burn the task budget on one dead endpoint.
"""

from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import BaseAgent, AgentContext
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


class _LoopAgent(BaseAgent):
    """Concrete agent that returns a scripted action plan sequence."""

    @property
    def agent_type(self) -> AgentType:
        return AgentType.RECON

    async def _execute(self, task: Task) -> dict:
        return {"status": "success"}

    async def _setup_resources(self) -> None:
        pass

    async def _cleanup_resources(self) -> None:
        pass


def _make_agent() -> "_LoopAgent":
    ctx = AgentContext(
        agent_id="loop-agent",
        agent_type=AgentType.RECON,
        session_id="s1",
        session_memory=AsyncMock(),
        graph_memory=AsyncMock(),
        vector_memory=AsyncMock(),
        llm_client=AsyncMock(),
        mcp_registry=AsyncMock(),
        rate_limiter=AsyncMock(),
        threat_intel_adapter=None,
        audit_callback=None,
        coordination_bus=None,
    )
    ctx.mcp_registry._servers = {}
    ctx.graph_memory.run_read_query = AsyncMock(return_value=[])
    ctx.session_memory.query_audit_log = AsyncMock(return_value=[])
    ctx.session_memory.load_session_state = AsyncMock(return_value=None)
    # AsyncMock auto-creates _users as a coroutine; _build_cognitive_context
    # calls .keys() on it directly, so pin it to a plain dict.
    ctx.session_memory._users = {}
    agent = _LoopAgent(ctx)
    # Intercept observation writes so we can assert on them.
    agent._record_observation = AsyncMock()
    return agent


def _tool_plan(target: str = "http://target.example") -> dict:
    return {
        "action": "tool",
        "reasoning": {"observation": "test", "why_chosen": "test"},
        "tool_call": {
            "server": "recon-mcp",
            "name": "probe",
            "parameters": {"target": target},
        },
    }


def _observation_keys(agent: "_LoopAgent") -> list:
    keys = []
    for call in agent._record_observation.await_args_list:
        obs = call.args[1] if len(call.args) > 1 else (call.kwargs.get("observation") or {})
        if isinstance(obs, dict):
            keys.append(list(obs.keys()))
    return keys


@pytest.mark.asyncio
async def test_identical_call_is_refused_after_three_attempts():
    """The 4th identical (server, name, params) call is refused by the loop."""
    agent = _make_agent()
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e1", scope_check=False)
    agent._think_autonomous = AsyncMock(return_value=_tool_plan())

    async def _boom(*a, **k):
        raise RuntimeError("tool down")

    agent.ctx.mcp_registry.execute_tool = AsyncMock(side_effect=_boom)

    await agent.execute_task(task)

    # Tool executed exactly 3 times (the budget), then identical repeats refused.
    assert agent.ctx.mcp_registry.execute_tool.call_count == 3
    # A blocked repeat was recorded as an observation.
    keys = _observation_keys(agent)
    assert any("tool_budget_exhausted" in k for k in keys), f"missing budget obs: {keys}"


@pytest.mark.asyncio
async def test_host_marked_degraded_after_five_failures():
    """After 5 consecutive failures against one host, host_degraded is recorded
    and a later call to that host is skipped.

    The identical-call budget (3) caps repeat probes, so the 5-failure host
    breaker fires across DIFFERENT calls to the same host — script a sequence of
    distinct failing calls against one host, then a final call that must be
    refused.
    """
    agent = _make_agent()
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e1", scope_check=False)

    # Script: 5 distinct failing probes against the same host, then a 6th probe
    # that must be skipped because the host is now DEGRADED.
    plans = [
        _tool_plan(target=f"http://target.example/p{i}")
        for i in range(5)
    ] + [_tool_plan(target="http://target.example/p5")]

    async def _sequence(*a, **k):
        if plans:
            return plans.pop(0)
        return {"action": "complete", "reasoning": {"why_chosen": "done"}, "conclusion": "done"}

    agent._think_autonomous = AsyncMock(side_effect=_sequence)

    async def _boom(*a, **k):
        raise RuntimeError("timeout")

    agent.ctx.mcp_registry.execute_tool = AsyncMock(side_effect=_boom)

    await agent.execute_task(task)

    # The 6th distinct call to the degraded host was refused: executed exactly 5.
    assert agent.ctx.mcp_registry.execute_tool.call_count == 5
    keys = _observation_keys(agent)
    assert any("host_degraded" in k for k in keys), f"missing degraded obs: {keys}"
    assert any("tool_skipped_degraded_host" in k for k in keys), f"missing skip obs: {keys}"


@pytest.mark.asyncio
async def test_success_clears_host_failure_streak():
    """A successful call against a host resets its failure streak and clears DEGRADED."""
    agent = _make_agent()
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e1", scope_check=False)

    # First two distinct calls fail, third succeeds -> streak is 2, not degraded.
    plans = [
        _tool_plan(target="http://target.example/a"),
        _tool_plan(target="http://target.example/b"),
        _tool_plan(target="http://target.example/c"),
    ]

    async def _sequence(*a, **k):
        if plans:
            return plans.pop(0)
        return {"action": "complete", "reasoning": {"why_chosen": "done"}, "conclusion": "done"}

    agent._think_autonomous = AsyncMock(side_effect=_sequence)

    calls = {"a": 0}
    async def _mixed(*a, **k):
        # Count executions; first two raise, third+ succeed.
        calls["a"] += 1
        if calls["a"] <= 2:
            raise RuntimeError("flaky")
        return {"status": "ok"}

    agent.ctx.mcp_registry.execute_tool = AsyncMock(side_effect=_mixed)
    agent._auto_extract_assets_from_result = AsyncMock()

    await agent.execute_task(task)

    # Two failures recorded, then a success cleared the streak.
    assert agent._host_failures.get("target.example", 0) == 0
    assert "target.example" not in agent._degraded_hosts


@pytest.mark.asyncio
async def test_degraded_host_is_skipped():
    """A call against a host already DEGRADED this task is refused before execution."""
    agent = _make_agent()
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e1", scope_check=False)

    # Seed the degraded set AFTER task start via the failure path: first call
    # fails and pushes streak to MAX, second (distinct) call must be skipped.
    plans = [
        _tool_plan(target="http://target.example/x1"),
        _tool_plan(target="http://target.example/x2"),
    ]

    async def _sequence(*a, **k):
        if plans:
            return plans.pop(0)
        return {"action": "complete", "reasoning": {"why_chosen": "done"}, "conclusion": "done"}

    agent._think_autonomous = AsyncMock(side_effect=_sequence)
    # Force the first failure to count as 4 pre-existing + this one = 5 -> degrade.
    agent.MAX_CONSECUTIVE_HOST_FAILURES = 1

    async def _boom(*a, **k):
        raise RuntimeError("down")

    agent.ctx.mcp_registry.execute_tool = AsyncMock(side_effect=_boom)

    await agent.execute_task(task)

    # First call executed, then host degraded -> second call refused.
    assert agent.ctx.mcp_registry.execute_tool.call_count == 1
    assert "target.example" in agent._degraded_hosts
    keys = _observation_keys(agent)
    assert any("tool_skipped_degraded_host" in k for k in keys), f"missing skip obs: {keys}"


@pytest.mark.asyncio
async def test_budget_state_is_per_task():
    """Retry budgets reset between tasks (not leaked across executions)."""
    agent = _make_agent()
    t1 = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e1", scope_check=False)
    t2 = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e1", scope_check=False)
    agent._think_autonomous = AsyncMock(return_value=_tool_plan())

    async def _boom(*a, **k):
        raise RuntimeError("down")

    agent.ctx.mcp_registry.execute_tool = AsyncMock(side_effect=_boom)

    await agent.execute_task(t1)
    first_count = agent.ctx.mcp_registry.execute_tool.call_count
    await agent.execute_task(t2)
    second_count = agent.ctx.mcp_registry.execute_tool.call_count

    # Each task independently allows its own 3 attempts.
    assert first_count == 3
    assert second_count - first_count == 3
