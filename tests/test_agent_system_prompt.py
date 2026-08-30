"""AIOSOP-PROMPT-001: the production system prompt is wired into the reasoning loop.

Verifies that `_think_autonomous` builds its messages with the production
behavioral contract (AUTONOMOUS_AGENT_SYSTEM_PROMPT) as the system prompt, that
the JSON-output discipline message still precedes the user prompt, and that the
loop no longer contains the tool-spam rule that encouraged retry storms.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import BaseAgent, AgentContext
from ai_osop.agents.prompts import AUTONOMOUS_AGENT_SYSTEM_PROMPT
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


class _ConcreteAgent(BaseAgent):
    @property
    def agent_type(self) -> AgentType:
        return AgentType.RECON

    async def _execute(self, task: Task) -> dict:
        return {"status": "success"}

    async def _setup_resources(self) -> None:
        pass

    async def _cleanup_resources(self) -> None:
        pass


def _ctx() -> AgentContext:
    ctx = AgentContext(
        agent_id="test-agent",
        agent_type=AgentType.RECON,
        session_id="test-session",
        session_memory=AsyncMock(),
        graph_memory=AsyncMock(),
        vector_memory=AsyncMock(),
        llm_client=AsyncMock(),
        mcp_registry=MagicMock(),
        rate_limiter=AsyncMock(),
        threat_intel_adapter=None,
        audit_callback=None,
        coordination_bus=None,
    )
    ctx.mcp_registry._servers = {}
    return ctx


@pytest.mark.asyncio
async def test_system_prompt_is_wired_into_loop():
    """_think_autonomous must use the production prompt as its system message."""
    agent = _ConcreteAgent(_ctx())
    ctx = {
        "known_assets": [],
        "known_endpoints": [],
        "active_hypotheses": [],
        "candidate_vulnerabilities": [],
        "recent_actions_and_decisions": [],
    }
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e1")
    # The llm_client returns a JSON action plan
    agent.ctx.llm_client.complete = AsyncMock(
        return_value='{"action": "complete", "reasoning": {"why_chosen": "done"}, "conclusion": "x"}'
    )
    plan = await agent._think_autonomous(ctx, [], task)
    assert plan.get("action") == "complete"

    # Verify the messages passed to the LLM contain the production prompt.
    call = agent.ctx.llm_client.complete.await_args
    assert call is not None
    messages = call.kwargs.get("messages") or call.args[0]
    system_contents = [m["content"] for m in messages if m["role"] == "system"]
    assert len(system_contents) == 2  # behavioral + JSON-discipline
    assert system_contents[0] == AUTONOMOUS_AGENT_SYSTEM_PROMPT
    assert "CRITICAL RULE: You MUST output ONLY a raw JSON object" in system_contents[1]


@pytest.mark.asyncio
async def test_loop_no_longer_forces_tool_spam():
    """The loop prompt must NOT tell the agent to call a tool every iteration."""
    agent = _ConcreteAgent(_ctx())
    ctx = {
        "known_assets": [],
        "known_endpoints": [],
        "active_hypotheses": [],
        "candidate_vulnerabilities": [],
        "recent_actions_and_decisions": [],
    }
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e1")
    agent.ctx.llm_client.complete = AsyncMock(
        return_value='{"action": "complete", "reasoning": {"why_chosen": "done"}, "conclusion": "x"}'
    )
    await agent._think_autonomous(ctx, [], task)
    call = agent.ctx.llm_client.complete.await_args
    messages = call.kwargs.get("messages") or call.args[0]
    joined = " ".join(str(m.get("content", "")) for m in messages)
    assert "MUST call a tool on every iteration" not in joined


@pytest.mark.asyncio
async def test_convergence_and_evidence_rules_present():
    """The behavioral prompt carries the anti-loop and evidence-standard sections."""
    for needle in [
        "convergence engine, not a timer",
        "Evidence over intuition",
        "Observation is not confirmation",
        "Absence of proof is not proof of absence",
        "Maximum 3 attempts per tool call",
        "Tool availability vs. absence",
    ]:
        assert needle in AUTONOMOUS_AGENT_SYSTEM_PROMPT
