"""
AIOSOP-AUDIT-2026-06-16 regression tests for BaseAgent lifecycle.

Guards the fix for the background-task leak: initialize() used to create the
_task_worker / _heartbeat_loop tasks with asyncio.create_task() and discard the
handles, so shutdown() could never cancel them (the worker blocks forever on
_task_queue.get() and never observes _running=False).
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


class _DummyAgent(BaseAgent):
    @property
    def agent_type(self) -> AgentType:
        return AgentType.RECON

    async def _setup_resources(self) -> None:
        pass

    async def _execute(self, task):
        return {}

    async def _cleanup_resources(self) -> None:
        pass


def _ctx():
    ctx = AsyncMock()
    ctx.agent_id = "dummy-1"
    ctx.get_agent_state = AsyncMock(return_value=None)
    ctx.session_memory.get_agent_state = AsyncMock(return_value=None)
    return ctx


@pytest.mark.asyncio
async def test_initialize_tracks_background_tasks():
    agent = _DummyAgent(_ctx())
    await agent.initialize()
    try:
        assert len(agent._bg_tasks) == 2
        assert all(not t.done() for t in agent._bg_tasks)
    finally:
        await agent.shutdown()


@pytest.mark.asyncio
async def test_shutdown_cancels_background_tasks():
    agent = _DummyAgent(_ctx())
    await agent.initialize()
    bg = list(agent._bg_tasks)

    await agent.shutdown()

    # Give the event loop a tick to finalize cancellations.
    await asyncio.sleep(0)
    assert agent._bg_tasks == []
    assert all(t.done() for t in bg), "background loops must be stopped after shutdown"
    assert agent._running is False


# ---- AIOSOP-AUDIT-2026-06-16: skill activation coverage is idempotent per task ----


@pytest.mark.asyncio
async def test_skill_activation_recorded_once_per_task():
    """Any agent records skill activations once per task — recon/vuln also resolving
    inside _execute must not double-count."""
    ctx = _ctx()
    engine = MagicMock()
    engine.resolve_ids = lambda ids: list(ids)  # passthrough
    engine.record_execution = MagicMock()
    ctx.skill_engine = engine

    agent = _DummyAgent(ctx)
    # full_recon maps to 3 skills in TASK_SKILL_MAP
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e", payload={})

    await agent._get_relevant_skills(task)
    await agent._get_relevant_skills(task)  # second call: same task id, must not re-record

    assert engine.record_execution.call_count == 3
    assert task.id in agent._activated_tasks
