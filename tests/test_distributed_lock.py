import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.orchestrator.orchestrator import Orchestrator
from tests._mocks import FakeSessionMemory, stub_agent_mock


@pytest.mark.asyncio
async def test_multi_orchestrator_agent_locking():
    """Verify that multiple orchestrators cannot claim the same agent concurrently."""
    shared_mem = FakeSessionMemory()

    # Orchestrator 1 setup: wire real lock methods from shared_mem
    mem1 = AsyncMock()
    mem1.acquire_lock = AsyncMock(side_effect=shared_mem.acquire_lock)
    mem1.release_lock = AsyncMock(side_effect=shared_mem.release_lock)
    mem1.add_busy_agent = AsyncMock()
    mem1.remove_busy_agent = AsyncMock()
    orch1 = Orchestrator(mem1, AsyncMock(), AsyncMock(), AsyncMock())

    # Orchestrator 2 setup
    mem2 = AsyncMock()
    mem2.acquire_lock = AsyncMock(side_effect=shared_mem.acquire_lock)
    mem2.release_lock = AsyncMock(side_effect=shared_mem.release_lock)
    mem2.add_busy_agent = AsyncMock()
    mem2.remove_busy_agent = AsyncMock()
    orch2 = Orchestrator(mem2, AsyncMock(), AsyncMock(), AsyncMock())

    # Use shared stub for the agent mock (reduces inline wiring)
    agent_id = "agent-recon-1"
    agent_mock = stub_agent_mock(agent_id=agent_id, agent_type=AgentType.RECON)

    # Register same agent ID to both orchestrators (simulating registration in cluster)
    orch1._agents[agent_id] = agent_mock
    orch2._agents[agent_id] = agent_mock

    # 1. Orchestrator 1 tries to claim the agent
    claimed_agent1 = await orch1._find_available_agent(AgentType.RECON, "recon")
    assert claimed_agent1 is not None
    assert claimed_agent1.ctx.agent_id == agent_id

    # Lock is now held globally in shared_mem
    assert shared_mem.is_locked(f"lock:agent:{agent_id}")

    # 2. Orchestrator 2 tries to claim the SAME agent concurrently
    claimed_agent2 = await orch2._find_available_agent(AgentType.RECON, "recon")
    # Should be rejected because the Redis lock is already held by Orch 1!
    assert claimed_agent2 is None

    # 3. Orchestrator 1 releases the agent
    await orch1._release_agent(agent_id)

    # Lock should be released
    assert not shared_mem.is_locked(f"lock:agent:{agent_id}")

    # 4. Now Orchestrator 2 should be able to claim the agent successfully
    claimed_agent2_after = await orch2._find_available_agent(AgentType.RECON, "recon")
    assert claimed_agent2_after is not None
    assert claimed_agent2_after.ctx.agent_id == agent_id
