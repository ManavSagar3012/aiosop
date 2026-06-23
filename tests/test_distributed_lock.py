import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest
from ai_osop.core.config import AgentType
from ai_osop.orchestrator.orchestrator import Orchestrator


class SharedFakeSessionMemory:
    """Shared session memory mock that simulates global Redis distributed locks."""

    def __init__(self):
        self.active_locks = {}

    async def acquire_lock(self, lock_key: str, lock_value: str, ttl_seconds: int = 30) -> bool:
        if lock_key in self.active_locks:
            return False
        self.active_locks[lock_key] = lock_value
        return True

    async def release_lock(self, lock_key: str, lock_value: str) -> bool:
        if self.active_locks.get(lock_key) == lock_value:
            self.active_locks.pop(lock_key, None)
            return True
        return False


@pytest.mark.asyncio
async def test_multi_orchestrator_agent_locking():
    """Verify that multiple orchestrators cannot claim the same agent concurrently."""
    shared_mem = SharedFakeSessionMemory()

    # Orchestrator 1 setup
    mem1 = MagicMock()
    mem1.acquire_lock = AsyncMock(side_effect=shared_mem.acquire_lock)
    mem1.release_lock = AsyncMock(side_effect=shared_mem.release_lock)
    orch1 = Orchestrator(mem1, AsyncMock(), AsyncMock(), AsyncMock())

    # Orchestrator 2 setup
    mem2 = MagicMock()
    mem2.acquire_lock = AsyncMock(side_effect=shared_mem.acquire_lock)
    mem2.release_lock = AsyncMock(side_effect=shared_mem.release_lock)
    orch2 = Orchestrator(mem2, AsyncMock(), AsyncMock(), AsyncMock())

    # Mock agent
    agent_id = "agent-recon-1"
    agent_mock = MagicMock()
    agent_mock.ctx.agent_id = agent_id
    agent_mock.ctx.agent_type = AgentType.RECON
    agent_mock.ctx.status = "idle"
    agent_mock.supports_task_type.return_value = True

    # Register same agent ID to both orchestrators (simulating registration in cluster)
    orch1._agents[agent_id] = agent_mock
    orch2._agents[agent_id] = agent_mock

    # 1. Orchestrator 1 tries to claim the agent
    claimed_agent1 = await orch1._find_available_agent(AgentType.RECON, "recon")
    assert claimed_agent1 is not None
    assert claimed_agent1.ctx.agent_id == agent_id

    # Lock is now held globally in shared_mem
    assert f"lock:agent:{agent_id}" in shared_mem.active_locks

    # 2. Orchestrator 2 tries to claim the SAME agent concurrently
    claimed_agent2 = await orch2._find_available_agent(AgentType.RECON, "recon")
    # Should be rejected because the Redis lock is already held by Orch 1!
    assert claimed_agent2 is None

    # 3. Orchestrator 1 releases the agent
    orch1._release_agent(agent_id)
    # Await yield to let the fire-and-forget create_task execute
    await asyncio.sleep(0.01)

    # Lock should be released
    assert f"lock:agent:{agent_id}" not in shared_mem.active_locks

    # 4. Now Orchestrator 2 should be able to claim the agent successfully
    claimed_agent2_after = await orch2._find_available_agent(AgentType.RECON, "recon")
    assert claimed_agent2_after is not None
    assert claimed_agent2_after.ctx.agent_id == agent_id
