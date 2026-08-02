import pytest

from ai_osop.memory.session_memory import SessionMemory


@pytest.mark.asyncio
async def test_busy_agents_lifecycle(session_memory):
    """Verify add_busy_agent, remove_busy_agent, is_busy_agent, and get_all_busy_agents."""
    # Ensure starting from a clean/known state
    await session_memory.remove_busy_agent("test-agent-1")
    await session_memory.remove_busy_agent("test-agent-2")

    # 1. Add busy agents
    await session_memory.add_busy_agent("test-agent-1")
    await session_memory.add_busy_agent("test-agent-2")

    # 2. Check if_busy_agent
    assert await session_memory.is_busy_agent("test-agent-1") is True
    assert await session_memory.is_busy_agent("test-agent-2") is True
    assert await session_memory.is_busy_agent("test-agent-3") is False

    # 3. Retrieve all busy agents
    all_busy = await session_memory.get_all_busy_agents()
    assert "test-agent-1" in all_busy
    assert "test-agent-2" in all_busy
    assert "test-agent-3" not in all_busy

    # 4. Remove one and check again
    await session_memory.remove_busy_agent("test-agent-1")
    assert await session_memory.is_busy_agent("test-agent-1") is False
    assert await session_memory.is_busy_agent("test-agent-2") is True

    all_busy_after = await session_memory.get_all_busy_agents()
    assert "test-agent-1" not in all_busy_after
    assert "test-agent-2" in all_busy_after

    # Cleanup remaining
    await session_memory.remove_busy_agent("test-agent-2")
    assert await session_memory.is_busy_agent("test-agent-2") is False
