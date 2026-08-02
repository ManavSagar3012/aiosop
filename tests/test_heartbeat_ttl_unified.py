"""Unit test: heartbeat TTL is unified at 30s.

Phase-1 issue #13: ``HeartbeatManager.update`` used ttl=30 while
``SessionMemory.update_agent_heartbeat`` used ttl=60 for the same logical
key ``agent:heartbeat:<id>``. Whichever writer ran last set the TTL, so a
crashed agent's heartbeat lingered between 30-60s non-deterministically.
This test pins the fix: both writers MUST use ttl=30.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.memory.heartbeat import HeartbeatManager


@pytest.mark.asyncio
async def test_heartbeat_manager_uses_ttl_30():
    """HeartbeatManager.update must use ttl=30 (the documented default)."""
    sm = MagicMock()
    sm.store_hot = AsyncMock()
    hm = HeartbeatManager(sm)

    await hm.update("agent-1", {"status": "running"})

    sm.store_hot.assert_awaited_once()
    args, kwargs = sm.store_hot.call_args
    # store_hot(key, state, ttl=...)
    assert args[0] == "agent:heartbeat:agent-1"
    assert kwargs.get("ttl") == 30 or (len(args) >= 3 and args[2] == 30)


@pytest.mark.asyncio
async def test_session_memory_uses_same_ttl_30():
    """SessionMemory.update_agent_heartbeat must use the SAME ttl=30 — not 60.
    A split TTL between the two writers was the root cause of the
    non-deterministic alive window."""
    # Import without invoking __init__ (which connects to Redis/PG).
    from ai_osop.memory.session_memory import SessionMemory

    sm = SessionMemory.__new__(SessionMemory)
    sm.store_hot = AsyncMock()

    await sm.update_agent_heartbeat("agent-1", {"status": "running"})

    sm.store_hot.assert_awaited_once()
    args, kwargs = sm.store_hot.call_args
    assert args[0] == "agent:heartbeat:agent-1"
    # The fix: was 60, now 30 to match HeartbeatManager.
    ttl = kwargs.get("ttl") if "ttl" in kwargs else (args[2] if len(args) >= 3 else None)
    assert ttl == 30, (
        f"SessionMemory.update_agent_heartbeat must use ttl=30 to match "
        f"HeartbeatManager; got ttl={ttl} (split-TTL bug regression)"
    )
