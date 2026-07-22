"""Shared test doubles.

Centralises the ``session_memory`` stub used by agent scan-unit tests. When
production adds a new resolver — as the scope-fix (cb19e3e) did with
``get_session_state_by_engagement_id`` — a single change here keeps every
test's double in sync, instead of each ``SimpleNamespace`` silently raising
``AttributeError`` the moment an agent calls the new method. That exact
regression is why this module exists.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Dict, Optional
from unittest.mock import AsyncMock, MagicMock


def stub_session_memory(**overrides: object) -> SimpleNamespace:
    """A stand-in for ``SessionMemory`` exposing the read API agents call.

    Both resolvers default to returning ``None`` (no active session, so agents
    skip browser initialisation). Any method can be overridden, e.g.::

        stub_session_memory(
            get_session_state_by_engagement_id=AsyncMock(return_value=session)
        )
    """
    defaults: dict[str, object] = {
        "get_session_state": AsyncMock(return_value=None),
        "get_session_state_by_engagement_id": AsyncMock(return_value=None),
        "store_engagement_id_mapping": AsyncMock(return_value=None),
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class FakeSessionMemory:
    """In-memory fake for SessionMemory with real lock acquire/release semantics.

    Unlike ``stub_session_memory()`` (which returns ``SimpleNamespace`` proxies
    that raise ``AttributeError`` when a new method is called), this class
    provides a real implementation of the lock API that multiple orchestrators
    can share to test distributed locking without mocking.

    Usage:
        shared = FakeSessionMemory()
        orch1 = Orchestrator(shared, ...)
        orch2 = Orchestrator(shared, ...)
    """

    def __init__(self) -> None:
        self.active_locks: Dict[str, str] = {}

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

    async def add_busy_agent(self, agent_id: str) -> None:
        pass

    async def remove_busy_agent(self, agent_id: str) -> None:
        pass

    async def ping(self) -> bool:
        return True

    async def load_session_state(self, session_id: str) -> Optional[object]:
        return None

    def is_locked(self, lock_key: str) -> bool:
        return lock_key in self.active_locks


def stub_agent_mock(
    agent_id: str = "agent-recon-1", agent_type=None, status: str = "idle"
) -> MagicMock:
    """Create a standard agent mock with minimal wiring.

    Returns a ``MagicMock`` whose ``ctx`` has ``agent_id``, ``agent_type``,
    and ``status`` set to sensible defaults.
    """
    from ai_osop.core.enums import AgentType

    agent = MagicMock()
    agent.ctx.agent_id = agent_id
    agent.ctx.agent_type = agent_type or AgentType.RECON
    agent.ctx.status = status
    agent.supports_task_type.return_value = True
    agent.execute_task = AsyncMock()
    return agent


def stub_async_context_manager(return_value=None) -> MagicMock:
    """Build a MagicMock usable as an async context manager.

    Usage:
        ctx = stub_async_context_manager(AsyncMock(status=200))
        mock_http.get.return_value = ctx
        async with mock_http.get("url") as resp:
            ...  # resp is return_value
    """
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=return_value)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


def stub_aiohttp_response(json_data: dict, status: int = 200) -> AsyncMock:
    """Create a mock aiohttp response with a JSON payload."""
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data)
    return resp


def stub_db_result(
    scalar_one_or_none=None,
    scalars: Optional[list] = None,
    all_rows: Optional[list] = None,
) -> MagicMock:
    """Create a mock DB result object."""
    result = MagicMock()
    if scalar_one_or_none is not None:
        result.scalar_one_or_none.return_value = scalar_one_or_none
    if scalars is not None:
        result.scalars.return_value = scalars
    if all_rows is not None:
        result.all.return_value = all_rows
    return result


def stub_async_session_maker(db_session) -> MagicMock:
    """Create a mock async session maker that returns ``db_session``."""
    maker = MagicMock()
    maker.return_value.__aenter__ = AsyncMock(return_value=db_session)
    maker.return_value.__aexit__ = AsyncMock(return_value=False)
    return maker
