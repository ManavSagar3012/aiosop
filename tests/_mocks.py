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
from unittest.mock import AsyncMock


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
