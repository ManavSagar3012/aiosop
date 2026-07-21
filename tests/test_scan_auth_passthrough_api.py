"""API-level tests for auth passthrough on POST /scan/deterministic.

The endpoint accepts an ``auth_user`` label; when a UserSession was captured for
it, the generalized surface oracles run through that authenticated SessionClient.
These tests drive the handler function directly (no HTTP server) with the module
dependencies monkeypatched, and assert:

  1. A known label resolves a session, opens ``store.as_user(...)``, threads the
     yielded client into ``run_generalized_scan``, closes it on exit, and reports
     ``authenticated_as``.
  2. An unknown label (no stored session) degrades to an unauthenticated scan
     (client=None) rather than erroring, and reports ``authenticated_as=None``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import ai_osop.api.routers.engagements as eng
import ai_osop.core.deterministic_scan as ds
from ai_osop.api import deps


class _CMClient:
    """Async-context-manager double standing in for a SessionClient; records
    whether it was entered and closed so we can assert lifecycle ownership."""

    def __init__(self):
        self.entered = False
        self.closed = False

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, *exc):
        self.closed = True
        return False


class _Store:
    """SessionStore double. ``sessions`` maps label -> truthy UserSession stub."""

    def __init__(self, sessions: dict, client: _CMClient):
        self._sessions = sessions
        self._client = client
        self.as_user_calls: list = []

    async def get_session_or_none(self, engagement_id, label):
        return self._sessions.get(label)

    def as_user(self, engagement_id, label, *, base_url="", governance_hook=None):
        self.as_user_calls.append((engagement_id, label, base_url))
        self.last_governance_hook = governance_hook
        return self._client


def _install_common(monkeypatch, store):
    """Patch auth + orchestrator + session_store so the handler reaches the scan."""
    # Real ScopeDefinition so the governed-client path (ScopeEnforcer(session.scope))
    # constructs cleanly — a SimpleNamespace lacks ips/exclusions/testing_window.
    from ai_osop.core.models import ScopeDefinition

    scope = ScopeDefinition(engagement_id="eng-1", domains=["target.test"])
    fake_session = SimpleNamespace(scope=scope)

    async def _fake_access(operator, session_id):
        return fake_session

    monkeypatch.setattr(eng, "assert_engagement_access", _fake_access)
    monkeypatch.setitem(
        deps.state,
        "orchestrator",
        SimpleNamespace(graph_memory=object(), rate_limiter=None),
    )
    monkeypatch.setitem(deps.state, "session_store", store)


@pytest.mark.asyncio
async def test_auth_user_threads_client_and_reports_identity(monkeypatch):
    client = _CMClient()
    store = _Store({"user_a": SimpleNamespace(bearer_token="tok")}, client)
    _install_common(monkeypatch, store)

    seen = {}

    async def fake_generalized(
        engagement_id, gm, *, oast_registry=None, client=None, governance_hook=None
    ):
        seen["client"] = client
        seen["governance_hook"] = governance_hook
        return [], 0

    monkeypatch.setattr(ds, "run_generalized_scan", fake_generalized)

    resp = await eng.deterministic_scan(
        "sess-1", mode="discovered", auth_user="user_a", operator={"role": "operator"}
    )

    # The exact client yielded by as_user() was threaded into the scan
    assert seen["client"] is client
    # ...and the governance hook was threaded too (governs jwt/idor sub-scans)
    assert seen["governance_hook"] is not None
    # as_user received the same governance hook (so authed probes are governed)
    assert store.last_governance_hook is not None
    # We opened AND closed it (caller owns the lifecycle)
    assert client.entered is True and client.closed is True
    assert store.as_user_calls == [("eng-1", "user_a", "http://target.test")]
    assert resp["authenticated_as"] == "user_a"


@pytest.mark.asyncio
async def test_unknown_auth_user_degrades_to_unauthenticated(monkeypatch):
    client = _CMClient()
    store = _Store({}, client)  # no session for any label
    _install_common(monkeypatch, store)

    seen = {}

    async def fake_generalized(
        engagement_id, gm, *, oast_registry=None, client=None, governance_hook=None
    ):
        seen["client"] = client
        seen["governance_hook"] = governance_hook
        return [], 0

    monkeypatch.setattr(ds, "run_generalized_scan", fake_generalized)

    resp = await eng.deterministic_scan(
        "sess-1", mode="discovered", auth_user="ghost", operator={"role": "operator"}
    )

    # No session -> unauthenticated scan: as_user() was never opened, no injected
    # client, but the governance hook IS threaded (M1) — the sub-scans build their
    # own clients with it attached, so every probe is still scope/rate/header'd.
    assert client.entered is False and client.closed is False
    assert seen["client"] is None
    assert seen["governance_hook"] is not None
    assert resp["authenticated_as"] is None
