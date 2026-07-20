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

    def as_user(self, engagement_id, label, *, base_url=""):
        self.as_user_calls.append((engagement_id, label, base_url))
        return self._client


def _install_common(monkeypatch, store):
    """Patch auth + orchestrator + session_store so the handler reaches the scan."""
    scope = SimpleNamespace(engagement_id="eng-1", domains=["http://target.test"])
    fake_session = SimpleNamespace(scope=scope)

    async def _fake_access(operator, session_id):
        return fake_session

    monkeypatch.setattr(eng, "assert_engagement_access", _fake_access)
    monkeypatch.setitem(
        deps.state, "orchestrator", SimpleNamespace(graph_memory=object())
    )
    monkeypatch.setitem(deps.state, "session_store", store)


@pytest.mark.asyncio
async def test_auth_user_threads_client_and_reports_identity(monkeypatch):
    client = _CMClient()
    store = _Store({"user_a": SimpleNamespace(bearer_token="tok")}, client)
    _install_common(monkeypatch, store)

    seen = {}

    async def fake_generalized(engagement_id, gm, *, oast_registry=None, client=None):
        seen["client"] = client
        return [], 0

    monkeypatch.setattr(ds, "run_generalized_scan", fake_generalized)

    resp = await eng.deterministic_scan(
        "sess-1", mode="discovered", auth_user="user_a", operator={"role": "operator"}
    )

    # The exact client yielded by as_user() was threaded into the scan
    assert seen["client"] is client
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

    async def fake_generalized(engagement_id, gm, *, oast_registry=None, client=None):
        seen["client"] = client
        return [], 0

    monkeypatch.setattr(ds, "run_generalized_scan", fake_generalized)

    resp = await eng.deterministic_scan(
        "sess-1", mode="discovered", auth_user="ghost", operator={"role": "operator"}
    )

    # No session -> unauthenticated scan, and as_user() was never opened
    assert seen["client"] is None
    assert client.entered is False and client.closed is False
    assert resp["authenticated_as"] is None
