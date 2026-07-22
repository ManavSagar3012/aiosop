"""Tests for the governed egress client (M1: scope + rate + header + audit).

Offline via httpx.MockTransport — no real network. These assert the compliance
guarantees the deterministic scan path relies on: out-of-scope traffic never
leaves, every request is throttled, and the research-identity header is stamped.
"""

from __future__ import annotations

import httpx
import pytest

from ai_osop.core.exceptions import OutOfScopeError
from ai_osop.safety.governed_client import (
    governance_hook,
    governed_client,
    research_header_from_settings,
)


class _Scope:
    def __init__(self, *allowed: str):
        self._allowed = set(allowed)

    def host_in_scope(self, host: str) -> bool:
        return host in self._allowed


class _Limiter:
    def __init__(self):
        self.calls: list = []

    async def acquire(self, target=None, tool=None):
        self.calls.append((target, tool))


def _echo_transport(sink: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        sink["headers"] = dict(request.headers)
        sink["url"] = str(request.url)
        return httpx.Response(200, text="ok")

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_in_scope_request_allowed_throttled_and_tagged():
    sink: dict = {}
    limiter = _Limiter()
    async with governed_client(
        scope=_Scope("in.example.com"),
        rate_limiter=limiter,
        research_header=("X-HackerOne-Research", "tester"),
        transport=_echo_transport(sink),
    ) as c:
        r = await c.get("https://in.example.com/?q=1")
    assert r.status_code == 200
    # header injected (httpx lowercases header names on the wire)
    assert sink["headers"].get("x-hackerone-research") == "tester"
    # rate limiter consulted once, keyed by host + tool
    assert limiter.calls == [("in.example.com", "scan")]


@pytest.mark.asyncio
async def test_out_of_scope_request_blocked_before_egress():
    sink: dict = {}
    limiter = _Limiter()
    async with governed_client(
        scope=_Scope("in.example.com"),
        rate_limiter=limiter,
        transport=_echo_transport(sink),
    ) as c:
        with pytest.raises(OutOfScopeError):
            await c.get("https://evil.example.net/")
    # the request never reached the transport, and the limiter was NOT consumed
    assert sink == {}
    assert limiter.calls == []


@pytest.mark.asyncio
async def test_no_guards_is_plain_httpx_behavior():
    """With scope/limiter/header all omitted the client must behave like a bare
    httpx.AsyncClient — migrating a call site is never a regression."""
    sink: dict = {}
    async with governed_client(transport=_echo_transport(sink)) as c:
        r = await c.get("https://anything.example.org/x")
    assert r.status_code == 200
    assert sink["url"] == "https://anything.example.org/x"


@pytest.mark.asyncio
async def test_caller_request_hook_is_preserved():
    """A caller-supplied request hook must still run alongside the governance hook."""
    sink: dict = {}
    ran = {"caller": False}

    async def _caller_hook(request: httpx.Request) -> None:
        ran["caller"] = True

    async with governed_client(
        scope=_Scope("in.example.com"),
        event_hooks={"request": [_caller_hook]},
        transport=_echo_transport(sink),
    ) as c:
        await c.get("https://in.example.com/")
    assert ran["caller"] is True


@pytest.mark.asyncio
async def test_rate_limit_is_per_request_not_per_client():
    """Three requests => three limiter acquisitions (per-request throttle, the B2 fix)."""
    sink: dict = {}
    limiter = _Limiter()
    async with governed_client(
        scope=_Scope("in.example.com"),
        rate_limiter=limiter,
        transport=_echo_transport(sink),
    ) as c:
        for _ in range(3):
            await c.get("https://in.example.com/")
    assert len(limiter.calls) == 3


def test_research_header_from_settings_disabled_when_name_blank(monkeypatch):
    from ai_osop.core import config

    monkeypatch.setattr(config.settings, "research_header_name", "", raising=False)
    monkeypatch.setattr(config.settings, "research_header_value", "x", raising=False)
    assert research_header_from_settings() is None


def test_research_header_from_settings_builds_pair(monkeypatch):
    from ai_osop.core import config

    monkeypatch.setattr(
        config.settings, "research_header_name", "X-HackerOne-Research", raising=False
    )
    monkeypatch.setattr(config.settings, "research_header_value", "h1user", raising=False)
    assert research_header_from_settings() == ("X-HackerOne-Research", "h1user")


@pytest.mark.asyncio
async def test_session_client_authed_path_is_governed(monkeypatch):
    """The authenticated SessionClient must apply the governance hook too: an
    out-of-scope request through it raises before egress (no network needed — the
    scope check fires in the request hook before any connection). This is the M1
    guarantee for the authed scan path."""
    from types import SimpleNamespace

    from ai_osop.auth.session_client import SessionClient
    from ai_osop.safety.governed_client import governance_hook

    sess = SimpleNamespace(
        cookies=[], bearer_token="", user_agent="", csrf_token="", extra_headers={}
    )
    hook = governance_hook(scope=_Scope("in.example.com"))
    client = SessionClient(session=sess, governance_hook=hook)
    try:
        with pytest.raises(OutOfScopeError):
            await client.get("https://evil.example.net/")
    finally:
        await client.aclose()
