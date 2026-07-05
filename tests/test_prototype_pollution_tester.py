"""Offline, deterministic tests for PrototypePollutionTester.

Uses httpx.MockTransport to model: a server whose prototype gets polluted (marker
leaks into a payload-free probe), a status-override-gadget server, a hardened
server (raw reflection only, no pollution), and a timing-out server.
"""
import json

import httpx
import pytest

from ai_osop.core.prototype_pollution_tester import (
    PrototypePollutionTester,
    SENTINEL_STATUS,
)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _extract_marker(request: httpx.Request):
    """Return (key, val) of a __proto__/constructor.prototype gadget in the body."""
    try:
        data = json.loads(request.content.decode() or "{}")
    except Exception:
        return None
    proto = data.get("__proto__") or data.get("constructor", {}).get("prototype")
    if not isinstance(proto, dict):
        return None
    return proto


async def test_vulnerable_reflected_property_confirms():
    """Pollution mutates a shared prototype: a later payload-free probe leaks the
    marker value -> confirmed via the reflected_property oracle."""
    polluted: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            proto = _extract_marker(request)
            if proto:
                polluted.update(proto)  # simulate Object.prototype mutation
            return httpx.Response(200, json={"ok": True})
        # GET probe carries NO payload; a vulnerable app leaks inherited props.
        return httpx.Response(200, json={"config": {}, "inherited": polluted})

    async with _client(handler) as c:
        tester = PrototypePollutionTester("http://t/merge", probe_url="http://t/status", client=c)
        findings = await tester.run()

    confirmed = tester.confirmed(findings)
    assert any(f.technique == "reflected_property" for f in confirmed), \
        "inherited-property leak must confirm prototype pollution"


async def test_vulnerable_status_override_confirms():
    """Polluting __proto__.status flips a follow-up response status to the sentinel."""
    state = {"polluted": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            proto = _extract_marker(request)
            if proto and proto.get("status") == SENTINEL_STATUS:
                state["polluted"] = True
            return httpx.Response(200, json={"ok": True})
        # baseline (before pollution) = 200; after pollution the app inherits status
        if state["polluted"]:
            return httpx.Response(SENTINEL_STATUS, text="overridden")
        return httpx.Response(200, text="normal")

    async with _client(handler) as c:
        tester = PrototypePollutionTester("http://t/merge", probe_url="http://t/probe", client=c)
        findings = await tester.run()

    confirmed = tester.confirmed(findings)
    assert any(f.technique == "status_override" for f in confirmed), \
        "status flip to sentinel must confirm prototype pollution"


async def test_reflection_only_is_not_confirmation():
    """Hardened server: it ECHOES the raw payload back (reflection) but never
    mutates a shared prototype, so a payload-free probe stays clean -> no confirm."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            # echo the payload straight back (pure reflection, no pollution)
            try:
                body = json.loads(request.content.decode() or "{}")
            except Exception:
                body = {}
            return httpx.Response(200, json={"echo": body})
        # payload-free probe: clean, deterministic, never returns the marker
        return httpx.Response(200, json={"config": {"safe": True}})

    async with _client(handler) as c:
        tester = PrototypePollutionTester("http://t/merge", probe_url="http://t/status", client=c)
        findings = await tester.run()

    assert not tester.confirmed(findings), "raw reflection must not be a false positive"


async def test_timeout_path_does_not_raise():
    """A timing-out endpoint degrades to unconfirmed, never raises."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("simulated timeout", request=request)

    async with _client(handler) as c:
        tester = PrototypePollutionTester("http://t/merge", client=c, timeout=0.5)
        findings = await tester.run()  # must not raise

    assert findings
    assert not tester.confirmed(findings)
