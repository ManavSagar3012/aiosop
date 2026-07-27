"""AIOSOP-NAV-RESILIENCE-001: navigate() must ride over a transient target blip.

Live, a single net::ERR_EMPTY_RESPONSE from a mid-restart Juice Shop burned
register's whole 180s task budget. navigate() now retries transient network
errors briefly; real navigation failures still raise immediately; the existing
local-http SSL downgrade is preserved.
"""
import asyncio

from ai_osop.adapters.browser_mcp import BrowserMCPAdapter
from ai_osop.core.exceptions import MCPException


def _adapter():
    a = BrowserMCPAdapter(registry=object())
    a._NAV_RETRY_BASE_SECONDS = 0  # no real sleeping in tests
    return a


async def _run():
    # 1. Transient blip then success -> navigate succeeds, does not raise.
    a = _adapter()
    calls = {"n": 0}

    async def flaky(action, params=None, **kw):
        calls["n"] += 1
        if calls["n"] < 3:
            raise MCPException("Browser action 'navigate' failed: net::ERR_EMPTY_RESPONSE")
        return {"ok": True}

    a.execute_action = flaky
    out = await a.navigate("http://127.0.0.1:3000/")
    assert out == {"ok": True}, out
    assert calls["n"] == 3, f"expected 2 retries then success, got {calls['n']} calls"

    # 2. Non-transient error raises immediately (no retry, no masking).
    a = _adapter()
    calls2 = {"n": 0}

    async def hard_fail(action, params=None, **kw):
        calls2["n"] += 1
        raise MCPException("Browser action 'navigate' failed: net::ERR_NAME_NOT_RESOLVED")

    a.execute_action = hard_fail
    raised = False
    try:
        await a.navigate("http://nope.invalid/")
    except MCPException:
        raised = True
    assert raised, "non-transient error should propagate"
    assert calls2["n"] == 1, f"non-transient must not retry, got {calls2['n']} calls"

    # 3. Persistent transient failure exhausts retries and raises.
    a = _adapter()
    calls3 = {"n": 0}

    async def always_blip(action, params=None, **kw):
        calls3["n"] += 1
        raise MCPException("net::ERR_ABORTED")

    a.execute_action = always_blip
    raised = False
    try:
        await a.navigate("http://127.0.0.1:3000/")
    except MCPException:
        raised = True
    assert raised, "exhausted retries should raise"
    assert calls3["n"] == a._NAV_MAX_ATTEMPTS, f"expected {a._NAV_MAX_ATTEMPTS} attempts, got {calls3['n']}"

    # 4. Local-http SSL downgrade preserved (one-shot, https -> http).
    a = _adapter()
    seen = {"urls": []}

    async def ssl_then_ok(action, params=None, **kw):
        u = (params or {}).get("url", "")
        seen["urls"].append(u)
        if u.startswith("https://"):
            raise MCPException("net::ERR_SSL_PROTOCOL_ERROR")
        return {"ok": "http"}

    a.execute_action = ssl_then_ok
    out = await a.navigate("https://127.0.0.1:3000/")
    assert out == {"ok": "http"}, out
    assert seen["urls"][-1].startswith("http://"), seen["urls"]

    print("OK: transient retry, hard-fail passthrough, exhaustion, SSL downgrade")


def test_browser_nav_resilience():
    asyncio.run(_run())


if __name__ == "__main__":
    test_browser_nav_resilience()
