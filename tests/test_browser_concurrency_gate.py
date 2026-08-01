"""AIOSOP-BROWSER-CONCURRENCY-001: the process-wide gate must cap concurrent
browser-mcp calls so the shared Chromium (and the single-process target) are not
driven into crash-loops by the scanner fan-out.
"""

import asyncio

import ai_osop.adapters.browser_mcp as bm
from ai_osop.adapters.browser_mcp import BrowserMCPAdapter


class _SlowRegistry:
    """Records the peak number of concurrent execute_tool calls."""

    def __init__(self):
        self.inflight = 0
        self.peak = 0

    async def execute_tool(self, server_id, tool, body, timeout_override=None):
        self.inflight += 1
        self.peak = max(self.peak, self.inflight)
        try:
            await asyncio.sleep(0.02)  # hold the slot so overlap is observable
        finally:
            self.inflight -= 1
        return type("R", (), {"status": "success", "result": {}})()


async def _run():
    reg = _SlowRegistry()
    a = BrowserMCPAdapter(registry=reg)
    # Force a known small cap regardless of settings/loop.
    bm._browser_semaphore = asyncio.Semaphore(3)

    # Fire 12 concurrent browser ops through the gate.
    await asyncio.gather(
        *[a.execute_action("eval", {"expression": "1"}, user_label=f"u{i}") for i in range(12)]
    )

    assert reg.peak <= 3, f"gate did not cap concurrency: peak={reg.peak}"
    assert reg.peak >= 2, f"gate serialised too hard (peak={reg.peak}); expected ~3"
    print(f"OK: 12 ops, peak concurrency {reg.peak} (cap 3)")


def test_browser_concurrency_gate():
    asyncio.run(_run())


if __name__ == "__main__":
    test_browser_concurrency_gate()
