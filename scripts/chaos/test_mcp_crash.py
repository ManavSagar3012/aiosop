"""Chaos Test: MCP Crash Loop

Simulates an MCP server entering a crash loop and verifies:
- Circuit breaker opens after threshold failures
- Tasks queue but don't cascade-fail
- Recovery happens after timeout

Run:
    python scripts/chaos/test_mcp_crash.py
"""

import asyncio
import sys
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, patch

sys.path.insert(0, "src")

from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest


class MCPCrashChaosTest:
    def __init__(self):
        self.results: list[dict] = []
        self.passed = 0
        self.failed = 0

    def _record(self, name: str, passed: bool, detail: str = "") -> None:
        self.results.append({"test": name, "passed": passed, "detail": detail})
        if passed:
            self.passed += 1
        else:
            self.failed += 1

    async def test_circuit_opens_on_crash_loop(self) -> None:
        """Simulate MCP crash loop: 10 consecutive connection failures."""
        conn = MCPConnection(server_id="crash-mcp", host="localhost", port=59999)
        # Simulate 10 failures
        for i in range(10):
            conn._record_failure()

        if conn._circuit_open and conn._failure_count >= conn.CIRCUIT_THRESHOLD:
            self._record("mcp_circuit_opens", True,
                f"Circuit breaker opened after {conn._failure_count} failures (threshold={conn.CIRCUIT_THRESHOLD})")
        else:
            self._record("mcp_circuit_opens", False,
                f"Circuit breaker NOT open after {conn._failure_count} failures")

    async def test_execution_blocked_when_open(self) -> None:
        """Verify tasks are blocked when circuit is open."""
        conn = MCPConnection(server_id="crash-mcp", host="localhost", port=59999)
        conn._circuit_open = True
        conn._circuit_opened_at = datetime.utcnow()
        conn._initialized = True

        req = MCPExecuteRequest(tool_name="test_tool", parameters={})
        resp = await conn.execute(req)
        if resp.status == "circuit_open":
            self._record("mcp_blocked_when_open", True,
                "Execution correctly blocked with circuit_open status")
        else:
            self._record("mcp_blocked_when_open", False,
                f"Unexpected status: {resp.status}")

    async def test_recovery_after_timeout(self) -> None:
        """Verify circuit breaker recovers after 30s."""
        conn = MCPConnection(server_id="crash-mcp", host="localhost", port=59999)
        conn._circuit_open = True
        conn._circuit_opened_at = datetime.utcnow() - __import__("datetime").timedelta(seconds=31)
        conn._failure_count = 5

        conn._circuit_breaker_check()
        if not conn._circuit_open:
            self._record("mcp_recovery", True,
                "Circuit breaker recovered after 31s")
        else:
            self._record("mcp_recovery", False,
                f"Circuit breaker still open after 31s")

    async def test_no_cascade_to_other_mcps(self) -> None:
        """Verify one MCP crash doesn't affect others."""
        crash_conn = MCPConnection(server_id="crash-mcp", host="localhost", port=59999)
        healthy_conn = MCPConnection(server_id="healthy-mcp", host="localhost", port=50050)

        # Crash one
        for _ in range(5):
            crash_conn._record_failure()

        # Other should still be fine
        if not healthy_conn._circuit_open:
            self._record("mcp_no_cascade", True,
                "Healthy MCP unaffected by crash loop in another MCP")
        else:
            self._record("mcp_no_cascade", False,
                "Healthy MCP incorrectly affected")

    async def run_all(self) -> None:
        print("=" * 60)
        print("Chaos Test: MCP Crash Loop")
        print("=" * 60)

        await self.test_circuit_opens_on_crash_loop()
        await self.test_execution_blocked_when_open()
        await self.test_recovery_after_timeout()
        await self.test_no_cascade_to_other_mcps()

        print("-" * 60)
        for r in self.results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"[{status}] {r['test']}: {r['detail']}")
        print("-" * 60)
        print(f"Results: {self.passed} passed, {self.failed} failed")
        print("=" * 60)

        if self.failed > 0:
            sys.exit(1)


async def main() -> None:
    await MCPCrashChaosTest().run_all()


if __name__ == "__main__":
    asyncio.run(main())
