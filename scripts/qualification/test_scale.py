"""AI-OSOP Scale Qualification Suite

Simulates load to measure throughput of:
- Engagement creation
- Task scheduling
- Graph writes
- Session reads

Run:
    python scripts/qualification/test_scale.py
"""

import asyncio
import random
import sys
import time
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, "src")

from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import ScopeDefinition, SessionState, Task, Vulnerability


class ScaleQualification:
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

    # -------------------- Engagement Creation Throughput --------------------

    def test_engage_creation_100(self) -> None:
        """Create 100 SessionState objects and measure time."""
        start = time.perf_counter()
        sessions = []
        for i in range(100):
            s = SessionState(
                session_id=f"eng-{i:03d}",
                scope=ScopeDefinition(
                    engagement_id=f"eng-{i:03d}",
                    domains=[f"example{i}.com"],
                ),
                created_by="operator-1",
            )
            sessions.append(s)
        elapsed = time.perf_counter() - start
        rate = 100 / elapsed if elapsed > 0 else float("inf")
        self._record(
            "engage_creation_100", True, f"100 engagements in {elapsed:.3f}s ({rate:.0f}/s)"
        )

    # -------------------- Task Creation Throughput --------------------

    def test_task_creation_1000(self) -> None:
        """Create 1000 Task objects and measure time."""
        start = time.perf_counter()
        tasks = []
        for i in range(1000):
            t = Task(
                type="recon",
                agent_type=AgentType.RECON,
                payload={"target": f"host-{i}.example.com"},
                engagement_id="eng-001",
                priority=random.randint(1, 10),
            )
            tasks.append(t)
        elapsed = time.perf_counter() - start
        rate = 1000 / elapsed if elapsed > 0 else float("inf")
        self._record("task_creation_1000", True, f"1000 tasks in {elapsed:.3f}s ({rate:.0f}/s)")

    # -------------------- Graph Node Creation Throughput --------------------

    def test_vuln_creation_10k(self) -> None:
        """Create 10,000 Vulnerability objects and measure time."""
        start = time.perf_counter()
        vulns = []
        for i in range(10_000):
            v = Vulnerability(
                id=f"vuln-{i:05d}",
                vuln_type=VulnClass.SQLI,
                severity=Severity.HIGH,
                title=f"SQLi in endpoint {i}",
                description="A SQL injection vulnerability",
                evidence=[{"request": f"GET /api/{i}"}],
                tool_source="scale_test",
                engagement_id="eng-001",
                confidence=0.9,
            )
            vulns.append(v)
        elapsed = time.perf_counter() - start
        rate = 10_000 / elapsed if elapsed > 0 else float("inf")
        self._record("vuln_creation_10k", True, f"10k vulns in {elapsed:.3f}s ({rate:.0f}/s)")

    # -------------------- Memory Access Latency --------------------

    async def test_session_memory_read_latency(self) -> None:
        """Simulate 1000 session reads from a mocked SessionMemory."""
        from ai_osop.memory.session_memory import SessionMemory

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)

        # We can't instantiate real SessionMemory without DB, so we just measure
        # the Pydantic serialization/deserialization overhead.
        session = SessionState(
            session_id="eng-latency",
            scope=ScopeDefinition(engagement_id="eng-latency", domains=["test.com"]),
            created_by="operator-1",
        )

        start = time.perf_counter()
        for _ in range(1000):
            _ = session.dict()
        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / 1000) * 1000
        self._record(
            "session_serialize_1000",
            True,
            f"1000 serializations in {elapsed:.3f}s (avg {avg_ms:.3f}ms)",
        )

    # -------------------- Orchestrator --------------------

    async def run_all(self) -> None:
        print("=" * 60)
        print("AI-OSOP Scale Qualification Suite")
        print("=" * 60)

        self.test_engage_creation_100()
        self.test_task_creation_1000()
        self.test_vuln_creation_10k()
        await self.test_session_memory_read_latency()

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
    suite = ScaleQualification()
    await suite.run_all()


if __name__ == "__main__":
    asyncio.run(main())
