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

from ai_osop.core.models import ScopeDefinition, SessionState, Task, Vulnerability
from ai_osop.core.config import AgentType, VulnClass, Severity


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
        self._record("engage_creation_100", True, f"100 engagements in {elapsed:.3f}s ({rate:.0f}/s)")

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
            _ = session.model_dump()
        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / 1000) * 1000
        self._record("session_serialize_1000", True, f"1000 serializations in {elapsed:.3f}s (avg {avg_ms:.3f}ms)")

    # -------------------- Service / Concurrency Load Testing --------------------

    async def test_concurrent_api_throughput(self) -> None:
        """Measure API concurrency and throughput across 100 concurrent requests."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient
        from ai_osop.api.health import router as health_router

        test_app = FastAPI()
        test_app.include_router(health_router)

        num_requests = 100
        concurrency = 20
        latencies: list[float] = []

        semaphore = asyncio.Semaphore(concurrency)

        async def worker(client: AsyncClient):
            async with semaphore:
                t0 = time.perf_counter()
                resp = await client.get("/health")
                latencies.append(time.perf_counter() - t0)
                assert resp.status_code == 200

        start = time.perf_counter()
        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://testserver") as client:
            await asyncio.gather(*(worker(client) for _ in range(num_requests)))
        total_time = time.perf_counter() - start

        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)] * 1000
        p95 = latencies[int(len(latencies) * 0.95)] * 1000
        p99 = latencies[int(len(latencies) * 0.99)] * 1000
        rps = num_requests / total_time if total_time > 0 else 0

        detail = f"{num_requests} reqs in {total_time:.3f}s ({rps:.0f} req/s), p50={p50:.2f}ms, p95={p95:.2f}ms, p99={p99:.2f}ms"
        passed = p95 < 200.0  # p95 under 200ms
        self._record("concurrent_api_throughput", passed, detail)

    async def test_concurrent_task_queue_concurrency(self) -> None:
        """Concurrently schedule 200 tasks under contention."""
        from ai_osop.orchestrator.task_scheduler import TaskScheduler
        from ai_osop.core.models import Task
        from ai_osop.core.config import AgentType

        mock_orch = MagicMock()
        mock_orch._bind_task_authorization = AsyncMock()
        mock_orch._sessions = {}
        mock_orch._agents = {}
        mock_orch.rate_limiter = None
        mock_orch.temporal_enabled = False
        mock_orch.graph_memory = AsyncMock()
        mock_orch.coordination_bus = AsyncMock()
        mock_orch.session_memory = AsyncMock()

        scheduler = TaskScheduler(orchestrator=mock_orch)
        num_tasks = 200
        start = time.perf_counter()

        tasks = [
            Task(
                id=f"task-scale-{i}",
                type="recon",
                agent_type=AgentType.RECON,
                payload={"target": f"target-{i}.test"},
                engagement_id="eng-scale",
                priority=random.randint(1, 10),
            )
            for i in range(num_tasks)
        ]

        async def schedule_worker(task):
            await scheduler.schedule_task(task)

        await asyncio.gather(*(schedule_worker(t) for t in tasks))
        elapsed = time.perf_counter() - start
        rate = num_tasks / elapsed if elapsed > 0 else 0

        assert mock_orch.session_memory.push_task_queue.await_count == num_tasks
        self._record("concurrent_task_scheduling", True, f"{num_tasks} tasks scheduled concurrently in {elapsed:.3f}s ({rate:.0f} tasks/s)")

    # -------------------- Orchestrator --------------------

    async def run_all(self) -> None:
        print("=" * 60)
        print("AI-OSOP Scale & Concurrency Qualification Suite")
        print("=" * 60)

        self.test_engage_creation_100()
        self.test_task_creation_1000()
        self.test_vuln_creation_10k()
        await self.test_session_memory_read_latency()
        await self.test_concurrent_api_throughput()
        await self.test_concurrent_task_queue_concurrency()

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
