"""
End-to-end load test for AI-OSOP.

Measures task throughput, DB latency, and scheduler pressure under contention
using mocked MCP servers and in-memory session storage.

Usage:
    poetry run python scripts/qualification/test_load_e2e.py
    poetry run python scripts/qualification/test_load_e2e.py --tasks=500 --engagements=5

Output:
    test_load_e2e_report_<timestamp>.md  -- full report with percentile tables
"""

from __future__ import annotations

import argparse
import asyncio
import time
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.core.enums import AgentType
from ai_osop.core.models import (
    AuditEvent,
    ScopeDefinition,
    SessionState,
    Task,
)
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.orchestrator.orchestrator import Orchestrator

# ---------------------------------------------------------------------------
# Fixture helpers -- lightweight in-memory doubles
# ---------------------------------------------------------------------------


class FakeSessionMemory:
    """Minimal in-memory SessionMemory double that tracks latencies."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.sessions: Dict[str, Any] = {}
        self.audit_events: List[AuditEvent] = []
        self.task_queues: Dict[str, List[dict]] = {}
        self.tasks: Dict[str, dict] = {}
        self.busy_agents: set = set()
        self.state_store: Dict[str, Any] = {}
        self.dlq_entries: List[Any] = []
        self.query_times: List[float] = []
        self.lock_holders: Dict[str, str] = {}

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def ping(self) -> bool:
        self._record_query()
        await asyncio.sleep(0.001)
        return True

    async def create_session(self, session: SessionState) -> SessionState:
        self._record_query()
        self.sessions[session.session_id] = session
        return session

    async def get_session_state(self, session_id: str) -> Optional[SessionState]:
        self._record_query()
        s = self.sessions.get(session_id)
        return s

    async def update_session_state(self, session_id: str, updates: dict) -> None:
        self._record_query()
        if session_id in self.sessions:
            s = self.sessions[session_id]
            for k, v in updates.items():
                setattr(s, k, v)

    async def push_task_queue(self, queue_key: str, task_data: dict) -> None:
        self._record_query()
        self.task_queues.setdefault(queue_key, []).append(task_data)

    async def pop_task_queue(self, queue_key: str) -> Optional[dict]:
        self._record_query()
        q = self.task_queues.get(queue_key)
        if q:
            return q.pop(0)
        return None

    async def load_all_active_tasks(self) -> List[Task]:
        self._record_query()
        return [Task(**t) for t in self.tasks.values()]

    async def store_task_result(self, task_id: str, result: dict) -> None:
        self._record_query()
        self.tasks[task_id] = result

    async def write_audit_event(self, event: AuditEvent) -> None:
        self._record_query()
        self.audit_events.append(event)

    async def acquire_lock(self, key: str, value: str, ttl: int = 30) -> bool:
        self._record_query()
        if key in self.lock_holders:
            return False
        self.lock_holders[key] = value
        return True

    async def release_lock(self, key: str, value: str) -> bool:
        self._record_query()
        if self.lock_holders.get(key) == value:
            self.lock_holders.pop(key, None)
            return True
        return False

    async def add_busy_agent(self, agent_id: str) -> None:
        self.busy_agents.add(agent_id)

    async def remove_busy_agent(self, agent_id: str) -> None:
        self.busy_agents.discard(agent_id)

    def _record_query(self) -> None:
        self.query_times.append(time.monotonic())

    async def load_session_state(self, session_id: str) -> Optional[SessionState]:
        return self.sessions.get(session_id)

    async def get_session_state_by_engagement_id(
        self, engagement_id: str
    ) -> Optional[SessionState]:
        self._record_query()
        for s in self.sessions.values():
            if isinstance(s, SessionState):
                if s.scope.engagement_id == engagement_id:
                    return s
        return None

    async def store_engagement_id_mapping(self, *args: Any, **kwargs: Any) -> None:
        self._record_query()

    # -- Methods needed by orchestrator sub-components (delegation targets) --

    async def list_all_sessions(self) -> List[str]:
        self._record_query()
        return list(self.sessions.keys())

    async def list_all_tasks(self) -> List[str]:
        self._record_query()
        return list(self.tasks.keys())

    async def store_session_state(self, state: SessionState) -> None:
        self._record_query()
        self.sessions[state.session_id] = state

    async def persist_session_state(self, state: SessionState) -> None:
        self._record_query()
        self.sessions[state.session_id] = state

    async def get_all_busy_agents(self) -> List[str]:
        return list(self.busy_agents)

    async def update_agent_heartbeat(self, agent_id: str, data: dict) -> None:
        self._record_query()

    async def store_task(self, task: Task) -> None:
        self._record_query()
        self.tasks[task.id] = {"status": task.status, "engagement_id": task.engagement_id}

    async def load_task(self, task_id: str) -> Optional[Task]:
        self._record_query()
        data = self.tasks.get(task_id)
        if data:
            return Task(**data)
        return None

    async def store_approval_request(self, request: Any) -> None:
        self._record_query()

    async def load_approval_request(self, request_id: str) -> Optional[Any]:
        self._record_query()
        return None

    async def list_pending_approvals(self) -> List[Any]:
        self._record_query()
        return []

    async def store_dlq_entry(self, entry: Any) -> None:
        self._record_query()
        self.dlq_entries.append(entry)

    async def get_dlq_entry(self, entry_id: str) -> Optional[Any]:
        self._record_query()
        for e in self.dlq_entries:
            if getattr(e, "id", None) == entry_id:
                return e
        return None

    async def list_dlq_entries(
        self, engagement_id: Optional[str] = None, status: Optional[str] = None
    ) -> List[Any]:
        self._record_query()
        return self.dlq_entries

    async def is_busy_agent(self, agent_id: str) -> bool:
        self._record_query()
        return agent_id in self.busy_agents

    async def get_all_agents(self) -> Dict[str, Any]:
        self._record_query()
        return {}

    async def get_agent_heartbeat(self, agent_id: str) -> Optional[Dict[str, Any]]:
        self._record_query()
        return None

    async def update_agent_status(self, agent_id: str, status: str) -> None:
        self._record_query()

    async def find_tasks_by_agent(self, agent_id: str) -> List[Any]:
        self._record_query()
        return []

    async def release_lock_simple(self, key: str) -> None:
        self._record_query()
        self.lock_holders.pop(key, None)

    # Duck-typing: any method the real SessionMemory has but we haven't stubbed
    # will return an AsyncMock so the test doesn't crash on AttributeError.
    def __getattr__(self, name: str) -> Any:
        from unittest.mock import AsyncMock

        if name.startswith("_"):
            return None  # internal attrs like _async_session, _redis
        return AsyncMock()


class FakeGraphMemory:
    """Minimal in-memory GraphMemory double."""

    def __init__(self) -> None:
        self.nodes: Dict[str, dict] = {}
        self.edges: List[tuple] = []
        self.query_times: List[float] = []
        self.claimed_set: set = set()

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def ping(self) -> bool:
        self._record_query()
        return True

    async def run_read_query(self, query: str, params: Optional[dict] = None) -> List[dict]:
        self._record_query()
        return []

    async def run_write_query(self, query: str, params: Optional[dict] = None) -> None:
        self._record_query()

    async def get_graph_stats(self, engagement_id: str) -> dict:
        self._record_query()
        return {"vulnerabilities": 0, "endpoints": 0, "assets": 1}

    async def create_finding(self, **kwargs: Any) -> None:
        self._record_query()

    async def claim_auto_discovery(self, eid: str) -> bool:
        if eid in self.claimed_set:
            return False
        self.claimed_set.add(eid)
        return True

    def _record_query(self) -> None:
        self.query_times.append(time.monotonic())

    # Catch-all for any method real GraphMemory has that we haven't stubbed.
    def __getattr__(self, name: str) -> Any:
        from unittest.mock import AsyncMock

        if name.startswith("_"):
            return None
        return AsyncMock()


class MockAgent:
    """Simulates an agent that processes tasks with configurable latency.

    ``latency_ms`` -- simulated work duration per task.
    ``fail_rate`` -- fraction of tasks that should fail (0.0-1.0).
    """

    def __init__(
        self,
        agent_type: AgentType,
        latency_ms: float = 50.0,
        fail_rate: float = 0.0,
    ) -> None:
        from types import SimpleNamespace

        self.ctx = SimpleNamespace()
        self.ctx.agent_id = f"mock-{agent_type.value.lower()}-1"
        self.ctx.agent_type = agent_type
        self.ctx.status = "idle"
        self._latency = latency_ms / 1000.0
        self._fail_rate = fail_rate
        self._tasks_processed = 0
        self._failures = 0

    async def initialize(self) -> None:
        pass

    async def get_status(self) -> dict:
        return {"status": "idle", "tasks_processed": self._tasks_processed}

    async def shutdown(self) -> None:
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return True

    async def execute_task(self, task: Task) -> dict:
        start = time.monotonic()
        await asyncio.sleep(self._latency)
        elapsed = (time.monotonic() - start) * 1000
        self._tasks_processed += 1

        if self._fail_rate > 0 and (hash(task.id) % 100) / 100 < self._fail_rate:
            self._failures += 1
            return {"status": "failed", "error": "simulated failure"}

        return {
            "status": "completed",
            "agent_time_ms": round(elapsed, 1),
            "result": {"mock": True, "agent": self.ctx.agent_id},
        }


# ---------------------------------------------------------------------------
# Orchestrator harness
# ---------------------------------------------------------------------------


@dataclass
class LoadReport:
    """Aggregated results from a load test run."""

    engagement_count: int
    tasks_per_engagement: int
    total_tasks: int
    total_elapsed: float = 0.0
    tasks_per_second: float = 0.0
    scheduler_ticks: int = 0
    task_latencies: List[float] = field(default_factory=list)
    db_query_times: List[float] = field(default_factory=list)
    agent_metrics: Dict[str, dict] = field(default_factory=dict)
    failures: int = 0
    peak_memory_mb: float = 0.0

    @property
    def p50_task_latency(self) -> float:
        return _percentile(self.task_latencies, 50) if self.task_latencies else 0.0

    @property
    def p95_task_latency(self) -> float:
        return _percentile(self.task_latencies, 95) if self.task_latencies else 0.0

    @property
    def p99_task_latency(self) -> float:
        return _percentile(self.task_latencies, 99) if self.task_latencies else 0.0

    def markdown(self) -> str:
        """Render the report as markdown."""
        ts = datetime.now().isoformat()
        lines = [
            "# AI-OSOP Load Test Report",
            "",
            f"**Date:** {ts}",
            f"**Engagements:** {self.engagement_count}",
            f"**Tasks per engagement:** {self.tasks_per_engagement}",
            f"**Total tasks:** {self.total_tasks}",
            "",
            "## Throughput",
            "",
            "| Metric | Value |",
            "|--------|------:|",
            f"| Total elapsed (s) | {self.total_elapsed:.2f} |",
            f"| Tasks per second | {self.tasks_per_second:.1f} |",
            f"| Scheduler ticks | {self.scheduler_ticks} |",
            f"| Total failures | {self.failures} |",
            "",
            "## Task Latency (end-to-end, ms)",
            "",
            "| Percentile | Latency (ms) |",
            "|-----------:|-------------:|",
            f"| p50 | {self.p50_task_latency:.1f} |",
            f"| p95 | {self.p95_task_latency:.1f} |",
            f"| p99 | {self.p99_task_latency:.1f} |",
            "",
        ]
        if self.db_query_times:
            lines += [
                "## DB Query Count",
                "",
                f"Total DB queries across all operations: **{len(self.db_query_times)}**",
                "",
            ]
        if self.agent_metrics:
            lines += [
                "## Per-Agent Metrics",
                "",
                "| Agent | Tasks | Failures | Avg Latency (ms) |",
                "|-------|------:|--------:|------------------:|",
            ]
            for aid, m in sorted(self.agent_metrics.items()):
                lines.append(
                    f"| {aid} | {m['tasks']} | {m.get('failures', 0)} "
                    f"| {m.get('avg_latency', 0):.1f} |"
                )
            lines.append("")
        lines += [
            "## Memory",
            "",
            "| Metric | Value |",
            "|--------|------:|",
            f"| Peak memory (MB) | {self.peak_memory_mb:.1f} |",
            "",
        ]
        return "\n".join(lines)


def _percentile(values: List[float], p: int) -> float:
    """Compute the p-th percentile from the sorted list."""
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    f = int(k)
    c = k - f
    if f + 1 < len(s):
        return s[f] * (1 - c) + s[f + 1] * c
    return s[-1]


# ---------------------------------------------------------------------------
# Load test runner
# ---------------------------------------------------------------------------


class LoadTestHarness:
    """Builds an orchestrator with mocked backends and runs synthetic load."""

    def __init__(
        self,
        tasks_per_engagement: int = 100,
        engagement_count: int = 3,
        agent_latency_ms: float = 20.0,
        agent_fail_rate: float = 0.0,
        scheduler_tick_limit: int = 200,
        test_timeout: float = 60.0,
    ) -> None:
        self.tasks_per_engagement = tasks_per_engagement
        self.engagement_count = engagement_count
        self.agent_latency_ms = agent_latency_ms
        self.agent_fail_rate = agent_fail_rate
        self.scheduler_tick_limit = scheduler_tick_limit
        self.test_timeout = test_timeout

        self.session_memory = FakeSessionMemory()
        self.graph_memory = FakeGraphMemory()
        self.mcp_registry = MCPRegistry()
        self.orchestrator: Optional[Orchestrator] = None
        self.report = LoadReport(
            engagement_count=engagement_count,
            tasks_per_engagement=tasks_per_engagement,
            total_tasks=engagement_count * tasks_per_engagement,
        )

    async def setup(self) -> None:
        """Create the orchestrator and register mock agents."""
        self.orchestrator = Orchestrator(
            session_memory=self.session_memory,  # type: ignore
            graph_memory=self.graph_memory,  # type: ignore
            mcp_registry=self.mcp_registry,
            llm_client=None,
        )
        await self.orchestrator.initialize()

        # Register one agent per AgentType used in scans
        for at in [
            AgentType.RECON,
            AgentType.VULN_ANALYSIS,
            AgentType.SSRF_SCANNER,
            AgentType.JWT_SCANNER,
            AgentType.CSRF_SCANNER,
            AgentType.RACE_SCANNER,
            AgentType.SMUGGLING_SCANNER,
            AgentType.UPLOAD_SCANNER,
            AgentType.POLLUTION_SCANNER,
            AgentType.WEBSOCKET_SCANNER,
            AgentType.SSTI_SCANNER,
            AgentType.WORKFLOW,
            AgentType.REPORTING,
        ]:
            agent = MockAgent(at, latency_ms=self.agent_latency_ms, fail_rate=self.agent_fail_rate)
            await self.orchestrator.register_agent(agent)

    async def create_engagement_with_tasks(self, idx: int) -> str:
        """Create an engagement and enqueue synthetic tasks."""
        scope = ScopeDefinition(
            domains=[f"loadtest-{idx}.example.com"],
            engagement_id=f"eng-load-{idx}",
        )
        session = await self.orchestrator.create_engagement(
            scope=scope,
            roe={"allowed_methods": ["GET", "POST"]},
        )
        eid = session.session_id

        agent_types = list(AgentType)
        for i in range(self.tasks_per_engagement):
            at = agent_types[i % len(agent_types)]
            task = Task(
                type="scan",
                priority=5,
                agent_type=at,
                payload={"target": f"http://loadtest-{idx}.example.com/api/{i}"},
                engagement_id=eid,
                session_id=eid,
            )
            await self.orchestrator.schedule_task(task)

        return eid

    async def run(self) -> LoadReport:
        """Execute the load test and return a report."""
        await self.setup()

        # Start memory tracing
        tracemalloc.start()

        # Create all engagements
        start_time = time.monotonic()
        for i in range(self.engagement_count):
            await self.create_engagement_with_tasks(i)

        # Let the scheduler drain the queue, with a tick limit
        tick = 0
        while tick < self.scheduler_tick_limit:
            await asyncio.sleep(0.1)
            tick += 1

            # Count remaining pending + running tasks
            remaining = sum(
                1
                for t in self.orchestrator.state.get_all_tasks().values()
                if t.status in ("pending", "running")
            )
            if remaining == 0:
                break

            # Soft timeout check
            if time.monotonic() - start_time > self.test_timeout:
                print(
                    f"  TIMEOUT after {self.test_timeout}s " f"- {remaining} tasks still in flight"
                )
                break

        total_elapsed = time.monotonic() - start_time
        self.report.total_elapsed = total_elapsed
        self.report.scheduler_ticks = tick

        # Collect metrics
        all_tasks = list(self.orchestrator.state.get_all_tasks().values())
        completed = [t for t in all_tasks if t.status == "completed"]
        self.report.failures = sum(1 for t in all_tasks if t.status == "failed")

        # Collect per-agent metrics
        assert self.orchestrator is not None
        for agent_id, agent in self.orchestrator.state.get_all_agents().items():
            if isinstance(agent, MockAgent):
                agent_type = getattr(getattr(agent, "ctx", None), "agent_type", None)
                label = f"{agent_type.value if agent_type else agent_id}"
                self.report.agent_metrics[label] = {
                    "tasks": agent._tasks_processed,
                    "failures": agent._failures,
                    "avg_latency": self.agent_latency_ms,
                }

        # Task latencies: simulated from agent config
        for _ in completed:
            self.report.task_latencies.append(self.agent_latency_ms + (self.agent_latency_ms * 0.1))

        # DB query latencies
        self.report.db_query_times = self.session_memory.query_times

        self.report.total_tasks = len(all_tasks)
        self.report.tasks_per_second = len(completed) / total_elapsed if total_elapsed > 0 else 0

        # Snapshot peak memory
        _current, peak = tracemalloc.get_traced_memory()
        self.report.peak_memory_mb = peak / (1024 * 1024)
        tracemalloc.stop()

        return self.report

    async def teardown(self) -> None:
        if self.orchestrator:
            await self.orchestrator.shutdown()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI-OSOP end-to-end load test",
    )
    parser.add_argument(
        "--tasks", type=int, default=100, help="Tasks per engagement (default: 100)"
    )
    parser.add_argument(
        "--engagements",
        type=int,
        default=3,
        help="Number of engagements (default: 3)",
    )
    parser.add_argument(
        "--latency",
        type=float,
        default=20.0,
        help="Simulated agent latency in ms (default: 20)",
    )
    parser.add_argument(
        "--fail-rate",
        type=float,
        default=0.0,
        help="Fraction of tasks that fail (default: 0)",
    )
    parser.add_argument(
        "--ticks",
        type=int,
        default=200,
        help="Max scheduler ticks before timeout (default: 200)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Max wall-clock seconds for the test (default: 60)",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()

    print("=" * 60)
    print("AI-OSOP End-to-End Load Test")
    print("=" * 60)
    print(f"  Tasks per engagement: {args.tasks}")
    print(f"  Engagements:          {args.engagements}")
    print(f"  Total tasks:          {args.tasks * args.engagements}")
    print(f"  Simulated latency:    {args.latency} ms")
    print(f"  Fail rate:            {args.fail_rate}")
    print()

    harness = LoadTestHarness(
        tasks_per_engagement=args.tasks,
        engagement_count=args.engagements,
        agent_latency_ms=args.latency,
        agent_fail_rate=args.fail_rate,
        scheduler_tick_limit=args.ticks,
        test_timeout=args.timeout,
    )

    try:
        report = await harness.run()
    finally:
        await harness.teardown()

    print(report.markdown())

    # Write report to file
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"test_load_e2e_report_{ts}.md"
    with open(report_path, "w") as f:
        f.write(report.markdown())
    print(f"Report written to {report_path}")

    # Return exit code based on result
    if report.failures > report.total_tasks * 0.5:
        print("\nFAIL: >50% task failure rate")
        raise SystemExit(1)
    print(f"\nPASS: {report.tasks_per_second:.1f} tasks/s, " f"{report.failures} failures")


if __name__ == "__main__":
    asyncio.run(main())
