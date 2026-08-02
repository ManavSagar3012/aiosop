"""Unit tests for graph_integrity_checker and orchestrator wiring.

Pins the Phase-1 issue #4 fix: ``graph_integrity_checker`` was previously a
CLI-only script. The orchestrator now runs it on a background loop so schema
drift is detected at runtime and self-heals by archiving orphans.

These tests are hermetic — no Neo4j. The graph is stubbed with a recording
double whose ``run_read_query`` returns canned counts.
"""

from __future__ import annotations

from typing import Dict, List
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory import graph_integrity_checker as gic


class _FakeGraph:
    """Records queries; returns canned counts per orphan key."""

    def __init__(self, counts: Dict[str, int], archived_rows: List[dict] | None = None):
        self._counts = counts
        self._archived_rows = archived_rows or []
        self.read_queries: List[str] = []
        self.write_queries: List[str] = []
        # Track write calls so cleanup tests can assert them.
        self.cleanup_calls = 0

    async def run_read_query(self, cypher: str, params=None):
        self.read_queries.append(cypher)
        # Match the canned count by inspecting which orphan key the query
        # belongs to. Each query starts with MATCH (label) and ends with a
        # count; we just key off the label.
        low = cypher.lower()
        for key, q in gic._ORPHAN_QUERIES.items():
            if cypher.strip().split("\n")[1].strip() == q.strip().split("\n")[1].strip():
                return [{"c": self._counts.get(key, 0)}]
        # Archived-nodes summary query.
        if "archived = true" in low and "labels(n)" in low:
            return self._archived_rows
        return [{"c": 0}]

    async def run_write_query(self, cypher: str, params=None):
        self.write_queries.append(cypher)
        self.cleanup_calls += 1
        return [{"cleaned_count": self._counts.get("_cleaned", 1)}]


# --------------------------------------------------------------------------- #
# run_integrity_check                                                         #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_clean_graph_returns_zero_total():
    gm = _FakeGraph(counts={k: 0 for k in gic._ORPHAN_QUERIES})
    report = await gic.run_integrity_check(gm, emit_prints=False)
    assert report["total_issues"] == 0
    assert report["orphan_vulnerabilities"] == 0
    assert report["ghost_workflows"] == 0
    assert report["archived_node_groups"] == 0


@pytest.mark.asyncio
async def test_orphan_counts_aggregate_into_total():
    gm = _FakeGraph(counts={
        "ghost_workflows": 2,
        "orphan_vulnerabilities": 5,
        "orphan_exploits": 1,
        # others zero
    })
    report = await gic.run_integrity_check(gm, emit_prints=False)
    assert report["ghost_workflows"] == 2
    assert report["orphan_vulnerabilities"] == 5
    assert report["orphan_exploits"] == 1
    assert report["total_issues"] == 8


@pytest.mark.asyncio
async def test_query_failure_records_minus_one_without_crashing():
    """A query that raises must NOT sink the whole check; the failing key
    records -1 so the anomaly is visible rather than silently zero."""

    class _BrokenGraph(_FakeGraph):
        async def run_read_query(self, cypher, params=None):
            if "Vulnerability" in cypher and "count" in cypher.lower():
                raise RuntimeError("simulated driver error")
            return await super().run_read_query(cypher, params)

    gm = _BrokenGraph(counts={k: 0 for k in gic._ORPHAN_QUERIES})
    report = await gic.run_integrity_check(gm, emit_prints=False)
    # The failing query's key is -1 (anomaly sentinel), not 0 (silent success).
    assert report["orphan_vulnerabilities"] == -1
    # Total excludes -1 so a failure does not subtract from real issues.
    assert report["total_issues"] == 0


@pytest.mark.asyncio
async def test_archived_node_groups_aggregated():
    gm = _FakeGraph(
        counts={k: 0 for k in gic._ORPHAN_QUERIES},
        archived_rows=[
            {"labels": ["Vulnerability"], "c": 12},
            {"labels": ["Workflow"], "c": 3},
        ],
    )
    report = await gic.run_integrity_check(gm, emit_prints=False)
    assert report["archived_node_groups"] == 15
    # Archived count is informational; not added to total_issues.
    assert report["total_issues"] == 0


# --------------------------------------------------------------------------- #
# cleanup_orphan_vulnerabilities                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_cleanup_runs_two_write_queries():
    """Cleanup archives orphan Vulnerabilities AND ghost Workflows — two
    separate write queries."""
    gm = _FakeGraph(counts={k: 0 for k in gic._ORPHAN_QUERIES})
    cleaned_v, cleaned_w = await gic.cleanup_orphan_vulnerabilities(gm)
    assert len(gm.write_queries) == 2
    assert "Vulnerability" in gm.write_queries[0]
    assert "Workflow" in gm.write_queries[1]


# --------------------------------------------------------------------------- #
# Orchestrator wiring                                                         #
# --------------------------------------------------------------------------- #


def test_orchestrator_has_graph_integrity_task_attribute():
    """The orchestrator must declare the ``_graph_integrity_task`` slot so
    shutdown can cancel it."""
    from ai_osop.orchestrator.orchestrator import Orchestrator

    # __init__ sets it to None; verify the slot exists.
    src = open(Orchestrator.__module__.replace("ai_osop.orchestrator.orchestrator", "").join([])) if False else None
    # Inspect the source for the slot declaration instead.
    import inspect

    src = inspect.getsource(Orchestrator)
    assert "_graph_integrity_task" in src, (
        "Orchestrator must declare _graph_integrity_task so shutdown cancels it"
    )
    assert "_graph_integrity_loop" in src, (
        "Orchestrator must implement _graph_integrity_loop"
    )


def test_orchestrator_shutdown_cancels_graph_integrity_task():
    """shutdown()'s cancellation loop must include _graph_integrity_task."""
    import inspect

    from ai_osop.orchestrator.orchestrator import Orchestrator

    shutdown_src = inspect.getsource(Orchestrator.shutdown)
    assert "_graph_integrity_task" in shutdown_src, (
        "shutdown must cancel _graph_integrity_task alongside the other bg tasks"
    )


def test_orchestrator_initialize_starts_graph_integrity_task():
    """initialize() must create_task the graph-integrity loop."""
    import inspect

    from ai_osop.orchestrator.orchestrator import Orchestrator

    init_src = inspect.getsource(Orchestrator.initialize)
    assert "_graph_integrity_loop" in init_src, (
        "initialize must start _graph_integrity_loop"
    )


def test_config_exposes_graph_integrity_interval():
    """The sweep interval must be configurable via OSOP_GRAPH_INTEGRITY_INTERVAL."""
    from ai_osop.core.config import settings

    assert hasattr(settings, "graph_integrity_check_interval_seconds")
    assert settings.graph_integrity_check_interval_seconds == 600


# --------------------------------------------------------------------------- #
# End-to-end loop behaviour (stubbed graph)                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_graph_integrity_loop_runs_once_then_sleeps(monkeypatch):
    """The loop runs the check, archives if there are orphans, then sleeps
    until the next tick. We assert: (1) check ran, (2) cleanup ran because
    total > 0, (3) loop yielded control via asyncio.sleep."""
    from ai_osop.orchestrator.orchestrator import Orchestrator

    # Stub graph that reports 3 orphan vulnerabilities -> triggers cleanup.
    fake_gm = _FakeGraph(counts={
        "ghost_workflows": 0,
        "orphan_vulnerabilities": 3,
        "orphan_steps": 0,
        "orphan_evidence": 0,
        "orphan_diff_auth_findings": 0,
        "orphan_exploits": 0,
        "orphan_replay_results": 0,
        "orphan_authorization_tests": 0,
        "orphan_workflow_bound_api_endpoints": 0,
    })

    # Build a bare Orchestrator shell — we only call _graph_integrity_loop.
    orch = object.__new__(Orchestrator)
    orch.graph_memory = fake_gm

    # Short-circuit the sleep so the loop iterates once, then exits via CancelledError.
    import asyncio as _asyncio

    sleep_calls: list[float] = []

    real_sleep = _asyncio.sleep

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)
        raise _asyncio.CancelledError

    monkeypatch.setattr(_asyncio, "sleep", fake_sleep)

    # Patch the loop's settings read so it always sees a fixed interval.
    from ai_osop.core import config as _cfg
    monkeypatch.setattr(_cfg.settings, "graph_integrity_check_interval_seconds", 600, raising=False)

    with pytest.raises(_asyncio.CancelledError):
        await orch._graph_integrity_loop()

    # Restore asyncio.sleep for any teardown.
    monkeypatch.setattr(_asyncio, "sleep", real_sleep)

    # The check ran once (at least one read query was issued).
    assert len(fake_gm.read_queries) >= len(gic._ORPHAN_QUERIES)
    # Cleanup ran because total_issues > 0.
    assert fake_gm.cleanup_calls == 2  # Vulnerabilities + Workflows
    # Loop yielded control via asyncio.sleep(interval).
    assert sleep_calls == [600]
