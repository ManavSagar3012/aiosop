"""AIOSOP-DEPEDGE-001: task dependencies must persist as SPAWNED graph edges.

Regression: ``TaskScheduler._persist_task_dependency`` called the nonexistent
``graph_memory.link_task_dependency``. The call raised AttributeError every
time — the live trigger is the EXPLOITATION phase entry at phase_monitor.py:1127,
where ``engagement_manager.transition_phase`` catches the hook failure, reverts
the in-memory phase, and raises WorkflowException (a phase transition that then
appears to "fail" for no visible reason). The fix reuses the exact parameterized
``run_write_query`` MERGE that ``_chain_authenticated_surface`` already uses for
the same parent→child edge, so the durable edge survives and a Neo4j blip can
never break task scheduling.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.task_scheduler import TaskScheduler


def _task(**kw) -> Task:
    defaults = dict(
        type="exploit_validation",
        agent_type=AgentType.EXPLOIT_VALIDATION,
        priority=9,
        engagement_id="eng-1",
    )
    defaults.update(kw)
    return Task(**defaults)


@pytest.mark.asyncio
async def test_persist_task_dependency_writes_spawned_edge_via_run_write_query():
    """The dependency persists through the generic Cypher writer (MERGE SPAWNED),
    matching the reader get_task_dependents and the _chain_authenticated_surface
    writer — not a call to a nonexistent graph_memory method."""
    parent = _task(id="parent-1")
    child = _task(id="child-1")
    graph = MagicMock()
    graph.run_write_query = AsyncMock(return_value=[])
    orch = MagicMock(graph_memory=graph)
    sched = TaskScheduler.__new__(TaskScheduler)
    sched._orch = orch

    await sched._persist_task_dependency(parent, child)

    graph.run_write_query.assert_awaited_once()
    cypher, params = graph.run_write_query.await_args.args
    assert "SPAWNED" in cypher and "MERGE" in cypher
    assert params["parent_id"] == "parent-1"
    assert params["child_id"] == "child-1"


@pytest.mark.asyncio
async def test_persist_task_dependency_swallows_graph_failure():
    """A Neo4j blip must not propagate out of the dependency persistence — the
    caller (phase monitor / engagement manager) treats it as best-effort."""
    parent = _task(id="parent-1")
    child = _task(id="child-1")
    graph = MagicMock()
    graph.run_write_query = AsyncMock(side_effect=RuntimeError("neo4j down"))
    orch = MagicMock(graph_memory=graph)
    sched = TaskScheduler.__new__(TaskScheduler)
    sched._orch = orch

    # Must not raise.
    await sched._persist_task_dependency(parent, child)
    graph.run_write_query.assert_awaited_once()


@pytest.mark.asyncio
async def test_persist_task_dependency_is_idempotent_merge():
    """Repeated persistence of the same pair reuses MERGE (never creates a
    second edge) — the exact shape get_task_dependents reads back."""
    parent = _task(id="parent-1")
    child = _task(id="child-1")
    graph = MagicMock()
    graph.run_write_query = AsyncMock(return_value=[])
    orch = MagicMock(graph_memory=graph)
    sched = TaskScheduler.__new__(TaskScheduler)
    sched._orch = orch

    await sched._persist_task_dependency(parent, child)
    await sched._persist_task_dependency(parent, child)

    assert graph.run_write_query.await_count == 2
    cypher, _ = graph.run_write_query.await_args.args
    # MERGE (not CREATE) keeps the second write idempotent.
    assert cypher.count("MERGE") == 1 and "CREATE" not in cypher
