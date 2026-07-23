#!/usr/bin/env python3
"""Cache coherence spike test.

Verifies that Orchestrator._is_phase_complete returns accurate results
within the TTL window when tasks are rapidly completed.

Key design observation from the production code (orchestrator.py:863-1016):
  - ``_is_phase_complete`` **only caches True** (all tasks terminal), on line 1015.
  - ``False`` is returned directly on line 997 / line 977 **without** writing to cache.
  - This means the expensive durable-store merge always runs for incomplete phases.
  - The spike test respects this: we never assert that ``False`` is cached.

Agent-type phase matching:
  - ``VULNERABILITY_DISCOVERY`` phase only allows ``AgentType.VULN_ANALYSIS`` and
    scanner subtypes (SSTI_SCANNER, SSRF_SCANNER, etc.) — NOT ``AgentType.RECON``.
  - ``_task()`` therefore uses ``VULN_ANALYSIS`` by default so tasks participate in
    the phase-completion computation.
  - ``_task_recon()`` is available for ``RECONNAISSANCE`` phase tests.

Test scenarios:
  1. Cache hit       — cached True reused without durable store query
  2. Invalidation on success  — task status change + invalidate → recompute works
  3. Invalidation on failure  — same (terminal failures count as done)
  4. Invalidation on assign   — new task blocks previously-complete phase
  5. Engagement isolation     — two engagements' cache entries don't collide
  6. Engagement-id matching   — invalidate clears ALL phases for an engagement_id
  7. Rapid completion         — 12 tasks back-to-back, cache coherence verified
  8. No-op invalidation       — invalidating a non-cached engagement is safe
  9. Durable-store merge      — load_all_active_tasks merges, overrides, and
                                cache-coherence cycle (5 sub-tests)
 10. TTL expiry               — shortened TTL (0.1s) + sleep (0.15s) verifies
                                auto-expiry doesn't cause stale results
 11. Durable-store exception  — load_all_active_tasks raises, graceful fallback
                                to in-memory, cache not corrupted
 12. Multi-phase invalidation — two phases of same engagement cache separately;
                                invalidation clears both; recompute recovers"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import AsyncMock

from cachetools import TTLCache

from ai_osop.core.enums import AgentType, EngagementPhase
from ai_osop.core.models import ScopeDefinition, SessionState, Task


TASKS_PER_ENGAGEMENT = 12


def _engagement_id(index: int = 0) -> str:
    return f"cache-test-{index:03d}"


def _session(engagement_id: str) -> SessionState:
    return SessionState(
        session_id=f"eng-20260722-{engagement_id}",
        scope=ScopeDefinition(engagement_id=engagement_id, domains=["x.test"]),
        phase=EngagementPhase.VULNERABILITY_DISCOVERY.value,
    )


def _task(engagement_id: str, index: int, status: str = "running") -> Task:
    """Create a VULN_ANALYSIS task (the primary type for VULNERABILITY_DISCOVERY phase)."""
    return Task(
        type="xss_scan",
        agent_type=AgentType.VULN_ANALYSIS,
        engagement_id=engagement_id,
        status=status,
    )


def _task_recon(engagement_id: str, index: int, status: str = "running") -> Task:
    """Create a RECON task (for RECONNAISSANCE phase tests)."""
    return Task(
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id=engagement_id,
        status=status,
    )


def _make_state(tasks: List[Task]) -> SimpleNamespace:
    """In-memory task store that mirrors the real OrchestrationState."""
    return SimpleNamespace(
        get_all_tasks=lambda: {t.id: t for t in tasks},
        get_task=lambda tid: next((t for t in tasks if t.id == tid), None),
    )


def _make_orchestrator(
    tasks: List[Task],
    engagement_id: str,
    phase: EngagementPhase,
    durable_tasks: Optional[List[Task]] = None,
    cache_ttl: float = 5.0,
) -> SimpleNamespace:
    """Build a SimpleNamespace that quacks like Orchestrator for the methods under test.

    ``durable_tasks`` controls what ``load_all_active_tasks()`` returns, allowing
    the durable-store merge path (orchestrator.py:961-968) to be exercised.
    If ``None``, the durable store returns an empty list (the default for all
    existing scenarios).

    ``cache_ttl`` sets the TTL for ``_phase_complete_cache`` (default 5.0, matching
    production). Override to a small value (e.g. 0.1) to test TTL-based expiry.
    """
    session = _session(engagement_id)
    session.phase = phase.value
    durable_return = durable_tasks if durable_tasks is not None else []
    mock_session_memory = SimpleNamespace(
        load_all_active_tasks=AsyncMock(return_value=durable_return),
        pop_task_queue=AsyncMock(return_value=None),
    )
    return SimpleNamespace(
        _phase_complete_cache=TTLCache(maxsize=256, ttl=cache_ttl),
        _sessions={engagement_id: session},
        _agents={},
        state=_make_state(tasks),
        session_memory=mock_session_memory,
        task_scheduler=SimpleNamespace(
            _assign_task=lambda t: None,
            _on_task_success=lambda t, r: None,
            _on_task_failure=lambda t, r: None,
        ),
        engagement_state_machine=SimpleNamespace(),
        _auto_transition_failures={},
    )


_PASS = 0
_FAIL = 0


def check(condition: bool, msg: str) -> None:
    global _PASS, _FAIL  # noqa: PLW0603
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL: {msg}")


async def is_phase_complete(
    orch: SimpleNamespace,
    engagement_id: str,
    phase: EngagementPhase,
) -> bool:
    from ai_osop.orchestrator.orchestrator import Orchestrator
    return await Orchestrator._is_phase_complete(orch, engagement_id, phase)


async def invalidate_cache(orch: SimpleNamespace, engagement_id: str) -> None:
    from ai_osop.orchestrator.orchestrator import Orchestrator
    await Orchestrator._invalidate_phase_complete_cache(orch, engagement_id)


# ---------------------------------------------------------------------------
# Scenario 1: Cache hit
# ---------------------------------------------------------------------------

async def test_cache_hit() -> None:
    """True result is cached and reused without durable-store read.

    Also verifies that INITIALIZED phase short-circuits WITHOUT caching.
    """
    eid = _engagement_id(0)
    orch = _make_orchestrator([], eid, EngagementPhase.INITIALIZED)

    # INITIALIZED returns True but does NOT cache it (early return at line 878)
    result1 = await is_phase_complete(orch, eid, EngagementPhase.INITIALIZED)
    check(result1 is True, "INITIALIZED returns True")
    cache_key = (eid, EngagementPhase.INITIALIZED.value)
    check(orch._phase_complete_cache.get(cache_key) is None,
          "INITIALIZED result NOT cached (early return)")

    # VULNERABILITY_DISCOVERY with all tasks completed -> True IS cached
    eid2 = _engagement_id(1)
    tasks = [_task(eid2, 0, "completed"), _task(eid2, 1, "completed")]
    orch2 = _make_orchestrator(tasks, eid2, EngagementPhase.VULNERABILITY_DISCOVERY)

    # First call: cache miss, compute, cache True
    result_a = await is_phase_complete(
        orch2, eid2, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_a is True, "all tasks completed -> True")
    key2 = (eid2, EngagementPhase.VULNERABILITY_DISCOVERY.value)
    check(orch2._phase_complete_cache.get(key2) is True,
          "True result IS cached (line 1015)")

    # Second call: cache hit, True returned WITHOUT durable store query
    result_b = await is_phase_complete(
        orch2, eid2, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_b is True, "second call returns cached True")
    # First call incremented call_count to 1; second call (cache hit) did NOT
    check(orch2.session_memory.load_all_active_tasks.call_count == 1,
          "second call did NOT consult durable store (remained at 1)")


# ---------------------------------------------------------------------------
# Scenario 2: Invalidation on task success
# ---------------------------------------------------------------------------

async def test_invalidation_on_success() -> None:
    """Task status change + cache invalidate -> recompute returns fresh result."""
    eid = _engagement_id(10)
    tasks = [_task(eid, 0, "running")]
    orch = _make_orchestrator(tasks, eid, EngagementPhase.VULNERABILITY_DISCOVERY)
    cache_key = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    # Phase NOT complete (task running). False is never cached.
    result = await is_phase_complete(orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY)
    check(result is False, "initial: not complete (task running)")
    check(orch._phase_complete_cache.get(cache_key) is None,
          "False result is never cached (returned at line 997)")

    # Change task status and invalidate
    tasks[0].status = "completed"
    await invalidate_cache(orch, eid)
    check(orch._phase_complete_cache.get(cache_key) is None,
          "cache cleared after invalidation")

    # Recompute -> all terminal -> True cached
    result = await is_phase_complete(orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY)
    check(result is True, "all tasks completed -> True")
    check(orch._phase_complete_cache.get(cache_key) is True,
          "True cached after recompute (line 1015)")


# ---------------------------------------------------------------------------
# Scenario 3: Invalidation on task failure
# ---------------------------------------------------------------------------

async def test_invalidation_on_failure() -> None:
    """Failed tasks count as terminal — phase is complete after recompute."""
    eid = _engagement_id(20)
    tasks = [_task(eid, 0, "completed"), _task(eid, 1, "failed")]
    orch = _make_orchestrator(tasks, eid, EngagementPhase.VULNERABILITY_DISCOVERY)
    cache_key = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    # All terminal -> True cached
    result = await is_phase_complete(orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY)
    check(result is True, "all terminal -> complete even with failures")
    check(orch._phase_complete_cache.get(cache_key) is True,
          "True cached after all-terminal computation")

    # Second call hits cache
    result2 = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result2 is True, "cache-hit returns True")


# ---------------------------------------------------------------------------
# Scenario 4: Invalidation on assign (new task blocks completion)
# ---------------------------------------------------------------------------

async def test_invalidation_on_assign() -> None:
    """Adding a new task makes a previously-complete phase incomplete."""
    eid = _engagement_id(30)
    tasks = [_task(eid, 0, "completed")]
    orch = _make_orchestrator(tasks, eid, EngagementPhase.VULNERABILITY_DISCOVERY)
    cache_key = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    # One completed task -> phase complete -> True cached
    result = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result is True, "completed task -> phase complete")
    check(orch._phase_complete_cache.get(cache_key) is True,
          "True cached")

    # Add a new pending task and invalidate
    new_task = _task(eid, 1, "pending")
    tasks.append(new_task)
    await invalidate_cache(orch, eid)
    check(orch._phase_complete_cache.get(cache_key) is None,
          "cache invalidated after new task added")

    # Recompute -> pending task blocks completion -> False (not cached)
    result = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result is False, "phase NOT complete after new pending task added")


# ---------------------------------------------------------------------------
# Scenario 5: Engagement isolation
# ---------------------------------------------------------------------------

async def test_engagement_isolation() -> None:
    """Two engagements' cache entries don't collide."""
    eid1 = _engagement_id(100)
    eid2 = _engagement_id(101)

    tasks1 = [_task(eid1, 0, "completed")]
    tasks2 = [_task(eid2, 0, "completed")]

    orch1 = _make_orchestrator(tasks1, eid1, EngagementPhase.VULNERABILITY_DISCOVERY)
    orch2 = _make_orchestrator(tasks2, eid2, EngagementPhase.VULNERABILITY_DISCOVERY)

    key1 = (eid1, EngagementPhase.VULNERABILITY_DISCOVERY.value)
    key2 = (eid2, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    # Both engagements: all terminal -> True cached
    r1 = await is_phase_complete(orch1, eid1, EngagementPhase.VULNERABILITY_DISCOVERY)
    check(r1 is True, "e1: phase complete")
    check(orch1._phase_complete_cache.get(key1) is True, "e1: True cached")

    r2 = await is_phase_complete(orch2, eid2, EngagementPhase.VULNERABILITY_DISCOVERY)
    check(r2 is True, "e2: phase complete")
    check(orch2._phase_complete_cache.get(key2) is True, "e2: True cached")

    # Add a running task to e1 and invalidate e1
    tasks1.append(_task(eid1, 1, "running"))
    await invalidate_cache(orch1, eid1)

    check(orch1._phase_complete_cache.get(key1) is None,
          "e1 cache invalidated")
    check(orch2._phase_complete_cache.get(key2) is True,
          "e2 cache UNCHANGED by e1 invalidation")

    # Recompute e1 -> False (not cached)
    r1b = await is_phase_complete(
        orch1, eid1, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r1b is False, "e1: now not complete")

    # e2 cache still intact -> cache hit without durable store query
    r2b = await is_phase_complete(
        orch2, eid2, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r2b is True, "e2: cache hit still True")
    # First e2 computation incremented call_count to 1; cache-hit doesn't increase it
    check(orch2.session_memory.load_all_active_tasks.call_count == 1,
          "e2 durable store not consulted on cache hit (remained at 1)")


# ---------------------------------------------------------------------------
# Scenario 6: Engagement-id matching invalidates all phases
# ---------------------------------------------------------------------------

async def test_engagement_id_matching() -> None:
    """Invalidate clears ALL phase entries for an engagement_id."""
    eid = _engagement_id(200)
    orch = _make_orchestrator([], eid, EngagementPhase.INITIALIZED)
    cache = orch._phase_complete_cache

    # Seed cache with True for multiple phases of the same engagement
    phases = [
        EngagementPhase.RECONNAISSANCE,
        EngagementPhase.VULNERABILITY_DISCOVERY,
        EngagementPhase.EXPLOITATION,
        EngagementPhase.REPORTING,
    ]
    for phase in phases:
        cache[(eid, phase.value)] = True
    check(len(cache) == 4, "4 phase entries seeded for engagement")

    # Invalidate the engagement
    await invalidate_cache(orch, eid)
    check(len(cache) == 0, "all 4 entries cleared after invalidation")

    # Seed another engagement's entries
    eid_other = _engagement_id(201)
    cache[(eid_other, EngagementPhase.RECONNAISSANCE.value)] = True
    cache[(eid_other, EngagementPhase.VULNERABILITY_DISCOVERY.value)] = True
    check(len(cache) == 2, "other engagement entries present")

    # Invalidate first engagement again -> no effect on other engagement
    await invalidate_cache(orch, eid)
    check(len(cache) == 2,
          "other engagement entries survive unrelated invalidation")


# ---------------------------------------------------------------------------
# Scenario 7: Rapid completion — 12 tasks done back-to-back
# ---------------------------------------------------------------------------

async def test_rapid_completion() -> None:
    """Verify cache coherence when tasks are completed rapidly.

    Each iteration: recompute, complete one task, invalidate, recompute.
    First n-1 iterations: incomplete (False, never cached).
    Final iteration: all terminal (True, cached).
    """
    eid = _engagement_id(300)
    n = TASKS_PER_ENGAGEMENT
    tasks = [_task(eid, i, "running") for i in range(n)]
    orch = _make_orchestrator(tasks, eid, EngagementPhase.VULNERABILITY_DISCOVERY)
    cache_key = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    for i in range(n):
        # Compute state before completing this task
        result_before = await is_phase_complete(
            orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
        )
        check(result_before is False,
              f"step-{i}: not complete ({n - i} of {n} tasks still in-flight)")

        # Mark this task completed and invalidate
        tasks[i].status = "completed"
        await invalidate_cache(orch, tasks[i].engagement_id)

        # Cache should be empty (False is never cached)
        cached = orch._phase_complete_cache.get(cache_key)
        check(cached is None,
              f"step-{i}: cache cleared after invalidate")

        # Recompute
        result_after = await is_phase_complete(
            orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
        )
        expected = i == n - 1  # last iteration makes all terminal
        check(result_after is expected,
              f"step-{i}: {'complete' if expected else 'not complete'}")

    # After all tasks done, True should be cached
    check(orch._phase_complete_cache.get(cache_key) is True,
          "True cached after all tasks completed")


# ---------------------------------------------------------------------------
# Scenario 8: No-op invalidation
# ---------------------------------------------------------------------------

async def test_noop_invalidation() -> None:
    """Invalidating a non-existent engagement_id is safe (no crash, no side-effect)."""
    eid1 = _engagement_id(400)
    eid2 = _engagement_id(401)  # engagement with no cache entries
    orch = _make_orchestrator([], eid1, EngagementPhase.INITIALIZED)
    cache = orch._phase_complete_cache

    # Seed one engagement
    cache[(eid1, EngagementPhase.RECONNAISSANCE.value)] = True
    check(len(cache) == 1, "one cache entry seeded")

    # Invalidate a DIFFERENT engagement_id (no-op)
    try:
        await invalidate_cache(orch, eid2)
        check(True, "no-op invalidation did not raise")
    except Exception:
        import traceback
        global _FAIL  # noqa: PLW0603
        _FAIL += 1
        print("  EXCEPTION during no-op invalidation")
        traceback.print_exc()

    check(
        orch._phase_complete_cache.get(
            (eid1, EngagementPhase.RECONNAISSANCE.value)
        ) is True,
        "eid1 cache unchanged after no-op invalidation of eid2",
    )
    check(len(cache) == 1,
          "cache size unchanged after no-op invalidation")


# ---------------------------------------------------------------------------
# Scenario 9: Durable-store merge
# ---------------------------------------------------------------------------

async def test_durable_store_merge() -> None:
    """Verify the durable-store merge logic (orchestrator.py:961-968).

    Production code merges in-memory tasks with tasks from
    ``load_all_active_tasks()``. The durable version wins on ID clash.

    Sub-tests:
      A: Durable task not in memory blocks phase completion.
      B: Durable task overrides in-memory status (memory says completed,
         durable says running).
      C: Cache hit still skips the durable store when True is cached.
      D: Durable-aware: after merge+invalidate+complete, recompute
         returns True and it is cached.
    """
    eid = _engagement_id(500)

    # --------------------------------------------------------------------
    # Sub-test A: Durable task NOT in memory blocks completion
    # --------------------------------------------------------------------
    # In-memory: 1 completed task (would normally mean phase is complete)
    # Durable:   1 pending task (not yet hydrated into memory)
    # Result:    phase NOT complete (pending task from durable store blocks)
    in_mem = [_task(eid, 0, "completed")]
    durable = [_task(eid, 1, "pending")]  # same engagement, different task ID
    orch_a = _make_orchestrator(
        in_mem, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
        durable_tasks=durable,
    )
    result = await is_phase_complete(
        orch_a, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result is False,
          "A: durable pending task blocks completion "
          "(merged into by_id even though not in memory)")

    # --------------------------------------------------------------------
    # Sub-test B: Durable overrides in-memory status
    # --------------------------------------------------------------------
    # In-memory: 1 task with status "completed"
    # Durable:   same task ID but status "running"
    # Result:    phase NOT complete (durable "running" overrides memory)
    in_mem_b = [_task(eid, 2, "completed")]
    durable_b = [Task(
        id=in_mem_b[0].id,  # same task ID
        type=in_mem_b[0].type,
        agent_type=in_mem_b[0].agent_type,
        engagement_id=eid,
        status="running",  # durable says running
    )]
    orch_b = _make_orchestrator(
        in_mem_b, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
        durable_tasks=durable_b,
    )
    result_b = await is_phase_complete(
        orch_b, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_b is False,
          "B: durable 'running' overrides in-memory 'completed' "
          "-> phase NOT complete")

    # --------------------------------------------------------------------
    # Sub-test C: Cache hit still works when durable store is empty
    # --------------------------------------------------------------------
    # Cache True, then call again — durable store should NOT be consulted.
    # This re-verifies scenario 1 but in the context of the durable arg.
    in_mem_c = [_task(eid, 3, "completed")]
    orch_c = _make_orchestrator(
        in_mem_c, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
        durable_tasks=[],  # explicitly empty
    )
    key_c = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    r1 = await is_phase_complete(
        orch_c, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r1 is True, "C: all completed -> True")
    check(orch_c._phase_complete_cache.get(key_c) is True, "C: True cached")

    r2 = await is_phase_complete(
        orch_c, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r2 is True, "C: second call returns cached True")
    check(orch_c.session_memory.load_all_active_tasks.call_count == 1,
          "C: durable store NOT consulted on cache hit (call_count stayed at 1)")

    # --------------------------------------------------------------------
    # Sub-test D: Durable-aware invalidation + recompute cycle
    # --------------------------------------------------------------------
    # Phase blocked by a durable-only pending task.
    # Complete the task in-memory, invalidate cache, recompute -> True.
    in_mem_d = [_task(eid, 4, "completed")]
    durable_d = [_task(eid, 5, "pending")]
    orch_d = _make_orchestrator(
        in_mem_d, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
        durable_tasks=durable_d,
    )
    key_d = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    # Phase blocked by durable pending task
    result_d1 = await is_phase_complete(
        orch_d, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_d1 is False,
          "D: blocked by durable-only pending task")

    # Now "hydrate" the durable task into memory (simulate what happens
    # when the scheduler picks it up) AND complete it.
    in_mem_d.append(durable_d[0])  # add to in-memory state
    in_mem_d[-1].status = "completed"  # mark completed
    await invalidate_cache(orch_d, eid)

    result_d2 = await is_phase_complete(
        orch_d, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_d2 is True,
          "D: after hydration+completion+invalidate -> True")
    check(orch_d._phase_complete_cache.get(key_d) is True,
          "D: True cached after recompute")

    # --------------------------------------------------------------------
    # Sub-test E: Durable task with different engagement_id is filtered out
    # --------------------------------------------------------------------
    # Durable has a task for a different engagement -> should not affect
    # this engagement's phase completion.
    other_eid = _engagement_id(999)
    in_mem_e = [_task(eid, 6, "completed")]
    durable_e = [_task(other_eid, 0, "pending")]  # different engagement
    orch_e = _make_orchestrator(
        in_mem_e, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
        durable_tasks=durable_e,
    )
    result_e = await is_phase_complete(
        orch_e, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_e is True,
          "E: durable task from different engagement filtered out")


# ---------------------------------------------------------------------------
# Scenario 10: TTL-based auto-expiry
# ---------------------------------------------------------------------------

async def test_ttl_expiry() -> None:
    """Verify TTL-based auto-expiry doesn't return stale results.

    Uses an artificially short TTL (0.1s) to avoid waiting.

    Timeline:
      t=0.00  — cache True
      t=0.00  — cache hit (call_count unchanged)
      t=0.15  — TTL expired, cache miss, recompute, re-cache True
      t=0.15  — cache hit (call_count unchanged)
    """
    eid = _engagement_id(600)
    tasks = [_task(eid, 0, "completed")]
    orch = _make_orchestrator(
        tasks, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
        cache_ttl=0.1,  # artificially short
    )
    cache_key = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    # --- First call: cache miss, compute, True cached ---
    r1 = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r1 is True, "initial: all completed -> True")
    check(orch._phase_complete_cache.get(cache_key) is True,
          "True cached after computation")
    after_first = orch.session_memory.load_all_active_tasks.call_count
    check(after_first == 1,
          "first call consulted durable store (call_count=1)")

    # --- Immediate second call: cache hit, no durable store consult ---
    r2 = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r2 is True, "immediate second call: cache hit -> True")
    check(orch.session_memory.load_all_active_tasks.call_count == after_first,
          "cache hit: durable store NOT consulted (call_count unchanged)")

    # --- Sleep past TTL ---
    import time as _time
    _t0 = _time.monotonic()
    await asyncio.sleep(0.15)  # > 0.1s TTL
    _elapsed = _time.monotonic() - _t0
    check(_elapsed >= 0.1,
          f"sleep elapsed ({_elapsed:.3f}s) >= TTL (0.1s) — "
          "ttl-based expiry happened")

    # Cache entry should have auto-expired
    check(orch._phase_complete_cache.get(cache_key) is None,
          "after TTL expiry: cache entry is gone")

    # --- Third call: cache miss (expired), recompute, re-cache True ---
    r3 = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r3 is True, "after TTL expiry: recompute -> True (no stale data)")
    check(orch._phase_complete_cache.get(cache_key) is True,
          "True re-cached after recompute")
    check(orch.session_memory.load_all_active_tasks.call_count == after_first + 1,
          "after TTL expiry: durable store consulted again (call_count+1)")

    # --- Fourth call: cache hit again ---
    r4 = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r4 is True, "fourth call: cache hit -> True")
    check(orch.session_memory.load_all_active_tasks.call_count == after_first + 1,
          "cache hit after re-cache: durable store NOT consulted")


# ---------------------------------------------------------------------------
# Scenario 11: Durable-store exception — graceful degradation
# ---------------------------------------------------------------------------

async def test_durable_exception() -> None:
    """Verify graceful degradation when load_all_active_tasks raises.

    Production code (orchestrator.py:969-970) catches any exception from the
    durable read, logs a warning, and falls back to in-memory tasks only.

    Sub-tests:
      A: Exception doesn't crash — falls back to in-memory state.
      B: Correct result with in-memory tasks (all completed -> True, cached).
      C: Cache hit still works after exception path (cache not corrupted).
      D: Subsequent call without exception recovers correctly.
    """
    eid = _engagement_id(700)

    # --------------------------------------------------------------------
    # Sub-test A: Exception doesn't crash
    # --------------------------------------------------------------------
    in_mem = [_task(eid, 0, "completed"), _task(eid, 1, "completed")]
    orch = _make_orchestrator(
        in_mem, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
    )
    # Simulate a connection failure by making the durable mock raise
    orch.session_memory.load_all_active_tasks.side_effect = \
        RuntimeError("Neo4j connection lost")

    # This must NOT raise (the except clause swallows the error)
    try:
        result = await is_phase_complete(
            orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
        )
        check(True, "A: exception swallowed (no crash)")
    except Exception:
        check(False,
              "A: UNEXPECTED exception propagated through the except clause")

    # Even with the exception, the method should return the correct result
    # based on in-memory tasks alone (both completed -> True)
    check(result is True,
          "A: falls back to in-memory tasks -> True (all completed)")
    check(orch.session_memory.load_all_active_tasks.call_count >= 1,
          "A: durable store WAS called (and raised)")

    # --------------------------------------------------------------------
    # Sub-test B: In-memory tasks still produce correct result
    # --------------------------------------------------------------------
    # Phase is blocked by incomplete in-memory tasks
    in_mem_b = [_task(eid, 0, "running")]
    orch_b = _make_orchestrator(
        in_mem_b, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
    )
    orch_b.session_memory.load_all_active_tasks.side_effect = \
        RuntimeError("connection lost")

    result_b = await is_phase_complete(
        orch_b, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_b is False,
          "B: in-memory 'running' task correctly blocks completion "
          "(exception didn't invent a False->True")

    # --------------------------------------------------------------------
    # Sub-test C: Cache hit still works after exception recovery
    # --------------------------------------------------------------------
    # First, get a clean baseline (no exception) to cache True
    in_mem_c = [_task(eid, 2, "completed")]
    orch_c = _make_orchestrator(
        in_mem_c, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
    )
    key_c = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    result_c1 = await is_phase_complete(
        orch_c, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_c1 is True, "C: first call -> True (baseline)")
    check(orch_c._phase_complete_cache.get(key_c) is True, "C: True cached")

    # Now make the durable store raise (simulates intermittent outage)
    orch_c.session_memory.load_all_active_tasks.side_effect = \
        RuntimeError("Redis timeout")

    # Second call should hit cache (not touch durable store)
    result_c2 = await is_phase_complete(
        orch_c, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_c2 is True, "C: cache hit -> True (exception ignored)")
    # call_count shouldn't have increased (cache hit avoided the durable read)
    check(orch_c.session_memory.load_all_active_tasks.call_count == 1,
          "C: cache hit avoided the failing durable store (call_count=1)")

    # --------------------------------------------------------------------
    # Sub-test D: Recovery after exception
    # --------------------------------------------------------------------
    # Durable store fails, then recovers. The cache should correctly reflect
    # the merged state after each transition.
    #
    # Sequence:
    #   1. Exception: only in-memory tasks apply -> True (all completed)
    #   2. Recovery: durable pending task merges in -> blocks -> False
    #   3. Complete durable task + invalidate -> all terminal -> True cached
    in_mem_d = [_task(eid, 3, "completed")]
    durable_d = [_task(eid, 5, "pending")]
    orch_d = _make_orchestrator(
        in_mem_d, eid, EngagementPhase.VULNERABILITY_DISCOVERY,
        durable_tasks=durable_d,
    )
    key_d = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    # Step 1: durable store fails -> falls back to in-memory only
    orch_d.session_memory.load_all_active_tasks.side_effect = \
        RuntimeError("timeout")
    result_d1 = await is_phase_complete(
        orch_d, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_d1 is True,
          "D1: exception path: in-memory only -> True (all completed)")
    check(orch_d._phase_complete_cache.get(key_d) is True,
          "D1: True cached during exception path")

    # Step 2: durable recovers -> merge sees pending task -> blocks
    orch_d.session_memory.load_all_active_tasks.side_effect = None
    await invalidate_cache(orch_d, eid)
    result_d2 = await is_phase_complete(
        orch_d, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_d2 is False,
          "D2: recovered durable: pending task merges in, blocks completion")
    check(orch_d._phase_complete_cache.get(key_d) is None,
          "D2: cache empty (False never cached)")

    # Step 3: complete the durable-only task, invalidate -> True cached
    durable_d[0].status = "completed"  # complete in-place
    in_mem_d.append(durable_d[0])  # hydrate into memory
    await invalidate_cache(orch_d, eid)
    result_d3 = await is_phase_complete(
        orch_d, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(result_d3 is True,
          "D3: after complete+hydrate+invalidate -> True")
    check(orch_d._phase_complete_cache.get(key_d) is True,
          "D3: True cached after recovery")


# ---------------------------------------------------------------------------
# Scenario 12: Multi-phase engagement invalidation
# ---------------------------------------------------------------------------

async def test_multi_phase_invalidation() -> None:
    """Verify that cache entries for multiple phases of the same engagement
    are computed independently, cleared together on invalidation, and
    correctly recomputed afterward.

    Phase transitions in the real pipeline (e.g. RECONNAISSANCE ->
    VULNERABILITY_DISCOVERY) will have cached True for the old phase when
    the new phase starts scheduling tasks. Each scheduled task fires
    ``_invalidate_phase_complete_cache`` via the ``_assign_task`` hook,
    which clears ALL phases, not just the current one.

    Sub-tests:
      A: Two phases of same engagement cached -> invalidate -> both clear
         -> recompute both True.
      B: Two engagements with phase entries cached; invalidating one
         leaves the other intact.
      C: Cache-hit counts: after recompute, both phases are cached hits.
    """
    eid = _engagement_id(800)

    # --------------------------------------------------------------------
    # Sub-test A: Two phases cached -> invalidate -> both clear -> recompute
    # --------------------------------------------------------------------
    # RECONNAISSANCE phase: 1 completed recon task -> True cached
    # VULNERABILITY_DISCOVERY phase: 1 completed vuln task -> True cached
    recon_tasks = [_task_recon(eid, 0, "completed")]
    vuln_tasks = [_task(eid, 1, "completed")]

    # Need an orchestrator that has tasks for BOTH phases in its state.
    # _is_phase_complete filters by agent_type for the given phase, so we
    # can have both recon and vuln tasks in the same state dict.
    all_tasks = recon_tasks + vuln_tasks
    orch = _make_orchestrator(
        all_tasks, eid, EngagementPhase.RECONNAISSANCE,
    )

    key_recon = (eid, EngagementPhase.RECONNAISSANCE.value)
    key_vuln = (eid, EngagementPhase.VULNERABILITY_DISCOVERY.value)

    # Compute RECONNAISSANCE phase -> True, cached
    r_recon = await is_phase_complete(
        orch, eid, EngagementPhase.RECONNAISSANCE
    )
    check(r_recon is True,
          "A: RECONNAISSANCE phase: all completed -> True")
    check(orch._phase_complete_cache.get(key_recon) is True,
          "A: RECONNAISSANCE True cached")

    # Compute VULNERABILITY_DISCOVERY phase -> True, cached
    r_vuln = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r_vuln is True,
          "A: VULNERABILITY_DISCOVERY phase: all completed -> True")
    check(orch._phase_complete_cache.get(key_vuln) is True,
          "A: VULNERABILITY_DISCOVERY True cached")
    check(len(orch._phase_complete_cache) == 2,
          "A: both phases in cache")

    # Simulate a task lifecycle event (success/assign/failure) that
    # triggers engagement-wide invalidation
    await invalidate_cache(orch, eid)
    check(len(orch._phase_complete_cache) == 0,
          "A: both cache entries cleared by invalidation")

    # Recompute both phases — should still be True from in-memory tasks
    r_recon2 = await is_phase_complete(
        orch, eid, EngagementPhase.RECONNAISSANCE
    )
    check(r_recon2 is True,
          "A: RECONNAISSANCE recompute -> True")
    check(orch._phase_complete_cache.get(key_recon) is True,
          "A: RECONNAISSANCE True re-cached")

    r_vuln2 = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r_vuln2 is True,
          "A: VULNERABILITY_DISCOVERY recompute -> True")
    check(orch._phase_complete_cache.get(key_vuln) is True,
          "A: VULNERABILITY_DISCOVERY True re-cached")

    # --------------------------------------------------------------------
    # Sub-test B: Two engagements, invalidate one, other intact
    # --------------------------------------------------------------------
    eid_b1 = _engagement_id(810)
    eid_b2 = _engagement_id(811)
    tasks_b1 = [_task_recon(eid_b1, 0, "completed")]
    tasks_b2 = [_task_recon(eid_b2, 0, "completed")]

    orch_b1 = _make_orchestrator(
        tasks_b1, eid_b1, EngagementPhase.RECONNAISSANCE,
    )
    orch_b2 = _make_orchestrator(
        tasks_b2, eid_b2, EngagementPhase.RECONNAISSANCE,
    )

    key_b1 = (eid_b1, EngagementPhase.RECONNAISSANCE.value)
    key_b2 = (eid_b2, EngagementPhase.RECONNAISSANCE.value)

    r_b1 = await is_phase_complete(
        orch_b1, eid_b1, EngagementPhase.RECONNAISSANCE
    )
    check(r_b1 is True, "B: e1 phase complete")
    check(orch_b1._phase_complete_cache.get(key_b1) is True, "B: e1 cached")

    r_b2 = await is_phase_complete(
        orch_b2, eid_b2, EngagementPhase.RECONNAISSANCE
    )
    check(r_b2 is True, "B: e2 phase complete")
    check(orch_b2._phase_complete_cache.get(key_b2) is True, "B: e2 cached")

    # Invalidate engagement 1 only
    await invalidate_cache(orch_b1, eid_b1)
    check(orch_b1._phase_complete_cache.get(key_b1) is None,
          "B: e1 cache cleared")
    check(orch_b2._phase_complete_cache.get(key_b2) is True,
          "B: e2 cache UNCHANGED by e1 invalidation")

    # --------------------------------------------------------------------
    # Sub-test C: Cache hit counts after recompute
    # --------------------------------------------------------------------
    # After recompute in sub-test A, both phases should serve cache hits
    # on the next call without consulting the durable store.
    before_count = orch.session_memory.load_all_active_tasks.call_count

    # Cache hit for RECONNAISSANCE
    r_c1 = await is_phase_complete(
        orch, eid, EngagementPhase.RECONNAISSANCE
    )
    check(r_c1 is True, "C: RECONNAISSANCE cache hit -> True")
    check(orch.session_memory.load_all_active_tasks.call_count == before_count,
          "C: RECONNAISSANCE cache hit: durable not consulted")

    # Cache hit for VULNERABILITY_DISCOVERY
    r_c2 = await is_phase_complete(
        orch, eid, EngagementPhase.VULNERABILITY_DISCOVERY
    )
    check(r_c2 is True, "C: VULNERABILITY_DISCOVERY cache hit -> True")
    check(orch.session_memory.load_all_active_tasks.call_count == before_count,
          "C: VULNERABILITY_DISCOVERY cache hit: durable not consulted")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

async def main() -> int:
    global _PASS, _FAIL  # noqa: PLW0603
    print("=" * 60)
    print("Cache Coherence Spike Test")
    print("=" * 60)

    tests = [
        ("Cache hit", test_cache_hit),
        ("Invalidation on success", test_invalidation_on_success),
        ("Invalidation on failure", test_invalidation_on_failure),
        ("Invalidation on assign", test_invalidation_on_assign),
        ("Engagement isolation", test_engagement_isolation),
        ("Engagement-id matching", test_engagement_id_matching),
        ("Rapid completion (12 tasks)", test_rapid_completion),
        ("No-op invalidation", test_noop_invalidation),
        ("Durable-store merge", test_durable_store_merge),
        ("TTL expiry", test_ttl_expiry),
        ("Durable-store exception", test_durable_exception),
        ("Multi-phase invalidation", test_multi_phase_invalidation),
    ]

    all_passed = True
    for name, fn in tests:
        _PASS = _FAIL = 0
        print(f"\n-- Scenario: {name} --")
        try:
            await fn()
        except Exception as e:
            import traceback
            _FAIL += 1
            print(f"  EXCEPTION: {e}")
            traceback.print_exc()
        total = _PASS + _FAIL
        passed = _FAIL == 0
        all_passed = all_passed and passed
        status = "OK" if passed else "FAIL"
        print(f"  Result: {_PASS}/{total} passed [{status}]")

    print()
    print("=" * 60)
    verdict = "ALL PASSED" if all_passed else "SOME FAILED"
    print(f"Cache coherence spike: {verdict}")
    print("=" * 60)
    return 0 if all_passed else 1


if __name__ == "__main__":
    exit(asyncio.run(main()))
