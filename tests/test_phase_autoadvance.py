"""Regression tests for autonomous phase-advance hang fixes (AIOSOP-AUTO-2026-06-16).

These cover the three stall points that previously prevented a domain-only
engagement from running end-to-end without manual intervention:

  1. VULNERABILITY_DISCOVERY -> EXPLOITATION is impossible when 0 vulnerabilities
     exist (transition_phase guard); the monitor must reroute to REPORTING instead
     of retrying the impossible hop forever. -> _resolve_auto_next
  2. POST_EXPLOITATION schedules no work of its own; _is_phase_complete must treat
     it as a pass-through (complete when no in-flight tasks) rather than hanging.
  3. Work-scheduling phases with tasks still in flight must NOT be considered
     complete (guards against premature advance).
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.orchestrator import EngagementPhase, Orchestrator


def _orch(vuln_count: int) -> Orchestrator:
    graph_memory = AsyncMock()
    graph_memory.get_graph_stats = AsyncMock(return_value={"vulnerabilities": vuln_count})
    orch = Orchestrator(AsyncMock(), graph_memory, AsyncMock(), AsyncMock())
    return orch


@pytest.mark.asyncio
async def test_reroute_skips_exploitation_when_no_vulns():
    """0 vulns -> auto-next must become REPORTING, not EXPLOITATION."""
    orch = _orch(vuln_count=0)
    nxt = await orch._resolve_auto_next(
        "eng-x", EngagementPhase.VULNERABILITY_DISCOVERY, EngagementPhase.EXPLOITATION
    )
    assert nxt == EngagementPhase.REPORTING


@pytest.mark.asyncio
async def test_no_reroute_when_vulns_exist():
    """>=1 vuln -> auto-next stays EXPLOITATION."""
    orch = _orch(vuln_count=3)
    nxt = await orch._resolve_auto_next(
        "eng-x", EngagementPhase.VULNERABILITY_DISCOVERY, EngagementPhase.EXPLOITATION
    )
    assert nxt == EngagementPhase.EXPLOITATION


@pytest.mark.asyncio
async def test_post_exploitation_is_pass_through_complete():
    """POST_EXPLOITATION schedules no tasks; must be considered complete so the
    monitor can advance it to REPORTING."""
    orch = _orch(vuln_count=0)
    orch._tasks = {}  # no tasks for this engagement
    done = await orch._is_phase_complete("eng-x", EngagementPhase.POST_EXPLOITATION)
    assert done is True


@pytest.mark.asyncio
async def test_recon_not_complete_until_tasks_present():
    """RECONNAISSANCE is a work-scheduling phase: with no tasks yet it is NOT
    complete (must wait for full_recon to be scheduled/finish)."""
    orch = _orch(vuln_count=0)
    orch._tasks = {}
    done = await orch._is_phase_complete("eng-x", EngagementPhase.RECONNAISSANCE)
    assert done is False


@pytest.mark.asyncio
async def test_recon_not_complete_while_task_running():
    """A running recon task blocks completion."""
    orch = _orch(vuln_count=0)
    t = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="eng-x")
    t.status = "running"
    orch._tasks = {t.id: t}
    done = await orch._is_phase_complete("eng-x", EngagementPhase.RECONNAISSANCE)
    assert done is False


@pytest.mark.asyncio
async def test_recon_complete_when_task_finished():
    """A completed recon task satisfies phase completion."""
    orch = _orch(vuln_count=0)
    t = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="eng-x")
    t.status = "completed"
    orch._tasks = {t.id: t}
    done = await orch._is_phase_complete("eng-x", EngagementPhase.RECONNAISSANCE)
    assert done is True
