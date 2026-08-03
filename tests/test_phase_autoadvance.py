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

Also covers the single-source-of-truth PHASE_POLICY consolidation (Part II
Task 19): the dead shadow dicts in core.config / core.enums are gone and the
EXPLOITATION row on Orchestrator requires operator approval to ENTER.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

import ai_osop.core.config as core_config
import ai_osop.core.enums as core_enums
from ai_osop.core.enums import AgentType, EngagementPhase
from ai_osop.core.models import Task
from ai_osop.orchestrator.orchestrator import Orchestrator


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


# ── Single-source-of-truth PHASE_POLICY (Part II Task 19) ─────────────────────


def test_dead_phase_policy_removed_from_config():
    """The shadow PHASE_POLICY in core.config used different keys
    (requires_manual_approval / automatic_next_phase) and was never imported.
    It must be deleted so Orchestrator.PHASE_POLICY is the only copy."""
    assert not hasattr(core_config, "PHASE_POLICY")


def test_dead_phase_policy_removed_from_enums():
    """The shadow PHASE_POLICY in core.enums (same dead shape) must be gone."""
    assert not hasattr(core_enums, "PHASE_POLICY")


def test_exploitation_entry_requires_manual_approval():
    """EXPLOITATION is gated on entry: manual_approval=True. Its EXIT stays
    automatic (auto_next=POST_EXPLOITATION)."""
    row = Orchestrator.PHASE_POLICY[EngagementPhase.EXPLOITATION]
    assert row["manual_approval"] is True
    assert row["auto_next"] is EngagementPhase.POST_EXPLOITATION


@pytest.mark.asyncio
async def test_auto_advance_halts_before_exploitation():
    """Gate (Task 26): when phase-completion would roll VULNERABILITY_DISCOVERY
    into EXPLOITATION, the monitor halts auto-advance and raises an ApprovalRequest
    instead. The suite's TestPhaseEntryApprovalGate class covers the deeper
    lifecycle; this is the canonical single-case gate regression probe."""
    from ai_osop.orchestrator.orchestrator import EngagementPhase
    from tests.test_orchestrator_transitions import _make_monitor_orch, _make_session

    orch, monitor = _make_monitor_orch(
        EngagementPhase.VULNERABILITY_DISCOVERY, EngagementPhase.EXPLOITATION, manual=True
    )
    session = _make_session(EngagementPhase.VULNERABILITY_DISCOVERY)
    await monitor._auto_advance_phase(session)

    orch.engagement_manager.transition_phase.assert_not_called()
    orch.approval_coordinator._raise_approval.assert_awaited_once()
    req = orch.approval_coordinator._raise_approval.await_args.args[0]
    assert req.engagement_id == "eng-1"
