"""AEGIS-RT v2 autonomy tests (2026-08-29).

Covers the two new behaviors implemented in the autonomy sprint:
  1. Engagement-card authorization gate: an engagement cannot leave INITIALIZED
     without an authorization_ref OR an operator-confirmed card, and confirm()
     fires once.
  2. Scope signature now covers the full scope (exclusions, techniques, window).
  3. The full auto-advance chain is wired in PHASE_POLICY, and the phase monitor
     enforces requires_manual_approval at runtime unless OSOP_AUTO_ADVANCE_ALL=1.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import (
    PHASE_POLICY,
    EngagementPhase,
    scope_signing_key,
)
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ScopeDefinition, SessionState
from ai_osop.orchestrator.engagement_manager import EngagementManager
from ai_osop.orchestrator.orchestrator import Orchestrator


def _orch() -> Orchestrator:
    session_memory = AsyncMock()
    graph_memory = AsyncMock()
    graph_memory.run_read_query = AsyncMock(return_value=[])
    graph_memory.get_graph_stats = AsyncMock(return_value={"vulnerabilities": 1})
    orch = Orchestrator(session_memory, graph_memory, AsyncMock(), AsyncMock())
    orch.rate_limiter = AsyncMock()
    return orch


def _scope(**kw) -> ScopeDefinition:
    base = dict(
        engagement_id="test-eng",
        domains=["example.com"],
        ips=[],
        exclusions=["admin.example.com"],
        allowed_techniques=["sqli", "xss"],
        restrictions=[],
        approval_required_for=["rce"],
        testing_window_start=datetime(2026, 8, 1),
        testing_window_end=datetime(2026, 8, 31),
    )
    base.update(kw)
    return ScopeDefinition(**base)


def _session(orch: Orchestrator, phase: EngagementPhase, scope: ScopeDefinition) -> SessionState:
    s = SessionState(
        session_id="test-session",
        scope=scope,
        roe={},
        phase=phase.value,
        agents={},
        checkpoint_id=None,
        audit_log_position="0",
    )
    orch._sessions["test-session"] = s
    return s


# --------------------------------------------------------------------------- #
# 1. Engagement-card authorization gate
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_transition_refused_without_authorization():
    """INITIALIZED -> RECONNAISSANCE must refuse when no authorization exists."""
    orch = _orch()
    _session(orch, EngagementPhase.INITIALIZED, _scope(authorization_ref=None))
    with pytest.raises(WorkflowException, match="not authorized"):
        await orch.transition_phase("test-session", EngagementPhase.RECONNAISSANCE)


@pytest.mark.asyncio
async def test_transition_allowed_with_authorization_ref():
    """authorization_ref on the scope satisfies the gate."""
    orch = _orch()
    _session(orch, EngagementPhase.INITIALIZED, _scope(authorization_ref="/path/roe.pdf"))
    updated = await orch.transition_phase("test-session", EngagementPhase.RECONNAISSANCE)
    assert updated.phase == EngagementPhase.RECONNAISSANCE.value


@pytest.mark.asyncio
async def test_confirm_unlocks_transition():
    """Operator confirmation is the one-shot unlock when no authorization_ref."""
    orch = _orch()
    _session(orch, EngagementPhase.INITIALIZED, _scope(authorization_ref=None))
    with pytest.raises(WorkflowException, match="not authorized"):
        await orch.transition_phase("test-session", EngagementPhase.RECONNAISSANCE)

    confirmed = await orch.confirm_engagement("test-session", "operator-1")
    assert confirmed.authorization_confirmed is True
    assert confirmed.confirmed_by == "operator-1"

    updated = await orch.transition_phase("test-session", EngagementPhase.RECONNAISSANCE)
    assert updated.phase == EngagementPhase.RECONNAISSANCE.value


@pytest.mark.asyncio
async def test_confirm_fires_once():
    """A second confirm is a no-op that preserves the original timestamp."""
    orch = _orch()
    session = _session(orch, EngagementPhase.INITIALIZED, _scope(authorization_ref=None))
    t0 = datetime.utcnow()
    await orch.confirm_engagement("test-session", "operator-1")
    first_at = session.confirmed_at
    assert first_at is not None
    await orch.confirm_engagement("test-session", "operator-2")
    assert session.confirmed_by == "operator-1"  # not overwritten
    assert session.confirmed_at == first_at


@pytest.mark.asyncio
async def test_exploitation_transition_still_requires_vulns():
    """The existing 0-vuln guard still blocks exploitation (gate composes)."""
    orch = _orch()
    graph_memory = AsyncMock()
    graph_memory.get_graph_stats = AsyncMock(return_value={"vulnerabilities": 0})
    orch.graph_memory = graph_memory
    _session(orch, EngagementPhase.VULNERABILITY_DISCOVERY, _scope(authorization_ref="x"))
    with pytest.raises(WorkflowException, match="without vulnerabilities"):
        await orch.transition_phase("test-session", EngagementPhase.EXPLOITATION)


# --------------------------------------------------------------------------- #
# 2. Scope signature covers the full scope
# --------------------------------------------------------------------------- #
def test_signature_covers_exclusions():
    """Changing exclusions must invalidate the signature."""
    key = scope_signing_key()
    s1 = _scope(exclusions=["admin.example.com"])
    s1.sign(key)
    s2 = _scope(exclusions=["admin.example.com", "extra.example.com"])
    s2.signature = s1.signature
    assert s2.verify_signature(key) is False


def test_signature_covers_allowed_techniques_and_window():
    """Technique and window edits must also be tamper-evident."""
    key = scope_signing_key()
    a = _scope(allowed_techniques=["sqli", "xss"])
    a.sign(key)
    b = _scope(allowed_techniques=["sqli"])
    b.signature = a.signature
    assert b.verify_signature(key) is False

    c = _scope(testing_window_end=datetime(2026, 9, 30))
    c.signature = a.signature
    assert c.verify_signature(key) is False


# --------------------------------------------------------------------------- #
# 3. Full auto-advance chain + manual-approval enforcement
# --------------------------------------------------------------------------- #
def test_phase_policy_has_full_autonomy_chain():
    """The full recon -> vuln -> attack -> report -> complete chain is wired."""
    chain = {
        EngagementPhase.VULNERABILITY_DISCOVERY: EngagementPhase.EXPLOITATION,
        EngagementPhase.EXPLOITATION: EngagementPhase.POST_EXPLOITATION,
        EngagementPhase.POST_EXPLOITATION: EngagementPhase.REPORTING,
        EngagementPhase.REPORTING: EngagementPhase.COMPLETED,
    }
    for phase, expected_next in chain.items():
        assert PHASE_POLICY[phase]["automatic_next_phase"] == expected_next


@pytest.mark.asyncio
async def test_auto_advance_respects_manual_approval_gate():
    """Operator-gated phases must NOT auto-advance by default."""
    orch = _orch()
    orch._auto_advance_all = False
    _session(orch, EngagementPhase.VULNERABILITY_DISCOVERY, _scope(authorization_ref="x"))
    orch._is_phase_complete = AsyncMock(return_value=True)
    orch.engagement_manager.transition_phase = AsyncMock(side_effect=AssertionError("should not advance"))
    # Patch the real transition_phase so a violation is loud, not silent.

    from ai_osop.orchestrator.phase_monitor import PhaseMonitor

    monitor = PhaseMonitor(orch)
    await monitor._auto_advance_phase(orch._sessions["test-session"])
    # If the gate is respected, transition_phase was never reached (no exception).
    orch.engagement_manager.transition_phase.assert_not_awaited()


@pytest.mark.asyncio
async def test_auto_advance_all_skips_gate():
    """OSOP_AUTO_ADVANCE_ALL=1 lets the monitor advance gated phases."""
    orch = _orch()
    orch._auto_advance_all = True
    _session(orch, EngagementPhase.VULNERABILITY_DISCOVERY, _scope(authorization_ref="x"))
    orch._is_phase_complete = AsyncMock(return_value=True)
    orch.engagement_manager.transition_phase = AsyncMock(return_value=orch._sessions["test-session"])

    from ai_osop.orchestrator.phase_monitor import PhaseMonitor

    monitor = PhaseMonitor(orch)
    await monitor._auto_advance_phase(orch._sessions["test-session"])
    orch.engagement_manager.transition_phase.assert_awaited_once()
