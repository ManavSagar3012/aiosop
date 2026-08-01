"""Unit tests for Orchestrator auto-transition backoff logic.

Tests the pure methods that manage auto-transition failure tracking:
- ``_auto_transition_ready``: backoff gate
- ``_record_auto_transition_failure``: failure tracking with exponential backoff
- ``_resolve_auto_next``: rerouting around guard conditions
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from ai_osop.core.enums import EngagementPhase
from ai_osop.orchestrator.orchestrator import Orchestrator

# ── _auto_transition_ready ────────────────────────────────────────────────────


def _make_orch():
    """Build a mock orchestrator with real auto-transition methods."""
    orch = MagicMock()
    orch._auto_transition_failures = {}
    # Bind real methods via Python's descriptor protocol
    orch.AUTO_TRANSITION_MAX_ATTEMPTS = 5
    orch.AUTO_TRANSITION_MAX_BACKOFF_TICKS = 30
    orch._auto_transition_ready = Orchestrator._auto_transition_ready.__get__(orch, Orchestrator)
    orch._record_auto_transition_failure = Orchestrator._record_auto_transition_failure.__get__(
        orch, Orchestrator
    )
    return orch


class TestAutoTransitionReady:
    """Tests for the backoff gate."""

    def test_no_failures_returns_true(self):
        orch = _make_orch()
        assert orch._auto_transition_ready("eng-1", EngagementPhase.RECONNAISSANCE, 1) is True

    def test_phase_changed_since_failure(self):
        """A phase change since the last failure resets the counter."""
        orch = _make_orch()
        orch._auto_transition_failures["eng-1"] = {
            "phase": "vulnerability_discovery",
            "count": 3,
            "next_tick": 10,
        }
        # Now the phase is different (reconnaissance vs vulnerability_discovery)
        assert orch._auto_transition_ready("eng-1", EngagementPhase.RECONNAISSANCE, 5) is True
        # The failure state should have been popped
        assert "eng-1" not in orch._auto_transition_failures

    def test_under_attempts_and_tick_ready(self):
        """Count < max and tick >= next_tick → ready."""
        orch = _make_orch()
        orch._auto_transition_failures["eng-1"] = {
            "phase": "reconnaissance",
            "count": 2,
            "next_tick": 5,
        }
        assert orch._auto_transition_ready("eng-1", EngagementPhase.RECONNAISSANCE, 10) is True

    def test_under_attempts_but_tick_not_ready(self):
        """Count < max but tick < next_tick → not ready."""
        orch = _make_orch()
        orch._auto_transition_failures["eng-1"] = {
            "phase": "reconnaissance",
            "count": 2,
            "next_tick": 10,
        }
        assert orch._auto_transition_ready("eng-1", EngagementPhase.RECONNAISSANCE, 5) is False

    def test_exceeded_max_attempts(self):
        """Count >= max attempts → not ready (permanently)."""
        orch = _make_orch()
        orch._auto_transition_failures["eng-1"] = {
            "phase": "reconnaissance",
            "count": 5,
            "next_tick": 0,
        }
        # Even with a high tick, max attempts has been reached
        assert orch._auto_transition_ready("eng-1", EngagementPhase.RECONNAISSANCE, 100) is False


# ── _record_auto_transition_failure ───────────────────────────────────────────


class TestRecordAutoTransitionFailure:
    """Tests for failure tracking with exponential backoff."""

    def test_first_failure(self):
        orch = _make_orch()
        orch._record_auto_transition_failure(
            "eng-1", EngagementPhase.RECONNAISSANCE, 10, ValueError("nope")
        )
        state = orch._auto_transition_failures.get("eng-1")
        assert state is not None
        assert state["count"] == 1
        assert state["phase"] == "reconnaissance"
        # backoff = min(2^1, 30) = 2
        assert state["next_tick"] == 10 + 2

    def test_second_failure_doubles_backoff(self):
        orch = _make_orch()
        orch._auto_transition_failures["eng-1"] = {
            "phase": "reconnaissance",
            "count": 1,
            "next_tick": 12,
        }
        orch._record_auto_transition_failure(
            "eng-1", EngagementPhase.RECONNAISSANCE, 15, ValueError("nope")
        )
        state = orch._auto_transition_failures["eng-1"]
        assert state["count"] == 2
        # backoff = min(2^2, 30) = 4
        assert state["next_tick"] == 15 + 4

    def test_max_backoff_capped(self):
        """Backoff is capped at AUTO_TRANSITION_MAX_BACKOFF_TICKS (30)."""
        orch = _make_orch()
        orch._auto_transition_failures["eng-1"] = {
            "phase": "reconnaissance",
            "count": 5,
            "next_tick": 100,
        }
        orch._record_auto_transition_failure(
            "eng-1", EngagementPhase.RECONNAISSANCE, 110, ValueError("nope")
        )
        state = orch._auto_transition_failures["eng-1"]
        # 2^6 = 64, capped to 30
        assert state["next_tick"] == 110 + 30

    def test_phase_change_resets_state(self):
        """A failure for a different phase creates a fresh counter."""
        orch = _make_orch()
        orch._auto_transition_failures["eng-1"] = {
            "phase": "reconnaissance",
            "count": 5,
            "next_tick": 100,
        }
        orch._record_auto_transition_failure(
            "eng-1", EngagementPhase.VULNERABILITY_DISCOVERY, 50, ValueError("nope")
        )
        state = orch._auto_transition_failures["eng-1"]
        assert state["count"] == 1  # reset to 1
        assert state["phase"] == "vulnerability_discovery"
        assert state["next_tick"] == 50 + 2  # fresh backoff


# ── _resolve_auto_next ────────────────────────────────────────────────────────


def _make_orch_with_graph_stats(stats=None, side_effect=None) -> MagicMock:
    """Build a mock orchestrator with a graph_memory that returns given stats."""
    from ai_osop.core.config import VALID_TRANSITIONS as _VT

    orch = MagicMock(spec=Orchestrator)
    orch._auto_transition_failures = {}
    # Explicitly set VALID_TRANSITIONS — spec=Orchestrator returns a MagicMock
    # for class attributes, not the actual dict value.
    orch.VALID_TRANSITIONS = _VT
    orch.graph_memory = MagicMock()
    if side_effect:
        orch.graph_memory.get_graph_stats = AsyncMock(side_effect=side_effect)
    else:
        orch.graph_memory.get_graph_stats = AsyncMock(return_value=stats or {})
    # Bind the real async method
    orch._resolve_auto_next = Orchestrator._resolve_auto_next.__get__(orch, Orchestrator)
    return orch


class TestResolveAutoNext:
    """Tests for the _resolve_auto_next rerouting method."""

    async def test_returns_desired_when_not_exploitation(self):
        """If desired_next is not EXPLOITATION, return it unchanged."""
        orch = _make_orch_with_graph_stats({})
        result = await orch._resolve_auto_next(
            "eng-1", EngagementPhase.RECONNAISSANCE, EngagementPhase.REPORTING
        )
        assert result == EngagementPhase.REPORTING

    async def test_returns_exploitation_when_vulns_exist(self):
        """When vulns exist, EXPLOITATION is returned unchanged."""
        orch = _make_orch_with_graph_stats({"vulnerabilities": 5})
        result = await orch._resolve_auto_next(
            "eng-1",
            EngagementPhase.VULNERABILITY_DISCOVERY,
            EngagementPhase.EXPLOITATION,
        )
        assert result == EngagementPhase.EXPLOITATION

    async def test_reroutes_to_reporting_when_no_vulns(self):
        """When vulns are 0, reroute to REPORTING (valid transition)."""
        orch = _make_orch_with_graph_stats({"vulnerabilities": 0})
        result = await orch._resolve_auto_next(
            "eng-1",
            EngagementPhase.VULNERABILITY_DISCOVERY,
            EngagementPhase.EXPLOITATION,
        )
        assert result == EngagementPhase.REPORTING

    async def test_reroutes_to_reporting_when_no_vulns_key(self):
        """When stats dict has no 'vulnerabilities' key, treat as 0."""
        orch = _make_orch_with_graph_stats({"endpoints": 100})
        result = await orch._resolve_auto_next(
            "eng-1",
            EngagementPhase.VULNERABILITY_DISCOVERY,
            EngagementPhase.EXPLOITATION,
        )
        assert result == EngagementPhase.REPORTING

    async def test_reroutes_to_reporting_when_none_vulns_not_rerouted(self):
        """When stats says vulnerabilities is None, the == 0 check returns False."""
        orch = _make_orch_with_graph_stats({"vulnerabilities": None})
        result = await orch._resolve_auto_next(
            "eng-1",
            EngagementPhase.VULNERABILITY_DISCOVERY,
            EngagementPhase.EXPLOITATION,
        )
        # None != 0 in Python, so stats.get("vulnerabilities", 0) == 0 is False
        assert result == EngagementPhase.EXPLOITATION

    async def test_reroutes_when_graph_stats_raises(self):
        """When get_graph_stats raises, treat as empty stats → reroute."""
        orch = _make_orch_with_graph_stats(
            {},
            side_effect=ValueError("DB down"),
        )
        result = await orch._resolve_auto_next(
            "eng-1",
            EngagementPhase.VULNERABILITY_DISCOVERY,
            EngagementPhase.EXPLOITATION,
        )
        assert result == EngagementPhase.REPORTING

    async def test_reroute_unavailable_when_reporting_not_in_valid_transitions(self):
        """When REPORTING is not a valid transition from current phase, keep EXPLOITATION."""
        # Use INITIALIZED as phase — REPORTING is NOT a valid transition from INITIALIZED
        orch = _make_orch_with_graph_stats({"vulnerabilities": 0})
        result = await orch._resolve_auto_next(
            "eng-1",
            EngagementPhase.INITIALIZED,
            EngagementPhase.EXPLOITATION,
        )
        assert result == EngagementPhase.EXPLOITATION  # fallback not available

    async def test_no_reroute_for_non_exploitation_phases(self):
        """Rerouting only applies when desired_next is EXPLOITATION."""
        orch = _make_orch_with_graph_stats({})
        for phase, expected in [
            (EngagementPhase.RECONNAISSANCE, EngagementPhase.VULNERABILITY_DISCOVERY),
            (EngagementPhase.EXPLOITATION, EngagementPhase.POST_EXPLOITATION),
            (EngagementPhase.POST_EXPLOITATION, EngagementPhase.REPORTING),
            (EngagementPhase.REPORTING, EngagementPhase.COMPLETED),
        ]:
            result = await orch._resolve_auto_next("eng-1", phase, expected)
            assert result == expected, f"Failed for phase={phase}"
