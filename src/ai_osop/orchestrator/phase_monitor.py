"""PhaseMonitor — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles phase monitoring and automatic task dispatch on phase entry.
"""

from __future__ import annotations

from typing import Any

from ai_osop.core.config import EngagementPhase
from ai_osop.core.models import SessionState


class PhaseMonitor:
    """Monitor engagement phases and trigger automatic tasks on phase entry."""

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator

    async def _on_phase_enter(self, session: SessionState, phase: EngagementPhase) -> None:
        """Use the canonical phase entry implementation."""
        await self._orch._on_phase_enter(session, phase)

    async def _phase_monitor(self) -> None:
        """Use the canonical monitor and its completion/uncertainty rules."""
        await self._orch._phase_monitor()
