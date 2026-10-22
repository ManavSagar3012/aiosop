"""EngagementManager — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles engagement lifecycle: creation, halting, phase transitions, authenticated discovery, and status queries.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.models import AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.core.tracing import trace_span
from ai_osop.core.observability import record_engagement_started, record_engagement_halted
from ai_osop.core.exceptions import WorkflowException, WorkflowTransitionError

import structlog

logger = structlog.get_logger("ai_osop.orchestrator.engagement_manager")


class EngagementManager:
    """Manage engagement lifecycle and transitions."""

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator

    async def create_engagement(
        self,
        scope: ScopeDefinition,
        roe: Dict[str, Any],
        created_by: Optional[str] = None,
        *,
        signed_roe: Optional[Dict[str, Any]] = None,
    ) -> SessionState:
        """Delegate to the sole signed, atomic PostgreSQL creation path.

        Never use the historical timestamp-prefixed session ID or unsigned
        direct Redis/SQL writes. API and internal callers share one verifier.
        """
        return await self._orch.create_engagement(
            scope, roe, created_by=created_by, signed_roe=signed_roe
        )

    async def halt_engagement(self, session_id: str, reason: str) -> None:
        """Emergency halt of engagement."""
        # Use the canonical orchestrator halt to persist warm state and cancel
        # Temporal executions; keeping two implementations caused drift.
        await self._orch.halt_engagement(session_id, reason)

    async def transition_phase(self, session_id: str, new_phase: EngagementPhase) -> SessionState:
        """Transition engagement to new phase with validation."""
        session = self._orch._sessions.get(session_id)
        if not session:
            raise WorkflowException(f"Session {session_id} not found")
        current = EngagementPhase(session.phase)
        if new_phase not in self._orch.VALID_TRANSITIONS.get(current, []):
            raise WorkflowTransitionError(
                f"Invalid transition: {current.value} -> {new_phase.value}"
            )
        if new_phase == EngagementPhase.EXPLOITATION:
            stats = await self._orch.graph_memory.get_graph_stats(session_id)
            if stats.get("vulnerabilities", 0) == 0:
                raise WorkflowException("Cannot transition to exploitation without vulnerabilities")
        session.phase = new_phase.value
        session.updated_at = datetime.utcnow()
        await self._orch.session_memory.store_session_state(session)
        await self._orch.session_memory.persist_session_state(session)
        await self._orch.phase_monitor._on_phase_enter(session, new_phase)
        await self._orch._audit_log(
            AuditEvent(
                event_type="phase_transition",
                severity="info",
                actor_type="system",
                actor_id="orchestrator",
                action={"from_phase": current.value, "to_phase": new_phase.value},
                result={"success": True},
                context={"session_id": session_id},
                engagement_id=session.scope.engagement_id,
            )
        )
        return session

    async def _engagement_is_authenticated(self, engagement_id: str) -> bool:
        """Use imported session state, not a potentially stale graph projection."""
        return await self._orch._engagement_is_authenticated(engagement_id)

    async def _pick_auth_user_label(self, engagement_id: str) -> Optional[str]:
        """Use the current imported session identity rather than Neo4j."""
        return await self._orch._pick_auth_user_label(engagement_id)

    async def claim_auto_discovery(
        self, engagement_id: str, auth_user_label: str, source_task_id: str
    ) -> None:
        """Delegate all admission to the canonical durable, signed scheduler.

        The historical graph-first claim permanently suppressed a child if a
        process died between Neo4j CREATE and TaskORM insertion. It also
        called a removed _schedule_authenticated_discovery method. A graph
        projection is never a work-admission or authorization ledger.
        """
        from ai_osop.memory.session_memory import SessionMemory

        if isinstance(self._orch.session_memory, SessionMemory):
            # For callback-originated discovery, require a genuinely completed
            # signed source Task in PostgreSQL; a caller's username/source ID
            # cannot stand in for durable completion and current ROE.
            if source_task_id != "session-import":
                source = await self._orch.session_memory.load_task_authoritative(
                    source_task_id
                )
                if (
                    source is None
                    or source.id != source_task_id
                    or source.engagement_id != engagement_id
                    or source.type != "auth_diff"
                    or source.status != "completed"
                    or not isinstance(source.payload, dict)
                    or type(source.payload.get("_authorization_version")) is not int
                ):
                    return
                await self._orch.session_memory.assert_signed_authorization(
                    engagement_id,
                    expected_version=source.payload["_authorization_version"],
                )
        # The label is a legacy hint only: the canonical scheduler independently
        # chooses and authoritatively checks the current imported identity.
        await self._orch.ensure_authenticated_discovery(engagement_id)

    async def ensure_authenticated_discovery(
        self, session_id: str, url_hint: Optional[str] = None
    ) -> None:
        """Use the single signed admission path for phase-entry and imports."""
        await self._orch.ensure_authenticated_discovery(session_id, url_hint=url_hint)
