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
        self, scope: ScopeDefinition, roe: Dict[str, Any], created_by: Optional[str] = None
    ) -> SessionState:
        """Create new engagement session."""
        with trace_span(
            "orchestrator.create_engagement",
            attributes={
                "engagement_id": scope.engagement_id,
                "created_by": created_by or "system",
            },
        ):
            session = SessionState(
                session_id=f"eng-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{scope.engagement_id}",
                scope=scope,
                roe=roe,
                phase=EngagementPhase.INITIALIZED.value,
                agents={},
                checkpoint_id=None,
                audit_log_position="0",
                created_by=created_by,
            )
            await self._orch.session_memory.store_session_state(session)
            await self._orch.session_memory.persist_session_state(session)
            self._orch._sessions[session.session_id] = session
            record_engagement_started(session.session_id)
            await self._orch._audit_log(
                AuditEvent(
                    event_type="engagement_created",
                    severity="info",
                    actor_type="system",
                    actor_id="orchestrator",
                    action={"scope": scope.model_dump(), "roe": roe},
                    result={"session_id": session.session_id},
                    context={"phase": session.phase},
                    engagement_id=scope.engagement_id,
                )
            )
            return session

    async def halt_engagement(self, session_id: str, reason: str) -> None:
        """Emergency halt of engagement."""
        with trace_span(
            "orchestrator.halt_engagement",
            attributes={"session_id": session_id, "reason": reason},
        ):
            session = self._orch._sessions.get(session_id)
            if not session:
                return
            session.phase = EngagementPhase.HALTED.value
            await self._orch.session_memory.store_session_state(session)
            record_engagement_halted(session_id)
            for task in self._orch._tasks.values():
                if task.engagement_id == session_id and task.status in ["pending", "running"]:
                    task.status = "cancelled"
            for agent in self._orch._agents.values():
                if agent.ctx.session_id == session_id:
                    await agent.shutdown()
            await self._orch._audit_log(
                AuditEvent(
                    event_type="engagement_halted",
                    severity="critical",
                    actor_type="system",
                    actor_id="orchestrator",
                    action={"reason": reason},
                    result={"session_id": session_id, "phase": "halted"},
                    context={"session_id": session_id},
                    engagement_id=session.scope.engagement_id,
                )
            )

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
        """Check whether the engagement has an authenticated session."""
        try:
            cypher = (
                "MATCH (s:Session {engagement_id: $eid}) "
                "RETURN s.authenticated as authenticated"
            )
            async with self._orch.graph_memory._driver.session() as g_session:
                result = await g_session.run(cypher, {"eid": engagement_id})
                record = await result.single()
                return bool(record and record.get("authenticated"))
        except Exception:
            return False

    async def _pick_auth_user_label(self, engagement_id: str) -> Optional[str]:
        """Pick a stable user label for authenticated discovery."""
        try:
            cypher = (
                "MATCH (s:Session {engagement_id: $eid}) "
                "RETURN s.username as username"
            )
            async with self._orch.graph_memory._driver.session() as g_session:
                result = await g_session.run(cypher, {"eid": engagement_id})
                record = await result.single()
                return record.get("username") if record else None
        except Exception:
            return None

    async def claim_auto_discovery(
        self, engagement_id: str, auth_user_label: str, source_task_id: str
    ) -> None:
        """Claim autonomous discovery for an authenticated engagement."""
        # Idempotent check in Neo4j
        async with self._orch.graph_memory._driver.session() as g_session:
            cypher = (
                "MATCH (d:AutoDiscoveryClaim {engagement_id: $eid}) "
                "RETURN d.id as id"
            )
            result = await g_session.run(cypher, {"eid": engagement_id})
            if await result.single():
                logger.info("auto_discovery_already_claimed", engagement_id=engagement_id)
                return
        # Claim it
        cypher = (
            "CREATE (d:AutoDiscoveryClaim { "
            "  id: $id, engagement_id: $eid, "
            "  auth_user_label: $label, source_task_id: $source, "
            "  claimed_at: datetime() "
            "})"
        )
        async with self._orch.graph_memory._driver.session() as g_session:
            await g_session.run(
                cypher,
                {
                    "id": f"auto-{engagement_id}",
                    "eid": engagement_id,
                    "label": auth_user_label,
                    "source": source_task_id,
                },
            )
        # Schedule authenticated discovery tasks
        await self._orch._schedule_authenticated_discovery(engagement_id, auth_user_label)

    async def ensure_authenticated_discovery(
        self, session_id: str, url_hint: Optional[str] = None
    ) -> None:
        """Ensure authenticated discovery is scheduled if the engagement has an authenticated session."""
        if not await self._engagement_is_authenticated(session_id):
            return
        auth_user_label = await self._pick_auth_user_label(session_id)
        if not auth_user_label:
            return
        await self.claim_auto_discovery(session_id, auth_user_label, "session-import")
