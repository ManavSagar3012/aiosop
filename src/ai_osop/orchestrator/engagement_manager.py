"""EngagementManager — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles engagement lifecycle: creation, halting, phase transitions, authenticated discovery, and status queries.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, Optional

import structlog

from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.exceptions import WorkflowException, WorkflowTransitionError
from ai_osop.core.models import AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.core.observability import record_engagement_halted, record_engagement_started
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger("ai_osop.orchestrator.engagement_manager")


class EngagementManager:
    """Manage engagement lifecycle and transitions."""

    # GAP-2-6: hard ceiling on how long a single agent shutdown may block during halt.
    HALT_DEADLINE_SECONDS = 10

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator

    async def create_engagement(
        self, scope: ScopeDefinition, roe: Dict[str, Any], created_by: Optional[str] = None
    ) -> SessionState:
        """Create new engagement session."""
        try:
            return await self._create_engagement_unsafe(scope, roe, created_by)
        except Exception as e:
            logger.error("engagement_creation_failed", error=str(e), exc_info=True)
            raise

    async def _create_engagement_unsafe(
        self, scope: ScopeDefinition, roe: Dict[str, Any], created_by: Optional[str] = None
    ) -> SessionState:
        with trace_span(
            "orchestrator.create_engagement",
            attributes={
                "engagement_id": scope.engagement_id,
                "created_by": created_by or "system",
            },
        ):
            # GAP-2-4: sign the scope manifest at creation so it is tamper-evident.
            # Unsigned scopes are signed here; an externally-supplied signature is
            # left intact (and later verified on exploit assignment).
            if not scope.signature:
                from ai_osop.core.config import scope_signing_key

                scope.sign(scope_signing_key())
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

            # GAP-2-6: a kill switch must actually STOP work, not just flip statuses.
            handles = getattr(self._orch, "_task_handles", {})
            for task in self._orch._tasks.values():
                if task.engagement_id == session_id and task.status in ["pending", "running"]:
                    task.status = "cancelled"
                    # Cancel the in-flight execution coroutine (may be mid-agent-call).
                    handle = handles.pop(task.id, None)
                    if handle is not None and not handle.done():
                        handle.cancel()

            # Drain any queued tasks for this engagement so the scheduler can't pull
            # and dispatch them after the halt (bounded so a flood can't spin forever).
            try:
                for _ in range(1000):
                    item = await self._orch.session_memory.pop_task_queue(f"tasks:{session_id}")
                    if not item:
                        break
            except Exception as e:
                logger.warning("halt_queue_drain_failed", session_id=session_id, error=str(e))

            # LIFECYCLE FIX (2026-07-11): agents are SHARED long-lived workers.
            # The old code called agent.shutdown() which permanently killed them,
            # and the orchestrator main loop (line 727-728) then unregistered them
            # from the pool — causing cumulative worker depletion.  Task handles
            # are already cancelled above (lines 101-108) which interrupts the
            # agent's _execute() via CancelledError.  Here we just reset any
            # agent that was mid-task for this engagement back to idle so it can
            # accept work from the next engagement.
            for agent in self._orch._agents.values():
                if (
                    agent.ctx.session_id == session_id
                    and agent.ctx.status == "running"
                ):
                    agent.ctx.current_task = None
                    agent.ctx.status = "idle"
                    logger.info(
                        "agent_released_from_halted_engagement",
                        agent_id=agent.ctx.agent_id,
                        session_id=session_id,
                    )
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
        # GAP-3-4: compare-and-set. The validation above can await (graph stats), so a
        # concurrent writer (e.g. halt_engagement) may have changed the phase in the
        # meantime. Re-check before committing so we never clobber a halt/transition
        # that landed during the await window.
        if EngagementPhase(session.phase) != current:
            raise WorkflowTransitionError(
                f"Concurrent phase change detected: expected {current.value}, "
                f"now {session.phase}; aborting transition to {new_phase.value}"
            )
        session.phase = new_phase.value

        # AIOSOP-PHASE-ENTER-FIRST: run _on_phase_enter BEFORE persisting the
        # phase change so that if task scheduling fails the phase is not left in a
        # partially-applied state (the auto-transition will retry). On success,
        # persist and audit-log. On failure, revert the in-memory phase (and do
        # NOT update updated_at) so the monitor retries naturally.
        try:
            await self._orch.phase_monitor._on_phase_enter(session, new_phase)
        except Exception:
            logger.exception("on_phase_enter_failed", session_id=session_id, phase=new_phase.value)
            session.phase = current.value
            raise WorkflowException(
                f"Phase entry hook failed for {new_phase.value}: see logs for details"
            )

        session.updated_at = datetime.utcnow()
        await self._orch.session_memory.store_session_state(session)
        await self._orch.session_memory.persist_session_state(session)
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

    @staticmethod
    def _domain_to_url(domain: str) -> str:
        """Build the discovery URL from a scope domain, choosing a sane scheme.

        Real bounty targets are HTTPS, but localhost/private-range test targets
        (e.g. a local Juice Shop on :3000) are HTTP; forcing https:// there yields
        net::ERR_SSL_PROTOCOL_ERROR and kills the autonomous run at navigation
        (surfaced by the autonomous benchmark, 2026-07-04). Respect an explicit
        scheme if the operator provided one.
        """
        d = (domain or "").strip()
        if d.startswith(("http://", "https://")):
            return d if d.endswith("/") else d + "/"
        host = d.split("/")[0].split(":")[0].lower()
        is_local = (
            host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
            or host.startswith(("10.", "192.168."))
            or (
                host.startswith("172.")
                and host.count(".") >= 1
                and host.split(".")[1].isdigit()
                and 16 <= int(host.split(".")[1]) <= 31
            )
        )
        scheme = "http" if is_local else "https"
        return f"{scheme}://{d}/"

    async def _engagement_is_authenticated(self, engagement_id: str) -> bool:
        """Check whether the engagement has an authenticated session."""
        try:
            records = await self._orch.graph_memory.run_read_query(
                "MATCH (s:Session {engagement_id: $eid}) RETURN s.authenticated as authenticated",
                {"eid": engagement_id},
            )
            if records:
                return bool(records[0].get("authenticated"))
            return False
        except Exception:
            return False

    async def _pick_auth_user_label(self, engagement_id: str) -> Optional[str]:
        """Pick a stable user label for authenticated discovery."""
        try:
            records = await self._orch.graph_memory.run_read_query(
                "MATCH (s:Session {engagement_id: $eid}) RETURN s.username as username",
                {"eid": engagement_id},
            )
            if records:
                return records[0].get("username")
            return None
        except Exception:
            return None

    async def claim_auto_discovery(
        self,
        engagement_id: str,
        auth_user_label: str,
        source_task_id: str,
        url_hint: Optional[str] = None,
    ) -> Optional[Task]:
        """Atomically claim autonomous discovery and dispatch a single map_workflow.

        GAP-4-2: the claim is an atomic Neo4j MERGE (graph_memory.claim_auto_discovery),
        so concurrent hooks and restarted processes cannot both win — replacing the
        former non-atomic MATCH-then-CREATE that could create duplicate claims/chains.

        GAP-1-5: on winning the claim we schedule the map_workflow directly here,
        replacing the call to the never-defined _schedule_authenticated_discovery that
        raised AttributeError (silently swallowed) on the live path."""
        won = await self._orch.graph_memory.claim_auto_discovery(engagement_id)
        if not won:
            logger.info("auto_discovery_already_claimed", engagement_id=engagement_id)
            return None

        url = url_hint or ""
        if not url:
            session = self._orch._sessions.get(engagement_id)
            if session and getattr(session, "scope", None) and session.scope.domains:
                url = self._domain_to_url(session.scope.domains[0])

        task = Task(
            type="map_workflow",
            priority=7,
            agent_type=AgentType.WORKFLOW,
            payload={
                "url": url,
                "user_label": auth_user_label,
                "name": "Auto Authenticated Journey",
                "source_task_id": source_task_id,
            },
            engagement_id=engagement_id,
        )
        await self._orch._audit_log(
            AuditEvent(
                event_type="auto_map_dispatch",
                severity="info",
                actor_type="system",
                actor_id="orchestrator",
                action={"created_task_id": task.id, "user_label": auth_user_label, "url": url},
                result={"success": True},
                context={"engagement_id": engagement_id},
                engagement_id=engagement_id,
            )
        )
        await self._orch.schedule_task(task)
        logger.info("auto_map_dispatched", task_id=task.id, engagement_id=engagement_id, url=url)
        return task

    async def ensure_authenticated_discovery(
        self, session_id: str, url_hint: Optional[str] = None
    ) -> Optional[Task]:
        """Schedule authenticated discovery (one map_workflow) if the engagement has an
        authenticated session. Idempotent via the atomic claim. Returns the task or None."""
        if not await self._engagement_is_authenticated(session_id):
            return None
        auth_user_label = await self._pick_auth_user_label(session_id)
        if not auth_user_label:
            return None
        return await self.claim_auto_discovery(
            session_id, auth_user_label, "session-import", url_hint=url_hint
        )
