"""PhaseMonitor — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles phase monitoring and automatic task dispatch on phase entry.
"""

from __future__ import annotations

from typing import Any

import structlog

from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.models import SessionState, Task
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger("ai_osop.orchestrator.phase_monitor")


class PhaseMonitor:
    """Monitor engagement phases and trigger automatic tasks on phase entry."""

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator

    async def _on_phase_enter(self, session: SessionState, phase: EngagementPhase) -> None:
        """Trigger automatic tasks when entering a phase."""
        if phase == EngagementPhase.RECONNAISSANCE:
            for domain in session.scope.domains:
                task = Task(
                    type="full_recon",
                    priority=5,
                    agent_type=AgentType.RECON,
                    payload={"domain": domain, "scope": session.scope.model_dump()},
                    engagement_id=session.session_id,
                )
                await self._orch.task_scheduler.schedule_task(task)
            url_hint = f"https://{session.scope.domains[0]}/" if session.scope.domains else None
            await self._orch.engagement_manager.ensure_authenticated_discovery(
                session.session_id, url_hint=url_hint
            )

        elif phase == EngagementPhase.VULNERABILITY_DISCOVERY:
            cypher = "MATCH (a:Asset {engagement_id: $sid}) RETURN a.value as domain"
            async with self._orch.graph_memory._driver.session() as g_session:
                result = await g_session.run(cypher, {"sid": session.session_id})
                async for record in result:
                    domain = record["domain"]
                    burp_task = Task(
                        type="burp_scan",
                        priority=7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={"url": f"https://{domain}"},
                        engagement_id=session.session_id,
                    )
                    await self._orch.task_scheduler.schedule_task(burp_task)
                    nuclei_task = Task(
                        type="nuclei_scan",
                        priority=7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={"targets": [f"https://{domain}"]},
                        engagement_id=session.session_id,
                    )
                    await self._orch.task_scheduler.schedule_task(nuclei_task)

        elif phase == EngagementPhase.EXPLOITATION:
            cypher = "MATCH (v:Vulnerability {engagement_id: $sid}) RETURN v.id as vuln_id"
            vuln_ids = []
            async with self._orch.graph_memory._driver.session() as g_session:
                result = await g_session.run(cypher, {"sid": session.session_id})
                async for record in result:
                    vuln_ids.append(record["vuln_id"])
            logger.info(
                "exhaustive_mode", session_id=session.session_id, vuln_count=len(vuln_ids)
            )
            for vid in vuln_ids:
                endpoint_url = await self._orch.graph_memory.get_endpoint_url_for_vulnerability(vid)
                task = Task(
                    type="exploit_validation",
                    priority=9,
                    agent_type=AgentType.EXPLOIT_VALIDATION,
                    approval_required=True,
                    payload={
                        "target": endpoint_url,
                        "vulnerability_id": vid,
                        "operator_approved": False,
                        "approval_id": f"auto-{vid}",
                    },
                    engagement_id=session.session_id,
                )
                await self._orch.task_scheduler.schedule_task(task)

        elif phase == EngagementPhase.REPORTING:
            task = Task(
                type="generate_report",
                priority=10,
                agent_type=AgentType.REPORTING,
                payload={"format": "markdown", "detail_level": "high"},
                engagement_id=session.session_id,
            )
            await self._orch.task_scheduler.schedule_task(task)

    async def _phase_monitor(self) -> None:
        """Background phase monitor: periodically check for phase advancement conditions."""
        while self._orch._running:
            try:
                await self._orch._phase_monitor_sleep()
                for session in list(self._orch._sessions.values()):
                    await self._auto_advance_phase(session)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("phase_monitor_error", error=str(e))
