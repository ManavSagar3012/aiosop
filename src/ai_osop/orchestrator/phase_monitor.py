"""PhaseMonitor — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles phase monitoring and automatic task dispatch on phase entry.
"""

from __future__ import annotations
import asyncio

from typing import Any, Dict, List

import structlog

from ai_osop.core.config import AgentType, EngagementPhase, settings
from ai_osop.core.models import SessionState, Task
from ai_osop.core.tracing import trace_span
from ai_osop.core.value_engine import batch_endpoints_for_scan

logger = structlog.get_logger("ai_osop.orchestrator.phase_monitor")


class PhaseMonitor:
    """Monitor engagement phases and trigger automatic tasks on phase entry."""

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator
        self._tick = 0

    async def _auto_advance_phase(self, session: SessionState) -> None:
        """Evaluate and advance the phase for a single session if tasks are complete."""
        session_id = session.session_id
        phase = EngagementPhase(session.phase)
        policy = self._orch.PHASE_POLICY.get(phase)

        if policy and policy.get("auto_next"):
            # Check if all tasks for current phase are complete
            if await self._orch._is_phase_complete(session_id, phase):
                next_phase = await self._orch._resolve_auto_next(
                    session_id, phase, policy["auto_next"]
                )
                if next_phase is None:
                    return
                if not self._orch._auto_transition_ready(session_id, phase, self._tick):
                    return
                try:
                    await self._orch.engagement_manager.transition_phase(session_id, next_phase)
                    logger.info(
                        "auto_transition", session_id=session_id, phase=next_phase.value
                    )
                    self._orch._auto_transition_failures.pop(session_id, None)
                except Exception as e:
                    self._orch._record_auto_transition_failure(session_id, phase, self._tick, e)

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
            # Sprint 15A/15B + nuclei self-heal (AIOSOP-NUCLEI-TIMEOUT/FANOUT-2026-06-24).
            # NOTE: this is the LIVE phase-entry implementation (Orchestrator._on_phase_enter
            # delegates here). Scans the discovered ENDPOINT surface ranked by the Attack
            # Surface Value Engine, batched into a BOUNDED number of high-value nuclei jobs,
            # with task timeouts aligned to nuclei_mcp_timeout and severity scoping so scans
            # complete instead of being killed at the 300s default and retry-storming.

            # 1) Per-asset Burp scan (Burp crawls from the host root).
            assets: List[str] = []
            async with self._orch.graph_memory._driver.session() as g_session:
                result = await g_session.run(
                    "MATCH (a:Asset {engagement_id: $sid}) RETURN a.value as domain",
                    {"sid": session.session_id},
                )
                async for record in result:
                    assets.append(record["domain"])

            for domain in assets:
                burp_task = Task(
                    type="burp_scan",
                    priority=7,
                    agent_type=AgentType.VULN_ANALYSIS,
                    payload={"url": f"https://{domain}"},
                    engagement_id=session.session_id,
                    timeout_seconds=600,
                )
                await self._orch.task_scheduler.schedule_task(burp_task)

            # 2) Endpoint-aware, value-ordered, batched Nuclei scans.
            endpoints: List[Dict[str, Any]] = []
            async with self._orch.graph_memory._driver.session() as g_session:
                result = await g_session.run(
                    """MATCH (e:Endpoint {engagement_id: $sid})
                       RETURN e.url AS url, e.method AS method,
                              e.status_code AS status_code, e.technologies AS technologies""",
                    {"sid": session.session_id},
                )
                async for r in result:
                    if r["url"]:
                        endpoints.append({
                            "url": r["url"],
                            "method": r["method"] or "GET",
                            "status_code": r["status_code"],
                            "technologies": r["technologies"] or [],
                        })

            batches = batch_endpoints_for_scan(endpoints, batch_size=20, max_targets=200)
            if batches:
                logger.info(
                    "value_batched_scan",
                    session_id=session.session_id,
                    endpoints=len(endpoints),
                    batches=len(batches),
                )
                for i, batch in enumerate(batches):
                    nuclei_task = Task(
                        type="nuclei_scan",
                        priority=9 if i == 0 else 7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={
                            "targets": batch,
                            "severity": "critical,high,medium",
                            "batch_index": i,
                        },
                        engagement_id=session.session_id,
                        timeout_seconds=settings.nuclei_mcp_timeout + 120,
                    )
                    await self._orch.task_scheduler.schedule_task(nuclei_task)
            else:
                for domain in assets:
                    nuclei_task = Task(
                        type="nuclei_scan",
                        priority=7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={
                            "targets": [f"https://{domain}"],
                            "severity": "critical,high,medium",
                        },
                        engagement_id=session.session_id,
                        timeout_seconds=settings.nuclei_mcp_timeout + 120,
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
                await asyncio.sleep(10)
                self._tick += 1
                for session in list(self._orch._sessions.values()):
                    await self._auto_advance_phase(session)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("phase_monitor_error", error=str(e))
