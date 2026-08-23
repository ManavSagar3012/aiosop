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
                    logger.info("auto_transition", session_id=session_id, phase=next_phase.value)
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
            url_hint = (
                self._orch.engagement_manager._domain_to_url(session.scope.domains[0])
                if session.scope.domains
                else None
            )
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
            asset_records = await self._orch.graph_memory.run_read_query(
                "MATCH (a:Asset {engagement_id: $sid}) RETURN a.value as domain",
                {"sid": session.session_id},
            )
            for record in asset_records:
                domain = record.get("domain")
                if domain:
                    assets.append(domain)

            for domain in assets:
                burp_task = Task(
                    type="burp_scan",
                    priority=7,
                    agent_type=AgentType.VULN_ANALYSIS,
                    payload={"url": self._orch.engagement_manager._domain_to_url(domain)},
                    engagement_id=session.session_id,
                    timeout_seconds=600,
                )
                await self._orch.task_scheduler.schedule_task(burp_task)

            # 2) Endpoint-aware, value-ordered, batched Nuclei scans.
            endpoints: List[Dict[str, Any]] = []
            # Only scan endpoints confirmed reachable by a probe (status_code set).
            # Seed endpoints (e.g. the scope domain seeded as https:// for recon to
            # start from) and failed probes carry a NULL status_code; feeding those
            # to nuclei made every template TLS-timeout against a dead scheme,
            # roughly doubling scan wall-time for zero added coverage.
            endpoint_records = await self._orch.graph_memory.run_read_query(
                """MATCH (e:Endpoint {engagement_id: $sid})
                   WHERE e.status_code IS NOT NULL
                   RETURN e.url AS url, e.method AS method,
                          e.status_code AS status_code, e.technologies AS technologies""",
                {"sid": session.session_id},
            )
            for r in endpoint_records:
                if r.get("url"):
                    endpoints.append(
                        {
                            "url": r["url"],
                            "method": r.get("method") or "GET",
                            "status_code": r.get("status_code"),
                            "technologies": r.get("technologies") or [],
                        }
                    )

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
                            "severity": "critical,high,medium,info",
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
                            "targets": [self._orch.engagement_manager._domain_to_url(domain)],
                            "severity": "critical,high,medium,info",
                        },
                        engagement_id=session.session_id,
                        timeout_seconds=settings.nuclei_mcp_timeout + 120,
                    )
                    await self._orch.task_scheduler.schedule_task(nuclei_task)

            # 3) Autonomous authenticated authorization testing — IDOR / BOLA /
            #    broken access control / horizontal + vertical privilege escalation.
            #    Runs only when the engagement has stored credentials. The
            #    diff-auth engine replays each captured API endpoint as
            #    user_a / user_b / anonymous and flags cross-identity access;
            #    high-confidence findings are bridged to CONFIRMED vulnerabilities.
            try:
                sessions = await self._orch.session_store.list_sessions(session.session_id)
            except Exception as e:  # noqa: BLE001 - session lookup must not break phase entry
                sessions = []
                logger.warning(
                    "authz_session_lookup_failed",
                    session_id=session.session_id,
                    error=str(e),
                )

            if sessions:
                labels = [s.user_label for s in sessions]
                primary = session.scope.domains[0] if session.scope.domains else None
                # 3a) Map the authenticated API surface (-> Endpoint{type:'api'}
                #     nodes carrying object IDs the diff-auth engine will test).
                surface_task = Task(
                    type="capture_authenticated_surface",
                    priority=8,
                    agent_type=AgentType.WORKFLOW,
                    payload={
                        "engagement_id": session.session_id,
                        "user_label": labels[0],
                        "url": (
                            self._orch.engagement_manager._domain_to_url(primary)
                            if primary
                            else None
                        ),
                    },
                    engagement_id=session.session_id,
                    timeout_seconds=300,
                )
                await self._orch.task_scheduler.schedule_task(surface_task)

                # 3b) Differential-authorization replay (depends on the surface
                #     capture). With a single stored identity it still runs the
                #     user-vs-anonymous comparison; with two it adds the
                #     user_a-vs-user_b IDOR/BOLA test.
                user_a = labels[0]
                user_b = labels[1] if len(labels) > 1 else labels[0]
                diff_task = Task(
                    type="run_diff_auth_analysis",
                    priority=8,
                    agent_type=AgentType.WORKFLOW,
                    payload={
                        "engagement_id": session.session_id,
                        "user_a": user_a,
                        "user_b": user_b,
                    },
                    engagement_id=session.session_id,
                    dependencies=[surface_task.id],
                    timeout_seconds=300,
                )
                await self._orch.task_scheduler.schedule_task(diff_task)
                logger.info(
                    "authz_testing_scheduled",
                    session_id=session.session_id,
                    sessions=len(labels),
                    user_a=user_a,
                    user_b=user_b,
                )
            else:
                logger.info(
                    "authz_testing_skipped_no_sessions",
                    session_id=session.session_id,
                )

        elif phase == EngagementPhase.EXPLOITATION:
            # AIOSOP-EXPLOIT-FILTER-001: only attempt exploit-validation on findings that
            # are plausibly exploitable. Info/low/unknown-severity detections (e.g. the
            # SSL/DNS informational nuclei templates) are never exploitable; creating an
            # approval-gated exploit task per such finding floods the operator (observed:
            # 58 info findings -> 58 high-risk approvals) and produces spurious traffic to
            # the target. Gate on severity; carry severity into the payload so the approval
            # risk is derived (not hardcoded) downstream.
            EXPLOITABLE_SEVERITIES = {"critical", "high", "medium"}
            # AIOSOP-FP-CATCHALL-001: findings below this confidence (e.g. catch-all
            # false positives the vuln agent down-ranked to ~0.2) are NOT auto-exploited.
            # They still appear in the report, but a human must confirm before the
            # platform throws payloads at what is probably a wildcard/catch-all artifact.
            MIN_EXPLOIT_CONFIDENCE = 0.4
            cypher = (
                "MATCH (v:Vulnerability {engagement_id: $sid}) "
                "RETURN v.id AS vuln_id, coalesce(v.severity, 'unknown') AS severity, "
                "coalesce(v.confidence, 1.0) AS confidence"
            )
            vuln_records = await self._orch.graph_memory.run_read_query(
                cypher, {"sid": session.session_id}
            )
            candidates = [
                (
                    r.get("vuln_id"),
                    str(r.get("severity", "")).strip().lower(),
                    float(r.get("confidence", 1.0) or 0.0),
                )
                for r in vuln_records
                if r.get("vuln_id")
            ]
            exploitable = [
                (vid, sev)
                for vid, sev, conf in candidates
                if sev in EXPLOITABLE_SEVERITIES and conf >= MIN_EXPLOIT_CONFIDENCE
            ]
            skipped_low_conf = sum(
                1
                for _vid, sev, conf in candidates
                if sev in EXPLOITABLE_SEVERITIES and conf < MIN_EXPLOIT_CONFIDENCE
            )
            logger.info(
                "exhaustive_mode",
                session_id=session.session_id,
                vuln_count=len(candidates),
                exploitable=len(exploitable),
                skipped_non_exploitable=len(candidates) - len(exploitable),
                skipped_low_confidence=skipped_low_conf,
            )
            for vid, sev in exploitable:
                endpoint_url = await self._orch.graph_memory.get_endpoint_url_for_vulnerability(vid)
                vuln_details = await self._orch.graph_memory.get_node_details(vid) or {}
                vuln_type = (
                    vuln_details.get("vuln_type") or vuln_details.get("classification") or "sqli"
                )

                # 1. Generate adaptive payloads for this vulnerability
                payload_task = Task(
                    type="generate_payloads",
                    priority=9,
                    agent_type=AgentType.PAYLOAD_MUTATION,
                    payload={
                        "vuln_type": vuln_type,
                        "context": {
                            "url": endpoint_url,
                            "vulnerability_id": vid,
                            "engagement_id": session.session_id,
                        },
                        "count": 5,
                    },
                    engagement_id=session.session_id,
                )
                await self._orch.task_scheduler.schedule_task(payload_task)

                # 2. Schedule exploit validation with dependency on payload generation
                exploit_task = Task(
                    type="exploit_validation",
                    priority=9,
                    agent_type=AgentType.EXPLOIT_VALIDATION,
                    approval_required=True,
                    payload={
                        "target": endpoint_url,
                        "vulnerability_id": vid,
                        "severity": sev,
                        "operator_approved": False,
                    },
                    engagement_id=session.session_id,
                    dependencies=[payload_task.id],
                )
                await self._orch.task_scheduler.schedule_task(exploit_task)

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
