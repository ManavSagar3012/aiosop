"""PhaseMonitor — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles phase monitoring and automatic task dispatch on phase entry.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import structlog

from ai_osop.core.config import AgentType, EngagementPhase, settings
from ai_osop.core.models import SessionState, Task
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

        if policy and policy.get("automatic_next_phase"):
            # AEGIS-RT v2 (2026-08-29): enforce `requires_manual_approval` at runtime.
            # The flag previously lived only in config as documentation — no code path
            # read it, so an operator-gated phase auto-advanced the moment its tasks
            # finished. Now: unless OSOP_AUTO_ADVANCE_ALL=1 (full autonomy mode), a
            # phase that requires manual approval will NOT auto-advance; it parks and
            # waits for the operator to call POST /engagements/{id}/transition. This is
            # the safety counterweight to the new full auto-advance chain in
            # PHASE_POLICY. (phase_monitor.py:31)
            if policy.get("requires_manual_approval") and not getattr(
                self._orch, "_auto_advance_all", False
            ):
                return
            # Check if all tasks for current phase are complete
            if await self._orch._is_phase_complete(session_id, phase):
                next_phase = await self._orch._resolve_auto_next(
                    session_id, phase, policy["automatic_next_phase"]
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
                    timeout_seconds=900,
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
            # AEGIS-RT v2 (2026-08-29): prime a new engagement with semantic memory
            # of past confirmed findings, so recon/vuln agents benefit from "what
            # worked before". Best-effort: if the RetrievalAgent isn't registered or
            # pgvector is down, the task errors harmlessly and recon continues.
            recall_task = Task(
                type="recall_findings",
                priority=3,
                agent_type=AgentType.RETRIEVAL,
                payload={
                    "query": session.scope.domains[0] if session.scope.domains else "",
                    "limit": 5,
                },
                engagement_id=session.session_id,
                timeout_seconds=60,
            )
            await self._orch.task_scheduler.schedule_task(recall_task)

        elif phase == EngagementPhase.VULNERABILITY_DISCOVERY:
            # Sprint 15A/15B + nuclei self-heal (AIOSOP-NUCLEI-TIMEOUT/FANOUT-2026-06-24).
            # NOTE: this is the LIVE phase-entry implementation (Orchestrator._on_phase_enter
            # delegates here). Scans the discovered ENDPOINT surface ranked by the Attack
            # Surface Value Engine, batched into a BOUNDED number of high-value nuclei jobs,
            # with task timeouts aligned to nuclei_mcp_timeout and severity scoping so scans
            # complete instead of being killed at the 300s default and retry-storming.

            # 1) Per-asset Burp scan (Burp crawls from the host root).
            assets: List[str] = []
            try:
                asset_records = await asyncio.wait_for(
                    self._orch.graph_memory.run_read_query(
                        "MATCH (a:Asset {engagement_id: $sid}) RETURN a.value as domain",
                        {"sid": session.session_id},
                    ),
                    timeout=10.0,
                )
                for record in asset_records:
                    domain_val = record.get("domain")
                    if domain_val:
                        assets.append(domain_val)
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning("asset_graph_query_failed", error=str(e))

            # Fallback: if no assets in graph, seed from scope domains
            if not assets and session.scope.domains:
                assets = list(session.scope.domains)
                logger.info("vuln_phase_seeded_from_scope", domains=assets)

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

                # WEB-AUDIT-001: integrated crawl -> probe -> differential audit per
                # asset — the open-components active-scan button (katana crawl +
                # in-process probe injection + behavioral-delta judgment). It
                # complements burp_scan (proxy-based) and nuclei (template-based)
                # with parameter-level differential coverage.
                web_audit_task = Task(
                    type="web_audit",
                    priority=6,
                    agent_type=AgentType.VULN_ANALYSIS,
                    payload={
                        "url": self._orch.engagement_manager._domain_to_url(domain),
                        "max_urls": 25,
                        "classes": ["sqli", "xss", "ssti"],
                    },
                    engagement_id=session.session_id,
                    timeout_seconds=900,
                )
                await self._orch.task_scheduler.schedule_task(web_audit_task)

            # 2) Endpoint-aware, value-ordered, batched Nuclei scans.
            endpoints: List[Dict[str, Any]] = []
            # Only scan endpoints confirmed reachable by a probe (status_code set).
            # Seed endpoints (e.g. the scope domain seeded as https:// for recon to
            # start from) and failed probes carry a NULL status_code; feeding those
            # to nuclei made every template TLS-timeout against a dead scheme,
            # roughly doubling scan wall-time for zero added coverage.
            try:
                endpoint_records = await asyncio.wait_for(
                    self._orch.graph_memory.run_read_query(
                        """MATCH (e:Endpoint {engagement_id: $sid})
                           WHERE e.status_code IS NOT NULL
                           RETURN e.url AS url, e.method AS method,
                                  e.status_code AS status_code, e.technologies AS technologies""",
                        {"sid": session.session_id},
                    ),
                    timeout=10.0,
                )
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning("endpoint_graph_query_failed", error=str(e))
                endpoint_records = []
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

            # AIOSOP-GOLDEN-001 (2026-08-30): login/authenticated-form SQLi
            # differential scan. sqlmap's query-string playbook cannot cover a
            # body parameter (login forms), so once recon has surfaced an
            # authentication-form endpoint we dispatch sqli_http_scan — a
            # deterministic control-vs-injection probe that mints a VALIDATED
            # finding without any external tooling.
            try:
                _form_records = await asyncio.wait_for(
                    self._orch.graph_memory.run_read_query(
                        """MATCH (e:Endpoint {engagement_id: $sid})
                           WHERE toLower(coalesce(e.url, '')) CONTAINS 'login'
                              OR toLower(coalesce(e.url, '')) CONTAINS 'signin'
                              OR toLower(coalesce(e.url, '')) CONTAINS 'auth'
                              OR toLower(coalesce(e.path, '')) CONTAINS 'login'
                              OR toLower(coalesce(e.path, '')) CONTAINS 'signin'
                              OR toLower(coalesce(e.path, '')) CONTAINS 'auth'
                              OR toLower(coalesce(e.path, '')) CONTAINS 'authenticate'
                              OR toLower(coalesce(e.path, '')) CONTAINS 'account'
                           RETURN e.url AS url""",
                        {"sid": session.session_id},
                    ),
                    timeout=10.0,
                )
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning("login_endpoint_graph_query_failed", error=str(e))
                _form_records = []

            _seen_login_urls: set = set()
            _LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "authenticate", "account")
            for _r in _form_records:
                _u = (_r.get("url") or "").strip()
                # Defense in depth: re-verify the login-form heuristic in Python
                # rather than trusting the graph query to filter. A recon record
                # that surfaced via another query must not be auto-scanned.
                _ul = _u.lower()
                if not _u or _u in _seen_login_urls or not any(_h in _ul for _h in _LOGIN_HINTS):
                    continue
                _seen_login_urls.add(_u)
                _sqli_task = Task(
                    type="sqli_http_scan",
                    priority=8,
                    agent_type=AgentType.VULN_ANALYSIS,
                    payload={"url": _u, "engagement_id": session.session_id},
                    engagement_id=session.session_id,
                    timeout_seconds=90,
                )
                await self._orch.task_scheduler.schedule_task(_sqli_task)
                logger.info(
                    "sqli_http_scan_scheduled",
                    session_id=session.session_id,
                    url=_u,
                )

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
