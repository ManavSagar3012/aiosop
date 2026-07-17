"""PhaseMonitor — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles phase monitoring and automatic task dispatch on phase entry.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.config import AgentType, EngagementPhase, VulnClass, settings
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.knowledge_engine import get_knowledge_engine
from ai_osop.core.models import AuditEvent, SessionState, Task
from ai_osop.core.value_engine import batch_endpoints_for_scan
from ai_osop.orchestrator.state_machine import EngagementStateMachine

logger = structlog.get_logger("ai_osop.orchestrator.phase_monitor")

from ai_osop.core.url_intelligence import _is_probable_param_key


class PhaseMonitor:
    """Monitor engagement phases and trigger automatic tasks on phase entry."""

    # sqlmap itself is bounded to 180 seconds by VulnAnalysisAgent (timeout_override),
    # but the task budget must cover the WHOLE agent turn: applicability check,
    # session/scope init, multi-step LLM reasoning, outbound network wait (~97s
    # observed against slow/remote targets), and potential multi-pass sqlmap probing.
    #
    # Empirical timeline on ginandjuice.shop (external target):
    #   120s budget  → cancelled at 120s, 0/25 sqli completed (pre-fix baseline)
    #   300s budget  → cancelled at 300s, 0/25 sqli completed (too short)
    #   600s budget  → cancelled at ~690s*, 0/25 sqli completed (*actual runtime)
    #   534s runtime → 1 sqli completed (eng-20260711025504, favorable run)
    #   ~690s runtime → consistent actual need against slow external target
    #
    # The scan needs ~650-700s of wall-clock time (sqlmap 180s inner + LLM multi-step
    # + ~97s network wait per request + session initialization). Setting 900s (the
    # same ceiling as the Nuclei budget) gives a generous margin without allowing
    # stalled SQLi jobs to occupy vuln-analysis workers indefinitely.
    # (AIOSOP-SQLI-BUDGET-003)
    # DEV-OVERRIDE-001 (2026-07-12): Drastically reduced from 900s → 240s and 600s →
    # 120s for development iteration speed. The sqlmap inner timeout_override is 180s,
    # so the task ceiling is 180s plus margin for LLM reasoning (45s ceiling) and
    # session init. 240s provides ~15s of headroom. With MCP stubs responding in
    # <30ms, even this is generous. Restore to 900/600 for production or slow
    # external targets.
    SQLI_TASK_TIMEOUT_SECONDS = 900

    # AIOSOP-ACTIVE-INJECTION-TIMEOUT-001 (2026-07-11): XSS, CSRF, JWT, and other
    # active scanners were hardcoded at 300s which caused them to be reaped before
    # completion against slow external targets (observed: xss task retry_count=1 at
    # 300s ceiling). Raising to 600s matches the burp_scan budget and gives scanners
    # adequate wall-clock time against remote targets.
    ACTIVE_SCAN_TIMEOUT_SECONDS = 600

    # These scanners are the execution path for vulnerability discovery.  Do not
    # enter the phase when a registered critical service is unavailable: otherwise
    # the phase can appear complete without having performed a real scan.
    _CRITICAL_VULN_MCP_SERVERS = ("nuclei-mcp", "burp-mcp")

    def __init__(
        self, orchestrator: Any, state_machine: Optional[EngagementStateMachine] = None
    ) -> None:
        self._orch = orchestrator
        self.state_machine = state_machine or getattr(
            orchestrator, "engagement_state_machine", None
        )
        self._tick = 0

    @staticmethod
    def _select_injection_targets(
        records: List[Dict[str, Any]], max_targets: int = 25
    ) -> List[Dict[str, Any]]:
        """One representative injectable URL per (path, parameter-set).

        Collapses e.g. productId=1..18 into a single scan target.  Targets must
        contain parameters observed in a concrete URL; graph metadata alone is
        never turned into a synthetic request.  Bounded so the active-scan phase
        stays time-boxed.
        """
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        # Param names classically worth injecting first. Generic (not app-specific)
        # so the cap keeps the highest-value targets in any engagement rather than
        # whichever ones happen to appear first in the recon records.
        INJECTABLE_HINTS = (
            "id",
            "product",
            "cat",
            "search",
            "term",
            "query",
            "q",
            "name",
            "user",
            "file",
            "page",
            "sort",
            "order",
            "email",
            "url",
            "redirect",
        )

        def _score(param_names: tuple) -> int:
            s = len(param_names)  # more params -> more surface
            for p in param_names:
                pl = p.lower()
                if any(h in pl for h in INJECTABLE_HINTS):
                    s += 5
            return s

        def _build_body(keys: List[str], content_type: str) -> str:
            """A whitespace-free injectable body (per the bridge sanitizer). sqlmap
            fuzzes each value; JSON bodies (e.g. a JSON login API) get a compact
            JSON object so sqlmap auto-detects application/json, form bodies get a
            urlencoded pair set."""
            if "json" in (content_type or "").lower():
                return json.dumps({k: "test" for k in keys}, separators=(",", ":"))
            return "&".join(f"{k}=test" for k in keys)

        seen: set = set()
        scored: List[tuple] = []
        for r in records:
            url = r.get("url")
            if not url:
                continue
            parsed = urlparse(url)
            method = r.get("method") or "GET"

            # (a) GET/query-string injectable params.
            q = {
                k: v
                for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                if _is_probable_param_key(k)
            }
            if q:
                param_names = tuple(sorted(q.keys()))
                key = (parsed.path, param_names)
                if key not in seen:
                    seen.add(key)
                    target_url = urlunparse(parsed._replace(query=urlencode(q)))
                    scored.append(
                        (
                            _score(param_names),
                            {
                                "url": target_url,
                                "method": method,
                                "technologies": r.get("technologies") or [],
                            },
                        )
                    )

            # (b) POST/PUT/PATCH body params. Recon records these as body_schema_keys
            # with has_body=true; without this branch a body-only injectable — e.g. a
            # JSON login's `email` — is never scanned, since the URL carries no '?'.
            body_keys = [k for k in (r.get("body_keys") or []) if _is_probable_param_key(k)]
            if r.get("has_body") and body_keys:
                bparam_names = tuple(sorted(body_keys))
                bkey = (parsed.path, ("__body__",) + bparam_names)
                if bkey not in seen:
                    seen.add(bkey)
                    scored.append(
                        (
                            _score(bparam_names),
                            {
                                "url": urlunparse(parsed._replace(query="")),
                                # A body implies a state-changing verb; never GET.
                                "method": method if method != "GET" else "POST",
                                "data": _build_body(body_keys, r.get("content_type") or ""),
                                "technologies": r.get("technologies") or [],
                            },
                        )
                    )
        # Highest injectability first (stable within equal scores), then cap so the
        # active-scan phase converges: 25 targets x ~4 scanners x ~240s / ~13 agents
        # drained >> the 1200s window; a smaller high-value set finishes in time.
        scored.sort(key=lambda t: t[0], reverse=True)
        return [t[1] for t in scored[:max_targets]]

    def _assert_vulnerability_mcp_ready(self) -> None:
        """Fail phase entry when a configured critical scanner is not usable.

        An empty registry is tolerated for isolated unit tests and deployments
        which intentionally run without MCP scanners.  Once MCP connections are
        registered, though, silently proceeding with an open/uninitialized
        nuclei or Burp connection would create a hollow discovery phase.
        """
        registry = self._orch.mcp_registry
        servers = getattr(registry, "_servers", {})
        if not servers:
            logger.warning("vuln_mcp_readiness_skipped_no_registered_servers")
            return

        unavailable: List[str] = []
        for server_id in self._CRITICAL_VULN_MCP_SERVERS:
            connection = registry.get_server(server_id)
            if connection is None:
                unavailable.append(f"{server_id}:missing")
                continue
            state = connection.get_circuit_state()
            if state != "closed" or not getattr(connection, "_initialized", False):
                unavailable.append(f"{server_id}:{state}")

        if unavailable:
            detail = ", ".join(unavailable)
            logger.error("vuln_mcp_readiness_failed", unavailable=unavailable)
            raise WorkflowException(
                "Cannot enter vulnerability_discovery; critical MCPs are not ready: " + detail
            )

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

                # Browser-driven XHR/API discovery (AIOSOP-SPA-XHR-RECON). The GET
                # link crawler above never observes a SPA's client-side XHR/fetch
                # calls (Angular /rest, /api), so the entire API surface of an app
                # like Juice Shop went undiscovered and active injection had no API
                # targets. A guest browser navigation records a HAR whose on-load
                # XHR requests are extracted into Endpoint{type:'api'} nodes. Runs
                # unconditionally (not gated on stored credentials, unlike the
                # authenticated-surface capture in vuln discovery) so unauthenticated
                # engagements still get an API surface. Best-effort: a browser-MCP
                # outage must never block reconnaissance.
                try:
                    surface_url = self._orch.engagement_manager._domain_to_url(domain)
                except Exception:  # noqa: BLE001 - URL derivation is best-effort
                    surface_url = None
                if surface_url:
                    # In-scope hostnames so HAR extraction persists ONLY in-scope
                    # endpoints. Without this the extractor's scope guard is disabled
                    # and every third-party host a page calls is stored as in-scope.
                    scope_hosts = [
                        d.split("://")[-1].split("/")[0].split(":")[0]
                        for d in session.scope.domains
                        if d
                    ]
                    xhr_task = Task(
                        type="capture_authenticated_surface",
                        priority=5,
                        agent_type=AgentType.WORKFLOW,
                        payload={
                            "engagement_id": session.session_id,
                            "user_label": "guest",
                            "url": surface_url,
                            "scope_hosts": scope_hosts,
                        },
                        engagement_id=session.session_id,
                        timeout_seconds=300,
                    )
                    await self._orch.task_scheduler.schedule_task(xhr_task)

                    # Guest login-probe (AIOSOP-SPA-XHR-RECON). Navigation captures
                    # only on-load GET XHR; an auth-gated POST endpoint (e.g. POST
                    # /rest/user/login) fires ONLY on form submit. A single benign
                    # login submission surfaces that endpoint and its body params in
                    # the HAR so it becomes a scannable Endpoint. Obviously-invalid
                    # probe credentials, one attempt; the submit only fires when a
                    # real login form (password field) is detected, and HAR
                    # extraction is scope-filtered. The 401 is expected and harmless.
                    login_task = Task(
                        type="authenticate",
                        priority=5,
                        agent_type=AgentType.WORKFLOW,
                        payload={
                            "engagement_id": session.session_id,
                            "login_url": surface_url.rstrip("/") + "/#/login",
                            "credentials": {
                                "email": "osop-recon-probe@example.invalid",
                                "password": "osop-recon-probe",
                            },
                            "user_label": "recon_probe",
                            "scope_hosts": scope_hosts,
                        },
                        engagement_id=session.session_id,
                        timeout_seconds=180,
                    )
                    await self._orch.task_scheduler.schedule_task(login_task)
            url_hint = (
                self._orch.engagement_manager._domain_to_url(session.scope.domains[0])
                if session.scope.domains
                else None
            )
            await self._orch.engagement_manager.ensure_authenticated_discovery(
                session.session_id, url_hint=url_hint
            )

        elif phase == EngagementPhase.VULNERABILITY_DISCOVERY:
            self._assert_vulnerability_mcp_ready()
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
                            "targets": [self._orch.engagement_manager._domain_to_url(domain)],
                            "severity": "critical,high,medium",
                        },
                        engagement_id=session.session_id,
                        timeout_seconds=settings.nuclei_mcp_timeout + 120,
                    )
                    await self._orch.task_scheduler.schedule_task(nuclei_task)

            # 2b) ACTIVE INJECTION TESTING against the discovered parametrized
            #     surface. nuclei (templates) + burp (crawl) above never inject
            #     payloads into individual GET/POST parameters, so app-logic SQLi
            #     and reflected/DOM XSS — the bulk of real findings on targets like
            #     ginandjuice.shop — went completely untested and the platform
            #     reported 0 vulns on a deliberately-vulnerable app. Here we
            #     dispatch the (already-implemented) active scanners: sqlmap-backed
            #     sqli_scan and browser-verified xss_scan, at ONE representative URL
            #     per (path, parameter-set) so productId=1..N collapses to a single
            #     job, bounded to keep wall-time sane.
            #     (AIOSOP-ACTIVE-INJECTION-WIRE-2026-07-08)
            param_endpoint_records = await self._orch.graph_memory.run_read_query(
                """MATCH (e:Endpoint {engagement_id: $sid})
                   WHERE e.status_code IS NOT NULL
                     AND (e.url CONTAINS '?'
                          OR (coalesce(e.has_body, false)
                              AND size(coalesce(e.body_schema_keys, [])) > 0))
                   RETURN e.url AS url, e.query_keys AS query_keys,
                          coalesce(e.method, 'GET') AS method,
                          e.technologies AS technologies,
                          coalesce(e.has_body, false) AS has_body,
                          coalesce(e.body_schema_keys, []) AS body_keys,
                          coalesce(e.content_type, '') AS content_type""",
                {"sid": session.session_id},
            )

            # Build a mapping of url -> list of technologies
            url_to_techs: Dict[str, List[str]] = {}
            for r in param_endpoint_records:
                url = r.get("url")
                if url:
                    url_to_techs[url] = r.get("technologies") or []

            # Cap at 12 (was 25): 25 targets x ~4 scanners drained well past the
            # 1200s window (last benchmark: 4/104 tasks completed). 12 high-value
            # targets converge; ranking in _select_injection_targets keeps the most
            # injectable endpoints. Grow the vuln-agent pool to raise this.
            injection_targets = self._select_injection_targets(
                param_endpoint_records, max_targets=12
            )

            # Active injection must be backed by an observed parameter.  Do not
            # manufacture ``?q=test`` targets from arbitrary pages: doing so lets
            # the planner claim scan coverage that recon never established.
            if not injection_targets:
                logger.warning(
                    "active_injection_not_dispatched_no_observed_parameters",
                    session_id=session.session_id,
                    parametrized_endpoint_records=len(param_endpoint_records),
                )
                await self._orch._audit_log(
                    AuditEvent(
                        event_type="active_injection_skipped",
                        severity="warning",
                        actor_type="system",
                        actor_id="phase_monitor",
                        action={"reason": "no_observed_query_parameters"},
                        result={"scheduled": 0},
                        context={"parametrized_endpoint_records": len(param_endpoint_records)},
                        engagement_id=session.session_id,
                    )
                )

            knowledge_engine = get_knowledge_engine()

            vuln_to_scanners = {
                VulnClass.SSTI: [AgentType.SSTI_SCANNER],
                VulnClass.SSRF: [AgentType.SSRF_SCANNER],
                VulnClass.CSRF: [AgentType.CSRF_SCANNER],
                VulnClass.JWT_ABUSE: [AgentType.JWT_SCANNER],
                VulnClass.REQUEST_SMUGGLING: [AgentType.SMUGGLING_SCANNER],
                VulnClass.RACE_CONDITION: [AgentType.RACE_SCANNER],
                VulnClass.SUBDOMAIN_TAKEOVER: [AgentType.TAKEOVER_SCANNER],
                VulnClass.AUTHENTICATION_WEAKNESS: [AgentType.SAML_SCANNER],
                VulnClass.LFI: [AgentType.UPLOAD_SCANNER],
                VulnClass.DESERIALIZATION: [AgentType.POLLUTION_SCANNER],
                VulnClass.VULN_SCAN: [
                    AgentType.UPLOAD_SCANNER,
                    AgentType.POLLUTION_SCANNER,
                    AgentType.WEBSOCKET_SCANNER,
                ],
            }

            for target in injection_targets:
                target_url = target["url"]
                target_method = target.get("method") or "GET"
                # Retrieve technologies for this target from the mapping.
                # Since _select_injection_targets might modify parameters,
                # we match by parsed path and host, or fallback to direct lookups.
                from urllib.parse import urlparse

                target_parsed = urlparse(target_url)
                target_key = (target_parsed.netloc, target_parsed.path)

                target_techs: List[str] = []
                for orig_url, techs in url_to_techs.items():
                    orig_parsed = urlparse(orig_url)
                    if (orig_parsed.netloc, orig_parsed.path) == target_key:
                        target_techs = techs
                        break

                # level=1 (was 2): level=2 multiplies requests per parameter, which
                # causes ~677s network_wait against slow external targets like
                # ginandjuice.shop and exhausts the 900s task budget. level=1 uses
                # the minimal set of payloads and completes in ~400-500s for the same
                # target. level=2+ can be re-enabled for local/fast targets.
                # (AIOSOP-SQLI-BUDGET-003)
                sqli_payload: Dict[str, Any] = {
                    "url": target_url,
                    "method": target_method,
                    "level": 1,
                    "risk": 1,
                }
                # Body-param targets carry an injectable POST body (JSON or form) so
                # sqlmap fuzzes body params (e.g. a JSON login's `email`), not just
                # query params. (AIOSOP-SQLI-POSTBODY-JS001)
                if target.get("data"):
                    sqli_payload["data"] = target["data"]
                sqli_task = Task(
                    type="sqli_scan",
                    priority=8,
                    agent_type=AgentType.VULN_ANALYSIS,
                    payload=sqli_payload,
                    engagement_id=session.session_id,
                    timeout_seconds=self.SQLI_TASK_TIMEOUT_SECONDS,
                )
                await self._orch.task_scheduler.schedule_task(sqli_task)

                xss_task = Task(
                    type="xss_scan",
                    priority=8,
                    agent_type=AgentType.VULN_ANALYSIS,
                    payload={"url": target_url, "method": target_method},
                    engagement_id=session.session_id,
                    timeout_seconds=self.ACTIVE_SCAN_TIMEOUT_SECONDS,
                )
                await self._orch.task_scheduler.schedule_task(xss_task)

                recommended_vulns = set()
                for tech in target_techs:
                    for vc in knowledge_engine.get_tech_recommendations(tech):
                        recommended_vulns.add(vc)

                # Fallback to CSRF and JWT if no technologies are identified
                if not recommended_vulns:
                    recommended_vulns = {VulnClass.CSRF, VulnClass.JWT_ABUSE}

                recommended_scanners = set()
                for vc in recommended_vulns:
                    scanners = vuln_to_scanners.get(vc, [])
                    for s in scanners:
                        recommended_scanners.add(s)

                # New functional scanners
                for scanner_type in [
                    AgentType.SSTI_SCANNER,
                    AgentType.SSRF_SCANNER,
                    AgentType.CSRF_SCANNER,
                    AgentType.JWT_SCANNER,
                    AgentType.SMUGGLING_SCANNER,
                    AgentType.RACE_SCANNER,
                    AgentType.UPLOAD_SCANNER,
                    AgentType.POLLUTION_SCANNER,
                    AgentType.WEBSOCKET_SCANNER,
                    AgentType.SAML_SCANNER,
                    AgentType.TAKEOVER_SCANNER,
                ]:
                    if scanner_type in recommended_scanners:
                        task = Task(
                            type=f"{scanner_type.value.replace('_scanner', '').replace('_agent', '')}_scan",
                            priority=8,
                            agent_type=scanner_type,
                            payload={"url": target_url, "method": target_method},
                            engagement_id=session.session_id,
                            timeout_seconds=self.ACTIVE_SCAN_TIMEOUT_SECONDS,
                        )
                        await self._orch.task_scheduler.schedule_task(task)
            if injection_targets:
                logger.info(
                    "active_injection_scheduled",
                    session_id=session.session_id,
                    targets=len(injection_targets),
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
            # New functional scanners
            target_url = self._orch.engagement_manager._domain_to_url(session.scope.domains[0])
            for scanner_type in [
                AgentType.SSTI_SCANNER,
                AgentType.SSRF_SCANNER,
                AgentType.CSRF_SCANNER,
                AgentType.JWT_SCANNER,
                AgentType.SMUGGLING_SCANNER,
                AgentType.RACE_SCANNER,
                AgentType.UPLOAD_SCANNER,
                AgentType.POLLUTION_SCANNER,
                AgentType.WEBSOCKET_SCANNER,
                AgentType.SAML_SCANNER,
                AgentType.TAKEOVER_SCANNER,
            ]:
                task = Task(
                    type=f"{scanner_type.value.replace('_scanner', '').replace('_agent', '')}_scan",
                    priority=8,
                    agent_type=scanner_type,
                    payload={"url": target_url},
                    engagement_id=session.session_id,
                    timeout_seconds=self.ACTIVE_SCAN_TIMEOUT_SECONDS,
                )
                await self._orch.task_scheduler.schedule_task(task)
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

                # Retrieve the vulnerability node properties to get the vuln_type
                vuln_node = await self._orch.graph_memory.get_node_details(vid)
                vuln_type = vuln_node.get("vuln_type", "unknown") if vuln_node else "unknown"

                payload_task = Task(
                    type="generate_payloads",
                    priority=9,
                    agent_type=AgentType.PAYLOAD_MUTATION,
                    payload={
                        "vuln_type": vuln_type,
                        "context": {
                            "target": endpoint_url,
                            "vulnerability_id": vid,
                            "engagement_id": session.session_id,
                        },
                        "count": 3,
                    },
                    engagement_id=session.session_id,
                )
                await self._orch.task_scheduler.schedule_task(payload_task)

                validation_task = Task(
                    type="exploit_validation",
                    priority=9,
                    agent_type=AgentType.EXPLOIT_VALIDATION,
                    approval_required=True,
                    dependencies=[payload_task.id],
                    payload={
                        "target": endpoint_url,
                        "vulnerability_id": vid,
                        "severity": sev,
                        "operator_approved": False,
                        "vuln_class": vuln_type,
                    },
                    engagement_id=session.session_id,
                )
                await self._orch.task_scheduler.schedule_task(validation_task)
                await self._orch.task_scheduler._persist_task_dependency(
                    payload_task, validation_task
                )
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
        """Background phase monitor: periodically check for phase advancement conditions.

        AIOSOP-SCALE-001 (2026-07-12): reduced sleep from 10s to 5s so the monitor
        detects completed phases faster and advances the engagement. With the inflight
        admission cap in the scheduler loop, tasks should complete more rapidly, so a
        quicker phase-detection loop prevents sessions from stalling on a completed
        phase while waiting for the next tick.
        """
        while self._orch._running:
            try:
                await asyncio.sleep(5)
                self._tick += 1
                for session in list(self._orch._sessions.values()):
                    await self._auto_advance_phase(session)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("phase_monitor_error", error=str(e))
