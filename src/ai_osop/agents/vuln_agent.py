"""
Vulnerability Analysis Agent
Specialized agent for vulnerability scanning, correlation, and validation.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ai_osop.adapters.burp_mcp import BurpMCPAdapter
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import AgentType, Severity, VulnClass, settings
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Asset, Endpoint, FindingStatus, Task, Vulnerability


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

        return await self._complete_supervised_messages(messages)

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
        elif task_type == "correlate_findings":
            return await self._execute_correlation(payload)
        elif task_type == "triage_finding":
            return await self._execute_triage(payload)
        else:
            raise AgentException(f"Unknown vuln analysis task: {task_type}")

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
        if not isinstance(url, str) or len(url) > 2048:
            raise AgentException("Burp scan requires a bounded, authorized target URL")
        parsed_target = urlsplit(url if "://" in url else "https://" + url)
        if (
            parsed_target.scheme not in {"http", "https"}
            or not parsed_target.hostname
            or parsed_target.username is not None
            or parsed_target.password is not None
            or parsed_target.fragment
        ):
            raise AgentException("Burp scan target origin is invalid")
        try:
            approved_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
        except ValueError as exc:
            raise AgentException("Burp scan target port is invalid") from exc
        domain = parsed_target.hostname.lower()
        config = payload.get("config", {})

        # This is a requested scope seed, NOT an independently observed DNS
        # asset. Do not publish it before an actual tool admission receipt.
        asset = Asset(
            id=f"asset-{domain}",
            type="domain",
            value=domain,
            source="scan_scope_seed_unverified",
            confidence=0.0,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            engagement_id=engagement_id,
            metadata={},
        )
        # Note: metadata might cause issues if Neo4j expects primitives,
        # but let's ensure we match the pydantic requirements first.

        # Ensure default Endpoint node exists for f"endpoint-{domain}"
        from ai_osop.core.models import Endpoint

        default_ep = Endpoint(
            id=f"endpoint-{domain}",
            url=f"{parsed_target.scheme}://{parsed_target.netloc}/",
            asset_id=asset.id,
            source="scan_scope_seed_unverified",
            confidence=0.0,
            engagement_id=engagement_id,
        )

        # Ensure adapter is initialized for this engagement
        session = await self.ctx.session_memory.get_session_state(engagement_id)
        if session:
            await self.burp_adapter.initialize(session.scope, session.session_id)

        # Launch Burp scan
        try:
            scan_result = await self.burp_adapter.scan_target(url, config)
        except Exception:
            # A dropped MCP acknowledgement cannot establish that a remotely
            # accepted scan stopped; never retry or load stale issues as new.
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "target": url,
                "findings_count": 0,
                "endpoints_count": 0,
                "reason": "burp_scan_dispatch_unconfirmed",
            }
        if getattr(scan_result, "status", None) != "success":
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "target": url,
                "findings_count": 0,
                "endpoints_count": 0,
                "reason": "burp_scan_dispatch_unconfirmed",
            }

        # Retrieve and normalize findings
        try:
            vulns = await self.burp_adapter.get_scan_issues(url)
            endpoints = await self.burp_adapter.get_sitemap(url_prefix=domain)
            history = await self.burp_adapter.get_proxy_history()
        except Exception:
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "target": url,
                "findings_count": 0,
                "endpoints_count": 0,
                "reason": "burp_observations_unconfirmed",
            }
        if (
            not isinstance(vulns, list)
            or not isinstance(endpoints, list)
            or not isinstance(history, list)
            or len(vulns) > 500
            or len(endpoints) > 1000
            or len(history) > 1000
            or any(not isinstance(v, Vulnerability) for v in vulns)
            or any(not isinstance(ep, Endpoint) for ep in endpoints)
        ):
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "target": url,
                "findings_count": 0,
                "endpoints_count": 0,
                "reason": "burp_observations_malformed",
            }

        def same_target(value: object) -> bool:
            if not isinstance(value, str) or len(value) > 2048:
                return False
            try:
                parsed = urlsplit(value)
                return (
                    parsed.scheme == parsed_target.scheme
                    and parsed.hostname == domain
                    and (parsed.port or (443 if parsed.scheme == "https" else 80)) == approved_port
                    and parsed.username is None
                    and parsed.password is None
                    and not parsed.fragment
                )
            except ValueError:
                return False

        # Proxy history and sitemap are global Burp workspace observations;
        # they may include another host or another operator's private traffic.
        # Ingest only exact-origin, bounded endpoint metadata, never raw bodies.
        endpoints = [ep for ep in endpoints if same_target(ep.url)]
        try:
            await self.ctx.graph_memory.add_asset(asset)
            await self.ctx.graph_memory.add_endpoint(default_ep)
        except Exception:
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "target": url,
                "findings_count": 0,
                "endpoints_count": 0,
                "reason": "burp_graph_projection_unconfirmed",
            }

        print(
            f"DEBUG: Burp returned {len(vulns)} issues, {len(endpoints)} sitemap entries, and {len(history)} history entries"
        )

        # Combine endpoints from sitemap and history
        all_endpoints = {ep.url: ep for ep in endpoints}
        for entry in history:
            if not isinstance(entry, dict):
                continue
            history_url = entry.get("url", "")
            if same_target(history_url) and history_url not in all_endpoints:
                all_endpoints[history_url] = Endpoint(
                    url=history_url,
                    method=entry.get("method", "GET"),
                    status_code=entry.get("status_code", 0),
                    host=entry.get("host", domain),
                    asset_id=asset.id,
                    source="burp_proxy_candidate_unverified",
                    confidence=0.0,
                    engagement_id=engagement_id,
                )

        print(f"DEBUG: Total unique endpoints for {domain}: {len(all_endpoints)}")

        # PATCH (REL-035, 2026-06-15): Persist findings + endpoints FIRST.
        # Pre-patch order was: reasoning (Ollama, often 60–1800s) → persist.
        # If the LLM hit the 300s task timeout, vulnerabilities were never
        # written to the graph. Now we persist immediately so partial results
        # survive any downstream timeout. Reasoning is best-effort with its
        # own short ceiling.
        persisted: List[Vulnerability] = []
        graph_unconfirmed = False
        for vuln in vulns:
            try:
                # A simulated finding, provider assertion or scanner issue
                # is never independently verified target-owned private effect.
                if vuln.tool_source == "vuln-agent-mock":
                    continue
                vuln.engagement_id = engagement_id
                vuln.endpoint_id = f"endpoint-{domain}"
                vuln.validated = False
                vuln.finding_status = FindingStatus.CANDIDATE
                vuln.validation_authority = None
                vuln.validation_state = "UNKNOWN"
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                persisted.append(vuln)
            except Exception:
                graph_unconfirmed = True

        for ep in all_endpoints.values():
            try:
                ep.engagement_id = engagement_id
                ep.asset_id = asset.id
                await self.ctx.graph_memory.add_endpoint(ep)
            except Exception:
                graph_unconfirmed = True

        if graph_unconfirmed:
            # Partial writes may already exist; never report a complete graph
            # projection or retry the external scan on an uncertain outcome.
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "target": url,
                "findings_count": len(persisted),
                "endpoints_count": 0,
                "reason": "burp_graph_projection_partial",
            }

        # Perform reasoning using security skills (best-effort, never blocks
        # finding persistence; bounded by a short timeout so vuln_agent fits
        # inside its 300s task budget even when Ollama is slow).
        analysis_context = f"Target {domain} identified. Initializing vulnerability analysis phase."
        if all_endpoints:
            analysis_context = (
                f"Analyzing {len(all_endpoints)} new endpoints for {domain} to identify potential vulnerabilities:\n"
                + "\n".join([e.url for e in list(all_endpoints.values())[:10]])
            )

        reasoning = "(reasoning skipped: not attempted)"
        try:
            reasoning_timeout = min(
                60.0, max(1.0, float(payload.get("reasoning_timeout_seconds", 45)))
            )
        except (ValueError, TypeError, OverflowError):
            reasoning_timeout = 45.0
        try:
            skills = await self._get_relevant_skills(self.ctx.current_task)
            reasoning = await asyncio.wait_for(
                self.think(analysis_context, skills),
                timeout=reasoning_timeout,
            )
            reasoning = f"[UNVERIFIED_PROVIDER_ANALYSIS] {reasoning}"
        except asyncio.TimeoutError:
            reasoning = f"(reasoning skipped: exceeded {reasoning_timeout}s budget)"
            print(f"WARN: vuln_agent reasoning timed out for {domain}; findings persisted anyway")
        except Exception:
            reasoning = "(reasoning unavailable: provider or safety gate denied)"
        print(f"AGENT REASONING: {reasoning}")

        return {
            "status": "success",
            "validation_state": "candidate_unverified",
            "tool": "burp_scanner",
            "target": url,
            "findings_count": len(persisted),
            "endpoints_count": len(all_endpoints),
            "reasoning": reasoning,
            "findings": [
                {"id": v.id, "verification_status": "candidate_unverified"} for v in persisted
            ],
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

            if getattr(response, "status", None) != "success":
                return {
                    "status": "execution_unknown",
                    "validation_state": "UNKNOWN",
                    "reason": "intruder_dispatch_unconfirmed",
                }
            return {
                "status": "success",
                "validation_state": "candidate_unverified",
                "target": url,
                "tab_name": tab_name,
                "remote_effect_verified": False,
            }

        except Exception:
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "reason": "intruder_dispatch_unconfirmed",
            }

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
        if (
            not isinstance(targets, list)
            or not 1 <= len(targets) <= 25
            or not all(isinstance(t, str) and 1 <= len(t) <= 2048 for t in targets)
            or not isinstance(templates, list)
            or len(templates) > 100
            or not all(isinstance(t, str) and 1 <= len(t) <= 256 for t in templates)
        ):
            raise AgentException("Nuclei targets/templates must be explicitly bounded")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not isinstance(engagement_id, str) or not engagement_id:
            raise AgentException("Nuclei requires a current engagement identity")

        def host(value: str) -> str:
            try:
                candidate = urlsplit(value if "://" in value else "https://" + value)
                if (
                    candidate.scheme not in {"http", "https"}
                    or not candidate.hostname
                    or candidate.username is not None
                    or candidate.password is not None
                    or candidate.fragment
                ):
                    return ""
                return candidate.hostname.lower()
            except ValueError:
                return ""

        target_hosts = {host(value) for value in targets}
        if not target_hosts or "" in target_hosts:
            raise AgentException("Nuclei target origin is not authorized for an observation")

        try:
            response = await self.ctx.mcp_registry.execute_tool(
                "nuclei-mcp",
                "scan",
                {"targets": targets, "templates": templates, "rate_limit": 150},
                timeout_override=settings.nuclei_mcp_timeout,
            )
        except Exception:
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "reason": "nuclei_remote_execution_unconfirmed",
            }

        if getattr(response, "status", None) != "success" or not isinstance(
            getattr(response, "result", None), dict
        ):
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "reason": "nuclei_observation_unconfirmed",
            }

        raw_findings = response.result.get("findings")
        if not isinstance(raw_findings, list) or len(raw_findings) > 500:
            return {
                "status": "execution_unknown",
                "validation_state": "UNKNOWN",
                "reason": "nuclei_observation_malformed",
            }
        normalized: List[Vulnerability] = []
        for finding in raw_findings:
            if not isinstance(finding, dict):
                return {
                    "status": "execution_unknown",
                    "validation_state": "UNKNOWN",
                    "reason": "nuclei_observation_malformed",
                }
            # A shared provider may send findings from its entire scan
            # workspace. Its `matched_at` must belong to this exact signed
            # Task's requested target host; query-string substrings don't count.
            matched = finding.get("matched_at")
            if not isinstance(matched, str) or host(matched) not in target_hosts:
                continue
            try:
                vuln = self._normalize_nuclei_finding(finding)
            except Exception:
                return {
                    "status": "execution_unknown",
                    "validation_state": "UNKNOWN",
                    "reason": "nuclei_observation_malformed",
                }
            vuln.engagement_id = engagement_id
            vuln.validated = False
            vuln.finding_status = FindingStatus.CANDIDATE
            vuln.validation_authority = None
            vuln.validation_state = "UNKNOWN"
            normalized.append(vuln)

        persisted: List[Vulnerability] = []
        for vuln in normalized:
            try:
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
                persisted.append(vuln)
            except Exception:
                return {
                    "status": "execution_unknown",
                    "validation_state": "UNKNOWN",
                    "reason": "nuclei_graph_projection_partial",
                    "persisted_candidates": len(persisted),
                }

        return {
            "status": "success",
            "validation_state": "candidate_unverified",
            "tool": "nuclei",
            "target_count": len(targets),
            "findings_count": len(persisted),
            "findings": [
                {"id": v.id, "verification_status": "candidate_unverified"} for v in persisted
            ],
        }

    async def _execute_correlation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate findings across tools."""
        engagement_id = payload["engagement_id"]

        # Get correlations from graph memory
        correlations = await self.ctx.graph_memory.correlate_vulnerabilities(engagement_id)

        # Similar provider reports are corroborating *leads*, not independent
        # target-owner effect proof. Never turn graph correlations into VERIFIED.
        correlated_candidates = []
        for vuln in self.findings.values():
            if vuln.engagement_id != engagement_id:
                continue
            similar = await self._find_similar_findings(vuln)
            if len(similar) > 1:
                vuln.validated = False
                vuln.finding_status = FindingStatus.CANDIDATE
                vuln.validation_state = "UNKNOWN"
                vuln.validation_authority = None
                vuln.correlated_ids = [
                    s.id for s in similar if s.id != vuln.id and s.engagement_id == engagement_id
                ]
                correlated_candidates.append(vuln)

        return {
            "status": "success",
            "validation_state": "candidate_unverified",
            "correlations": correlations if isinstance(correlations, int) else None,
            "confirmed_findings": 0,
            "confirmed_details": [],
            "correlated_candidates": len(correlated_candidates),
            "candidate_ids": [v.id for v in correlated_candidates],
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
            outcome = "likely_false_positive"
        else:
            # An absence of a heuristic false-positive signal cannot
            # independently prove target-owned unauthorized access.
            outcome = "not_flagged_by_heuristic"
        vuln.validated = False
        vuln.finding_status = FindingStatus.CANDIDATE
        vuln.validation_authority = None
        vuln.validation_state = "UNKNOWN"

        return {
            "status": "success",
            "finding_id": finding_id,
            "triage_result": outcome,
            "confidence": vuln.confidence,
            "independent_effect_verified": False,
        }

    def _normalize_nuclei_finding(self, finding: Dict[str, Any]) -> Vulnerability:
        """Convert Nuclei finding to Vulnerability model."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        # Map template type to VulnClass
        template_id = finding.get("template_id", "")
        vuln_type = self._map_nuclei_to_vuln_class(template_id)

        return Vulnerability(
            cwe=finding.get("cwe"),
            vuln_type=vuln_type,
            severity=severity_map.get(finding.get("severity", "info"), Severity.INFO),
            title=finding.get("info", {}).get("name", "Unknown"),
            description=finding.get("info", {}).get("description", ""),
            evidence=[
                {
                    "type": "nuclei_finding",
                    "template": template_id,
                    "matched_at": finding.get("matched_at"),
                    "extracted_results": finding.get("extracted_results"),
                }
            ],
            tool_source="nuclei",
            endpoint_id=finding.get("endpoint_id"),
            confidence=0.90 if finding.get("verified") else 0.70,
            exploitability="high" if finding.get("severity") == "critical" else "medium",
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
        return VulnClass.RCE

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
