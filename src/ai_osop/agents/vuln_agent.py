"""
Vulnerability Analysis Agent
Specialized agent for vulnerability scanning, correlation, and validation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.adapters.burp_mcp import BurpMCPAdapter
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType, Severity, VulnClass, settings
from ai_osop.core.models import Asset, Endpoint, Task, Vulnerability


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
        self.findings: Dict[str, Vulnerability] = {}
        self.false_positive_patterns: List[str] = []

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
        url = payload["url"]
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        config = payload.get("config", {})

        # Ensure base Asset exists for graph linking
        asset = Asset(
            id=f"asset-{domain}",
            type="domain",
            value=domain,
            source="manual_input",
            confidence=1.0,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            engagement_id=self.ctx.current_task.engagement_id,
            metadata={},
        )
        # Note: metadata might cause issues if Neo4j expects primitives,
        # but let's ensure we match the pydantic requirements first.
        await self.ctx.graph_memory.add_asset(asset)

        # Ensure adapter is initialized for this engagement
        session = await self.ctx.session_memory.get_session_state(
            self.ctx.current_task.engagement_id
        )
        if session:
            await self.burp_adapter.initialize(session.scope, session.session_id)

        # Launch Burp scan
        scan_result = await self.burp_adapter.scan_target(url, config)
        burp_error = None

        if scan_result.status != "success":
            burp_error = scan_result.error
            print(f"WARN: Burp scan failed to start: {burp_error}")

        # Retrieve and normalize findings
        print(f"DEBUG: Requesting issues, sitemap, and proxy history for {url}")
        vulns = await self.burp_adapter.get_scan_issues(url)
        
        # --- MOCK DISCOVERY TRIGGER ---
        if settings.mock_llm and len(vulns) == 0:
            print("MOCK_MODE: Simulating advanced attack chain for exploitation phase trigger.")
            from ai_osop.core.config import Severity, VulnClass
            
            # 1. WAF Bypass finding
            vuln1 = Vulnerability(
                id=f"vuln-waf-{int(datetime.utcnow().timestamp())}",
                vuln_type="waf_bypass",
                severity=Severity.MEDIUM,
                title="WAF Configuration Weakness (Simulated)",
                description="Detected pattern-based WAF bypass using HTTP Parameter Pollution.",
                evidence=[{"type": "mock_probe", "payload": "param=1&param=2"}],
                tool_source="vuln-agent-mock",
                endpoint_id=f"endpoint-{domain}",
                confidence=0.8,
                engagement_id=self.ctx.current_task.engagement_id
            )
            
            # 2. Blind SQL Injection
            vuln2 = Vulnerability(
                id=f"vuln-blind-sqli-{int(datetime.utcnow().timestamp()) + 1}",
                vuln_type=VulnClass.SQLI,
                severity=Severity.HIGH,
                title="Blind SQL Injection (Simulated)",
                description="Blind SQL injection detected behind bypassed WAF.",
                evidence=[{"type": "mock_probe", "payload": "AND 1=SLEEP(5)"}],
                tool_source="vuln-agent-mock",
                endpoint_id=f"endpoint-{domain}",
                confidence=0.9,
                engagement_id=self.ctx.current_task.engagement_id
            )
            vulns = [vuln1, vuln2]
        # -----------------------------

        endpoints = await self.burp_adapter.get_sitemap(url_prefix=domain)
        history = await self.burp_adapter.get_proxy_history()

        print(
            f"DEBUG: Burp returned {len(vulns)} issues, {len(endpoints)} sitemap entries, and {len(history)} history entries"
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
                    engagement_id=self.ctx.current_task.engagement_id,
                )

        print(f"DEBUG: Total unique endpoints for {domain}: {len(all_endpoints)}")

        # Perform reasoning using security skills
        analysis_context = f"Target {domain} identified. Initializing vulnerability analysis phase."
        if all_endpoints:
            analysis_context = (
                f"Analyzing {len(all_endpoints)} new endpoints for {domain} to identify potential vulnerabilities:\n"
                + "\n".join([e.url for e in list(all_endpoints.values())[:10]])
            )

        skills = self._get_relevant_skills(self.ctx.current_task)
        reasoning = await self.think(analysis_context, skills)
        reasoning = f"[VERIFIED_V0.1.2] {reasoning}"  # Force unique prefix
        print(f"AGENT REASONING: {reasoning}")

        # Store findings
        for vuln in vulns:
            try:
                vuln.engagement_id = self.ctx.current_task.engagement_id
                vuln.endpoint_id = f"endpoint-{domain}"
                await self.ctx.graph_memory.add_vulnerability(vuln)
                self.findings[vuln.id] = vuln
            except Exception as e:
                print(f"ERROR: Failed to add vulnerability {vuln.id} to graph: {e}")

        for ep in all_endpoints.values():
            try:
                ep.engagement_id = self.ctx.current_task.engagement_id
                ep.asset_id = asset.id
                await self.ctx.graph_memory.add_endpoint(ep)
            except Exception as e:
                print(f"ERROR: Failed to add endpoint {ep.url} to graph: {e}")

        return {
            "status": "success",
            "tool": "burp_scanner",
            "target": url,
            "findings_count": len(vulns),
            "endpoints_count": len(all_endpoints),
            "reasoning": reasoning,
            "burp_error": burp_error,
            "findings": [v.dict() for v in vulns],
        }

    async def _execute_intruder_fuzz(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate Burp Intruder for payload fuzzing."""
        url = payload.get("url")
        method = payload.get("method", "GET")
        body = payload.get("body", "")
        payload_set = payload.get("payload_set", ["' OR 1=1 --", "admin'--", "<script>alert(1)</script>"])
        tab_name = payload.get("tab_name", f"AI-FUZZ-{int(datetime.utcnow().timestamp())}")

        print(f"DEBUG: Deploying Intruder attack against {url}")
        
        # Prepare the base request definition expected by our Java MCP adapter
        mock_request = {
            "method": method,
            "url": url,
            "headers": {"User-Agent": "AI-OSOP-Intruder/1.0"},
            "body": body
        }

        # The actual integration would pass positions, but for the MCP adapter
        # we mapped it to just take the request for now.
        try:
            # We use extension_call or direct mapping based on Java implementation.
            # Given our Java update mapped "intruder_attack":
            response = await self.burp_adapter.intruder_attack(
                request=mock_request,
                payload_positions=[], # Handled dynamically by Burp in Sniper mode if empty
                payload_set=payload_set,
                config={"attack_type": "sniper", "tab_name": tab_name}
            )
            
            # Simulated reasoning over Intruder decision
            reasoning = f"[INTRUDER_DEPLOYED] Dispatched Sniper attack to {url} with {len(payload_set)} payloads targeting dynamic parameters."
            
            return {
                "status": "success",
                "target": url,
                "tab_name": tab_name,
                "reasoning": reasoning,
                "mcp_response": response.dict() if hasattr(response, 'dict') else str(response)
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _execute_nuclei_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Nuclei scan on targets."""
        targets = payload["targets"]
        templates = payload.get("templates", [])

        # Execute via MCP
        response = await self.ctx.mcp_registry.execute_tool(
            "nuclei-mcp", "scan", {"targets": targets, "templates": templates, "rate_limit": 150}
        )

        if response.status != "success":
            return {"status": "error", "error": response.error}

        # Normalize Nuclei findings
        raw_findings = response.result.get("findings", [])
        vulns = []

        for finding in raw_findings:
            vuln = self._normalize_nuclei_finding(finding)
            vuln.engagement_id = self.ctx.current_task.engagement_id
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
            vulns.append(vuln)

        return {
            "status": "success",
            "tool": "nuclei",
            "targets": targets,
            "findings_count": len(vulns),
            "findings": [v.dict() for v in vulns],
        }

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
            "confirmed_details": [v.dict() for v in confirmed_findings],
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
