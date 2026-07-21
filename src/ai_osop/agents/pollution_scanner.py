"""
Pollution Scanner Agent
Specialized agent for Prototype Pollution detection.
"""

from typing import Any, Dict

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.payload_engine.engine import AdaptivePayloadEngine


class PollutionScanner(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for Prototype Pollution vulnerabilities using the platform's
    payload engine.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.POLLUTION_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "pollution_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute Prototype Pollution scan task."""
        target_url = task.payload.get("url") or task.payload.get("target") or task.payload.get("target_url")
        if not target_url:
            return {"status": "failed", "error": "url parameter is required"}

        self.logger.info(f"Starting Prototype Pollution scan for {target_url}")

        try:
            gov_client = self.get_governed_client(tool="pollution", timeout=15.0)
            tester = PrototypePollutionTester(
                target_url,
                client=gov_client,
                timeout=15.0,
            )
            findings = await tester.run()

            created_vulns = []
            for f in findings:
                if not f.confirmed:
                    continue
                vuln = Vulnerability(
                    vuln_type=VulnClass.PROTOTYPE_POLLUTION,
                    severity=Severity.HIGH,
                    title=f"Prototype Pollution ({f.technique}) on {target_url}",
                    description=(
                        f"Prototype pollution confirmed via {f.technique} technique at {target_url}. "
                        f"Gadget '{f.gadget}' allowed mutation of Object.prototype."
                    ),
                    evidence=[
                        {
                            "type": "prototype_pollution",
                            "technique": f.technique,
                            "gadget": f.gadget,
                            "detail": f.detail,
                            "evidence": f.evidence,
                        }
                    ],
                    tool_source="pollution_scanner",
                    confidence=0.95,
                    validated=True,
                    engagement_id=task.engagement_id,
                )
                await self.persist_finding(vuln)
                created_vulns.append(vuln.model_dump())

            if created_vulns:
                return {
                    "status": "vulnerable",
                    "findings_count": len(created_vulns),
                    "vulnerabilities": created_vulns,
                }

            return {
                "status": "success",
                "message": "Pollution scan completed, no prototype pollution vulnerabilities confirmed.",
            }
        except Exception as e:
            self.logger.error("pollution_scan_failed", url=target_url, error=str(e))
            return {"status": "failed", "error": str(e)}
