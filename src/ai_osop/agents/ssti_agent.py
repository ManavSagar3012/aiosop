"""
SSTI Scanner Agent
Specialized agent for Server-Side Template Injection detection.
"""

from typing import Any, Dict

import httpx

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.payload_engine.engine import PayloadTemplateLibrary


class SSTIAgent(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for SSTI vulnerabilities using the platform's
    payload engine.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.SSTI_SCANNER

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "ssti_scan"

    async def _setup_resources(self) -> None:
        """Initialize SSTI scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup SSTI scanner resources."""
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute SSTI scan task."""
        if task.type == "ssti_scan":
            return await self._execute_ssti_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_ssti_scan(self, task: Task) -> Dict[str, Any]:
        """
        Implement SSTI scanning logic.
        """
        target_url = task.payload.get("url")
        param = task.payload.get("param", "q")
        templates = PayloadTemplateLibrary.get_templates(VulnClass.SSTI)

        async with httpx.AsyncClient() as client:
            for template in templates:
                params = {param: template}
                try:
                    response = await client.get(target_url, params=params, timeout=10.0)
                    if template in response.text:
                        vuln = Vulnerability(
                            vuln_type=VulnClass.SSTI,
                            severity=Severity.HIGH,
                            title=f"Server-Side Template Injection in parameter '{param}'",
                            description=f"Potential SSTI detected in {target_url} with parameter '{param}'.",
                            evidence=[
                                {
                                    "type": "ssti_reflection",
                                    "url": target_url,
                                    "parameter": param,
                                    "template": template,
                                }
                            ],
                            tool_source="ssti_scanner",
                            confidence=0.85,
                            engagement_id=task.engagement_id,
                        )
                        await self.persist_finding(vuln)
                except Exception as e:
                    self.logger.error(f"Error scanning {target_url}: {e}")
        return {"status": "success", "message": f"SSTI scan completed for {target_url}"}
