"""
CSRF Scanner Agent
Specialized agent for Cross-Site Request Forgery detection.
"""

from typing import Any, Dict

import httpx

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.payload_engine.engine import PayloadTemplateLibrary


class CSRFAgent(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for CSRF vulnerabilities.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CSRF_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "csrf_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute CSRF scan task."""
        if task.type == "csrf_scan":
            return await self._execute_csrf_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_csrf_scan(self, task: Task) -> Dict[str, Any]:
        """
        Implement CSRF scanning logic.
        """
        target_url = task.payload.get("url")
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(target_url, timeout=10.0)
                token_patterns = ["csrf_token", "authenticity_token", "_csrf"]
                has_token = any(pattern in response.text for pattern in token_patterns)

                if not has_token:
                    vuln = Vulnerability(
                        vuln_type=VulnClass.CSRF,
                        severity=Severity.MEDIUM,
                        title=f"Missing CSRF Protection on {target_url}",
                        description=f"Potential CSRF vulnerability: no CSRF token found in {target_url}.",
                        evidence=[
                            {
                                "type": "missing_csrf_token",
                                "url": target_url,
                                "checked_patterns": token_patterns,
                            }
                        ],
                        tool_source="csrf_scanner",
                        confidence=0.7,
                        engagement_id=task.engagement_id,
                    )
                    await self.persist_finding(vuln)
            except Exception as e:
                self.logger.error(f"Error scanning {target_url}: {e}")

        return {"status": "success", "message": f"CSRF scan completed for {target_url}"}
