"""
Takeover Scanner Agent
Specialized agent for Subdomain Takeover detection.
"""

import uuid
from typing import Any, Dict

import httpx

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability


class TakeoverAgent(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for Subdomain Takeover vulnerabilities.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.TAKEOVER_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "takeover_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute Takeover scan task."""
        if task.type == "takeover_scan":
            return await self._execute_takeover_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_takeover_scan(self, task: Task) -> Dict[str, Any]:
        """
        Implementation for Subdomain Takeover scanning.
        """
        target_url = task.payload.get("url")
        if not target_url:
            raise Exception("No URL provided for Takeover scan")

        # Common takeover signatures
        signatures = [
            "There is no app configured at that hostname",
            "NoSuchBucket",
            "This domain is not configured yet",
        ]

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(target_url)
                for sig in signatures:
                    if sig in response.text:
                        vuln = Vulnerability(
                            vuln_type=VulnClass.SUBDOMAIN_TAKEOVER,
                            severity=Severity.HIGH,
                            title=f"Subdomain Takeover: {target_url}",
                            description=f"Potential subdomain takeover detected: signature '{sig}' found.",
                            evidence=[
                                {
                                    "type": "subdomain_takeover",
                                    "url": target_url,
                                    "signature": sig,
                                }
                            ],
                            tool_source="takeover_scanner",
                            confidence=0.95,
                            engagement_id=task.engagement_id,
                        )
                        await self.persist_finding(vuln)
                        return {"status": "vulnerable", "finding": "Subdomain takeover detected"}
            except Exception as e:
                return {"status": "failed", "message": f"Takeover scan failed: {str(e)}"}

        return {"status": "safe", "message": "No Takeover vulnerability found"}
