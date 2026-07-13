"""
WebSocket Scanner Agent
Specialized agent for WebSocket vulnerability detection.
"""

import uuid
from typing import Any, Dict

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.core.websocket_tester import WebSocketTester


class WebSocketAgent(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for WebSocket vulnerabilities.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.WEBSOCKET_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "websocket_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute WebSocket scan task."""
        if task.type == "websocket_scan":
            return await self._execute_websocket_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_websocket_scan(self, task: Task) -> Dict[str, Any]:
        """
        Implementation for WebSocket scanning using WebSocketTester.
        """
        target_url = task.payload.get("url")
        if not target_url:
            raise Exception("No URL provided for WebSocket scan")

        tester = WebSocketTester(
            url=target_url,
            origin=task.payload.get("origin"),
            cookies=task.payload.get("cookies"),
            auth_markers=task.payload.get("auth_markers", []),
            probe=task.payload.get("probe"),
        )

        # Run CSWSH test as an example
        finding = await tester.test_cswsh()

        if finding.confirmed:
            vuln = Vulnerability(
                vuln_type=VulnClass.VULN_SCAN,
                severity=Severity.CRITICAL,
                title=f"WebSocket CSWSH on {target_url}",
                description=finding.detail,
                evidence=[
                    {
                        "type": "websocket_cswsh",
                        "url": target_url,
                        "evidence": str(finding.evidence),
                    }
                ],
                tool_source="websocket_scanner",
                confidence=0.95,
                engagement_id=task.engagement_id,
            )
            await self.persist_finding(vuln)
            return {"status": "vulnerable", "finding": finding.description}

        return {"status": "safe", "message": "No CSWSH vulnerability found"}
