"""
JWT Scanner Agent
Specialized agent for JWT vulnerability detection.
"""

from typing import Any, Dict

import jwt

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.payload_engine.engine import PayloadTemplateLibrary


class JWTAgent(BaseVulnerabilityAgent):
    """
    Analyzes JWT tokens for vulnerabilities.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.JWT_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "jwt_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute JWT scan task."""
        if task.type == "jwt_scan":
            return await self._execute_jwt_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_jwt_scan(self, task: Task) -> Dict[str, Any]:
        """
        Implement JWT scanning logic.
        """
        token = task.payload.get("token")
        if not token:
            return {"status": "error", "message": "No token provided"}

        try:
            # 1. Analyze header for 'alg: none'
            header = jwt.get_unverified_header(token)
            if header.get("alg") == "none":
                vuln = Vulnerability(
                    vuln_type=VulnClass.JWT_ABUSE,
                    severity=Severity.CRITICAL,
                    title="JWT Algorithm None Signature Bypass",
                    description="JWT uses 'alg: none' algorithm, allowing token signature verification bypass.",
                    evidence=[
                        {
                            "type": "jwt_alg_none",
                            "header": header,
                        }
                    ],
                    tool_source="jwt_scanner",
                    confidence=0.95,
                    engagement_id=task.engagement_id,
                )
                await self.persist_finding(vuln)

        except Exception as e:
            self.logger.error(f"Error analyzing JWT: {e}")

        return {"status": "success", "message": "JWT scan completed"}
