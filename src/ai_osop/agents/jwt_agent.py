"""
JWT Scanner Agent
Specialized agent for JWT vulnerability detection.
"""

from typing import Any, Dict

import jwt

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.enums import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability


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
        # The generic active-scan dispatch schedules jwt_scan with only {url, method}
        # (no token). A JWT scan without a token has nothing to test — that is a clean
        # skip, not a failure. Returning "error" here marked every such task as
        # task_failed. Authenticated flows that DO supply a token still scan below.
        token = task.payload.get("token")
        if not token:
            self.logger.info("jwt_scan_skipped: no token in scope for %s", task.payload.get("url"))
            return {
                "status": "success",
                "message": "skipped: no JWT token in scope",
                "findings_count": 0,
            }

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
                    validated=True,
                )
                await self.persist_finding(vuln)

        except Exception as e:
            self.logger.error(f"Error analyzing JWT: {e}")

        return {"status": "success", "message": "JWT scan completed"}
