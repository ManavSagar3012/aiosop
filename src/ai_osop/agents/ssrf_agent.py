"""
SSRF Scanner Agent
Specialized agent for Server-Side Request Forgery detection.
"""

import asyncio
from typing import Any, Dict

import httpx

from ai_osop.adapters.oast_mcp import OASTAdapter
from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.payload_engine.engine import PayloadTemplateLibrary


class SSRFAgent(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for SSRF vulnerabilities using the platform's
    payload engine and OAST for verification.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.SSRF_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "ssrf_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute SSRF scan task."""
        if task.type == "ssrf_scan":
            return await self._execute_ssrf_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_ssrf_scan(self, task: Task) -> Dict[str, Any]:
        """
        Implement SSRF scanning logic.
        """
        target_url = task.payload.get("url")
        oast_adapter = OASTAdapter(self.ctx.mcp_registry)
        probe = await oast_adapter.generate_probe()
        templates = PayloadTemplateLibrary.get_templates(VulnClass.SSRF)

        async with httpx.AsyncClient() as client:
            for template in templates:
                payload = template.replace("{{OAST_CALLBACK}}", probe.url)
                try:
                    # Simplistic injection: assuming SSRF via a 'url' param
                    params = {"url": payload}
                    await client.get(target_url, params=params, timeout=5.0)
                except Exception:
                    pass

        # Wait for callbacks
        await asyncio.sleep(5)  # Simple wait
        callbacks = await oast_adapter.poll_callbacks(probe.id)

        if callbacks:
            vuln = Vulnerability(
                vuln_type=VulnClass.SSRF,
                severity=Severity.HIGH,
                title=f"Server-Side Request Forgery on {target_url}",
                description=f"SSRF detected in {target_url} via OAST callback validation.",
                evidence=[
                    {
                        "type": "oast_callback",
                        "url": target_url,
                        "callbacks": callbacks,
                    }
                ],
                tool_source="ssrf_scanner",
                confidence=0.95,
                engagement_id=task.engagement_id,
            )
            await self.persist_finding(vuln)

        return {"status": "success", "message": f"SSRF scan completed for {target_url}"}
