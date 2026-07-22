"""
Smuggling Scanner Agent
Specialized agent for HTTP Request Smuggling detection.
"""

from typing import Any, Dict

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.enums import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability


class SmugglingScanner(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for HTTP Request Smuggling vulnerabilities using the platform's
    payload engine.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.SMUGGLING_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "smuggling_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute HTTP Request Smuggling scan task."""
        target_url = (
            task.payload.get("url") or task.payload.get("target") or task.payload.get("target_url")
        )
        if not target_url:
            return {"status": "failed", "error": "url parameter is required"}

        self.logger.info(f"Starting Request Smuggling scan for {target_url}")

        try:
            from urllib.parse import urlparse

            from ai_osop.core.smuggle_probe import probe_desync

            parsed = urlparse(target_url)
            host = parsed.hostname or target_url
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_tls = parsed.scheme == "https"
            path = parsed.path or "/"

            res = probe_desync(host=host, port=port, use_tls=use_tls, path=path)
            if res.get("vulnerable"):
                technique = res.get("technique", "HTTP Desync")
                vuln = Vulnerability(
                    vuln_type=VulnClass.REQUEST_SMUGGLING,
                    severity=Severity.HIGH,
                    title=f"HTTP Request Smuggling ({technique}) on {host}",
                    description=f"HTTP Request Smuggling vulnerability confirmed via timing desync probe at {target_url}.",
                    evidence=[
                        {
                            "type": "request_smuggling",
                            "technique": technique,
                            "host": host,
                            "baseline_ms": res.get("baseline_ms"),
                            "probe_ms": res.get("probe_ms"),
                        }
                    ],
                    tool_source="smuggling_scanner",
                    confidence=0.95,
                    validated=True,
                    engagement_id=task.engagement_id,
                )
                await self.persist_finding(vuln)
                return {
                    "status": "vulnerable",
                    "vulnerability": vuln.model_dump(),
                    "probe_result": res,
                }

            return {
                "status": "success",
                "message": "Smuggling scan completed, no HTTP desync vulnerability detected.",
                "probe_result": res,
            }
        except Exception as e:
            self.logger.error("smuggling_scan_failed", url=target_url, error=str(e))
            return {"status": "failed", "error": str(e)}
