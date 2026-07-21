"""
Upload Scanner Agent
Specialized agent for Insecure File Upload detection.
"""

from typing import Any, Dict

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.payload_engine.engine import AdaptivePayloadEngine


class UploadScanner(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for Insecure File Upload vulnerabilities using the platform's
    payload engine.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.UPLOAD_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "upload_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute Insecure File Upload scan task."""
        target_url = task.payload.get("url") or task.payload.get("target") or task.payload.get("target_url")
        if not target_url:
            return {"status": "failed", "error": "url parameter is required"}

        self.logger.info(f"Starting Upload scan for {target_url}")

        try:
            gov_client = self.get_governed_client(tool="upload", timeout=20.0)
            tester = FileUploadTester(
                target_url,
                client=gov_client,
                timeout=20.0,
            )
            findings = await tester.run()

            created_vulns = []
            for f in findings:
                if not f.confirmed:
                    continue
                vuln = Vulnerability(
                    vuln_type=VulnClass.FILE_UPLOAD,
                    severity=Severity.HIGH,
                    title=f"Unrestricted File Upload ({f.technique}) on {target_url}",
                    description=(
                        f"Unrestricted file upload vulnerability confirmed at {target_url}. "
                        f"Technique: {f.technique}. Uploaded file was served at {f.served_url} "
                        f"with content-type '{f.content_type}'."
                    ),
                    evidence=[
                        {
                            "type": "file_upload",
                            "technique": f.technique,
                            "filename": f.filename,
                            "served_url": f.served_url,
                            "content_type": f.content_type,
                            "evidence": f.evidence,
                        }
                    ],
                    tool_source="upload_scanner",
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

            return {"status": "success", "message": "Upload scan completed, no file upload vulnerabilities confirmed."}
        except Exception as e:
            self.logger.error("upload_scan_failed", url=target_url, error=str(e))
            return {"status": "failed", "error": str(e)}
