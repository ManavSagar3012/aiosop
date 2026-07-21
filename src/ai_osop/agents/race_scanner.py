"""
Race Scanner Agent
Specialized agent for Race Condition detection.
"""

from typing import Any, Dict

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.payload_engine.engine import AdaptivePayloadEngine


class RaceScanner(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for Race Condition vulnerabilities using the platform's
    payload engine.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.RACE_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "race_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute Race Condition scan task."""
        target_url = task.payload.get("url") or task.payload.get("target") or task.payload.get("target_url")
        if not target_url:
            return {"status": "failed", "error": "url parameter is required"}

        self.logger.info(f"Starting Race Condition scan for {target_url}")

        try:
            import asyncio
            import httpx

            # Send 15 concurrent requests in parallel to test for race conditions / TOCTOU
            concurrency = task.payload.get("concurrency", 15)
            method = task.payload.get("method", "POST")
            headers = task.payload.get("headers", {})
            body = task.payload.get("body", {})

            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                async def make_req():
                    try:
                        if method.upper() == "POST":
                            return await client.post(target_url, json=body, headers=headers)
                        else:
                            return await client.get(target_url, headers=headers)
                    except Exception as exc:
                        return exc

                tasks = [make_req() for _ in range(concurrency)]
                responses = await asyncio.gather(*tasks)

                success_count = 0
                status_codes = []
                for resp in responses:
                    if isinstance(resp, httpx.Response):
                        status_codes.append(resp.status_code)
                        if resp.status_code in (200, 201, 202, 204):
                            success_count += 1

                # If a once-only action succeeded > 1 time during rapid concurrent firing
                limit = task.payload.get("limit", 1)
                if success_count > limit:
                    vuln = Vulnerability(
                        vuln_type=VulnClass.RACE_CONDITION,
                        severity=Severity.HIGH,
                        title=f"Race Condition / TOCTOU Double-Spend on {target_url}",
                        description=(
                            f"Race condition confirmed at {target_url}. Action succeeded {success_count} "
                            f"times under {concurrency} concurrent requests (limit={limit})."
                        ),
                        evidence=[
                            {
                                "type": "race_condition",
                                "url": target_url,
                                "concurrency": concurrency,
                                "success_count": success_count,
                                "status_codes": status_codes,
                            }
                        ],
                        tool_source="race_scanner",
                        confidence=0.95,
                        validated=True,
                        engagement_id=task.engagement_id,
                    )
                    await self.persist_finding(vuln)
                    return {
                        "status": "vulnerable",
                        "vulnerability": vuln.model_dump(),
                        "success_count": success_count,
                    }

            return {
                "status": "success",
                "message": "Race scan completed, no race condition confirmed.",
                "status_codes": status_codes,
            }
        except Exception as e:
            self.logger.error("race_scan_failed", url=target_url, error=str(e))
            return {"status": "failed", "error": str(e)}
