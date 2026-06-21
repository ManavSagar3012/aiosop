"""
Cloud Specialist Agent
Specializes in identifying cloud-specific vulnerabilities, IAM trust relationship flaws, and exposed metadata.
"""

# PATCH (REL-028, 2026-06-15): This agent is not instantiated by the
# current orchestrator (api/main.py register_agents). Marked experimental
# until either (a) registered for production use or (b) archived.
__experimental__ = True

import logging
from typing import Any, Dict, List, Optional

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Observation, Task

logger = logging.getLogger(__name__)


class CloudSpecialistAgent(BaseAgent):
    """
    Cloud Specialist Agent (V5.1)

    Responsibilities:
    - AWS/GCP/Azure IAM policy analysis.
    - S3/Blob storage exposure detection.
    - Cloud Metadata API (SSRF) exploitation.
    - Identifying cross-account trust relationship risks.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CLOUD_SPECIALIST

    async def _setup_resources(self) -> None:
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        task_type = task.type
        payload = task.payload

        if task_type == "analyze_iam":
            return await self._analyze_iam_policy(payload)
        elif task_type == "probe_metadata":
            return await self._probe_cloud_metadata(payload)
        else:
            return {"status": "failed", "error": f"Unknown task type: {task_type}"}

    async def _analyze_iam_policy(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IAM policies for over-permissive actions."""
        target_account = payload.get("account_id")
        target_principal = payload.get("principal_arn")

        await self.think(
            "Analyzing IAM policy for excessive permissions and trust relationships.",
            ["iam", "least_privilege", "privilege_escalation"],
        )

        try:
            from ai_osop.adapters.cloud_mcp import CloudMCPAdapter

            # PATCH (REL-034, 2026-06-15): self.context -> self.ctx (BaseAgent
            # stores AgentContext as self.ctx; self.context is undefined).
            adapter = CloudMCPAdapter(self.ctx.mcp_registry)
            await adapter.initialize(
                self.ctx.scope.dict() if self.ctx.scope else {},
                self.ctx.session_id,
            )

            findings = []

            # Analyze trusts
            trust_results = await adapter.analyze_iam_trust_policies(target_account)
            for f in trust_results.get("findings", []):
                findings.append(f)
                await self.observe(
                    target_id=f.get("role", "unknown-role"),
                    obs_type="cloud_iam_trust_misconfig",
                    data=f,
                    confidence=0.9,
                )

            # Discover privesc
            privesc_results = await adapter.discover_privilege_escalation(target_principal)
            for p in privesc_results.get("paths", []):
                findings.append(p)
                await self.observe(
                    target_id=p.get("target", "unknown-target"),
                    obs_type="cloud_iam_privesc",
                    data=p,
                    confidence=0.95,
                )

            return {
                "status": "success",
                "findings_count": len(findings),
                "msg": f"IAM policy analysis complete. Found {len(findings)} risks.",
            }

        except Exception as e:
            logger.error(f"Failed to analyze IAM roles: {e}")
            return {"status": "failed", "error": str(e)}

    async def _probe_cloud_metadata(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Probe for Cloud Metadata SSRF vulnerabilities."""
        target_url = payload.get("url")

        await self.think(
            f"Probing {target_url} for Cloud Metadata SSRF.", ["ssrf", "cloud_metadata"]
        )

        return {"status": "success", "msg": "Metadata probing initialized."}

    async def _cleanup_resources(self) -> None:
        pass
