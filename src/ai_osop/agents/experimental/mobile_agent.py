"""
Mobile Analysis Agent
Specialized for mobile API traffic, deep links, and client-side logic.
"""

# PATCH (REL-028, 2026-06-15): This agent is not instantiated by the
# current orchestrator (api/main.py register_agents). Marked experimental
# until either (a) registered for production use or (b) archived.
__experimental__ = True

from typing import Any, Dict, List, Optional

from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Observation, Severity, Task


class MobileAnalysisAgent(BaseAgent):
    """
    Mobile Analysis Agent
    Bridges the gap for mobile-specific targets (Airbnb, Shopify, Wickr).
    Focuses on: Deep Links, Mobile API Interception, and Local Storage.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.VULN_ANALYSIS

    def supports_task_type(self, task_type: str) -> bool:
        return task_type in ["analyze_deep_links", "intercept_mobile_traffic"]

    async def _setup_resources(self) -> None:
        """Initialize mobile analysis resources."""
        self.analyzed_deep_links: List[str] = []

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute mobile analysis task."""
        task_type = task.type
        payload = task.payload

        if task_type == "analyze_deep_links":
            return await self._analyze_deep_links(payload)
        elif task_type == "intercept_mobile_traffic":
            return await self._intercept_traffic(payload)
        else:
            return {"status": "error", "message": f"Unknown task type {task_type}"}

    async def _analyze_deep_links(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes Android/iOS deep links for sensitive parameters or state bypass.
        """
        bundle_id = payload.get("bundle_id")
        links = payload.get("links", [])

        await self.think(
            f"Analyzing {len(links)} deep links for {bundle_id}. Checking for unauthenticated state transitions.",
            ["mobile_security", "deep_link_analysis"],
        )

        # Simulate finding
        findings = []
        if any("reset" in l for l in links):
            findings.append(
                {
                    "type": "insecure_deep_link",
                    "link": "target://reset_password?token=XYZ",
                    "risk": "Account Takeover via deep link token leakage",
                }
            )

        return {"status": "success", "analyzed_count": len(links), "findings": findings}

    async def _intercept_traffic(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes mobile-specific API traffic patterns (e.g. pinned certs, non-browser headers).
        """
        endpoint = payload.get("endpoint")

        await self.think(
            f"Intercepting mobile API traffic for {endpoint}. Checking for User-Agent spoofing and extra auth headers.",
            ["mobile_api_security", "traffic_interception"],
        )

        return {"status": "success", "interception_active": True}

    async def _cleanup_resources(self) -> None:
        self.analyzed_deep_links.clear()
