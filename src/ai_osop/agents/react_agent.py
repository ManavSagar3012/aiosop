"""
React Specialist Agent
Specializes in identifying DOM-based vulnerabilities and component-level flaws in React applications.
"""

import logging
from typing import Any, Dict

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task

logger = logging.getLogger(__name__)


class ReactSpecialistAgent(BaseAgent):
    """
    React Specialist Agent (V5.1)

    Responsibilities:
    - DOM XSS detection in React components.
    - Identifying dangerous dangerouslySetInnerHTML usage.
    - Probing client-side routing vulnerabilities.
    - State-based logic flaw analysis.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.REACT_SPECIALIST

    async def _setup_resources(self) -> None:
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        task_type = task.type
        payload = task.payload

        if task_type == "analyze_bundle":
            return await self._analyze_js_bundle(payload)
        elif task_type == "probe_components":
            return await self._probe_components(payload)
        else:
            return {"status": "failed", "error": f"Unknown task type: {task_type}"}

    async def _analyze_js_bundle(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze React JS bundles for dangerous patterns."""
        target_url = payload.get("url")

        if not target_url:
            return {"status": "failed", "error": "target_url is required"}

        await self.think(
            f"Analyzing React bundle for {target_url}.",
            ["static_analysis", "dangerous_sinks", "sourcemaps"],
        )

        try:
            from ai_osop.adapters.source_map_mcp import SourceMapMCPAdapter

            # PATCH (REL-034, 2026-06-15): self.context -> self.ctx.
            adapter = SourceMapMCPAdapter(self.ctx.mcp_registry)
            await adapter.initialize(
                self.ctx.scope.model_dump() if self.ctx.scope else {},
                self.ctx.session_id,
            )
            result = await adapter.fetch_and_parse_sourcemap(target_url)

            findings = result.get("secrets", [])
            for f in findings:
                await self.observe(
                    target_id=target_url, obs_type="hardcoded_secret", data=f, confidence=0.95
                )

            return {
                "status": "success",
                "findings_count": len(findings),
                "msg": result.get("msg", ""),
            }

        except Exception as e:
            logger.error(f"Failed to analyze sourcemap: {e}")
            return {"status": "failed", "error": str(e)}

    async def _probe_components(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dynamically probe React components for state-based logic flaws.

        Dynamic component probing is not yet implemented. Rather than claim a
        misleading "success", report the real status so callers don't treat a
        no-op as a completed probe. Static React bundle analysis (real) is
        available via the `analyze_bundle` task type.
        """
        return {
            "status": "not_implemented",
            "msg": (
                "Dynamic React component probing is not implemented; no probing "
                "was performed. Use 'analyze_bundle' for real static analysis."
            ),
            "findings_count": 0,
        }

    async def _cleanup_resources(self) -> None:
        pass
