"""
ChainComposer Agent
Reason over findings and suggest multi-hop exploit chains.
"""

from typing import Any, Dict

import structlog

from ai_osop.agents.base import BaseAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task

logger = structlog.get_logger(__name__)


class ChainComposerAgent(BaseAgent):
    """
    Composes multi-hop exploit chains from individual vulnerabilities.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.ATTACK_CHAIN

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "compose_exploit_chain"

    async def _setup_resources(self) -> None:
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        engagement_id = task.engagement_id

        # 1. Find chains
        chains = await self.ctx.graph_memory.find_vulnerability_chains(engagement_id)

        # 2. Reason over chains
        if not chains:
            return {"status": "success", "message": "No vulnerability chains found"}

        analysis = await self.think(
            f"Analyzing {len(chains)} potential exploit chains.",
            ["attack_graph", "chain_composition"],
        )

        return {"status": "success", "chains": chains, "analysis": analysis}

    async def _cleanup_resources(self) -> None:
        pass
