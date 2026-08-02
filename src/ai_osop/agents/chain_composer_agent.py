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

# Vuln-class synonyms: different scanners/report paths label the same technique
# differently (e.g. IDOR vs BOLA, xss vs cross_site_scripting). Normalize both the
# scope's allowed_techniques and each hop's vuln type through this map before the
# admissibility check so chains aren't dropped on vocabulary alone.
_CLASS_SYNONYMS: Dict[str, str] = {
    "bola": "idor",
    "cross_site_scripting": "xss",
}


def _normalize_class(raw: Any) -> str:
    """Lowercase + collapse synonym classes to a canonical token."""
    tok = str(raw or "").strip().lower()
    return _CLASS_SYNONYMS.get(tok, tok)


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

        if not chains:
            return {"status": "success", "message": "No vulnerability chains found"}

        # 2. Admissibility filter: drop chains whose hops use techniques outside
        #    scope.allowed_techniques. Filtering happens BEFORE LLM reasoning so
        #    the model never sees (and never proposes) out-of-scope chains.
        scope = getattr(self.ctx, "scope", None)
        allowed = {
            _normalize_class(t)
            for t in (getattr(scope, "allowed_techniques", []) or [])
        }
        allowed.discard("")
        if allowed:
            admissible = []
            for chain in chains:
                hop_types = {
                    _normalize_class(n.get("vuln", {}).get("type", ""))
                    for n in chain.get("nodes", [])
                }
                hop_types.discard("")
                if hop_types and hop_types.issubset(allowed):
                    admissible.append(chain)
                else:
                    logger.info("chain.filtered", dropped=sorted(hop_types - allowed))
            chains = admissible
        if not chains:
            return {"status": "success", "message": "No admissible chains for scope"}

        # 3. Reason over chains
        analysis = await self.think(
            f"Analyzing {len(chains)} potential exploit chains.",
            ["attack_graph", "chain_composition"],
        )

        return {"status": "success", "chains": chains, "analysis": analysis}

    async def _cleanup_resources(self) -> None:
        pass
