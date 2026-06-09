"""Local MCP-style adapter for attack graph operations."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, cast

from ai_osop.core.exceptions import MCPException, MCPTimeoutError
from ai_osop.memory.graph_memory import GraphMemory


class AttackGraphMCPAdapter:
    """Expose GraphMemory operations through a timeout-bound adapter."""

    def __init__(self, graph_memory: GraphMemory, timeout_seconds: float = 30.0):
        self.graph_memory = graph_memory
        self.timeout_seconds = timeout_seconds

    async def get_stats(self, engagement_id: str) -> Dict[str, Any]:
        """Return graph statistics for an engagement."""
        return cast(
            Dict[str, Any],
            await self._run(self.graph_memory.get_graph_stats(engagement_id)),
        )

    async def find_attack_paths(
        self,
        entry_node_id: str,
        goal_types: List[str],
        max_depth: int = 5,
        min_confidence: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """Return attack paths serialized as dictionaries."""
        paths = await self._run(
            self.graph_memory.find_attack_paths(
                entry_node_id=entry_node_id,
                goal_types=goal_types,
                max_depth=max_depth,
                min_confidence=min_confidence,
            )
        )
        return [path.dict() for path in paths]

    async def propagate_risk(self, exploit_id: str, impact_score: float) -> Dict[str, Any]:
        """Propagate risk from a validated exploit through the graph."""
        await self._run(self.graph_memory.propagate_risk(exploit_id, impact_score))
        return {"status": "success", "exploit_id": exploit_id, "impact_score": impact_score}

    async def _run(self, awaitable: Any) -> Any:
        try:
            return await asyncio.wait_for(awaitable, timeout=self.timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise MCPTimeoutError("Attack graph MCP operation timed out") from exc
        except MCPException:
            raise
        except Exception as exc:
            raise MCPException(f"Attack graph MCP operation failed: {exc}") from exc
