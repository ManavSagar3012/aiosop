"""Context Manager Agent.

Maintains compact engagement context for other agents by summarizing session,
graph, and semantic memory into reusable snapshots.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task


class ContextManagerAgent(BaseAgent):
    """Builds and retrieves cross-agent engagement context."""

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CONTEXT_MANAGER

    async def _setup_resources(self) -> None:
        self.context_snapshots: Dict[str, Dict[str, Any]] = {}

    async def _execute(self, task: Task) -> Dict[str, Any]:
        if task.type == "summarize_context":
            return await self._summarize_context(task.payload)
        if task.type == "retrieve_context":
            return await self._retrieve_context(task.payload)
        if task.type == "store_context_snapshot":
            return await self._store_context_snapshot(task.payload)
        raise AgentException(f"Unknown context manager task type: {task.type}")

    async def _summarize_context(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        engagement_id = payload.get("engagement_id", self.ctx.session_id)
        graph_stats = await self.ctx.graph_memory.get_graph_stats(engagement_id)

        recent_state = {}
        try:
            recent_state = await self.ctx.session_memory.get_session_state(engagement_id)
        except Exception:
            recent_state = {}

        prompt_context = {
            "engagement_id": engagement_id,
            "phase": payload.get("phase", "unknown"),
            "graph_stats": graph_stats,
            "recent_state": recent_state,
            "focus": payload.get("focus", "overall engagement context"),
        }
        messages = [
            {
                "role": "system",
                "content": (
                    "Summarize security engagement context for downstream agents. "
                    "Keep it factual, compact, and preserve open risks and next actions."
                ),
            },
            {"role": "user", "content": str(prompt_context)},
        ]
        summary = await self.ctx.llm_client.complete(messages)

        snapshot = {
            "engagement_id": engagement_id,
            "summary": summary,
            "graph_stats": graph_stats,
            "created_at": datetime.utcnow().isoformat(),
            "focus": prompt_context["focus"],
        }
        await self._persist_snapshot(engagement_id, snapshot)

        return {"status": "success", "context_snapshot": snapshot}

    async def _retrieve_context(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        query = payload.get("query", "")
        payload_type = payload.get("payload_type")
        limit = int(payload.get("limit", 5))

        embedding = await self.ctx.llm_client.get_embedding(query)
        similar = await self.ctx.vector_memory.search_similar_payloads(
            embedding, payload_type=payload_type, limit=limit
        )

        return {"status": "success", "query": query, "matches": similar}

    async def _store_context_snapshot(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        engagement_id = payload.get("engagement_id", self.ctx.session_id)
        snapshot = {
            "engagement_id": engagement_id,
            "summary": payload.get("summary", ""),
            "graph_stats": payload.get("graph_stats", {}),
            "created_at": datetime.utcnow().isoformat(),
            "focus": payload.get("focus", "manual"),
        }
        await self._persist_snapshot(engagement_id, snapshot)

        return {"status": "success", "context_snapshot": snapshot}

    async def _persist_snapshot(self, engagement_id: str, snapshot: Dict[str, Any]) -> None:
        key = f"context:{engagement_id}"
        self.context_snapshots[key] = snapshot
        await self.ctx.session_memory.store_agent_state(
            self.ctx.agent_id,
            {
                "status": self.ctx.status,
                "latest_context_key": key,
                "latest_context_snapshot": snapshot,
            },
        )

    async def _cleanup_resources(self) -> None:
        self.context_snapshots.clear()
