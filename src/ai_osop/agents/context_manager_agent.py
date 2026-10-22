"""Context Manager Agent.

Maintains compact engagement context for other agents by summarizing session,
graph, and semantic memory into reusable snapshots.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, List

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task
from ai_osop.orchestrator.context_compaction import (
    ContextBoundary,
    ContextCompactionDenied,
    compact_context,
    durable_task_sources,
    source_sha256,
    task_assignment_sha256,
)


class ContextManagerAgent(BaseAgent):
    """Builds and retrieves cross-agent engagement context."""

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CONTEXT_MANAGER

    def supports_task_type(self, task_type: str) -> bool:
        return task_type in [
            "summarize_context",
            "retrieve_context",
            "store_context_snapshot",
            "compact_context",
        ]

    async def _setup_resources(self) -> None:
        self.context_snapshots: Dict[str, Dict[str, Any]] = {}

    async def _execute(self, task: Task) -> Dict[str, Any]:
        if task.type == "compact_context":
            return await self._compact_context(task.payload)
        if task.type == "summarize_context":
            return await self._summarize_context(task.payload)
        if task.type == "retrieve_context":
            return await self._retrieve_context(task.payload)
        if task.type == "store_context_snapshot":
            return await self._store_context_snapshot(task.payload)
        raise AgentException(f"Unknown context manager task type: {task.type}")

    async def _compact_context(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Optional free, deterministic flow-scoped snapshot from durable tasks.

        This deliberately does not overwrite the older context:{engagement}
        key whose reader lacks revision/authorization fencing. Consumers must
        verify the recorded boundary before reusing this context as a *hint*.
        No LLM call, arbitrary summary, payload text or evidence is persisted.
        """
        assigned = self.ctx.current_task
        sm = self.ctx.session_memory
        expected_version = (
            assigned.payload.get("_authorization_version")
            if assigned is not None and isinstance(assigned.payload, dict)
            else None
        )
        if (
            assigned is None
            or assigned.type != "compact_context"
            or assigned.engagement_id != self.ctx.session_id
            or not isinstance(assigned.flow_id, str)
            or type(expected_version) is not int
            or expected_version < 1
        ):
            raise AgentException("Compaction requires an assigned, signed-version-fenced Flow task")
        requested = payload.get("source_task_ids", [])
        max_items = payload.get("max_items", 24)
        if (
            not isinstance(requested, list)
            or len(requested) > 64
            or any(not isinstance(item, str) or not item.startswith("task-") for item in requested)
        ):
            raise AgentException("Durable compaction task sources must be bounded task IDs")
        try:
            durable = await asyncio.wait_for(sm.load_task_authoritative(assigned.id), timeout=3)
            flow = await asyncio.wait_for(sm.load_flow(assigned.flow_id), timeout=3)
            auth = await asyncio.wait_for(
                sm.assert_signed_authorization(
                    self.ctx.session_id, expected_version=expected_version
                ),
                timeout=3,
            )
            if (
                durable is None
                or durable.engagement_id != self.ctx.session_id
                or durable.flow_id != assigned.flow_id
                or durable.type != assigned.type
                or durable.payload.get("_authorization_version") != expected_version
                or durable.status not in {"pending", "running"}
                or flow is None
                or flow.engagement_id != self.ctx.session_id
                or flow.id != assigned.flow_id
                or flow.status not in {"pending", "running"}
                or auth.version != expected_version
            ):
                raise ContextCompactionDenied("Durable current task or flow unavailable")
            durable_hash = task_assignment_sha256(durable)
            boundary = ContextBoundary(
                engagement_id=self.ctx.session_id,
                flow_id=flow.id,
                flow_revision=flow.revision,
                task_id=durable.id,
                task_state_sha256=durable_hash,
                authorization_id=auth.authorization_id,
                authorization_version=auth.version,
                authorization_sha256=auth.policy_sha256,
            )
            tasks = {}
            for source_id in requested:
                source = await asyncio.wait_for(
                    sm.load_task_authoritative(source_id),
                    timeout=3,
                )
                if (
                    source is None
                    or source.id != source_id
                    or source.engagement_id != boundary.engagement_id
                    or source.flow_id != boundary.flow_id
                ):
                    raise ContextCompactionDenied("Cross-flow or missing task source")
                tasks[source_id] = source
            sources = durable_task_sources(list(tasks.values()))
            snapshot = compact_context(
                boundary=boundary,
                source_ids=requested,
                durable_source_loader=lambda source_id: sources[source_id],
                max_items=max_items,
            )
            # Re-check before writing a non-authoritative hint; these are not
            # transactional CAS locks and MUST NEVER authorize execution.
            fresh_auth = await asyncio.wait_for(
                sm.assert_signed_authorization(
                    self.ctx.session_id,
                    expected_version=boundary.authorization_version,
                ),
                timeout=3,
            )
            fresh_flow = await asyncio.wait_for(sm.load_flow(flow.id), timeout=3)
            fresh_task = await asyncio.wait_for(
                sm.load_task_authoritative(assigned.id),
                timeout=3,
            )
            if (
                fresh_auth.policy_sha256 != boundary.authorization_sha256
                or fresh_auth.authorization_id != boundary.authorization_id
                or fresh_flow is None
                or fresh_flow.revision != boundary.flow_revision
                or fresh_flow.engagement_id != boundary.engagement_id
                or fresh_flow.status not in {"pending", "running"}
                or fresh_task is None
                or fresh_task.status not in {"pending", "running"}
                or task_assignment_sha256(fresh_task) != durable_hash
            ):
                raise ContextCompactionDenied("Compaction authority or task revision changed")
            for source_id, initial in tasks.items():
                fresh_source = await asyncio.wait_for(
                    sm.load_task_authoritative(source_id),
                    timeout=3,
                )
                if (
                    fresh_source is None
                    or fresh_source.id != source_id
                    or fresh_source.engagement_id != boundary.engagement_id
                    or fresh_source.flow_id != boundary.flow_id
                    or source_sha256(fresh_source.model_dump(mode="json"))
                    != source_sha256(initial.model_dump(mode="json"))
                ):
                    raise ContextCompactionDenied("Durable compaction source changed")
            key = (
                f"context_compacted:{boundary.engagement_id}:{boundary.flow_id}:"
                f"{boundary.task_id}:{boundary.authorization_version}:"
                f"{boundary.flow_revision}"
            )
            await asyncio.wait_for(sm.store_hot(key, snapshot, ttl=86400), timeout=3)
            # A non-authoritative Flow/revision-scoped locator lets other
            # executing Flow tasks find this snapshot without globbing Redis.
            # Neither the locator nor snapshot grants authorization; both
            # must be replay-verified against fresh PostgreSQL task records.
            locator = (
                f"context_compacted_index:{boundary.engagement_id}:{boundary.flow_id}:"
                f"{boundary.authorization_version}:{boundary.flow_revision}"
            )
            await asyncio.wait_for(
                sm.store_hot(
                    locator,
                    {
                        "schema": "ai-osop-compaction-index-v1",
                        "context_key": key,
                        "producer_task_id": boundary.task_id,
                        "source_task_ids": requested[:],
                        "max_items": max_items,
                        "snapshot_sha256": snapshot["snapshot_sha256"],
                    },
                    ttl=86400,
                ),
                timeout=3,
            )
        except Exception as exc:
            raise AgentException("Verified durable context compaction unavailable") from exc
        return {"status": "success", "context_snapshot": snapshot, "context_key": key}

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

        executing = self.ctx.current_task
        if executing is None or executing.engagement_id != self.ctx.session_id:
            raise AgentException("Semantic retrieval requires the assigned engagement task")
        embedding = await self.ctx.llm_client.get_embedding(query)
        similar = await self.ctx.vector_memory.search_similar_payloads(
            embedding,
            payload_type=payload_type,
            limit=limit,
            engagement_id=self.ctx.session_id,
            task_id=executing.id,
            category=payload.get("category", "payload"),
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
        # Snapshot is engagement-scoped. The previous agent-id-only key was
        # overwritten by heartbeats and could not be read by other agents.
        await self.ctx.session_memory.store_hot(key, snapshot, ttl=604800)
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
