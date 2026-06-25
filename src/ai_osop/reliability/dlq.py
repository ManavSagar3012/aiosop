"""Dead Letter Queue (DLQ) for AI-OSOP.

When a task exhausts its retry budget, it is sent to the DLQ for operator review.
Operators can requeue (with retry_count reset) or permanently discard the task.

Storage: Redis (hot) + Postgres (warm) for durability.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ai_osop.core.models import Task
from ai_osop.core.tracing import trace_span


class DLQEntry(BaseModel):
    """A single entry in the Dead Letter Queue."""

    id: str = Field(default_factory=lambda: f"dlq-{uuid.uuid4().hex[:16]}")
    task_id: str
    engagement_id: str
    task_type: str
    agent_type: str
    reason: str  # e.g., "retry_budget_exhausted", "terminal_failure"
    final_error: str
    task_payload: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending_review"  # pending_review, requeued, discarded
    operator_notes: Optional[str] = None
    retry_count: Optional[int] = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None


class DeadLetterQueue:
    """Dead Letter Queue for failed tasks.

    Usage:
        dlq = DeadLetterQueue(session_memory)
        await dlq.enqueue(task, reason="retry_budget_exhausted", final_error="...")
        entries = await dlq.list_entries(engagement_id="eng-123")
        task = await dlq.requeue(dlq_entry_id="dlq-abc")
    """

    def __init__(self, session_memory: Any) -> None:
        self._session_memory = session_memory

    @trace_span("dlq.enqueue")
    async def enqueue(self, task: Task, reason: str, final_error: str) -> str:
        """Add a failed task to the DLQ.

        Returns the DLQ entry ID.
        """
        entry = DLQEntry(
            task_id=task.id,
            engagement_id=task.engagement_id,
            task_type=task.type,
            agent_type=task.agent_type.value,
            reason=reason,
            final_error=final_error[:2000],  # truncate to avoid huge payloads
            task_payload=task.model_dump(mode='json'),
            retry_count=getattr(task, "retry_count", 0),
        )

        # Store in hot + warm tier
        if hasattr(self._session_memory, "store_dlq_entry"):
            await self._session_memory.store_dlq_entry(entry)
        else:
            redis_key = f"dlq:{entry.id}"
            await self._session_memory.store_hot(redis_key, entry.model_dump(), ttl=86400 * 7)

        # Also add to engagement-scoped list
        list_key = f"dlq:list:{task.engagement_id}"
        await self._session_memory._redis.rpush(list_key, entry.id)

        return entry.id

    @trace_span("dlq.list_entries")
    async def list_entries(
        self,
        engagement_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[DLQEntry]:
        """List DLQ entries for operator review.

        If engagement_id is provided, only entries for that engagement are returned.
        If status is provided, only entries with that status are returned.
        """
        if hasattr(self._session_memory, "list_dlq_entries"):
            return await self._session_memory.list_dlq_entries(engagement_id, status)

        if engagement_id:
            list_key = f"dlq:list:{engagement_id}"
            entry_ids = await self._session_memory._redis.lrange(list_key, 0, -1)
            entry_ids = [eid.decode() if isinstance(eid, bytes) else eid for eid in entry_ids]
        else:
            # Scan all DLQ keys (use sparingly — not for large datasets)
            keys = await self._session_memory._redis.keys("dlq:dlq-*")
            entry_ids = [
                k.decode().split(":", 1)[1] if isinstance(k, bytes) else k.split(":", 1)[1]
                for k in keys
            ]

        entries = []
        for entry_id in entry_ids:
            data = await self._session_memory.retrieve_hot(f"dlq:{entry_id}")
            if data:
                entry = DLQEntry(**data)
                if status is None or entry.status == status:
                    entries.append(entry)

        # Sort by created_at descending
        entries.sort(key=lambda e: e.created_at, reverse=True)
        return entries

    @trace_span("dlq.requeue")
    async def requeue(self, dlq_entry_id: str) -> Optional[Task]:
        """Requeue a DLQ task back into the normal task queue.

        Resets retry_count to 0 and updates the DLQ entry status.
        Returns the requeued Task or None if not found.
        """
        if hasattr(self._session_memory, "get_dlq_entry"):
            entry = await self._session_memory.get_dlq_entry(dlq_entry_id)
        else:
            data = await self._session_memory.retrieve_hot(f"dlq:{dlq_entry_id}")
            entry = DLQEntry(**data) if data else None

        if not entry:
            return None

        if entry.status != "pending_review":
            return None

        # Reconstruct the task from the stored payload
        task = Task(**entry.task_payload)
        task.retry_count = 0
        task.status = "pending"
        task.result = None
        task.completed_at = None
        task.started_at = None
        task.assigned_agent_id = None

        # Update DLQ entry status
        entry.status = "requeued"
        entry.updated_at = datetime.utcnow()
        entry.retry_count = 0  # Reset retry count on requeue

        if hasattr(self._session_memory, "store_dlq_entry"):
            await self._session_memory.store_dlq_entry(entry)
        else:
            await self._session_memory.store_hot(f"dlq:{entry.id}", entry.model_dump(), ttl=86400 * 7)

        return task

    @trace_span("dlq.discard")
    async def discard(self, dlq_entry_id: str, operator_notes: str) -> None:
        """Permanently discard a DLQ entry."""
        if hasattr(self._session_memory, "get_dlq_entry"):
            entry = await self._session_memory.get_dlq_entry(dlq_entry_id)
        else:
            data = await self._session_memory.retrieve_hot(f"dlq:{dlq_entry_id}")
            entry = DLQEntry(**data) if data else None

        if not entry:
            return

        entry.status = "discarded"
        entry.updated_at = datetime.utcnow()
        entry.operator_notes = operator_notes

        if hasattr(self._session_memory, "store_dlq_entry"):
            await self._session_memory.store_dlq_entry(entry)
        else:
            await self._session_memory.store_hot(f"dlq:{entry.id}", entry.model_dump(), ttl=86400 * 7)

    @trace_span("dlq.get_stats")
    async def get_stats(self) -> Dict[str, int]:
        """Return DLQ stats: pending, requeued, discarded counts."""
        if hasattr(self._session_memory, "get_dlq_stats"):
            return await self._session_memory.get_dlq_stats()

        # Scan all DLQ entries
        keys = await self._session_memory._redis.keys("dlq:dlq-*")
        pending = requeued = discarded = 0

        for key in keys:
            data = await self._session_memory.retrieve_hot(
                key.decode() if isinstance(key, bytes) else key
            )
            if data:
                status = data.get("status", "pending_review")
                if status == "pending_review":
                    pending += 1
                elif status == "requeued":
                    requeued += 1
                elif status == "discarded":
                    discarded += 1

        return {"pending": pending, "requeued": requeued, "discarded": discarded}
