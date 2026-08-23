"""Tests for ai_osop.reliability.dlq module."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.reliability.dlq import DeadLetterQueue, DLQEntry


class TestDeadLetterQueue:
    @pytest.fixture
    def mock_session_memory(self):
        """Mock session memory with Redis-like interface."""
        mem = MagicMock(spec=["store_hot", "retrieve_hot", "_redis"])
        mem._redis = MagicMock()
        mem._redis.rpush = AsyncMock()
        mem._redis.lrange = AsyncMock(return_value=[])
        mem._redis.keys = AsyncMock(return_value=[])
        mem.store_hot = AsyncMock()
        mem.retrieve_hot = AsyncMock(return_value=None)
        return mem

    @pytest.fixture
    def dlq(self, mock_session_memory):
        return DeadLetterQueue(mock_session_memory)

    @pytest.fixture
    def sample_task(self):
        return Task(
            id="task-abc123",
            type="test_task",
            priority=5,
            agent_type=AgentType.RECON,
            payload={"url": "http://example.com"},
            engagement_id="eng-123",
            retry_count=3,
            max_retries=3,
        )

    async def test_enqueue_creates_entry(self, dlq, mock_session_memory, sample_task):
        """enqueue should create a DLQ entry and store it in Redis."""
        entry_id = await dlq.enqueue(
            sample_task, reason="retry_budget_exhausted", final_error="timeout"
        )
        assert entry_id.startswith("dlq-")
        mock_session_memory.store_hot.assert_called_once()
        mock_session_memory._redis.rpush.assert_called_once()

    async def test_enqueue_truncates_long_errors(self, dlq, mock_session_memory, sample_task):
        """enqueue should truncate errors longer than 2000 chars."""
        long_error = "x" * 5000
        await dlq.enqueue(sample_task, reason="retry_budget_exhausted", final_error=long_error)
        call_args = mock_session_memory.store_hot.call_args[0][1]
        assert len(call_args["final_error"]) <= 2000

    async def test_requeue_resets_retry_count(self, dlq, mock_session_memory, sample_task):
        """requeue should reset retry_count to 0 and update status."""
        entry = DLQEntry(
            task_id=sample_task.id,
            engagement_id=sample_task.engagement_id,
            task_type=sample_task.type,
            agent_type=sample_task.agent_type.value,
            reason="retry_budget_exhausted",
            final_error="timeout",
            task_payload=sample_task.model_dump(),
        )
        mock_session_memory.retrieve_hot = AsyncMock(return_value=entry.model_dump())
        dlq._session_memory = mock_session_memory

        task = await dlq.requeue(entry.id)
        assert task is not None
        assert task.retry_count == 0
        assert task.status == "pending"

    async def test_requeue_returns_none_for_non_pending(self, dlq, mock_session_memory):
        """requeue should return None if entry is not pending_review."""
        entry = DLQEntry(
            task_id="task-1",
            engagement_id="eng-1",
            task_type="test",
            agent_type="recon",
            reason="retry_budget_exhausted",
            final_error="timeout",
            status="discarded",
        )
        mock_session_memory.retrieve_hot = AsyncMock(return_value=entry.model_dump())
        dlq._session_memory = mock_session_memory

        task = await dlq.requeue(entry.id)
        assert task is None

    async def test_discard_updates_status(self, dlq, mock_session_memory, sample_task):
        """discard should update status to discarded and add operator notes."""
        entry = DLQEntry(
            task_id=sample_task.id,
            engagement_id=sample_task.engagement_id,
            task_type=sample_task.type,
            agent_type=sample_task.agent_type.value,
            reason="retry_budget_exhausted",
            final_error="timeout",
            task_payload=sample_task.model_dump(),
        )
        mock_session_memory.retrieve_hot = AsyncMock(return_value=entry.model_dump())
        dlq._session_memory = mock_session_memory

        await dlq.discard(entry.id, "operator_decided_to_skip")
        # Verify store_hot was called with updated status
        call_args = mock_session_memory.store_hot.call_args[0][1]
        assert call_args["status"] == "discarded"
        assert call_args["operator_notes"] == "operator_decided_to_skip"
        assert call_args["updated_at"] is not None

    async def test_get_stats_empty(self, dlq, mock_session_memory):
        """get_stats should return zeros for empty DLQ."""
        mock_session_memory._redis.keys = AsyncMock(return_value=[])
        stats = await dlq.get_stats()
        assert stats == {"pending": 0, "requeued": 0, "discarded": 0}

    async def test_list_entries_by_engagement(self, dlq, mock_session_memory, sample_task):
        """list_entries should filter by engagement_id."""
        entry = DLQEntry(
            task_id=sample_task.id,
            engagement_id=sample_task.engagement_id,
            task_type=sample_task.type,
            agent_type=sample_task.agent_type.value,
            reason="retry_budget_exhausted",
            final_error="timeout",
            task_payload=sample_task.model_dump(),
        )
        mock_session_memory._redis.lrange = AsyncMock(return_value=[entry.id])
        mock_session_memory.retrieve_hot = AsyncMock(return_value=entry.model_dump())
        dlq._session_memory = mock_session_memory

        entries = await dlq.list_entries(engagement_id=sample_task.engagement_id)
        assert len(entries) == 1
        assert entries[0].task_id == sample_task.id
