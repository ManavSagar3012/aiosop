"""Tests for AI-OSOP reliability layer (Sprint 7).

Covers:
- retry_with_backoff utility
- Dead Letter Queue operations
- Agent shutdown sentinel pattern
- MCP health endpoint structure
- GraphMemory connect retry
- SessionMemory connect retry
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from ai_osop.core.models import AgentType, Task
from ai_osop.reliability.dlq import DeadLetterQueue, DLQEntry
from ai_osop.reliability.retry import retry_with_backoff, with_retry

# =============================================================================
# retry_with_backoff tests
# =============================================================================


class TestRetryWithBackoff:
    """Test the shared retry utility."""

    async def test_succeeds_on_first_attempt(self):
        """Should return immediately when the callable succeeds."""

        async def fn():
            return "success"

        result = await retry_with_backoff(fn, max_retries=3, retry_name="test")
        assert result == "success"

    async def test_retries_on_failure_then_succeeds(self):
        """Should retry on failure and return when it finally succeeds."""
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("fail")
            return "success"

        result = await retry_with_backoff(fn, max_retries=5, base_delay=0.01, retry_name="test")
        assert result == "success"
        assert call_count == 3

    async def test_raises_after_exhausting_retries(self):
        """Should raise the last exception when all retries are exhausted."""

        async def fn():
            raise ConnectionError("always fails")

        with pytest.raises(ConnectionError, match="always fails"):
            await retry_with_backoff(fn, max_retries=2, base_delay=0.01, retry_name="test")

    async def test_respects_exception_filter(self):
        """Should not retry on exceptions not in the filter."""

        async def fn():
            raise ValueError("not in filter")

        with pytest.raises(ValueError, match="not in filter"):
            await retry_with_backoff(
                fn, max_retries=3, base_delay=0.01, exceptions=ConnectionError, retry_name="test"
            )

    async def test_zero_retries(self):
        """Should only try once when max_retries=0."""
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            raise RuntimeError("fail")

        with pytest.raises(RuntimeError, match="fail"):
            await retry_with_backoff(fn, max_retries=0, retry_name="test")
        assert call_count == 1


class TestWithRetryDecorator:
    """Test the retry decorator."""

    async def test_decorator_retries_then_succeeds(self):
        call_count = 0

        @with_retry(max_retries=3, base_delay=0.01, exceptions=ConnectionError)
        async def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("fail")
            return "ok"

        result = await flaky()
        assert result == "ok"
        assert call_count == 2

    async def test_decorator_name_override(self):
        call_count = 0

        @with_retry(max_retries=0, retry_name="custom_name")
        async def named_fn():
            nonlocal call_count
            call_count += 1
            raise RuntimeError("fail")

        with pytest.raises(RuntimeError, match="fail"):
            await named_fn()
        assert call_count == 1


# =============================================================================
# Dead Letter Queue tests
# =============================================================================


class TestDeadLetterQueue:
    """Test DLQ enqueue, list, requeue, discard."""

    @pytest.fixture
    def mock_session_memory(self):
        """Mock session memory with Redis-like hot storage."""
        store = {}
        lists = {}

        async def store_hot(key, value, ttl=None):
            store[key] = value

        async def retrieve_hot(key):
            return store.get(key)

        class FakeRedis:
            async def rpush(self, key, value):
                if key not in lists:
                    lists[key] = []
                lists[key].append(value)

            async def lrange(self, key, start, end):
                return lists.get(key, [])

            async def keys(self, pattern):
                return [k for k in store.keys() if k.startswith("dlq:")]

        mem = MagicMock(spec=["store_hot", "retrieve_hot", "_redis"])
        mem.store_hot = AsyncMock(side_effect=store_hot)
        mem.retrieve_hot = AsyncMock(side_effect=retrieve_hot)
        mem._redis = FakeRedis()
        return mem, store, lists

    @pytest.fixture
    def sample_task(self):
        return Task(
            type="test_task",
            agent_type=AgentType.RECON,
            engagement_id="eng-123",
            payload={"url": "https://example.com"},
            max_retries=3,
        )

    async def test_enqueue_creates_entry(self, mock_session_memory, sample_task):
        mem, store, _ = mock_session_memory
        dlq = DeadLetterQueue(mem)

        entry_id = await dlq.enqueue(sample_task, reason="retry_exhausted", final_error="timeout")

        assert entry_id.startswith("dlq-")
        assert f"dlq:{entry_id}" in store
        data = store[f"dlq:{entry_id}"]
        assert data["task_id"] == sample_task.id
        assert data["reason"] == "retry_exhausted"
        assert data["final_error"] == "timeout"
        assert data["status"] == "pending_review"

    async def test_list_entries_by_engagement(self, mock_session_memory, sample_task):
        mem, store, _ = mock_session_memory
        dlq = DeadLetterQueue(mem)

        await dlq.enqueue(sample_task, reason="retry_exhausted", final_error="timeout")
        entries = await dlq.list_entries(engagement_id="eng-123")

        assert len(entries) == 1
        assert entries[0].engagement_id == "eng-123"

    async def test_requeue_resets_task(self, mock_session_memory, sample_task):
        mem, store, _ = mock_session_memory
        dlq = DeadLetterQueue(mem)

        entry_id = await dlq.enqueue(sample_task, reason="retry_exhausted", final_error="timeout")
        # Simulate the task having been retried before
        store[f"dlq:{entry_id}"]["task_payload"]["retry_count"] = 3
        store[f"dlq:{entry_id}"]["task_payload"]["status"] = "failed"

        task = await dlq.requeue(entry_id)

        assert task is not None
        assert task.retry_count == 0
        assert task.status == "pending"
        assert task.result is None

    async def test_requeue_returns_none_for_non_pending(self, mock_session_memory, sample_task):
        mem, store, _ = mock_session_memory
        dlq = DeadLetterQueue(mem)

        entry_id = await dlq.enqueue(sample_task, reason="retry_exhausted", final_error="timeout")
        store[f"dlq:{entry_id}"]["status"] = "requeued"

        task = await dlq.requeue(entry_id)
        assert task is None

    async def test_discard_updates_status(self, mock_session_memory, sample_task):
        mem, store, _ = mock_session_memory
        dlq = DeadLetterQueue(mem)

        entry_id = await dlq.enqueue(sample_task, reason="retry_exhausted", final_error="timeout")
        await dlq.discard(entry_id, operator_notes="False positive")

        data = store[f"dlq:{entry_id}"]
        assert data["status"] == "discarded"
        assert data["operator_notes"] == "False positive"
        assert data["updated_at"] is not None

    async def test_get_stats(self, mock_session_memory, sample_task):
        mem, store, _ = mock_session_memory
        dlq = DeadLetterQueue(mem)

        e1 = await dlq.enqueue(sample_task, reason="retry_exhausted", final_error="e1")
        e2 = await dlq.enqueue(sample_task, reason="retry_exhausted", final_error="e2")
        await dlq.requeue(e1)
        await dlq.discard(e2, "discarded")

        stats = await dlq.get_stats()
        assert stats["pending"] == 0
        assert stats["requeued"] == 1
        assert stats["discarded"] == 1

    async def test_enqueue_truncates_long_errors(self, mock_session_memory, sample_task):
        mem, store, _ = mock_session_memory
        dlq = DeadLetterQueue(mem)

        long_error = "x" * 5000
        entry_id = await dlq.enqueue(sample_task, reason="retry_exhausted", final_error=long_error)

        data = store[f"dlq:{entry_id}"]
        assert len(data["final_error"]) <= 2000


# =============================================================================
# Agent shutdown sentinel tests
# =============================================================================


class TestAgentShutdown:
    """Test agent task worker shutdown with sentinel pattern."""

    async def test_task_worker_exits_on_sentinel(self):
        """The worker should exit when it receives a None sentinel."""
        import asyncio

        from ai_osop.agents.base import AgentContext, BaseAgent

        class FakeAgent(BaseAgent):
            @property
            def agent_type(self):
                return AgentType.RECON

            async def _setup_resources(self):
                pass

            async def _execute(self, task):
                return {"status": "ok"}

            async def _cleanup_resources(self):
                pass

        # Create a minimal context
        ctx = MagicMock(spec=AgentContext)
        ctx.agent_id = "test-agent"
        ctx.agent_type = AgentType.RECON
        ctx.session_id = "test-session"
        ctx.session_memory = AsyncMock()
        ctx.graph_memory = MagicMock()
        ctx.vector_memory = MagicMock()
        ctx.llm_client = MagicMock()
        ctx.mcp_registry = MagicMock()
        ctx.rate_limiter = MagicMock()
        ctx.threat_intel_adapter = MagicMock()
        ctx.audit_callback = AsyncMock()
        ctx.coordination_bus = MagicMock()
        ctx.working_memory = {}
        ctx.task_history = []
        ctx.current_task = None
        ctx.status = "idle"
        ctx.last_heartbeat = datetime.utcnow()
        ctx.scope = None
        ctx.task_executor = None
        ctx.skill_engine = None
        ctx.persona = None
        ctx.cost_incurred = 0.0

        agent = FakeAgent(ctx)
        agent._running = True

        # Start the worker
        worker_task = asyncio.create_task(agent._task_worker())

        # Give it a moment to start and block on get()
        await asyncio.sleep(0.05)

        # Signal shutdown
        agent._running = False
        agent._shutting_down = True
        agent._task_queue.put_nowait(None)

        # The worker should exit within a short timeout
        try:
            await asyncio.wait_for(worker_task, timeout=1.0)
        except asyncio.TimeoutError:
            pytest.fail("Task worker did not exit after sentinel was injected")

    async def test_shutdown_injects_sentinel(self):
        """shutdown() should inject a None sentinel into the queue."""
        import asyncio

        from ai_osop.agents.base import AgentContext, BaseAgent

        class FakeAgent(BaseAgent):
            @property
            def agent_type(self):
                return AgentType.RECON

            async def _setup_resources(self):
                pass

            async def _execute(self, task):
                return {"status": "ok"}

            async def _cleanup_resources(self):
                pass

        ctx = MagicMock(spec=AgentContext)
        ctx.agent_id = "test-agent"
        ctx.agent_type = AgentType.RECON
        ctx.session_id = "test-session"
        ctx.session_memory = AsyncMock()
        ctx.graph_memory = MagicMock()
        ctx.vector_memory = MagicMock()
        ctx.llm_client = MagicMock()
        ctx.mcp_registry = MagicMock()
        ctx.rate_limiter = MagicMock()
        ctx.threat_intel_adapter = MagicMock()
        ctx.audit_callback = AsyncMock()
        ctx.coordination_bus = MagicMock()
        ctx.working_memory = {}
        ctx.task_history = []
        ctx.current_task = None
        ctx.status = "idle"
        ctx.last_heartbeat = datetime.utcnow()
        ctx.scope = None
        ctx.task_executor = None
        ctx.skill_engine = None
        ctx.persona = None
        ctx.cost_incurred = 0.0

        agent = FakeAgent(ctx)
        agent._running = True
        agent._bg_tasks = [asyncio.create_task(agent._task_worker())]

        await asyncio.sleep(0.05)
        await agent.shutdown()

        # The sentinel should have been consumed (or the queue still has it if
        # shutdown raced). Either way, the worker should be done.
        assert agent._bg_tasks == []


# =============================================================================
# GraphMemory connect retry (structural test)
# =============================================================================


class TestGraphMemoryRetry:
    """Verify GraphMemory.connect uses retry_with_backoff."""

    def test_connect_uses_retry_import(self):
        """GraphMemory should import and use retry_with_backoff."""
        import inspect

        from ai_osop.memory.graph_memory import GraphMemory

        source = inspect.getsource(GraphMemory.connect)
        assert "retry_with_backoff" in source
        assert "_connect" in source


# =============================================================================
# SessionMemory connect retry (structural test)
# =============================================================================


class TestSessionMemoryRetry:
    """Verify SessionMemory.connect uses retry_with_backoff."""

    def test_connect_uses_retry_import(self):
        """SessionMemory should import and use retry_with_backoff."""
        import inspect

        from ai_osop.memory.session_memory import SessionMemory

        source = inspect.getsource(SessionMemory.connect)
        assert "retry_with_backoff" in source
        assert "_connect_redis" in source
        assert "_connect_postgres" in source


# =============================================================================
# System router MCP health endpoint (structural test)
# =============================================================================


class TestSystemRouter:
    """Verify system router has Sprint 7 endpoints."""

    def test_mcp_health_endpoint_exists(self):
        """The system router should have /mcp/health endpoint."""
        from ai_osop.api.routers.system import router

        routes = [r.path for r in router.routes]
        assert "/system/mcp/health" in routes

    def test_dlq_stats_endpoint_exists(self):
        """The system router should have /dlq/stats endpoint."""
        from ai_osop.api.routers.system import router

        routes = [r.path for r in router.routes]
        assert "/system/dlq/stats" in routes

    def test_dlq_entries_endpoint_exists(self):
        """The system router should have /dlq/entries endpoint."""
        from ai_osop.api.routers.system import router

        routes = [r.path for r in router.routes]
        assert "/system/dlq/entries" in routes

    def test_dlq_requeue_endpoint_exists(self):
        """The system router should have /dlq/requeue endpoint."""
        from ai_osop.api.routers.system import router

        routes = [r.path for r in router.routes]
        assert "/system/dlq/requeue" in routes

    def test_dlq_discard_endpoint_exists(self):
        """The system router should have /dlq/discard endpoint."""
        from ai_osop.api.routers.system import router

        routes = [r.path for r in router.routes]
        assert "/system/dlq/discard" in routes
