"""Tests for the Execution Observatory (execution_trace.py).

Covers:
- TaskExecutionTrace lifecycle (record, failure, summary, serialization)
- ExecutionStage enum values
- FailureCategory enum values
- attach_trace / get_trace / record_stage / record_failure helpers
- store_trace_to_redis / load_trace_from_redis persistence helpers
- StageRecord serialization
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.execution_trace import (
    ExecutionStage,
    FailureCategory,
    StageRecord,
    TaskExecutionTrace,
    attach_trace,
    get_trace,
    load_trace_from_redis,
    record_failure,
    record_stage,
    store_trace_to_redis,
)


class TestExecutionStage:
    """Verify all 21 lifecycle stages exist."""

    def test_all_stages_present(self):
        stages = {s.value for s in ExecutionStage}
        expected = {
            "task_created", "task_persisted", "task_queued",
            "worker_lease_requested", "worker_lease_granted", "worker_assigned",
            "dependency_injection_complete",
            "redis_connected", "neo4j_connected", "postgres_connected",
            "mcp_connected", "mcp_connect_failed",
            "planner_started",
            "scanner_started", "scanner_skipped", "scanner_timed_out", "scanner_failed",
            "verification_started",
            "persistence_completed",
            "dashboard_updated",
            "task_completed", "task_failed",
        }
        assert stages == expected, f"Missing: {expected - stages} Extra: {stages - expected}"

    def test_values_are_strings(self):
        for stage in ExecutionStage:
            assert isinstance(stage.value, str)


class TestFailureCategory:
    """Verify all 13 failure categories exist."""

    def test_all_categories_present(self):
        cats = {c.value for c in FailureCategory}
        expected = {
            "infrastructure", "queue", "worker", "dependency", "mcp",
            "planner", "recon", "parser", "scanner", "verification",
            "persistence", "dashboard", "unknown",
        }
        assert cats == expected, f"Missing: {expected - cats} Extra: {cats - expected}"

    def test_unknown_is_last_fallback(self):
        assert FailureCategory.UNKNOWN.value == "unknown"


class TestStageRecord:
    """Test individual stage observation records."""

    def test_basic_creation(self):
        rec = StageRecord(stage="task_created", metadata={"task_type": "sqli_scan"})
        assert rec.stage == "task_created"
        assert rec.error is None
        assert rec.metadata["task_type"] == "sqli_scan"
        assert rec.timestamp > 0

    def test_serialization_to_dict(self):
        rec = StageRecord(stage="scanning", duration_ms=150.5, error="timeout")
        d = rec.to_dict()
        assert d["stage"] == "scanning"
        assert d["duration_ms"] == 150.5
        assert d["error"] == "timeout"
        assert "timestamp" in d

    def test_optional_fields_omitted_when_none(self):
        rec = StageRecord(stage="task_created")
        d = rec.to_dict()
        assert "error" not in d
        assert "duration_ms" not in d


class TestTaskExecutionTrace:
    """Test full trace lifecycle."""

    def test_create_trace(self):
        trace = TaskExecutionTrace(task_id="task-001", engagement_id="eng-001")
        assert trace.task_id == "task-001"
        assert trace.engagement_id == "eng-001"
        assert len(trace._stages) == 0
        assert not trace.is_complete

    def test_record_stages_sequentially(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_created")
        trace.record("task_persisted")
        trace.record("task_queued")
        assert len(trace._stages) == 3
        for i, stage in enumerate(trace._stages):
            assert stage.stage in ("task_created", "task_persisted", "task_queued")
            if i > 0:
                assert stage.duration_ms is not None

    def test_record_with_metadata_and_error(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_created", metadata={"task_type": "sqli"})
        trace.record("mcp_connect_failed", error="Connection refused")
        stages = trace.stages
        assert stages[0]["metadata"]["task_type"] == "sqli"
        assert stages[1]["error"] == "Connection refused"

    def test_is_complete_true_for_completed(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_created")
        trace.record("task_completed")
        assert trace.is_complete

    def test_is_complete_true_for_failed(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_created")
        trace.record("task_failed")
        assert trace.is_complete

    def test_is_complete_false_when_running(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("scanner_started")
        assert not trace.is_complete

    def test_is_complete_false_for_empty_trace(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        assert not trace.is_complete

    def test_to_dict_structure(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_created")
        trace.record("task_completed")
        d = trace.to_dict()
        assert d["task_id"] == "task-001"
        assert d["is_complete"] is True
        assert d["stage_count"] == 2
        assert d["failure"] is None

    def test_summary_format(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_created")
        trace.record("task_completed")
        summary = trace.summary()
        assert "task-001" in summary
        assert "task_completed" in summary


class TestTraceFailureRecording:
    """Test failure classification and recording."""

    def test_record_mcp_failure(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_created")
        trace.record_failure(
            FailureCategory.MCP, "MCP timeout", component="nuclei-mcp"
        )
        assert trace._failure["category"] == "mcp"
        assert trace._failure["component"] == "nuclei-mcp"
        assert trace.is_complete
        assert trace._stages[-1].stage == "task_failed"

    def test_record_failure_with_details(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record_failure(
            FailureCategory.WORKER, "timeout", details={"timeout_seconds": 300}
        )
        assert trace._failure["details"]["timeout_seconds"] == 300

    def test_failure_appears_in_to_dict(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record_failure(FailureCategory.MCP, "timeout", component="nuclei-mcp")
        d = trace.to_dict()
        assert d["failure"]["category"] == "mcp"
        assert d["failure"]["reason"] == "timeout"

    def test_all_failure_categories(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        for cat in FailureCategory:
            trace.record_failure(cat, f"test {cat.value}")
            assert trace._failure["category"] == cat.value

    def test_summary_with_failure(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_created")
        trace.record_failure(FailureCategory.WORKER, "Timeout")
        summary = trace.summary()
        assert "FAILURE" in summary
        assert "Timeout" in summary


class FakeTask:
    """Minimal task-like object."""
    def __init__(self, task_id="task-001", engagement_id="eng-001"):
        self.id = task_id
        self.engagement_id = engagement_id
        self.type = "sqli_scan"
        self.agent_type = type("AT", (), {
            "value": "vuln_analysis",
            "__str__": lambda s: "vuln_analysis",
        })()


class TestTraceHelpers:
    """Test the convenience helper functions."""

    def test_attach_trace_creates_and_records(self):
        task = FakeTask()
        trace = attach_trace(task)
        assert trace.task_id == "task-001"
        assert trace.engagement_id == "eng-001"
        assert len(trace._stages) == 1
        assert trace._stages[0].stage == "task_created"

    def test_get_trace_returns_attached(self):
        task = FakeTask()
        attach_trace(task)
        trace = get_trace(task)
        assert trace is not None
        assert trace.task_id == "task-001"

    def test_get_trace_returns_none_when_not_attached(self):
        assert get_trace(FakeTask()) is None

    def test_record_stage_on_traced_task(self):
        task = FakeTask()
        attach_trace(task)
        record_stage(task, "scanner_started", metadata={"scanner": "sqli"})
        trace = get_trace(task)
        assert len(trace._stages) == 2
        assert trace._stages[1].stage == "scanner_started"

    def test_record_stage_noop_on_untraced(self):
        record_stage(FakeTask(), "scanner_started")

    def test_record_failure_on_traced_task(self):
        task = FakeTask()
        attach_trace(task)
        record_failure(task, FailureCategory.MCP, "MCP down")
        trace = get_trace(task)
        assert trace._failure["category"] == "mcp"

    def test_record_failure_noop_on_untraced(self):
        record_failure(FakeTask(), FailureCategory.MCP, "MCP down")


class TestTracePersistence:
    """Test Redis persistence helpers."""

    @pytest.mark.asyncio
    async def test_store_trace_to_redis(self):
        trace = TaskExecutionTrace("task-001", "eng-001")
        trace.record("task_completed")
        mock_session = MagicMock()
        mock_session.store_hot = AsyncMock()
        await store_trace_to_redis(mock_session, trace, ttl=3600)
        mock_session.store_hot.assert_called_once()
        args = mock_session.store_hot.call_args[0]
        assert args[0] == "trace:task-001"

    @pytest.mark.asyncio
    async def test_store_trace_failure_is_swallowed(self):
        mock_session = MagicMock()
        mock_session.store_hot = AsyncMock(side_effect=Exception("Redis down"))
        await store_trace_to_redis(mock_session, TaskExecutionTrace("t1", "e1"))

    @pytest.mark.asyncio
    async def test_load_trace_from_redis(self):
        mock_session = MagicMock()
        mock_session.retrieve_hot = AsyncMock(
            return_value={"task_id": "task-001", "engagement_id": "eng-001"}
        )
        result = await load_trace_from_redis(mock_session, "task-001")
        assert result is not None
        assert result["task_id"] == "task-001"
        mock_session.retrieve_hot.assert_called_once_with("trace:task-001")

    @pytest.mark.asyncio
    async def test_load_trace_not_found(self):
        mock_session = MagicMock()
        mock_session.retrieve_hot = AsyncMock(return_value=None)
        assert await load_trace_from_redis(mock_session, "task-999") is None

    @pytest.mark.asyncio
    async def test_load_trace_failure_is_swallowed(self):
        mock_session = MagicMock()
        mock_session.retrieve_hot = AsyncMock(side_effect=Exception("Redis down"))
        assert await load_trace_from_redis(mock_session, "task-001") is None


class TestComplexLifecycle:
    """Test realistic full-lifecycle scenarios."""

    def test_full_successful_scan_lifecycle(self):
        trace = TaskExecutionTrace("task-sqli-001", "eng-gin-001")
        trace.record("task_created", metadata={"task_type": "sqli_scan"})
        trace.record("task_persisted")
        trace.record("task_queued")
        trace.record("worker_lease_granted", metadata={"agent_id": "vuln-agent-001"})
        trace.record("scanner_started")
        trace.record("verification_started")
        trace.record("persistence_completed")
        trace.record("dashboard_updated")
        trace.record("task_completed")
        assert trace.is_complete
        assert trace._failure is None

    def test_full_failed_scan_lifecycle(self):
        trace = TaskExecutionTrace("task-xss-001", "eng-gin-001")
        trace.record("task_created")
        trace.record("scanner_started")
        trace.record_failure(
            FailureCategory.MCP, "MCP timed out", component="nuclei-mcp"
        )
        assert trace.is_complete
        assert trace._failure["category"] == "mcp"
        assert trace._failure["component"] == "nuclei-mcp"
        assert trace._stages[-1].stage == "task_failed"
