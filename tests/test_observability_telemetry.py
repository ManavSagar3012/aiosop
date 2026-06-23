"""Tests for ai_osop.core.telemetry module."""

from __future__ import annotations

import uuid

import pytest

from ai_osop.core.telemetry import (
    RequestContext,
    TelemetryCarrier,
    extract_trace_context,
    extract_trace_id_from_traceparent,
    generate_request_id,
    inject_trace_context,
)


class TestRequestContext:
    def test_bind_sets_contextvars(self) -> None:
        """Binding IDs should set contextvars and be retrievable."""
        RequestContext.clear()
        RequestContext.bind(request_id="req-123", engagement_id="eng-456", task_id="task-789")
        ctx = RequestContext.get()
        assert ctx["request_id"] == "req-123"
        assert ctx["engagement_id"] == "eng-456"
        assert ctx["task_id"] == "task-789"

    def test_clear_resets_all(self) -> None:
        """Clear should reset all contextvars to empty strings."""
        RequestContext.bind(request_id="req-123")
        RequestContext.clear()
        ctx = RequestContext.get()
        assert all(v == "" for v in ctx.values())

    def test_isolated_per_async_task(self) -> None:
        """Contextvars should be isolated between different contexts."""
        import asyncio

        async def task_a() -> str:
            RequestContext.bind(request_id="req-a")
            await asyncio.sleep(0)
            return RequestContext.get()["request_id"]

        async def task_b() -> str:
            RequestContext.bind(request_id="req-b")
            await asyncio.sleep(0)
            return RequestContext.get()["request_id"]

        async def run() -> None:
            a, b = await asyncio.gather(task_a(), task_b())
            assert a == "req-a"
            assert b == "req-b"

        asyncio.run(run())


class TestGenerateRequestId:
    def test_generates_unique_ids(self) -> None:
        """Generated request IDs should be unique."""
        ids = {generate_request_id() for _ in range(100)}
        assert len(ids) == 100

    def test_has_prefix(self) -> None:
        """Generated IDs should start with 'req-'."""
        req_id = generate_request_id()
        assert req_id.startswith("req-")


class TestExtractTraceIdFromTraceparent:
    def test_extracts_valid_traceparent(self) -> None:
        """Should extract trace_id from a valid W3C traceparent."""
        traceparent = "00-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-a1b2c3d4e5f6a7b8-01"
        trace_id = extract_trace_id_from_traceparent(traceparent)
        assert trace_id == "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

    def test_returns_none_for_invalid(self) -> None:
        """Should return None for invalid traceparent strings."""
        assert extract_trace_id_from_traceparent(None) is None
        assert extract_trace_id_from_traceparent("") is None
        assert extract_trace_id_from_traceparent("invalid") is None


class TestTelemetryCarrier:
    def test_inject_puts_traceparent(self) -> None:
        """Inject should add traceparent to carrier dict."""
        carrier: dict = {}
        inject_trace_context(carrier)
        assert "traceparent" in carrier
        assert carrier["traceparent"].startswith("00-")

    def test_extract_from_empty_returns_invalid(self) -> None:
        """Extract from empty dict should return invalid span context."""
        span_ctx = extract_trace_context({})
        assert not span_ctx.is_valid

    def test_roundtrip_inject_extract(self) -> None:
        """Inject then extract should yield a valid span context."""
        carrier: dict = {}
        inject_trace_context(carrier)
        span_ctx = extract_trace_context(carrier)
        assert span_ctx.is_valid
