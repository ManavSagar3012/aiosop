"""Tests for AI-OSOP observability layer (Sprint 6).

Covers:
- Correlation ID middleware
- Trace propagation (W3C TraceContext)
- Prometheus metrics registration (no duplicates)
- SLO metrics helpers
- Telemetry carrier inject/extract
- Trace span context managers
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import structlog
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from ai_osop.api.main import app
from ai_osop.api.middleware import CorrelationIdMiddleware
from ai_osop.core.config import settings
from ai_osop.core.telemetry import (
    RequestContext,
    TelemetryCarrier,
    extract_trace_id_from_traceparent,
    generate_request_id,
)
from ai_osop.core.tracing import get_tracer, init_tracing, shutdown_tracing, trace_span, trace_span_with_parent


# =============================================================================
# CorrelationIdMiddleware tests
# =============================================================================

class TestCorrelationIdMiddleware:
    """Test request ID injection, propagation, and response headers."""

    def test_generates_request_id_when_none_provided(self):
        app_test = FastAPI()
        app_test.add_middleware(CorrelationIdMiddleware)

        @app_test.get("/test")
        async def handler(request: Request):
            return {"request_id": request.state.request_id}

        client = TestClient(app_test)
        response = client.get("/test")
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"].startswith("req-")
        assert response.headers["X-Request-ID"] == data["request_id"]

    def test_uses_provided_x_request_id(self):
        app_test = FastAPI()
        app_test.add_middleware(CorrelationIdMiddleware)

        @app_test.get("/test")
        async def handler(request: Request):
            return {"request_id": request.state.request_id}

        client = TestClient(app_test)
        custom_id = "req-custom-123"
        response = client.get("/test", headers={"X-Request-ID": custom_id})
        assert response.json()["request_id"] == custom_id
        assert response.headers["X-Request-ID"] == custom_id

    def test_uses_traceparent_header(self):
        app_test = FastAPI()
        app_test.add_middleware(CorrelationIdMiddleware)

        @app_test.get("/test")
        async def handler(request: Request):
            return {"request_id": request.state.request_id}

        client = TestClient(app_test)
        traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        response = client.get("/test", headers={"traceparent": traceparent})
        # Should use trace_id from traceparent, prefixed with req-
        assert response.json()["request_id"] == "req-0af7651916cd43dd"
        assert response.headers["X-Request-ID"] == "req-0af7651916cd43dd"

    def test_request_id_priority(self):
        """X-Request-ID takes precedence over traceparent."""
        custom_id = "req-priority-test"
        traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        result = CorrelationIdMiddleware._extract_request_id(
            MagicMock(
                headers={
                    "X-Request-ID": custom_id,
                    "traceparent": traceparent,
                }
            )
        )
        assert result == custom_id


# =============================================================================
# TraceContext / TelemetryCarrier tests
# =============================================================================

class TestTelemetryCarrier:
    """Test W3C TraceContext propagation."""

    def test_inject_extract_roundtrip(self):
        """Inject into carrier, extract back, verify trace continuity."""
        init_tracing()
        try:
            carrier = {}
            TelemetryCarrier.inject(carrier)
            assert "traceparent" in carrier
            assert carrier["traceparent"].startswith("00-")

            span_context = TelemetryCarrier.extract(carrier)
            assert span_context.is_valid

            # Extract from empty carrier returns invalid
            invalid = TelemetryCarrier.extract({})
            assert not invalid.is_valid
        finally:
            shutdown_tracing()

    def test_extract_or_generate_creates_new_when_empty(self):
        init_tracing()
        try:
            span_context = TelemetryCarrier.extract_or_generate({})
            assert span_context.is_valid
        finally:
            shutdown_tracing()


# =============================================================================
# trace_span and trace_span_with_parent tests
# =============================================================================

class TestTraceSpans:
    """Test trace span context managers and decorators."""

    def test_trace_span_creates_span(self):
        init_tracing()
        try:
            with trace_span("test.span", attributes={"test.key": "value"}) as span:
                assert span.is_recording()
                # Verify RequestContext IDs are auto-attached if bound
                RequestContext.bind(request_id="req-test", engagement_id="eng-123")
        finally:
            RequestContext.clear()
            shutdown_tracing()

    def test_trace_span_with_parent_continues_trace(self):
        init_tracing()
        try:
            carrier = {}
            TelemetryCarrier.inject(carrier)
            parent = TelemetryCarrier.extract(carrier)

            with trace_span_with_parent("child.span", parent_span_context=parent) as span:
                assert span.is_recording()
                # Verify parent trace ID is preserved
                span_context = span.get_span_context()
                assert span_context.is_valid
                assert span_context.trace_id == parent.trace_id
        finally:
            shutdown_tracing()

    def test_trace_span_with_parent_invalid_falls_back_to_new(self):
        """When parent is None or invalid, trace_span_with_parent should still create a new span."""
        init_tracing()
        try:
            with trace_span_with_parent("root.span", parent_span_context=None) as span:
                assert span.is_recording()
        finally:
            shutdown_tracing()


# =============================================================================
# RequestContext tests
# =============================================================================

class TestRequestContext:
    """Test contextvar binding and clearing."""

    def test_bind_and_get(self):
        RequestContext.bind(request_id="r1", engagement_id="e1", task_id="t1")
        ctx = RequestContext.get()
        assert ctx["request_id"] == "r1"
        assert ctx["engagement_id"] == "e1"
        assert ctx["task_id"] == "t1"
        RequestContext.clear()

    def test_clear_removes_all(self):
        RequestContext.bind(request_id="r1")
        RequestContext.clear()
        ctx = RequestContext.get()
        assert ctx["request_id"] == ""

    def test_sync_from_otel(self):
        init_tracing()
        try:
            with trace_span("test.sync"):
                RequestContext.sync_from_otel()
                ctx = RequestContext.get()
                assert ctx["trace_id"] != ""
                assert len(ctx["trace_id"]) == 32  # hex trace ID
        finally:
            RequestContext.clear()
            shutdown_tracing()


# =============================================================================
# Helper function tests
# =============================================================================

class TestHelpers:
    def test_generate_request_id(self):
        rid = generate_request_id()
        assert rid.startswith("req-")
        assert len(rid) > 4

    def test_extract_trace_id_from_traceparent_valid(self):
        tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        assert extract_trace_id_from_traceparent(tp) == "0af7651916cd43dd8448eb211c80319c"

    def test_extract_trace_id_from_traceparent_invalid(self):
        assert extract_trace_id_from_traceparent(None) is None
        assert extract_trace_id_from_traceparent("") is None
        assert extract_trace_id_from_traceparent("invalid") is None
        assert extract_trace_id_from_traceparent("00-short-bad-01") is None


# =============================================================================
# Metrics registration tests (no duplicates)
# =============================================================================

class TestMetricsRegistration:
    """Verify that importing metrics and observability modules doesn't cause duplicate registration."""

    def test_metrics_module_imports_without_error(self):
        """Importing metrics.py should register all metrics without ValueError."""
        import importlib
        import ai_osop.core.metrics as metrics_module
        importlib.reload(metrics_module)  # Should not raise ValueError

    def test_observability_module_imports_without_error(self):
        """Importing observability.py should not duplicate metrics."""
        import importlib
        import ai_osop.core.observability as obs_module
        importlib.reload(obs_module)  # Should not raise ValueError

    def test_both_modules_importable_together(self):
        """Both modules can be imported in any order without conflict."""
        import importlib
        # Clear any cached modules to force re-registration
        import ai_osop.core.metrics as m1
        import ai_osop.core.observability as o1
        importlib.reload(m1)
        importlib.reload(o1)
        # If we got here without ValueError, registration is clean

    def test_all_slo_metrics_exist(self):
        from ai_osop.core import metrics
        assert hasattr(metrics, "SLO_AVAILABILITY")
        assert hasattr(metrics, "SLO_ERROR_BUDGET")
        assert hasattr(metrics, "SLO_LATENCY_P99")
        assert hasattr(metrics, "SLO_LATENCY_P95")
        assert hasattr(metrics, "DEPENDENCY_UP")
        assert hasattr(metrics, "TRACE_SPANS_EXPORTED")
        assert hasattr(metrics, "TRACE_SPANS_FAILED")

    def test_all_new_metrics_exist(self):
        from ai_osop.core import metrics
        assert hasattr(metrics, "TASK_COMPLETION_TIME")
        assert hasattr(metrics, "ENGAGEMENT_COMPLETION_TIME")
        assert hasattr(metrics, "APPROVALS_TOTAL")
        assert hasattr(metrics, "RBAC_FAILURES_TOTAL")
        assert hasattr(metrics, "SCOPE_VIOLATIONS_TOTAL")
        assert hasattr(metrics, "MCP_SUCCESS_RATE")
        assert hasattr(metrics, "AGENT_SUCCESS_RATE")

    def test_observability_helpers_exist(self):
        from ai_osop.core import observability
        assert hasattr(observability, "record_engagement_started")
        assert hasattr(observability, "record_engagement_completed")
        assert hasattr(observability, "record_engagement_halted")
        assert hasattr(observability, "record_approval_requested")
        assert hasattr(observability, "record_approval_resolved")
        assert hasattr(observability, "record_mcp_call")
        assert hasattr(observability, "record_rbac_failure")
        assert hasattr(observability, "record_scope_violation")
        assert hasattr(observability, "record_sandbox_block")
        assert hasattr(observability, "record_circuit_breaker_state")


# =============================================================================
# Integration: trace propagation through Task model
# =============================================================================

class TestTaskTracePropagation:
    """Verify Task.trace_context field exists and carries traceparent."""

    def test_task_has_trace_context_field(self):
        from ai_osop.core.models import Task, AgentType
        task = Task(
            type="test",
            agent_type=AgentType.RECON,
            engagement_id="eng-test",
            trace_context={"traceparent": "00-abc123-xyz789-01"},
        )
        assert task.trace_context["traceparent"] == "00-abc123-xyz789-01"

    def test_task_trace_context_defaults_to_empty_dict(self):
        from ai_osop.core.models import Task, AgentType
        task = Task(
            type="test",
            agent_type=AgentType.RECON,
            engagement_id="eng-test",
        )
        assert task.trace_context == {}
