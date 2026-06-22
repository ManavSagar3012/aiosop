"""Telemetry layer for AI-OSOP.

Provides:
- RequestContext: contextvars-based request ID binding
- Trace propagation: inject/extract OTel trace context across async boundaries
- Structured logging integration: binds contextvars to structlog

Usage:
    from ai_osop.core.telemetry import RequestContext, inject_trace_context, extract_trace_context

    # In middleware or entry point:
    RequestContext.bind(request_id="req-abc", engagement_id="eng-123", user_id="user-456")

    # Before serializing a task:
    inject_trace_context(task.trace_context)

    # After deserializing a task:
    parent_context = extract_trace_context(task.trace_context)
"""

from __future__ import annotations

import contextvars
import uuid
from typing import Any, Dict, Optional

import structlog
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Context variables for observability IDs
REQUEST_ID_CTX_VAR = contextvars.ContextVar("request_id", default="")
ENGAGEMENT_ID_CTX_VAR = contextvars.ContextVar("engagement_id", default="")
TASK_ID_CTX_VAR = contextvars.ContextVar("task_id", default="")
USER_ID_CTX_VAR = contextvars.ContextVar("user_id", default="")
TRACE_ID_CTX_VAR = contextvars.ContextVar("trace_id", default="")


def _get_current_trace_id() -> str:
    """Return the current OTel trace ID as a hex string, or empty."""
    span = trace.get_current_span()
    span_context = span.get_span_context()
    if span_context.is_valid:
        return format(span_context.trace_id, "032x")
    return ""


class RequestContext:
    """Context manager for binding observability IDs to contextvars and structlog.

    All IDs are stored in both Python contextvars (for async isolation) and
    structlog contextvars (for automatic log injection).
    """

    @staticmethod
    def bind(
        request_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        task_id: Optional[str] = None,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        """Bind one or more IDs to the current async context.

        Args:
            request_id: Unique request identifier (X-Request-ID).
            engagement_id: Engagement/session identifier.
            task_id: Task identifier.
            user_id: Operator/user identifier.
            trace_id: OpenTelemetry trace ID (hex string).
        """
        ctx: Dict[str, Any] = {}
        if request_id is not None:
            REQUEST_ID_CTX_VAR.set(request_id)
            ctx["request_id"] = request_id
        if engagement_id is not None:
            ENGAGEMENT_ID_CTX_VAR.set(engagement_id)
            ctx["engagement_id"] = engagement_id
        if task_id is not None:
            TASK_ID_CTX_VAR.set(task_id)
            ctx["task_id"] = task_id
        if user_id is not None:
            USER_ID_CTX_VAR.set(user_id)
            ctx["user_id"] = user_id
        if trace_id is not None:
            TRACE_ID_CTX_VAR.set(trace_id)
            ctx["trace_id"] = trace_id
        if ctx:
            structlog.contextvars.bind_contextvars(**ctx)

    @staticmethod
    def get() -> Dict[str, str]:
        """Return all currently bound IDs as a dict."""
        return {
            "request_id": REQUEST_ID_CTX_VAR.get(),
            "engagement_id": ENGAGEMENT_ID_CTX_VAR.get(),
            "task_id": TASK_ID_CTX_VAR.get(),
            "user_id": USER_ID_CTX_VAR.get(),
            "trace_id": TRACE_ID_CTX_VAR.get() or _get_current_trace_id(),
        }

    @staticmethod
    def clear() -> None:
        """Clear all bound IDs from the current async context."""
        REQUEST_ID_CTX_VAR.set("")
        ENGAGEMENT_ID_CTX_VAR.set("")
        TASK_ID_CTX_VAR.set("")
        USER_ID_CTX_VAR.set("")
        TRACE_ID_CTX_VAR.set("")
        structlog.contextvars.clear_contextvars()

    @staticmethod
    def sync_from_otel() -> None:
        """Sync the OTel trace ID into TRACE_ID_CTX_VAR and structlog."""
        trace_id = _get_current_trace_id()
        if trace_id:
            TRACE_ID_CTX_VAR.set(trace_id)
            structlog.contextvars.bind_contextvars(trace_id=trace_id)


class TelemetryCarrier:
    """Serializable carrier for trace context across async boundaries.

    This is the format stored in Task.trace_context (dict) and serialized
    to Redis/Postgres/Neo4j.
    """

    @staticmethod
    def inject(carrier: Dict[str, Any]) -> None:
        """Inject the current OTel trace context into a dict carrier.

        The carrier is mutated in place with W3C TraceContext headers.
        """
        propagator = TraceContextTextMapPropagator()
        propagator.inject(carrier)

    @staticmethod
    def extract(carrier: Dict[str, Any]) -> trace.SpanContext:
        """Extract an OTel trace context from a dict carrier.

        Returns a valid SpanContext if found, otherwise an invalid one.
        """
        if not carrier:
            return trace.INVALID_SPAN_CONTEXT
        propagator = TraceContextTextMapPropagator()
        context = propagator.extract(carrier)
        span = trace.get_current_span(context)
        return span.get_span_context()

    @staticmethod
    def extract_or_generate(carrier: Dict[str, Any]) -> trace.SpanContext:
        """Extract from carrier or generate a new trace context if none exists."""
        span_context = TelemetryCarrier.extract(carrier)
        if span_context.is_valid:
            return span_context
        # Generate a new trace ID and span ID
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("task.deserialized") as span:
            return span.get_span_context()


# Convenience aliases for shorter imports
inject_trace_context = TelemetryCarrier.inject
extract_trace_context = TelemetryCarrier.extract
extract_or_generate_trace_context = TelemetryCarrier.extract_or_generate


def generate_request_id() -> str:
    """Generate a new correlation/request ID."""
    return f"req-{uuid.uuid4().hex[:16]}"


def extract_trace_id_from_traceparent(traceparent: Optional[str]) -> Optional[str]:
    """Extract the trace_id from a W3C traceparent header string.

    Format: 00-<trace_id>-<span_id>-<trace_flags>
    Returns the 32-hex-character trace_id, or None on parse failure.
    """
    if not traceparent:
        return None
    try:
        parts = traceparent.split("-")
        if len(parts) >= 2 and len(parts[1]) == 32:
            return parts[1]
    except Exception:
        pass
    return None
