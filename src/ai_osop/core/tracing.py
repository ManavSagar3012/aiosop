"""OpenTelemetry tracing for AI-OSOP.

Provides distributed tracing across:
  API → Orchestrator → Agent → MCP → Neo4j

Configuration (env):
  OSOP_OTEL_ENABLED=true        # toggle
  OSOP_OTEL_ENDPOINT=localhost:4317  # OTLP gRPC endpoint (Jaeger/Tempo)
  OSOP_OTEL_SERVICE_NAME=ai-osop
  OSOP_OTEL_ENVIRONMENT=dev

Usage:
  from ai_osop.core.tracing import tracer, trace_span

  with trace_span("task.execute", engagement_id=eid, task_id=tid):
      ...
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Dict, Optional

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import (
    DEPLOYMENT_ENVIRONMENT,
    SERVICE_NAME,
    SERVICE_VERSION,
    Resource,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import SpanContext

from ai_osop.core.config import settings
from ai_osop.core.telemetry import RequestContext

OTEL_ENABLED = settings.otel_enabled
OTEL_ENDPOINT = settings.otel_endpoint
OTEL_SERVICE_NAME = settings.otel_service_name
OTEL_ENV = settings.otel_environment
OTEL_SAMPLING_RATE = settings.otel_sampling_rate

_tracer: Optional[trace.Tracer] = None
_provider: Optional[TracerProvider] = None


def init_tracing() -> None:
    """Initialize the global TracerProvider with OTLP export."""
    global _tracer, _provider
    if not OTEL_ENABLED:
        _tracer = trace.get_tracer(__name__)
        return

    resource = Resource.create(
        {
            SERVICE_NAME: OTEL_SERVICE_NAME,
            SERVICE_VERSION: "1.0.0",
            DEPLOYMENT_ENVIRONMENT: OTEL_ENV,
            "ai_osop.version": "1.0.0",
        }
    )

    provider = TracerProvider(resource=resource)

    # Use gRPC endpoint for OTLP; config value should not include scheme
    endpoint = OTEL_ENDPOINT
    if not endpoint.startswith("http"):
        endpoint = f"http://{endpoint}"

    exporter = OTLPSpanExporter(
        endpoint=endpoint,
        insecure=True,  # internal network; use TLS in production via env
    )
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)
    _provider = provider
    _tracer = trace.get_tracer(__name__)


def get_tracer() -> trace.Tracer:
    """Return the global tracer, initializing if needed."""
    global _tracer
    if _tracer is None:
        init_tracing()
    return _tracer


def shutdown_tracing() -> None:
    """Shutdown the tracer provider and flush pending spans."""
    global _provider
    if _provider is not None:
        _provider.shutdown()
        _provider = None


@contextmanager
def trace_span(
    name: str,
    kind: trace.SpanKind = trace.SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None,
) -> Any:
    """Context manager for a named trace span.

    Automatically injects RequestContext IDs as span attributes.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(name, kind=kind) as span:
        # Inject context IDs from RequestContext
        ctx = RequestContext.get()
        for key, value in ctx.items():
            if value:
                span.set_attribute(f"ai_osop.{key}", value)
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, v)
        yield span


@contextmanager
def trace_span_with_parent(
    name: str,
    parent_span_context: Optional[SpanContext] = None,
    kind: trace.SpanKind = trace.SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None,
) -> Any:
    """Context manager that starts a span with an explicit parent context.

    Used when continuing a trace across async boundaries (e.g., task queue).
    If parent_span_context is None or invalid, a new root span is created
    using the current OTel context.
    """
    tracer = get_tracer()
    if parent_span_context is not None and parent_span_context.is_valid:
        from opentelemetry.trace import NonRecordingSpan, set_span_in_context

        parent = NonRecordingSpan(parent_span_context)
        ctx = set_span_in_context(parent)
        with tracer.start_as_current_span(name, context=ctx, kind=kind) as span:
            ctx_ids = RequestContext.get()
            for key, value in ctx_ids.items():
                if value:
                    span.set_attribute(f"ai_osop.{key}", value)
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            yield span
    else:
        with tracer.start_as_current_span(name, kind=kind) as span:
            ctx_ids = RequestContext.get()
            for key, value in ctx_ids.items():
                if value:
                    span.set_attribute(f"ai_osop.{key}", value)
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            yield span


def trace_method(name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None):
    """Decorator to auto-trace a method/function."""

    def decorator(fn: Callable) -> Callable:
        span_name = name or fn.__qualname__

        @wraps(fn)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(span_name) as span:
                _set_attrs(span, attributes, args, kwargs)
                return await fn(*args, **kwargs)

        @wraps(fn)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(span_name) as span:
                _set_attrs(span, attributes, args, kwargs)
                return fn(*args, **kwargs)

        return async_wrapper if asyncio.iscoroutinefunction(fn) else sync_wrapper

    return decorator


def _set_attrs(span, attributes, args, kwargs):
    if attributes:
        for k, v in attributes.items():
            span.set_attribute(k, v)
    # Auto-inject common IDs from kwargs if present
    for key in ("engagement_id", "task_id", "workflow_id", "agent_id", "session_id"):
        if key in kwargs:
            span.set_attribute(key, kwargs[key])
    # Also inject RequestContext IDs
    ctx = RequestContext.get()
    for key, value in ctx.items():
        if value:
            span.set_attribute(f"ai_osop.{key}", value)
