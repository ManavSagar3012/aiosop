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

import os
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

from ai_osop.core.config import settings

OTEL_ENABLED = os.getenv("OSOP_OTEL_ENABLED", "true").lower() in ("true", "1", "yes")
OTEL_ENDPOINT = os.getenv("OSOP_OTEL_ENDPOINT", "localhost:4317")
OTEL_SERVICE_NAME = os.getenv("OSOP_OTEL_SERVICE_NAME", "ai-osop")
OTEL_ENV = os.getenv("OSOP_OTEL_ENVIRONMENT", "dev")

_tracer: Optional[trace.Tracer] = None


def init_tracing() -> None:
    """Initialize the global TracerProvider with OTLP export."""
    global _tracer
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

    exporter = OTLPSpanExporter(
        endpoint=f"http://{OTEL_ENDPOINT}",
        insecure=True,  # internal network; use TLS in production via env
    )
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(__name__)


def get_tracer() -> trace.Tracer:
    """Return the global tracer, initializing if needed."""
    global _tracer
    if _tracer is None:
        init_tracing()
    return _tracer


@contextmanager
def trace_span(
    name: str,
    kind: trace.SpanKind = trace.SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None,
) -> Any:
    """Context manager for a named trace span."""
    tracer = get_tracer()
    with tracer.start_as_current_span(name, kind=kind) as span:
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


import asyncio
