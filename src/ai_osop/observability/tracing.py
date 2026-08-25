# AI-OSOP Distributed Tracing & Observability Module
# Implements OpenTelemetry-compatible tracing and Prometheus metrics

import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

try:
    from prometheus_client import (  # noqa: F401 - availability probe; CONTENT_TYPE_LATEST re-exported for /metrics handlers
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


@dataclass
class Span:
    """Represents a distributed trace span"""

    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    start_time: float
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    status: str = "OK"  # OK, ERROR
    error_message: Optional[str] = None


@dataclass
class MetricSample:
    """Represents a metric sample"""

    name: str
    value: float
    labels: Dict[str, str]
    timestamp: float = field(default_factory=time.time)


class DistributedTracer:
    """Distributed tracing implementation with OpenTelemetry compatibility"""

    def __init__(self, service_name: str = "ai-osop", jaeger_endpoint: str = "http://jaeger:4317"):
        self.service_name = service_name
        self.jaeger_endpoint = jaeger_endpoint
        self._spans: List[Span] = []
        self._active_spans: Dict[str, Span] = {}
        self._otel_tracer = None

        if OTEL_AVAILABLE:
            try:
                provider = TracerProvider()
                processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=jaeger_endpoint))
                provider.add_span_processor(processor)
                trace.set_tracer_provider(provider)
                self._otel_tracer = trace.get_tracer(service_name)
            except Exception as e:
                print(f"OpenTelemetry initialization failed: {e}, using fallback tracer")

    def start_span(
        self, name: str, parent_context: Optional[str] = None, attributes: Optional[Dict] = None
    ) -> str:
        """Start a new trace span"""
        trace_id = parent_context.split(":")[0] if parent_context else str(uuid.uuid4())
        span_id = str(uuid.uuid4())[:16]

        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_context.split(":")[1] if parent_context else None,
            name=name,
            start_time=time.time(),
            attributes=attributes or {},
        )

        self._active_spans[span_id] = span
        return f"{trace_id}:{span_id}"

    def end_span(self, span_context: str, status: str = "OK", error_message: Optional[str] = None):
        """End a trace span"""
        parts = span_context.split(":")
        if len(parts) != 2:
            return

        span_id = parts[1]
        if span_id in self._active_spans:
            span = self._active_spans[span_id]
            span.end_time = time.time()
            span.status = status
            span.error_message = error_message
            self._spans.append(span)
            del self._active_spans[span_id]

            # Export to OpenTelemetry if available
            if self._otel_tracer and OTEL_AVAILABLE:
                try:
                    with self._otel_tracer.start_as_current_span(
                        span.name,
                        context=trace.set_span_in_context(
                            trace.NonRecordingSpan(
                                trace.SpanContext(
                                    trace_id=int(span.trace_id.replace("-", ""), 16)
                                    & ((1 << 128) - 1),
                                    span_id=int(span_id, 16) & ((1 << 64) - 1),
                                    is_remote=False,
                                )
                            )
                        ),
                    ) as otel_span:
                        for key, value in span.attributes.items():
                            otel_span.set_attribute(key, value)
                        if status == "ERROR":
                            otel_span.record_exception(Exception(error_message))
                except Exception as e:
                    print(f"OpenTelemetry export failed: {e}")

    @asynccontextmanager
    async def trace_block(
        self, name: str, parent_context: Optional[str] = None, attributes: Optional[Dict] = None
    ):
        """Async context manager for tracing code blocks"""
        span_context = self.start_span(name, parent_context, attributes)
        try:
            yield span_context
            self.end_span(span_context, "OK")
        except Exception as e:
            self.end_span(span_context, "ERROR", str(e))
            raise

    def get_trace(self, trace_id: str) -> List[Dict]:
        """Retrieve all spans for a specific trace"""
        return [
            {
                "trace_id": s.trace_id,
                "span_id": s.span_id,
                "parent_span_id": s.parent_span_id,
                "name": s.name,
                "start_time": s.start_time,
                "end_time": s.end_time,
                "duration_ms": (s.end_time - s.start_time) * 1000 if s.end_time else None,
                "status": s.status,
                "error_message": s.error_message,
                "attributes": s.attributes,
            }
            for s in self._spans
            if s.trace_id == trace_id
        ]

    def get_all_traces(self) -> List[Dict]:
        """Get all recorded traces"""
        return self.get_trace("*")


class MetricsCollector:
    """Prometheus-compatible metrics collection"""

    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()
        self._counters: Dict[str, Counter] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._gauges: Dict[str, Gauge] = {}

        if PROMETHEUS_AVAILABLE:
            self._init_default_metrics()

    def _init_default_metrics(self):
        """Initialize default AI-OSOP metrics"""
        # Event processing metrics
        self._counters["events_processed"] = Counter(
            "aiosop_events_processed_total",
            "Total number of events processed",
            ["agent_type", "event_type", "status"],
            registry=self.registry,
        )

        self._histograms["event_latency"] = Histogram(
            "aiosop_event_latency_seconds",
            "Event processing latency",
            ["agent_type", "event_type"],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
            registry=self.registry,
        )

        # Agent metrics
        self._gauges["active_agents"] = Gauge(
            "aiosop_active_agents",
            "Number of active agents",
            ["agent_type"],
            registry=self.registry,
        )

        self._counters["findings_generated"] = Counter(
            "aiosop_findings_generated_total",
            "Total number of security findings",
            ["severity", "finding_type"],
            registry=self.registry,
        )

        # Redis Stream metrics
        self._gauges["redis_stream_length"] = Gauge(
            "aiosop_redis_stream_length",
            "Current length of Redis Streams",
            ["stream_name"],
            registry=self.registry,
        )

        self._counters["dlq_messages"] = Counter(
            "aiosop_dlq_messages_total",
            "Total messages sent to Dead Letter Queue",
            ["reason"],
            registry=self.registry,
        )

        # MCP Server metrics
        self._histograms["mcp_call_latency"] = Histogram(
            "aiosop_mcp_call_latency_seconds",
            "MCP server call latency",
            ["server_name", "tool_name"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            registry=self.registry,
        )

        self._counters["mcp_calls"] = Counter(
            "aiosop_mcp_calls_total",
            "Total MCP server calls",
            ["server_name", "tool_name", "status"],
            registry=self.registry,
        )

    def inc_counter(self, name: str, labels: Optional[Dict[str, str]] = None, value: int = 1):
        """Increment a counter metric"""
        if PROMETHEUS_AVAILABLE and name in self._counters:
            if labels:
                self._counters[name].labels(**labels).inc(value)
            else:
                self._counters[name].inc(value)

    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Observe a histogram value"""
        if PROMETHEUS_AVAILABLE and name in self._histograms:
            if labels:
                self._histograms[name].labels(**labels).observe(value)
            else:
                self._histograms[name].observe(value)

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge value"""
        if PROMETHEUS_AVAILABLE and name in self._gauges:
            if labels:
                self._gauges[name].labels(**labels).set(value)
            else:
                self._gauges[name].set(value)

    def record_event_processed(self, agent_type: str, event_type: str, status: str, latency: float):
        """Record event processing metrics"""
        self.inc_counter(
            "events_processed",
            {"agent_type": agent_type, "event_type": event_type, "status": status},
        )
        self.observe_histogram(
            "event_latency", latency, {"agent_type": agent_type, "event_type": event_type}
        )

    def record_finding(self, severity: str, finding_type: str):
        """Record a security finding"""
        self.inc_counter("findings_generated", {"severity": severity, "finding_type": finding_type})

    def record_mcp_call(self, server_name: str, tool_name: str, status: str, latency: float):
        """Record MCP server call metrics"""
        self.inc_counter(
            "mcp_calls", {"server_name": server_name, "tool_name": tool_name, "status": status}
        )
        self.observe_histogram(
            "mcp_call_latency", latency, {"server_name": server_name, "tool_name": tool_name}
        )

    def get_metrics(self) -> str:
        """Get all metrics in Prometheus format"""
        if PROMETHEUS_AVAILABLE:
            return generate_latest(self.registry).decode("utf-8")
        return "# Prometheus not available\n"


# Global instances
_global_tracer: Optional[DistributedTracer] = None
_global_metrics: Optional[MetricsCollector] = None


def get_tracer(service_name: str = "ai-osop") -> DistributedTracer:
    """Get or create global tracer instance"""
    global _global_tracer
    if _global_tracer is None:
        _global_tracer = DistributedTracer(service_name)
    return _global_tracer


def get_metrics() -> MetricsCollector:
    """Get or create global metrics collector"""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = MetricsCollector()
    return _global_metrics


# Decorator for automatic tracing
def traced_operation(name: Optional[str] = None):
    """Decorator to automatically trace function execution"""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            operation_name = name or func.__name__

            # Extract parent context from kwargs if present
            parent_context = kwargs.pop("trace_context", None)

            async with tracer.trace_block(operation_name, parent_context) as span_context:
                kwargs["trace_context"] = span_context
                result = await func(*args, **kwargs)
                return result

        return wrapper

    return decorator
