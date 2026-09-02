# AI-OSOP Sprint 6 — Observability Excellence Design Document

**Version:** 1.0  
**Date:** 2025-01-18  
**Status:** Approved for implementation  
**Scope:** Traceability Foundation → Metrics Foundation → Operational Visibility → Error Intelligence

---

## Table of Contents

1. [Observability Architecture Diagram](#1-observability-architecture-diagram)
2. [Trace Propagation Design](#2-trace-propagation-design)
3. [Correlation-ID Strategy](#3-correlation-id-strategy)
4. [Metrics Catalog](#4-metrics-catalog)
5. [Grafana Dashboard Design](#5-grafana-dashboard-design)
6. [OTel Verification Plan](#6-otel-verification-plan)
7. [Rollback Plan](#7-rollback-plan)
8. [Test Plan](#8-test-plan)

---

## 1. Observability Architecture Diagram

### 1.1 High-Level Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INGRESS LAYER                                   │
│  ┌──────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐   │
│  │  FastAPI     │  │ CorrelationId       │  │ PrometheusMetrics        │   │
│  │  Gateway     │──│ Middleware          │──│ Middleware               │   │
│  └──────────────┘  └─────────────────────┘  └──────────────────────────┘   │
│         │                  │                          │                      │
│         ▼                  ▼                          ▼                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  RequestContext (contextvars)                                      │    │
│  │  {request_id, engagement_id, task_id, user_id, trace_id}          │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           APPLICATION LAYER                                  │
│  ┌──────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐   │
│  │ Orchestrator │  │ BaseAgent            │  │ MCP Adapters             │   │
│  │  (spans)     │──│  (spans)             │──│  (spans)                 │   │
│  └──────────────┘  └─────────────────────┘  └──────────────────────────┘   │
│         │                  │                          │                      │
│         ▼                  ▼                          ▼                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  OpenTelemetry Tracer (propagated via context + task metadata)     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         INFRASTRUCTURE LAYER                                 │
│  ┌──────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐   │
│  │ Redis        │  │ Neo4j               │  │ PostgreSQL               │   │
│  │ (spans)      │  │ (spans)             │  │ (spans)                  │   │
│  └──────────────┘  └─────────────────────┘  └──────────────────────────┘   │
│         │                  │                          │                      │
│         ▼                  ▼                          ▼                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Exporters: OTLP → Jaeger / Prometheus → Pushgateway / Grafana    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Interaction Map

```text
API Request
    │
    ├──► CorrelationIdMiddleware ──► generates X-Request-ID / trace_id
    │       │
    │       ├──► RequestContext.bind(request_id, user_id, engagement_id)
    │       │
    │       ├──► structlog.contextvars.bind(request_id=..., trace_id=...)
    │       │
    │       └──► OTel tracer.start_as_current_span("api.request")
    │               │
    │               ├──► Orchestrator.create_engagement()
    │               │       │
    │               │       ├──► trace_span("orchestrator.create_engagement")
    │               │       │       │
    │               │       │       ├──► SessionMemory.store_session_state()
    │               │       │       │       └──► trace_span("redis.store_session")
    │               │       │       │
    │               │       │       └──► GraphMemory.add_engagement()
    │               │       │               └──► trace_span("neo4j.add_engagement")
    │               │       │
    │               │       └──► Task scheduled with trace_id in metadata
    │               │
    │               ├──► Task picked up by Agent
    │               │       │
    │               │       ├──► trace extracted from task.metadata.trace_id
    │               │       │
    │               │       ├──► trace_span("agent.execute_task")
    │               │       │       │
    │               │       │       ├──► MCPRegistry.execute_tool()
    │               │       │       │       └──► trace_span("mcp.execute_tool")
    │               │       │       │
    │               │       │       └──► GraphMemory.upsert_task()
    │               │       │               └──► trace_span("neo4j.upsert_task")
    │               │       │
    │               │       └──► Result returned with trace_id preserved
    │               │
    │               └──► Report generated with trace_id in metadata
    │
    └──► Response ──► X-Request-ID header returned
```

### 1.3 Data Flow for Single Trace

The golden path trace must show:

```text
Trace: a1b2c3d4e5f6
├── Span: api.request (root, HTTP GET /engagements)
│   ├── Span: orchestrator.create_engagement
│   │   ├── Span: session_memory.store_session_state
│   │   │   └── Span: redis.setex
│   │   ├── Span: graph_memory.add_engagement
│   │   │   └── Span: neo4j.run (MERGE)
│   │   └── Span: orchestrator.schedule_task
│   │       ├── Span: graph_memory.upsert_task
│   │       │   └── Span: neo4j.run (MERGE)
│   │       └── Span: redis.zadd (queue push)
│   │
│   ├── Span: scheduler._assign_task
│   │   └── Span: orchestrator._execute_via_agent
│   │       └── Span: agent.execute_task
│   │           ├── Span: agent._execute (agent-specific)
│   │           │   ├── Span: mcp.execute_tool (burp-mcp.scan_target)
│   │           │   │   └── Span: http.post (MCP server)
│   │           │   ├── Span: graph_memory.add_vulnerability
│   │           │   │   └── Span: neo4j.run (MERGE)
│   │           │   └── Span: llm_client.complete
│   │           │
│   │           ├── Span: agent._log_task_completion
│   │           │   └── Span: postgres.execute (audit log)
│   │           │
│   │           └── Span: orchestrator._on_task_success
│   │               ├── Span: graph_memory.upsert_task
│   │               └── Span: redis.zadd (downstream trigger)
│   │
│   └── Span: api.response (root closure)
```

---

## 2. Trace Propagation Design

### 2.1 Current Gap Analysis

| Gap | Current State | Target State |
|-----|--------------|--------------|
| Trace context across API → Task | No propagation; each span is isolated | Trace ID injected into task metadata, extracted by agent |
| Trace context across Task → Agent | No link; agent creates new root span | Agent continues trace from task metadata |
| Trace context across Agent → MCP | No span wrapping in MCP layer | MCP span as child of agent span |
| Trace context across Redis ops | No spans | Redis ops wrapped with trace spans |
| Trace context across Neo4j ops | Some spans exist but not all | All graph_memory methods traced |
| Trace context across Postgres | No spans | Audit writes traced |
| OTel enabled by default | `OSOP_OTEL_ENABLED=false` | `OSOP_OTEL_ENABLED=true` in production |

### 2.2 Propagation Mechanism

#### 2.2.1 W3C Trace Context (HTTP Ingress)

- **Incoming:** Parse `traceparent` and `tracestate` headers if present.
- **Outgoing:** Inject `traceparent` into any HTTP calls made by MCP adapters.
- **Fallback:** If no `traceparent` header, generate a new `trace_id` and use it as the `request_id`.

#### 2.2.2 Task Metadata Propagation (Async Boundary)

The `Task` model will carry a `trace_context` field:

```python
class Task(BaseModel):
    ... existing fields ...
    trace_context: Dict[str, Any] = Field(default_factory=dict)
    # Stores: {"trace_id": "...", "span_id": "...", "trace_flags": "..."}
```

**Propagation flow:**

1. **API Layer** creates a span → extracts `trace_id` → stores in `RequestContext`.
2. **Orchestrator** when creating a task:
   - Reads current trace context from OTel context
   - Serializes it into `task.trace_context`
   - Persists it with the task (Redis + Postgres + Neo4j)
3. **Scheduler** when assigning task:
   - Reads `task.trace_context`
   - Reconstructs OTel `SpanContext`
   - Starts a new span with `link` or `parent` relationship
4. **Agent** when executing task:
   - Extracts `trace_context` from task
   - Creates a `NonRecordingSpan` with the parent context
   - Uses `tracer.start_as_current_span` with that parent
5. **MCP / Memory** calls within the agent:
   - Automatically inherit the active trace context

#### 2.2.3 Redis Pub/Sub Propagation

For coordination bus events:
- Serialize trace context into event payload
- Subscriber extracts and continues trace

#### 2.2.4 WebSocket Propagation

- WebSocket connection handshake reads `traceparent` query param or generates one
- All messages sent/received carry `trace_id` in metadata

### 2.3 Trace Context Serialization Format

```python
# Inject current trace context into a dict for serialization
def inject_trace_context(carrier: Dict[str, Any]) -> None:
    """Inject current OTel trace context into a carrier dict."""
    from opentelemetry import trace
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    propagator = TraceContextTextMapPropagator()
    propagator.inject(carrier)

# Extract from task metadata
def extract_trace_context(carrier: Dict[str, Any]) -> Optional[trace.SpanContext]:
    """Extract OTel trace context from a carrier dict."""
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    propagator = TraceContextTextMapPropagator()
    context = propagator.extract(carrier)
    return trace.get_current_span(context).get_span_context()
```

### 2.4 Span Naming Convention

```text
Component    Span Name Pattern                          Example
─────────────────────────────────────────────────────────────────────────
API          api.<method>.<path>                        api.post.engagements
Orchestrator orchestrator.<method>                       orchestrator.schedule_task
Agent        agent.<agent_type>.execute_task            agent.recon.execute_task
             agent.<agent_type>.<task_type>             agent.recon.full_recon
MCP          mcp.<server_id>.<tool_name>                mcp.burp-mcp.scan_target
Redis        redis.<operation>                          redis.zadd
Neo4j        neo4j.<operation>                          neo4j.run
Postgres     postgres.<operation>                       postgres.execute
LLM          llm.<provider>.<model>                     llm.openai.gpt-4o
```

### 2.5 Span Attribute Schema

All spans MUST include these attributes when available:

```python
# Common attributes
"ai_osop.request_id": str       # Correlation ID
"ai_osop.engagement_id": str     # Engagement/session ID
"ai_osop.task_id": str           # Task ID
"ai_osop.agent_id": str          # Agent ID
"ai_osop.agent_type": str        # Agent type (recon, vuln_analysis, etc.)
"ai_osop.user_id": str           # Operator/user ID

# Component-specific
"ai_osop.mcp.server_id": str     # MCP server ID
"ai_osop.mcp.tool_name": str     # MCP tool name
"ai_osop.mcp.status": str        # MCP response status
"ai_osop.redis.operation": str  # Redis command
"ai_osop.neo4j.query_type": str  # Neo4j query classification
"ai_osop.neo4j.duration_ms": float
"ai_osop.postgres.table": str   # Postgres table
```

---

## 3. Correlation-ID Strategy

### 3.1 Requirements

1. **Every request** gets a unique `X-Request-ID` or reuses one from upstream
2. **Same ID** follows the request through the entire system
3. **Log correlation:** Every log line contains `request_id`
4. **Trace linking:** `request_id` maps to OTel `trace_id` (or equals it)
5. **Response header:** `X-Request-ID` returned in every HTTP response
6. **WebSocket:** `request_id` propagated via message metadata

### 3.2 Generation Rules

```text
Source of Request ID:
─────────────────────────────────────────────────────────────────
Client provides X-Request-ID header      → Use client's ID
Client provides traceparent header       → Extract trace_id as request_id
Neither provided                        → Generate UUID4
WebSocket connection                     → Generate on connect, send in messages
```

### 3.3 Implementation: CorrelationIdMiddleware

```python
class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        # 1. Extract or generate
        request_id = (
            request.headers.get("X-Request-ID")
            or extract_trace_id_from_traceparent(request.headers.get("traceparent"))
            or str(uuid.uuid4())
        )
        
        # 2. Bind to contextvars
        request.state.request_id = request_id
        REQUEST_ID_CTX_VAR.set(request_id)
        
        # 3. Bind to structlog
        structlog.contextvars.bind_contextvars(request_id=request_id)
        
        # 4. Process request
        response = await call_next(request)
        
        # 5. Return in response header
        response.headers["X-Request-ID"] = request_id
        return response
```

### 3.4 RequestContext (contextvars)

```python
import contextvars

REQUEST_ID_CTX_VAR = contextvars.ContextVar("request_id", default="")
ENGAGEMENT_ID_CTX_VAR = contextvars.ContextVar("engagement_id", default="")
TASK_ID_CTX_VAR = contextvars.ContextVar("task_id", default="")
USER_ID_CTX_VAR = contextvars.ContextVar("user_id", default="")
TRACE_ID_CTX_VAR = contextvars.ContextVar("trace_id", default="")

class RequestContext:
    """Context manager for binding observability IDs to contextvars."""
    
    @staticmethod
    def bind(
        request_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        task_id: Optional[str] = None,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        if request_id:
            REQUEST_ID_CTX_VAR.set(request_id)
            structlog.contextvars.bind_contextvars(request_id=request_id)
        if engagement_id:
            ENGAGEMENT_ID_CTX_VAR.set(engagement_id)
            structlog.contextvars.bind_contextvars(engagement_id=engagement_id)
        if task_id:
            TASK_ID_CTX_VAR.set(task_id)
            structlog.contextvars.bind_contextvars(task_id=task_id)
        if user_id:
            USER_ID_CTX_VAR.set(user_id)
            structlog.contextvars.bind_contextvars(user_id=user_id)
        if trace_id:
            TRACE_ID_CTX_VAR.set(trace_id)
            structlog.contextvars.bind_contextvars(trace_id=trace_id)
    
    @staticmethod
    def get() -> Dict[str, str]:
        return {
            "request_id": REQUEST_ID_CTX_VAR.get(),
            "engagement_id": ENGAGEMENT_ID_CTX_VAR.get(),
            "task_id": TASK_ID_CTX_VAR.get(),
            "user_id": USER_ID_CTX_VAR.get(),
            "trace_id": TRACE_ID_CTX_VAR.get(),
        }
    
    @staticmethod
    def clear() -> None:
        REQUEST_ID_CTX_VAR.set("")
        ENGAGEMENT_ID_CTX_VAR.set("")
        TASK_ID_CTX_VAR.set("")
        USER_ID_CTX_VAR.set("")
        TRACE_ID_CTX_VAR.set("")
```

### 3.5 Log Format Integration

All structlog loggers will be configured with a processor that injects contextvars:

```python
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,  # Injects request_id, etc.
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.AsyncBoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
```

Example log line:
```json
{
  "timestamp": "2025-01-18T12:34:56.789Z",
  "request_id": "req-abc123",
  "trace_id": "a1b2c3d4e5f6",
  "engagement_id": "eng-20250118-xyz",
  "task_id": "task-def456",
  "agent_id": "recon-agent-001",
  "event": "task_completed",
  "status": "success",
  "duration_ms": 1234
}
```

---

## 4. Metrics Catalog

### 4.1 Existing Metrics (Current State)

| Metric | Type | Labels | Status | Notes |
|--------|------|--------|--------|-------|
| `ai_osop_requests_total` | Counter | method, path, status_code | ✅ Active | Recorded in PrometheusMetricsMiddleware |
| `ai_osop_request_duration_seconds` | Histogram | method, path | ✅ Active | Recorded in PrometheusMetricsMiddleware |
| `ai_osop_errors_total` | Counter | status_code, path | ✅ Active | Recorded in PrometheusMetricsMiddleware |
| `ai_osop_build_info` | Info | version, git_sha | ✅ Active | Set at startup |
| `ai_osop_tasks_total` | Counter | status, agent_type | ✅ Active | Recorded in `record_task()` |
| `ai_osop_tasks_completed_total` | Counter | agent_type | ✅ Active | Recorded in `record_task()` |
| `ai_osop_tasks_failed_total` | Counter | agent_type | ✅ Active | Recorded in `record_task()` |
| `ai_osop_task_duration_seconds` | Histogram | agent_type | ✅ Active | Recorded in `record_task()` |
| `ai_osop_active_engagements` | Gauge | — | ❌ **Stub** | Defined but never updated |
| `ai_osop_pending_approvals` | Gauge | — | ❌ **Stub** | Defined but never updated |
| `ai_osop_tasks_by_status` | Gauge | status | ❌ **Stub** | Defined but never updated |
| `ai_osop_active_agent_count` | Gauge | agent_type | ❌ **Stub** | Defined but never updated |
| `ai_osop_task_schedule_duration_seconds` | Histogram | — | ❌ **Stub** | Defined but never updated |
| `ai_osop_agent_execution_duration_seconds` | Histogram | agent_type | ❌ **Stub** | Defined but never updated |
| `ai_osop_mcp_call_duration_seconds` | Histogram | server_id, tool_name | ❌ **Stub** | Defined but never updated |
| `ai_osop_mcp_circuit_breaker_state` | Gauge | server_id | ❌ **Stub** | Defined but never updated |
| `ai_osop_mcp_errors_total` | Counter | server_id, error_type | ❌ **Stub** | Defined but never updated |
| `ai_osop_graph_query_duration_seconds` | Histogram | query_type | ❌ **Stub** | Defined but never updated |
| `ai_osop_llm_call_duration_seconds` | Histogram | model | ❌ **Stub** | Defined but never updated |
| `ai_osop_running_tasks` | Gauge | — | ❌ **Stub** | Defined but never updated |
| `ai_osop_queued_tasks` | Gauge | — | ❌ **Stub** | Defined but never updated |
| `ai_osop_failed_tasks` | Gauge | — | ❌ **Stub** | Defined but never updated |
| `ai_osop_active_agents` | Gauge | — | ❌ **Stub** | Defined but never updated |
| `ai_osop_mcp_latency_seconds` | Histogram | server_id, method | ❌ **Stub** | Defined but never updated |
| `ai_osop_graph_write_duration_seconds` | Histogram | operation | ❌ **Stub** | Defined but never updated |
| `ai_osop_redis_latency_seconds` | Histogram | operation | ❌ **Stub** | Defined but never updated |
| `ai_osop_postgres_latency_seconds` | Histogram | operation | ❌ **Stub** | Defined but never updated |
| `ai_osop_llm_calls_total` | Counter | model, operation | ❌ **Stub** | Defined but never updated |
| `ai_osop_llm_tokens_total` | Counter | model, type | ❌ **Stub** | Defined but never updated |
| `ai_osop_llm_cost_usd_total` | Counter | model | ❌ **Stub** | Defined but never updated |
| `ai_osop_engagement_cost_usd_total` | Counter | engagement_id | ❌ **Stub** | Defined but never updated |
| `ai_osop_rate_limit_events_total` | Counter | type | ❌ **Stub** | Defined but never updated |
| `ai_osop_agent_utilization` | Gauge | agent_type | ❌ **Stub** | Defined but never updated |
| `ai_osop_browser_runtime_seconds` | Histogram | task_type | ❌ **Stub** | Defined but never updated |
| `ai_osop_sandbox_runtime_seconds` | Histogram | task_type | ❌ **Stub** | Defined but never updated |

### 4.2 Metrics to Instrument (Implementation Plan)

#### Phase 1: Critical Infrastructure Metrics

| Metric | Type | Labels | Where to Instrument |
|--------|------|--------|---------------------|
| `ai_osop_active_engagements` | Gauge | — | `orchestrator.create_engagement` / `halt_engagement` |
| `ai_osop_pending_approvals` | Gauge | — | `_register_approval` / `resolve_approval` |
| `ai_osop_tasks_by_status` | Gauge | status | `schedule_task`, `_on_task_success`, `_on_task_failure` |
| `ai_osop_active_agent_count` | Gauge | agent_type | `register_agent`, `get_status` |
| `ai_osop_running_tasks` | Gauge | — | `BaseAgent.execute_task` start/end |
| `ai_osop_queued_tasks` | Gauge | — | `push_task_queue` / `pop_task_queue` |
| `ai_osop_failed_tasks` | Gauge | — | `_on_task_failure` |

#### Phase 2: MCP & Storage Metrics

| Metric | Type | Labels | Where to Instrument |
|--------|------|--------|---------------------|
| `ai_osop_mcp_call_duration_seconds` | Histogram | server_id, tool_name | `MCPConnection.execute` wrapper |
| `ai_osop_mcp_circuit_breaker_state` | Gauge | server_id | `MCPConnection._record_success/failure` |
| `ai_osop_mcp_errors_total` | Counter | server_id, error_type | `MCPConnection.execute` exception handlers |
| `ai_osop_graph_query_duration_seconds` | Histogram | query_type | `GraphMemory` decorator |
| `ai_osop_redis_latency_seconds` | Histogram | operation | `SessionMemory` decorator |
| `ai_osop_postgres_latency_seconds` | Histogram | operation | `SessionMemory` decorator |

#### Phase 3: SLO Metrics (NEW)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ai_osop_task_completion_time_seconds` | Histogram | agent_type, task_type | End-to-end task duration (schedule → complete) |
| `ai_osop_engagement_completion_time_seconds` | Histogram | — | Engagement duration (create → complete) |
| `ai_osop_agent_success_rate` | Gauge | agent_type | `completed / (completed + failed)` per agent_type |
| `ai_osop_mcp_success_rate` | Gauge | server_id | `success / (success + error)` per MCP server |
| `ai_osop_approval_wait_time_seconds` | Histogram | — | Time from request to resolution |
| `ai_osop_api_latency_p50` | Summary | method, path | API latency 50th percentile |
| `ai_osop_api_latency_p95` | Summary | method, path | API latency 95th percentile |
| `ai_osop_api_latency_p99` | Summary | method, path | API latency 99th percentile |
| `ai_osop_task_throughput` | Counter | agent_type | Tasks completed per unit time |
| `ai_osop_agent_throughput` | Counter | agent_type | Agent executions per unit time |

#### Phase 4: Security & Operations Metrics (NEW)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ai_osop_approvals_total` | Counter | decision | approved / rejected / timeout |
| `ai_osop_denied_actions_total` | Counter | action_type | Blocked by approval gate |
| `ai_osop_rbac_failures_total` | Counter | endpoint, required_role | RBAC rejections |
| `ai_osop_ownership_violations_total` | Counter | resource_type | Ownership check failures |
| `ai_osop_sandbox_blocks_total` | Counter | block_type | eBPF/sandbox blocks |
| `ai_osop_scope_violations_total` | Counter | rule | Out-of-scope detections |

### 4.3 Recording Pattern

All metrics will use a decorator pattern for clean instrumentation:

```python
from functools import wraps
import time

def timed_metric(metric: Histogram, label_extractor: Callable):
    def decorator(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            start = time.monotonic()
            try:
                result = await fn(*args, **kwargs)
                labels = label_extractor(result, args, kwargs)
                metric.labels(**labels).observe(time.monotonic() - start)
                return result
            except Exception as e:
                labels = label_extractor(None, args, kwargs)
                metric.labels(**labels).observe(time.monotonic() - start)
                raise
        return wrapper
    return decorator
```

---

## 5. Grafana Dashboard Design

### 5.1 Dashboard JSON Model Approach

All dashboards will be defined as **JSON model files** (not provisioned via API) committed to:

```
observability/grafana/dashboards/
├── executive.json      # Executive overview
├── reliability.json    # Infrastructure health
├── security.json       # Security & approvals
├── performance.json    # API & task performance
└── overview.json       # Single-pane summary
```

### 5.2 Executive Dashboard

**Panel 1: Active Engagements**
- Metric: `ai_osop_active_engagements`
- Visualization: Stat (single number)
- Alert: > 100 active engagements

**Panel 2: Active Agents**
- Metric: `ai_osop_active_agent_count`
- Visualization: Stat + time series
- Group by: `agent_type`

**Panel 3: Queue Depth**
- Metric: `ai_osop_queued_tasks`
- Visualization: Stat
- Alert: > 500 queued

**Panel 4: Task Success Rate (24h)**
- Metric: `rate(ai_osop_tasks_completed_total[24h]) / rate(ai_osop_tasks_total[24h])`
- Visualization: Gauge (0-100%)
- Threshold: green > 95%, yellow > 90%, red < 90%

**Panel 5: Current Failures**
- Metric: `ai_osop_failed_tasks`
- Visualization: Stat
- Alert: > 50 failed

**Panel 6: Engagement Throughput (24h)**
- Metric: `rate(ai_osop_engagement_completion_time_seconds_count[24h])`
- Visualization: Graph

### 5.3 Reliability Dashboard

**Panel 1: Redis Health**
- Metric: `up{job="redis"}` (or custom Redis ping metric)
- Visualization: Status indicator

**Panel 2: Neo4j Query Latency (p50/p95/p99)**
- Metric: `histogram_quantile(0.50, ai_osop_graph_query_duration_seconds_bucket)`
- Visualization: Graph (3 lines)

**Panel 3: Postgres Connection Pool**
- Metric: Custom health metric or `up{job="postgres"}`
- Visualization: Time series

**Panel 4: MCP Health Grid**
- Metric: `ai_osop_mcp_circuit_breaker_state`
- Visualization: Table/Grid (server_id, status)

**Panel 5: MCP Error Rate by Server**
- Metric: `rate(ai_osop_mcp_errors_total[5m])`
- Visualization: Graph
- Group by: `server_id`

**Panel 6: Circuit Breaker States**
- Metric: `ai_osop_mcp_circuit_breaker_state`
- Visualization: State timeline
- Values: 0=closed (green), 1=open (red)

**Panel 7: Infrastructure Uptime**
- Metric: `up` for each service
- Visualization: Status timeline

### 5.4 Security Dashboard

**Panel 1: Pending Approvals**
- Metric: `ai_osop_pending_approvals`
- Visualization: Stat
- Alert: > 10 pending (over 30 min)

**Panel 2: Approval Decisions Over Time**
- Metric: `rate(ai_osop_approvals_total[5m])`
- Visualization: Stacked bar
- Group by: `decision`

**Panel 3: Approval Wait Time (p50/p95)**
- Metric: `histogram_quantile(0.95, ai_osop_approval_wait_time_seconds_bucket)`
- Visualization: Graph

**Panel 4: Denied Actions**
- Metric: `rate(ai_osop_denied_actions_total[5m])`
- Visualization: Bar chart
- Group by: `action_type`

**Panel 5: RBAC Failures**
- Metric: `rate(ai_osop_rbac_failures_total[5m])`
- Visualization: Table
- Group by: `endpoint`, `required_role`

**Panel 6: Ownership Violations**
- Metric: `rate(ai_osop_ownership_violations_total[5m])`
- Visualization: Graph

**Panel 7: Sandbox Blocks**
- Metric: `rate(ai_osop_sandbox_blocks_total[5m])`
- Visualization: Graph
- Group by: `block_type`

### 5.5 Performance Dashboard

**Panel 1: API Latency (p50/p95/p99)**
- Metric: `histogram_quantile(0.99, ai_osop_request_duration_seconds_bucket)`
- Visualization: Graph (3 lines)
- Group by: `method`, `path` (top 5)

**Panel 2: Task Throughput**
- Metric: `rate(ai_osop_task_completion_time_seconds_count[5m])`
- Visualization: Graph
- Group by: `agent_type`

**Panel 3: Agent Throughput**
- Metric: `rate(ai_osop_agent_execution_duration_seconds_count[5m])`
- Visualization: Graph
- Group by: `agent_type`

**Panel 4: Task Completion Time (p50/p95)**
- Metric: `histogram_quantile(0.95, ai_osop_task_completion_time_seconds_bucket)`
- Visualization: Graph
- Group by: `agent_type`

**Panel 5: MCP Latency by Server**
- Metric: `histogram_quantile(0.95, ai_osop_mcp_call_duration_seconds_bucket)`
- Visualization: Graph
- Group by: `server_id`

**Panel 6: LLM Latency by Model**
- Metric: `histogram_quantile(0.95, ai_osop_llm_call_duration_seconds_bucket)`
- Visualization: Graph
- Group by: `model`

**Panel 7: Error Rate by Endpoint**
- Metric: `rate(ai_osop_errors_total[5m]) / rate(ai_osop_requests_total[5m])`
- Visualization: Table
- Group by: `path`

### 5.6 Dashboard Provisioning

```yaml
# docker-compose.observability.yml
version: "3.8"
services:
  prometheus:
    image: prom/prometheus:v2.47.0
    volumes:
      - ./observability/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./observability/prometheus/rules:/etc/prometheus/rules
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:10.1.0
    volumes:
      - ./observability/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./observability/grafana/datasources:/etc/grafana/provisioning/datasources
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin

  jaeger:
    image: jaegertracing/all-in-one:1.49
    ports:
      - "16686:16686"
      - "4317:4317"
    environment:
      - COLLECTOR_OTLP_ENABLED=true
```

---

## 6. OTel Verification Plan

### 6.1 Verification Objectives

1. **Trace Creation:** Every API request creates a trace
2. **Span Linkage:** Orchestrator, Agent, MCP, Neo4j spans link under one trace
3. **Context Propagation:** Trace survives Redis task queue handoff
4. **Attribute Fidelity:** All required attributes present on every span
5. **Exporter Health:** Spans actually reach Jaeger (not just logged)
6. **No Broken Parent:** No orphan spans with no parent

### 6.2 Verification Steps

#### Step 1: Local OTel Stack Startup

```bash
# Start Jaeger + Prometheus + Grafana
docker-compose -f docker-compose.observability.yml up -d

# Verify Jaeger UI accessible
curl http://localhost:16686
```

#### Step 2: API Request Trace Test

```bash
# Create engagement with traceparent
curl -X POST http://localhost:8200/engagements \
  -H "Content-Type: application/json" \
  -H "traceparent: 00-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-a1b2c3d4e5f6a7b8-01" \
  -H "X-Request-ID: test-verification-001" \
  -d '{"scope": {"domains": ["example.com"], "engagement_id": "test-eng-001"}}'
```

**Expected:**
- Response contains `X-Request-ID: test-verification-001`
- Jaeger shows trace `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`
- Trace contains `api.post.engagements` span

#### Step 3: End-to-End Trace Test

```bash
# 1. Create engagement
# 2. Create task (triggers scheduling)
# 3. Wait for agent execution
# 4. Query Jaeger for trace
```

**Expected trace structure:**
```
Trace ID: <generated>
├── api.post.engagements
│   ├── orchestrator.create_engagement
│   │   └── neo4j.run
│   └── orchestrator.schedule_task
│       └── redis.zadd
└── (after task execution)
    └── orchestrator._execute_via_agent
        └── agent.recon.execute_task
            ├── mcp.burp-mcp.scan_target
            │   └── http.post
            └── neo4j.run (upsert_task)
```

#### Step 4: Task Queue Propagation Test

```python
# Pseudo-test
async def test_trace_propagation_through_task_queue():
    # Create engagement (sets trace context)
    engagement = await orch.create_engagement(...)
    
    # Schedule task
    task = await orch.schedule_task(Task(...))
    
    # Assert task.trace_context has trace_id
    assert "trace_id" in task.trace_context
    assert task.trace_context["trace_id"] == current_trace_id()
    
    # Simulate agent picking up task
    agent = await orch._find_available_agent(AgentType.RECON)
    result = await agent.execute_task(task)
    
    # Verify agent span is child of orchestrator span
    spans = get_jaeger_spans_for_trace(task.trace_context["trace_id"])
    assert span_parent_exists("agent.execute_task", "orchestrator.schedule_task")
```

#### Step 5: Redis Operation Trace Test

```python
async def test_redis_trace_spans():
    with get_jaeger_spans() as spans:
        await session_memory.store_hot("key", "value")
    
    redis_spans = [s for s in spans if s.name == "redis.setex"]
    assert len(redis_spans) > 0
    assert redis_spans[0].attributes["ai_osop.redis.operation"] == "setex"
```

#### Step 6: Neo4j Operation Trace Test

```python
async def test_neo4j_trace_spans():
    with get_jaeger_spans() as spans:
        await graph_memory.add_asset(Asset(...))
    
    neo4j_spans = [s for s in spans if s.name.startswith("neo4j.")]
    assert len(neo4j_spans) > 0
```

#### Step 7: MCP Operation Trace Test

```python
async def test_mcp_trace_spans():
    with get_jaeger_spans() as spans:
        await mcp_registry.execute_tool("burp-mcp", "scan_target", {...})
    
    mcp_spans = [s for s in spans if s.name.startswith("mcp.")]
    assert len(mcp_spans) > 0
    assert mcp_spans[0].attributes["ai_osop.mcp.server_id"] == "burp-mcp"
```

#### Step 8: Span Attribute Verification

```python
def verify_span_attributes(span):
    required = ["ai_osop.request_id", "ai_osop.trace_id"]
    for attr in required:
        assert attr in span.attributes, f"Missing {attr} on span {span.name}"
```

### 6.3 Acceptance Criteria

| Criterion | Verification Method | Pass Threshold |
|-----------|-------------------|----------------|
| Every API request has a trace | Automated test | 100% |
| Task execution trace links to creator trace | Jaeger UI inspection | 100% |
| Agent span parent = orchestrator span | Jaeger UI / API | 100% |
| MCP span parent = agent span | Jaeger UI / API | 100% |
| Redis span exists per operation | Automated test | > 95% |
| Neo4j span exists per operation | Automated test | > 95% |
| No orphan spans (missing parent) | Jaeger query | 0 orphan |
| Trace export latency < 5s | Jaeger timestamp check | < 5s |

---

## 7. Rollback Plan

### 7.1 Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| OTel exporter failure degrades API | Medium | High | Exporter is async; failures must not block requests |
| Contextvar leakage between requests | Low | Medium | Per-request cleanup in middleware |
| Metrics cardinality explosion | Low | High | Label value validation; path sanitization |
| Performance regression from spans | Low | Medium | Sampling; disable in dev |
| Memory leak from trace buffers | Low | High | BatchSpanProcessor with max_queue_size |

### 7.2 Rollback Triggers

1. **API latency increases > 20%** after deployment
2. **OTel exporter errors > 1%** of requests
3. **Memory usage grows** unboundedly
4. **Trace correlation fails** > 5% of requests
5. **Any P0/P1 test failure** in observability tests

### 7.3 Rollback Procedure

```bash
# 1. Disable OTel (immediate, no restart needed)
export OSOP_OTEL_ENABLED=false

# 2. Disable CorrelationIdMiddleware (requires restart)
# Comment out in api/main.py:
# app.add_middleware(CorrelationIdMiddleware)

# 3. Disable metrics collection (requires restart)
# Comment out PrometheusMetricsMiddleware

# 4. Verify health
python -c "import requests; print(requests.get('http://localhost:8200/health').json())"

# 5. If full rollback needed, revert git commit
git revert HEAD --no-edit
```

### 7.4 Feature Flags

All observability features will be behind feature flags:

```python
# src/ai_osop/core/config.py
class Settings(BaseSettings):
    # ... existing fields ...
    
    # Observability feature flags
    otel_enabled: bool = Field(default=False, validation_alias="OSOP_OTEL_ENABLED")
    otel_endpoint: str = Field(default="localhost:4317", validation_alias="OSOP_OTEL_ENDPOINT")
    otel_service_name: str = Field(default="ai-osop", validation_alias="OSOP_OTEL_SERVICE_NAME")
    otel_environment: str = Field(default="dev", validation_alias="OSOP_OTEL_ENVIRONMENT")
    
    correlation_id_enabled: bool = Field(default=True, validation_alias="OSOP_CORRELATION_ID_ENABLED")
    metrics_enabled: bool = Field(default=True, validation_alias="OSOP_METRICS_ENABLED")
    trace_propagation_enabled: bool = Field(default=True, validation_alias="OSOP_TRACE_PROPAGATION_ENABLED")
    
    # Sampling
    otel_sampling_rate: float = Field(default=1.0, validation_alias="OSOP_OTEL_SAMPLING_RATE")
```

### 7.5 Gradual Rollout

1. **Dev environment:** Enable all features, run full test suite
2. **Staging environment:** Enable for 24h, monitor metrics
3. **Production (canary):** Enable on 1 instance, monitor for 1 hour
4. **Production (full):** Enable on all instances

---

## 8. Test Plan

### 8.1 Test Categories

```text
Unit Tests (fast, no external deps)
├── test_correlation_id.py
├── test_request_context.py
├── test_metrics_recording.py
├── test_trace_context_serialization.py
└── test_structlog_integration.py

Integration Tests (require Redis/Neo4j/Postgres)
├── test_otel_trace_propagation.py
├── test_task_queue_trace.py
├── test_agent_trace_parent.py
├── test_mcp_trace_span.py
├── test_memory_trace_spans.py
└── test_health_readiness.py

End-to-End Tests (full stack)
├── test_e2e_trace_flow.py
├── test_e2e_grafana_dashboards.py
└── test_e2e_jaeger_export.py
```

### 8.2 Unit Tests

#### `test_correlation_id.py`

```python
class TestCorrelationIdMiddleware:
    async def test_generates_request_id_when_missing(self):
        """If no X-Request-ID header, middleware generates UUID."""
    
    async def test_uses_provided_request_id(self):
        """If X-Request-ID header present, use it."""
    
    async def test_returns_request_id_in_response(self):
        """Response includes X-Request-ID header."""
    
    async def test_extracts_traceparent_as_request_id(self):
        """If traceparent header present, extract trace_id as request_id."""
    
    async def test_binds_to_structlog_context(self):
        """Request ID appears in structlog contextvars."""
```

#### `test_request_context.py`

```python
class TestRequestContext:
    def test_bind_sets_contextvars(self):
        """bind() sets all contextvars."""
    
    def test_get_returns_all_values(self):
        """get() returns dict of all bound values."""
    
    def test_clear_resets_all(self):
        """clear() resets all contextvars to empty."""
    
    def test_isolated_per_async_task(self):
        """Contextvars are isolated between concurrent tasks."""
```

#### `test_metrics_recording.py`

```python
class TestMetricsRecording:
    def test_active_engagements_gauge_updated(self):
        """Gauge updated on create_engagement and halt_engagement."""
    
    def test_task_status_gauge_updated(self):
        """Gauge updated on task lifecycle transitions."""
    
    def test_mcp_latency_histogram_recorded(self):
        """MCP call records latency histogram."""
    
    def test_neo4j_latency_histogram_recorded(self):
        """Neo4j query records latency histogram."""
```

### 8.3 Integration Tests

#### `test_otel_trace_propagation.py`

```python
class TestOTelTracePropagation:
    async def test_api_request_creates_trace(self):
        """POST /engagements creates a trace in Jaeger."""
    
    async def test_task_inherits_trace_context(self):
        """Scheduled task has trace_context from API request."""
    
    async def test_agent_executes_with_parent_span(self):
        """Agent span has orchestrator span as parent."""
    
    async def test_mcp_span_has_agent_parent(self):
        """MCP span has agent span as parent."""
    
    async def test_neo4j_span_has_agent_parent(self):
        """Neo4j span has agent span as parent."""
```

#### `test_task_queue_trace.py`

```python
class TestTaskQueueTracePropagation:
    async def test_trace_context_preserved_in_redis_queue(self):
        """Task pushed to Redis queue retains trace_context."""
    
    async def test_trace_context_restored_from_redis_queue(self):
        """Task popped from Redis queue restores trace_context."""
    
    async def test_trace_context_persisted_in_postgres(self):
        """Task stored in Postgres retains trace_context."""
    
    async def test_trace_context_persisted_in_neo4j(self):
        """Task stored in Neo4j retains trace_context."""
```

#### `test_health_readiness.py`

```python
class TestHealthReadiness:
    async def test_health_returns_200(self):
        """/health returns 200 without auth."""
    
    async def test_readiness_checks_all_deps(self):
        """/ready checks Redis, Neo4j, Postgres, MCP registry."""
    
    async def test_readiness_fails_when_redis_down(self):
        """/ready returns 503 when Redis unavailable."""
    
    async def test_readiness_fails_when_neo4j_down(self):
        """/ready returns 503 when Neo4j unavailable."""
    
    async def test_readiness_fails_when_postgres_down(self):
        """/ready returns 503 when Postgres unavailable."""
```

### 8.4 End-to-End Tests

#### `test_e2e_trace_flow.py`

```python
class TestE2ETraceFlow:
    async def test_full_engagement_trace(self):
        """
        1. Create engagement
        2. Create task
        3. Wait for agent execution
        4. Query Jaeger for trace
        5. Verify complete chain: API → Orchestrator → Task → Agent → MCP → Neo4j
        """
```

#### `test_e2e_jaeger_export.py`

```python
class TestE2EJaegerExport:
    async def test_spans_reach_jaeger(self):
        """After API request, spans appear in Jaeger within 5 seconds."""
    
    async def test_trace_attributes_complete(self):
        """Every span has required attributes."""
    
    async def test_no_orphan_spans(self):
        """No spans with missing parent in trace."""
```

### 8.5 Test Data & Fixtures

```python
# fixtures
@pytest.fixture
def jaeger_client():
    """Client for querying Jaeger API."""
    return JaegerClient("http://localhost:16686")

@pytest.fixture
def prometheus_client():
    """Client for querying Prometheus API."""
    return PrometheusClient("http://localhost:9090")

@pytest.fixture
def trace_context():
    """Sample trace context for injection into tasks."""
    return {
        "traceparent": "00-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-a1b2c3d4e5f6a7b8-01",
        "trace_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        "span_id": "a1b2c3d4e5f6a7b8",
    }
```

### 8.6 Coverage Requirements

| Module | Minimum Coverage | Key Behaviors to Test |
|--------|-----------------|----------------------|
| `core/telemetry.py` | 95% | Context binding, trace injection, trace extraction |
| `api/middleware.py` | 90% | Correlation ID generation, header propagation, structlog binding |
| `core/metrics.py` | 85% | All metric definitions, recording helpers |
| `core/observability.py` | 85% | `record_task`, `update_*`, latency recorders |
| `core/tracing.py` | 90% | `trace_span`, `trace_method`, `init_tracing` |
| `orchestrator/orchestrator.py` | 70% | Trace context in task, metrics update on lifecycle |
| `agents/base.py` | 70% | Trace parent extraction, metrics recording |
| `mcp/protocol.py` | 70% | MCP span wrapping, metrics recording |
| `memory/session_memory.py` | 60% | Redis/Postgres spans, latency recording |
| `memory/graph_memory.py` | 60% | Neo4j spans, latency recording |
| `api/main.py` | 60% | Middleware registration, health/ready endpoints |

---

## Appendix A: File Inventory

### New Files to Create

```
src/ai_osop/core/telemetry.py          # RequestContext, trace propagation helpers
src/ai_osop/api/middleware.py          # CorrelationIdMiddleware, health/ready endpoints
src/ai_osop/api/health.py              # /health and /ready routers
tests/test_observability_*.py          # All observability tests
observability/grafana/dashboards/*.json  # Grafana dashboards
observability/prometheus/rules/*.yml   # Alert rules
docker-compose.observability.yml         # Local observability stack
```

### Files to Modify

```
src/ai_osop/api/main.py
  - Add CorrelationIdMiddleware
  - Replace /health with /ready
  - Register health router

src/ai_osop/core/config.py
  - Add observability settings (otel_endpoint, sampling, feature flags)

src/ai_osop/core/models.py
  - Add trace_context field to Task model

src/ai_osop/core/tracing.py
  - Add trace context injection/extraction helpers
  - Add W3C TraceContext propagation
  - Fix OTLP endpoint configuration

src/ai_osop/core/metrics.py
  - Add SLO metrics
  - Add decorator/helpers for recording

src/ai_osop/core/observability.py
  - Add metrics recording calls to existing helpers
  - Add engagement lifecycle metrics

src/ai_osop/orchestrator/orchestrator.py
  - Inject trace context into task metadata on schedule
  - Update metrics on lifecycle transitions
  - Extract trace context from task on assignment

src/ai_osop/agents/base.py
  - Extract trace context from task on execute
  - Record agent execution metrics

src/ai_osop/mcp/protocol.py
  - Wrap execute with trace span
  - Record MCP latency/error metrics

src/ai_osop/memory/session_memory.py
  - Wrap Redis/Postgres ops with trace spans + latency metrics

src/ai_osop/memory/graph_memory.py
  - Wrap Neo4j ops with trace spans + latency metrics
  - Ensure all public methods are traced
```

---

## Appendix B: Implementation Order

**Phase 1: Foundation (Sprint 6A)**
1. `telemetry.py` — RequestContext, trace propagation helpers
2. `middleware.py` — CorrelationIdMiddleware
3. `api/main.py` — Register middleware, health/ready endpoints
4. `tracing.py` — Fix OTel config, add propagation helpers
5. `models.py` — Add `trace_context` to Task

**Phase 2: Instrumentation (Sprint 6A-6B)**
6. `orchestrator.py` — Inject/extract trace context, update metrics
7. `agents/base.py` — Extract trace context, record metrics
8. `mcp/protocol.py` — Trace spans, record metrics
9. `memory/session_memory.py` — Trace spans, record metrics
10. `memory/graph_memory.py` — Trace spans, record metrics

**Phase 3: Metrics Completion (Sprint 6B)**
11. `metrics.py` — Add SLO metrics, recording decorators
12. `observability.py` — Wire up all recording calls

**Phase 4: Dashboards & Verification (Sprint 6C-6D)**
13. Grafana dashboard JSON models
14. Prometheus alert rules
15. docker-compose.observability.yml
16. Sentry integration design (code or config)

**Phase 5: Testing (Sprint 6E)**
17. Unit tests for all new modules
18. Integration tests for trace propagation
19. E2E tests for full trace flow
20. Jaeger verification script

---

*End of Design Document*
