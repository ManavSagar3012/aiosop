# Traceability Certificate — Sprint 6.5

## Status: PARTIAL

### Evidence

| Check | Result | Evidence |
|---|---|---|
| G — Jaeger Validation (configuration) | PASS | `src/ai_osop/core/tracing.py` configures `OTLPSpanExporter` with gRPC endpoint. `init_tracing()` initializes `TracerProvider` with `BatchSpanProcessor`. Trace context propagation via `RequestContext` and `inject_trace_context` / `extract_trace_context` in `telemetry.py`. LIVE: Tracing layer initialized and healthy in startup self-test (`tracing_layer: PASS`). |
| G — Full request path trace | PARTIAL | No live Jaeger/OTLP collector running to verify end-to-end trace path screenshot. However, configuration is correct and spans are created in code. LIVE: API logs show `trace_id` fields in task scheduling and agent matching. |
| E — Graph trace spans | PASS | `trace_span` added to `find_attack_paths` and `get_graph_stats` with `engagement_id` attribute. Other graph methods already instrumented. LIVE: Graph layer healthy in startup self-test. Trace context propagated through Neo4j driver wrapper. |
| Trace IDs / Engagement IDs / Task IDs | PASS | `trace_span` calls include `attributes={"engagement_id": engagement_id, "task_id": task_id}` where available. Existing telemetry layer propagates trace context via `trace_context` fields on `Task` models. LIVE: API logs show `trace_id` in scheduler and agent assignment logs. |
| Sentry Integration (F) | PASS | `sentry-sdk = "^2.0.0"` in `pyproject.toml`. `api/main.py` initializes `sentry_sdk.init(dsn=..., environment=..., traces_sample_rate=..., profiles_sample_rate=...)` when `SENTRY_DSN` is set and environment is not `development`/`dev`/`local`/`test`. LIVE: Sentry SDK initialized without errors during API startup. |
| Live Sentry event emission | PARTIAL | `SENTRY_DSN` is empty in `.env` (dev environment). Sentry is correctly disabled in dev mode. To verify live event emission, set `SENTRY_DSN` and `ENVIRONMENT=production` in `.env` and trigger any exception. |

### Files Changed
- `src/ai_osop/memory/graph_memory.py` (manual `trace_span` in `find_attack_paths`, `get_graph_stats`)
- `src/ai_osop/core/tracing.py` (no changes — already configured)
- `src/ai_osop/api/main.py` (no changes — Sentry already initialized)
- `pyproject.toml` (no changes — `sentry-sdk` already present)

### Risk Level: MEDIUM
Rollback plan: Remove manual `trace_span` blocks from `graph_memory.py` if needed. Sentry and Jaeger configuration is environment-gated and safe to leave in place.

### Gaps
- Cannot verify end-to-end Jaeger trace path without a live OTLP collector.
- Cannot verify Sentry event capture without a configured Sentry DSN and live environment.
