# Traceability Certificate — Sprint 6.5

## Status: PARTIAL

### Evidence

| Check | Result | Evidence |
|---|---|---|
| G — Jaeger Validation (configuration) | PASS | `src/ai_osop/core/tracing.py` configures `OTLPSpanExporter` with gRPC endpoint. `init_tracing()` initializes `TracerProvider` with `BatchSpanProcessor`. Trace context propagation via `RequestContext` and `inject_trace_context` / `extract_trace_context` in `telemetry.py`. |
| G — Full request path trace | FAIL | No live Jaeger/OTLP collector running to verify end-to-end trace path: API → Orchestrator → Agent → MCP → Graph → Report. Cannot produce trace screenshot or exported JSON. |
| E — Graph trace spans | PASS | `find_attack_paths` and `get_graph_stats` manually instrumented with `trace_span` including `engagement_id` attribute. Other graph methods already had `trace_span` in `add_asset`, `add_endpoint`, `add_vulnerability`, `upsert_task`. |
| Trace IDs / Engagement IDs / Task IDs | PASS | `trace_span` calls include `attributes={"engagement_id": engagement_id, "task_id": task_id}` where available. Existing telemetry layer propagates trace context via `trace_context` fields on `Task` models. |
| Sentry Integration (F) | PASS | `sentry-sdk = "^2.0.0"` in `pyproject.toml`. `api/main.py` initializes `sentry_sdk.init(dsn=..., environment=..., traces_sample_rate=..., profiles_sample_rate=...)` when `SENTRY_DSN` is set and environment is not `development`/`dev`/`local`/`test`. |
| Live Sentry event emission | FAIL | No live Sentry DSN configured in `.env` (`SENTRY_DSN=` is empty). Cannot trigger and capture a live exception event. |

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
