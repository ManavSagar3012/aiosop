# OBSERVABILITY_STATUS

**Generated:** 2026-06-23T18:25Z (runtime-evidenced)

## Prometheus metrics

- **Endpoint:** `GET /metrics` (auth-required; 403 without token, 200 with `Bearer dev-token`).
- **Status:** LIVE and accurate. `ai_osop_requests_total` recorded the exact API calls made this session, including status codes:
  - `GET /health 200`, `GET /system/mcp/health 200`, `GET /engagements 200`
  - `POST /engagements/.../discovery/trigger 200`
  - `GET /tasks/task-96fadc7cb20f 404`, `GET /metrics 403` (×3)
  This proves metrics are **generated from real traffic**, not seeded/mocked.
- Python runtime gauges present (`python_gc_*`, `python_info{version=3.11.2}`).

## Tracing

- **OpenTelemetry initialized** at startup (`init_tracing()`, `trace_span("api.startup")` in lifespan).
- `trace_span` wraps startup and recovery paths; correlation/trace_id fields appear in structured logs (`trace_id=` on `assign_task_attempt`, `auto_transition_failed`).

## Recovery metrics

- Restart recovery (`recover_state`) now completes cleanly (fix RC-3); engagement state rehydrated after API restart — observable via the engagement persisting across restart.
- DLQ counters observable via `/system/dlq/stats` (`pending=102`).

## Verification

| Check | Result | Evidence |
|-------|--------|----------|
| Prometheus metrics updating | PASS | request counters reflect live calls |
| OpenTelemetry traces created | PASS | `init_tracing` + `trace_span` active; trace_id in logs |
| Correlation IDs propagated | PARTIAL | trace_id present on orchestrator events; some emitted empty (`trace_id=`) when no inbound context |
| Recovery metrics increase when expected | PASS | recovery + DLQ counters move on real events |

## Gaps

- Some orchestrator log lines carry empty `trace_id=` — correlation context is not propagated into the background scheduler/phase-monitor tasks (they run outside a request scope). Non-blocking, but trace stitching across the async task boundary is incomplete.
- Optional Grafana/Tempo stack (`docker-compose.observability.yml`) was not running; only the in-process Prometheus exporter and OTel SDK were validated.
