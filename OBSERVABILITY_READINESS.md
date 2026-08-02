# OBSERVABILITY READINESS

## 1. Metrics & Exports
- **Prometheus Metrics**:
  - Endpoint `/metrics` exposed on the main API port `8090`.
  - Exposes counters for engagements, task schedules, and active agent execution times.
  - Implements the `READY_STATUS` metric tracking database and dependency health.
- **Trace Dependency**:
  - OpenTelemetry configuration initialized during lifespan startup.
  - Generates trace spans for all database queries and external MCP call scopes.

## 2. Dashboards
- Pre-built Grafana dashboards are located in the repository:
  - `dashboards/grafana_system_health.json`
  - `dashboards/grafana_task_agent_metrics.json`
  - `dashboards/grafana_error_dashboard.json`
- **Audit**: Datasources need manual target mapping to the Prometheus/Jaeger collector hosts in production deployments.
