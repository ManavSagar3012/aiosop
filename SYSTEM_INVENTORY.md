# SYSTEM_INVENTORY.md — AI-OSOP Platform Inventory

## Executive Summary
This document provides a comprehensive runtime inventory of the AI-OSOP (Autonomous Offensive Security Orchestration Platform) subsystems, databases, core orchestrator components, and Model Context Protocol (MCP) servers. Every component has been verified at runtime.

---

## 1. Backing Services & Databases
All backing databases are run via Docker Compose and have been verified as active and listening on localhost:

| Service | Port | Docker Container | Driver/Library | Status | Runtime Verification |
|---|---|---|---|---|---|
| **Redis** | 6379 | `ai-osop-redis` | `redis-py` | ACTIVE | Port open, connection established, healthcheck passed, keys writable. |
| **Neo4j** | 7687 (Bolt) / 7474 (HTTP) | `ai-osop-neo4j` | `neo4j` | ACTIVE | Port open, Bolt handshake successful, Cypher queries runnable. |
| **PostgreSQL** | 5432 | `ai-osop-postgres` | `asyncpg` / `SQLAlchemy` | ACTIVE | Port open, connection pool initialized, migrations applied. |

---

## 2. Core Platform Components
The core orchestration engine lives in Python (`src/ai_osop/`) and exposes a FastAPI gateway:

| Subsystem | Path / Entrypoint | Responsibility | Status | Details |
|---|---|---|---|---|
| **FastAPI API Gateway** | `src/ai_osop/api/main.py` | Exposes REST & WebSocket endpoints for engagements, tasks, agents, and approvals. | ACTIVE | Configured to run on port 8200. Exposes `/health`, `/health/tooling`, and `/metrics`. |
| **Orchestrator** | `src/ai_osop/orchestrator/orchestrator.py` | Enforces phase transitions, schedules tasks, claims/releases agents. | ACTIVE | Core engine managing the lifecycle of offensive engagements. |
| **Task Scheduler** | `src/ai_osop/orchestrator/task_scheduler.py` | Fetches pending tasks, matches them to idle agents, handles retries. | ACTIVE | Uses Redis sorted sets for task queues, sorted by task priority (1-10). |
| **Phase Monitor** | `src/ai_osop/orchestrator/phase_monitor.py` | Tracks phase completion and handles auto-advancement of phases. | ACTIVE | Drives transitions through Initialization -> Recon -> Discovery -> Vuln Scan -> Reporting. |
| **Agent Registry** | In-memory inside `Orchestrator` | Holds references to all active/idle agents in the system. | ACTIVE | Keyed by `agent_id`, manages active connections. |
| **Heartbeat System** | `src/ai_osop/memory/heartbeat.py` | Periodically registers and renews agent/orchestrator leases. | ACTIVE | Writes heartbeats to Redis to maintain cluster health. |
| **Lease Manager** | Handled in `BaseAgent` / `Orchestrator` | Ensures tasks/agents are not double-claimed and handles expiration. | ACTIVE | Uses Redis TTLs and distributed locks (repaired to lock on `lock:agent:<id>`). |
| **Agent Reaper** | `src/ai_osop/reliability/agent_reaper.py` | Scans for dead/stale agents and reclaims their leases. | ACTIVE | Periodically cleans up agents whose heartbeats have expired. |
| **Dead Letter Queue (DLQ)** | `src/ai_osop/reliability/dlq.py` | Stores tasks that have exhausted their retry budgets. | ACTIVE | Persists failed tasks to PostgreSQL with failure context. |
| **Session Memory** | `src/ai_osop/memory/session_memory.py` | Manages transient session state, task queues, and locks in Redis/Postgres. | ACTIVE | Hot state in Redis, audit logs in Postgres. |
| **Metrics System** | `src/ai_osop/core/metrics.py` | Tracks API latency, task durations, queue depths, and success rates. | ACTIVE | Exposes metrics internally for reporting. |
| **Prometheus Exporter** | Exposes `/metrics` endpoint | Exposes Prometheus-format metrics from python-client. | ACTIVE | Integrated with FastAPI router. |
| **Tracing System** | `src/ai_osop/core/tracing.py` | Integrates OpenTelemetry tracing for API, HTTP client, and DB operations. | ACTIVE | Exports OTLP traces. |

---

## 3. Model Context Protocol (MCP) Tooling Layer
AI-OSOP utilizes 14 MCP servers to execute actual offensive actions. The servers are classified below based on runtime verification:

| # | MCP Server | Port | Process/Binary | Reality Classification | Primary Dependencies |
|---|---|---|---|---|---|
| 1 | **burp-mcp** | 8081 | Burp Suite Professional + MCP Extension | **REAL** | Live Burp Suite application (operator-started) |
| 2 | **recon-mcp** | 8082 | Go binary (`mcp-servers/go/recon-mcp.exe`) | **REAL** | Native TCP connect scan, `httpx` CLI, `curl` (crt.sh/wayback) |
| 3 | **payload-mcp** | 8083 | Python stub (`mcp_stub.py`) | **STUB** | Honest stub (returns `tools: []`). Go mock binary is unwired. |
| 4 | **nuclei-mcp** | 8084 | Go binary (`mcp-servers/go/nuclei-mcp.exe`) | **REAL** | `nuclei` CLI (must be in system PATH) |
| 5 | **shodan-mcp** | 8085 | Go binary (`shodan-mcp.exe`) | **REAL** | `api.shodan.io` (needs `OSOP_SHODAN_API_KEY`) |
| 6 | **threat-intel-mcp** | 8086 | Go binary (`threat-intel-mcp.exe`) | **REAL** | NVD API (CVE), CISA KEV JSON API |
| 7 | **security-bridge** | 8087 | Go binary (`security-bridge.exe`) | **PARTIAL** | Real `sqlmap` / `ffuf` (Go source rebuilt); 6 other tools stubbed. |
| 8 | **session-memory-mcp** | 8090 | Python stub (`mcp_stub.py`) | **STUB** | Honest stub. Redis/Postgres state handled natively by orchestrator. |
| 9 | **browser-mcp** | 8091 | Python script (`browser_mcp.py`) | **REAL** | Playwright + Chromium (installed in `.venv`) |
| 10 | **reporting-mcp** | 8092 | Python stub (`mcp_stub.py`) | **STUB** | Honest stub. Core reporting engine lives in `src/ai_osop/reporting/`. |
| 11 | **attack-graph-mcp** | 8093 | Python stub (`mcp_stub.py`) | **STUB** | Honest stub. Core Neo4j graph logic handled natively. |
| 12 | **source-map-mcp** | 8096 | Python script (`source_map_mcp.py`) | **REAL** | Real HTTP fetch + regex parse + sourcemap extraction |
| 13 | **cloud-mcp** | 8097 | Python stub (`mcp_stub.py`) | **STUB** | Honest stub. AWS IAM data is simulated. |
| 14 | **turbo-intruder-mcp** | 8098 | Python script (`turbo_intruder_mcp.py`) | **STUB** | Simulated race-condition responses (no raw sockets) |

---

## 4. Frontend Dashboard
The user interface lives in `ui/` and connects to the FastAPI backend:

* **Technology**: Vite + React + TypeScript + Tailwind CSS.
* **Default Ports**: Dev server runs on `http://localhost:5173`.
* **State & Communication**: Connects to the backend via REST and a WebSocket stream (`ws://127.0.0.1:8200/api/v1/ws`) for live task and engagement updates.
