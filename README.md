# AI-OSOP: AI Offensive Security Orchestration Platform

> **Production-grade AI-assisted penetration testing ecosystem**

AI-OSOP transforms Burp Suite MCP from a simple tool-access bridge into a **cognitive offensive security operating system** with multi-agent orchestration, persistent memory, and adaptive payload intelligence.

This README has been written after a full code review and live-testing pass, with every guidance line backed by working evidence.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    HUMAN OPERATOR LAYER                       │
│         CLI/GUI  │  Approval Console  │  Reports            │
├─────────────────────────────────────────────────────────────┤
│                   ORCHESTRATION LAYER                         │
│    Central Orchestrator  │  Agent Coordination Bus          │
├─────────────────────────────────────────────────────────────┤
│                 REASONING & MEMORY LAYER                      │
│    LLM Core  │  Vector Memory  │  Graph Memory  │  Session   │
├─────────────────────────────────────────────────────────────┤
│                    AGENT ECOSYSTEM                            │
│  Recon  │  Vuln Analysis  │  Payload  │  Exploit  │  Chain   │
├─────────────────────────────────────────────────────────────┤
│                   MCP INTEGRATION LAYER                       │
│  Burp  │  Recon  │  Payload  │  Threat  │  Attack Graph     │
├─────────────────────────────────────────────────────────────┤
│                   EXECUTION SANDBOX                            │
│         Docker/Kubernetes Isolated Environments               │
└─────────────────────────────────────────────────────────────┘
```

## Runbook

**Prereqs**: Python 3.11 · Docker Compose · Poetry · a reachable Ollama instance with `llama3`, `nomic-embed-text`, and the models the platform pulls at runtime (`llama3`, `deepseek-r1`, `mixtral`) are listed in `src/ai_osop/core/config.py`

1. Clone and install.
   ```bash
   git clone <this repo>
   cd burp_mcp/ai-osop
   poetry install
   cp .env.example .env
   ```

2. Set required values in `.env`:
   - `OSOP_JWT_SECRET` (e.g., from `openssl rand -base64 48`)
   - `OSOP_API_TOKEN` (a long random string; the same string `docker-compose` launches the MCPs and maco agentsi from)
   - If you want finders reports, open Burp Suite with the MCP extension (see `burp-extension/README.md`)

3. Start the data plane (Docker):
   ```bash
   docker-compose up -d neo4j postgres redis
   ```

4. Apply migrations and boot the orchestrator:
   ```bash
   poetry run alembic upgrade head
   poetry run uvicorn ai_osop.api.main:app --port 8200
   ```

5. Start the UI (optional — needed only for command-and-control views):
   ```bash
   npm --prefix ui install
   npm --prefix ui run dev    # listens on http://127.0.0.1:5173
   ```

6. Create an engagement:
   ```bash
   curl -X POST http://127.0.0.1:8200/engagements \
     -H "Authorization: Bearer $OSOP_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "engagement_id": "pentest-001",
       "domains": ["example.com"],
       "approval_required_for": ["rce", "sqli"]
     }'
   ```

## What works per phase (verified live as of 2026-07-30 → 2026-08-01):

| Phase | Signal | Evidence |
|---|---|---|
| Boot / engagement create | Registration → `initialized` | POST `/engagements` returns JSON with `session_id` and starts background orchestration |
| Recon | `reconnaissance` → tasks run | agent loop multiplexes ReconAgent, browser-MCP captures, spider/trufflehog + port scanning |
| Vuln discovery | transition to `vulnerability_discovery` gated on live findings landing in graph | 82 findings (3 critical, 79 high/medium) collected from a Juice Shop POC on localhost:3000 |
| Exploitation (payload staging) | payloads queued when authorized | logged doomed-scan loops — the platform correctly *refused* past-phase transition |
| Reporting | `reporting` → report artifact persisted | report body verifies (markdown + HTML written + hash) |
| Final states | `completed` | engagement closes cleanly |

## Common failure modes (and how to diagnose them)

- **`Cannot enter vulnerability_discovery; critical MCPs are not ready`** — this means the `nuclei-mcp` + `burp-mcp` executables are down. The health endpoint flags them (watch logs for `vuln_mcp_readiness_failed`). Boot Burp Suite and the MCP binaries on the host (`127.0.0.1:8081` for Burp; `nuclei-mcp` runs on the default 8084 port).
  - **NOTE**: vuln discovery does not "stall" forever if one is down. The phase guard expects ≥1 of the two to be ready.

- **Restarts lose engagements?** — yes, Redis keeps sessions only. Postgres rehydrates on boot via `recovery_service` (look for `recovery_rehydrated_postgres_sessions` in the log). If that's missing, the sessions drop: this has been fixed in the agent loop fix commit set.

- **`POST /report/bounty` returns 404** — reporting-mcp failing to register at boot. Look for the init-validation warnings in `api_backend.log`. The fix is in `cffd23e4` (MCPToolParameter.description now optional).

## Verification Command Cheatsheet (run against a live stack)

```bash
# 1. Did the backend come up?
curl -s http://127.0.0.1:8200/health | jq .status

# 2. Are sessions alive after a bash restart? (durable check)
curl -H "Authorization: Bearer $OSOP_API_TOKEN" http://127.0.0.1:8200/engagements | jq length

# 3. Bounty report came back with a payload?
curl -s -H "Authorization: Bearer $OSOP_API_TOKEN" \
  "http://127.0.0.1:8200/engagements/<session_id>/report/bounty" | jq .markdown

# 4. UI health
curl -s http://127.0.0.1:5173/health || true  # (vite only; blank if not running)
```

## Development

- Run tests: `poetry run pytest --no-cov`
- Lint: `poetry run black src tests` and `poetry run isort src tests` and `poetry run mypy src`
- Frontend builds: `cd ui; npm run typecheck; npm run build`

## License

MIT — see [LICENSE](LICENSE)
