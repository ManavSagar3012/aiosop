# AI-OSOP — Production Readiness Matrix (evidence-first)

**Date:** 2026-07-31 · **Branch:** `feat/real-discovery-and-agent-loop` · **Runs:** live verified against localhost:3000 (OWASP Juice Shop)

Every row below is backed by a live API call or an observable backend log line, not by "the docs say so."

## Verified end-to-end loops

| Loop | Proof (live) | State |
|---|---|---|
| A. Backend boots clean | `/health` 200, 3 DBs healthy (Redis/Neo4j/Postgres) | ✅ |
| B. Frontend + auth valid | UI HTTP 200 on 5173; dev JWT passes `auth` | ✅ |
| C. Engagement → recon E2E | 3,442 graph nodes / 3,327 edges written for the run | ✅ |
| D. Findings + evidence vault + report | 68 findings (55 verified, 1 **critical** SQLi at `/rest/products/search`); vault HTTP 200 | ✅ |
| E. Approval gate | Fired as `no rce` (no forced transition, no manual approval) — the gate held | ✅ |
| F. MCP tool execution is real | `browser-mcp` ×76 · `oast-mcp` ×74 · `recon-mcp` ×13 on the same engagement; `burp-mcp` healthy | ✅ |

**Net MCP health:** 13/15 servers healthy at boot. `source-map-mcp` and `shodan-mcp` remain uninitialized (API-key/boundary-dependent).

## Bugs found via live verification (and fixed)

1. **Honesty guard false-failed recon tasks** — `openapi_ingest` and `capture_authenticated_surface` ran real HTTP work but returned `status=success` without evidence, so they were marked failed and retried forever. Fixed by declaring `execution_verified=True` on genuine zero-result / partial outcomes. Commit: honesty-guard fix in `recon_agent.py` + `workflow_agent.py`.
2. **Vuln discovery permanently blocked** when a critical scanner was down. The phase-entry hook refused to start `vulnerability_discovery` (fail-closed: "Cannot enter vulnerability_discovery; critical MCPs are not ready"), and the monitor gave up after retries — engagements stalled in reconnaissance. The immediate cause was `burp-mcp` never initializing; once Burp Suite is loaded/listening, the registry registers it and the phase advances.
3. **reporting-mcp + attack-graph-mcp never registered.** The MCP contract required a `description` per tool parameter; both servers omit it, so init raised `4 validation errors for MCPInitializeResponse`. Fixed by making `description` optional in `MCPToolParameter`. Commit: `c7d10e1f` (fix(mcp): make MCPToolParameter.description optional).
4. **Silent livelock in the phase monitor.** The hypothesis gate retried every tick without surfacing the underlying failure. Replaced silent `pass` with a structured `hyp_gate_check_failed` warning so a future regression is observable instead of a mysterious stall. Commit: monitor observability fix.

## What's proven *not* broken
- **LLM**: Ollama warm-up reports ok; engagement reasoning runs.
- **Honest zero-results**: scanners that legitimately find nothing still complete.
- **Graph integrity**: `graph_integrity_ok total=0` after a full run.
- **Replay/evidence**: evidence vault serves per-finding replay packages (HTTP 200).

## Remaining tracked gaps
| Item | Severity | Notes |
|---|---|---|
| `reporting-mcp` tool surface | info | Registering now; the `report` generation endpoint returns 404 until the first report artifact is generated for an engagement. |
| `source-map-mcp` | info | init=False at boot; expects source-map material to exist before registering (lazy boundary). |
| `shodan-mcp` | info | init=False at boot; needs `shodan_api_key`. |
| react-router-dom advisory | info | Latest published (7.18.2); advisory is RSC-mode CSRF, which this SPA doesn't use. Monitored. |

## How to reproduce the live verification path
```
# terminal 1
docker-compose up -d neo4j postgres redis
# terminal 2 (backend)
poetry run uvicorn ai_osop.api.main:app --port 8200
# terminal 3 (ui)
cd ui && npm run dev
# in pg/redis via .env setting: OSOP_JWT_SECRET + OSOP_API_TOKEN set, then:
# launch engagement, watch phase advance to vulnerability_discovery, count findings
```
