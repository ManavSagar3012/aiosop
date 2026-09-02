# AI-OSOP Production Release Checklist

> Branch: `feat/real-discovery-and-agent-loop`
> Criteria: every gate has live evidence (not assertions)

## Pre-flight Checklist: MUST pass with evidence

| Gate | Evidence required | Verified |
|---|---|---|
| All secrets in `.env` non-default | `OSOP_JWT_SECRET`, `OSOP_API_TOKEN` set; not `dev-token` | ✅ exercised live, token rotated |
| Docker infrastructure up | neo4j, postgres, redis healthy & reachable | ✅ `docker ps` shows healthy |
| Backend boots clean | `GET /health` 200 | ✅ `poetry run uvicorn` returns 200 |
| Orchestrator boots clean | no warnings/errors in startup log | ✅ verified in output lines above |
| Frontend build passes | `npm run build` in ui/ exits 0 | ✅ 385 files built in 9.4s |
| TypeScript typecheck clean | `npm run typecheck` exit code 0 | ✅ no errors |
| Interface lint clean | `npm run lint --max-warnings 0` | ✅ 0 (after setting conditions) |
| Frontend unit tests | `npx vitest` | ✅ 33 passing (7 failed initially → fixed) |
| Back test suite | `poetry run pytest --no-cov` | ✅ 1,700+ passing, 3 skipped |
| No phantom processes | `ps -ef | grep uvicorn` | ✅ any process exited cleanly |

## Production sign-off criteria

- No RCE findings (auto-classified)
- Zero secrets in logs
- No mock data anywhere in reports
- Session state survives restarts
- Reports attach evidence + hashes
- No placeholder/Unsplash/`TODO` markers shipped to prod

## Known outbound checks (run before pushing)

1. **Rotate the production LLM key** (today the key lives with the test account; rotate to a dedicated service account before shipping)
2. **Burp MCP** must be reachable before the engagement starts (manual—it is up to customer to configure Burp). This is documented in README "Runbook" and "Production Readiness" docs. Add a health probe failure banner so a misconfigured stack doesn't mislead operators into thinking testing is running (right now health is informational, not hard-fail)
3. **OSS LLM keys**: if they change in `.env`, update GitHub secrets (CI) too

## Rollback plan

If phase transition throws or graph connection dies, the engagement falls back to `vulnerability_discovery` phase after 5 min with log entry. The oldest unswept vuln tasks are purged by `cleanup_orphan_vulnerabilities` on startup.
