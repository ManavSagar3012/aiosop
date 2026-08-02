# Operations Certificate — Sprint 6.5

## Status: PARTIAL

### Evidence

| Check | Result | Evidence |
|---|---|---|
| H1 — Prometheus Adapter | PASS | Created `k8s/prometheus-adapter-config.yaml` mapping `ai_osop_queued_tasks` and `ai_osop_running_tasks` to Custom Metrics API. HPA manifest (`k8s/hpa.yaml`) already references these metrics under `type: Pods`. |
| H1 — Live HPA scaling | FAIL | No live Kubernetes cluster or Prometheus Adapter running. Cannot execute `kubectl get hpa` or observe scaling behavior. |
| H2 — IRSA | PASS | Created `k8s/irsa.yaml` with `ServiceAccount` (ai-osop, ai-osop-backup), `Role`, `RoleBinding`, and `eks.amazonaws.com/role-arn` annotation placeholder. `k8s/orchestrator-deployment.yaml` already uses `serviceAccountName: ai-osop`. |
| H2 — Live AWS identity | FAIL | No live EKS cluster or IAM roles to verify pod-assumed identity. |
| H3 — Backup validation | PARTIAL | `k8s/backup-cronjobs.yaml` schedules Postgres, Neo4j, and Redis backups. Removed static AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) in favor of IRSA. S3 bucket `ai-osop-backups` referenced in scripts. |
| H3 — Live backup/restore | FAIL | No live cluster or S3 bucket to execute backup/restore and compare checksums. |
| H4 — Neo4j backup permissions | PASS | Neo4j backup cronjob uses `neo4j:5.18-community` image with `neo4j-admin database dump`. Community edition `dump` works without enterprise `backup` privileges. |
| H4 — Live Neo4j backup | FAIL | No live Neo4j instance to verify backup execution and restore. |
| B — Startup Self Test | PASS | `api/health.py` `run_startup_self_test()` checks all 10 required layers: Redis, Postgres, Neo4j, MCP Registry, Task Queue, Session Store, Approval Store, Graph Layer, Tracing Layer, Metrics Layer. Returns PASS/FAIL/LATENCY/ERROR per check. `api/main.py` raises `RuntimeError` on critical dependency failure. `GET /health/startup` endpoint added. |
| B — Live startup blocking | FAIL | No live API deployment to bring down a dependency and verify startup refusal. |
| C — Agent Shutdown Safety | PASS | `agents/base.py` `shutdown()` wraps `await self._cleanup_resources()` in `asyncio.wait_for(timeout=settings.agent_cleanup_timeout_seconds)`. Config added to `core/config.py` (`AGENT_CLEANUP_TIMEOUT_SECONDS`). Logs warning on timeout. |
| C — Live timeout verification | FAIL | No live hanging agent to verify timeout behavior. |

### Files Changed
- `k8s/prometheus-adapter-config.yaml` (new)
- `k8s/irsa.yaml` (new)
- `k8s/backup-cronjobs.yaml` (removed static AWS credentials from Postgres, Neo4j, Redis backups)
- `src/ai_osop/api/health.py` (expanded `run_startup_self_test`, added `/health/startup` endpoint)
- `src/ai_osop/api/main.py` (uncommented `RuntimeError` on startup self-test failure)
- `src/ai_osop/agents/base.py` (wrapped `_cleanup_resources` in `asyncio.wait_for`)
- `src/ai_osop/core/config.py` (added `agent_cleanup_timeout_seconds`)

### Risk Level: MEDIUM
Rollback plan: Revert K8s manifests to previous versions. Revert startup and agent shutdown changes in Python files.

### Gaps
- All live Kubernetes/AWS verification blocked by absence of running cluster.
- Live startup blocking verification blocked by absence of deployed API.
- Live agent timeout verification blocked by absence of running agents.
