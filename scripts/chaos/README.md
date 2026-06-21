# Chaos Testing Scripts

Resilience validation for AI-OSOP. Each script simulates a real-world failure scenario and verifies the system handles it gracefully.

## Scripts

| Script | Failure Scenario | Expected Behavior |
|--------|------------------|-------------------|
| `kill_redis.py` | Redis stopped | Hot tier falls back to warm tier (Postgres); API survives; auto-reconnect on restore |
| `kill_neo4j.py` | Neo4j stopped | Tasks queue to Postgres; graph dedupe resumes on restore; no scheduler crash |
| `kill_postgres.py` | PostgreSQL stopped | Redis hot tier survives; tasks continue from in-memory state; warm tier replays later |
| `kill_api.py` | API container restarted | Pending approvals + active tasks recovered from warm tier on restart; no duplication |
| `kill_mcp.py` | MCP servers stopped | Circuit breaker opens; scheduler retries with backoff; API continues processing other tasks |

## Prerequisites

- AI-OSOP running via `docker-compose up`
- API accessible on `localhost:8200`
- `docker-compose` CLI available

## Usage

```bash
# Test individual failure modes
python scripts/chaos/kill_redis.py
python scripts/chaos/kill_neo4j.py
python scripts/chaos/kill_postgres.py
python scripts/chaos/kill_api.py
python scripts/chaos/kill_mcp.py

# Or run all (recommended order)
for script in scripts/chaos/kill_*.py; do
    echo "=== Running $script ==="
    python "$script" || echo "FAILED: $script"
    sleep 5
done
```

## Safety

- All scripts restore services at the end (even on failure)
- Test engagement IDs are prefixed with `chaos-test-` for easy cleanup
- Do not run in production without supervision
