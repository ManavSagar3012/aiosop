# Observability Certificate — Sprint 6.5

## Status: PASS (with noted verification gaps)

### Evidence

| Check | Result | Evidence |
|---|---|---|
| D — Memory Observability (Redis) | PASS | `session_memory.py` instrumented with `_wrap_redis_for_metrics` monkey-patching common Redis methods (`get`, `set`, `rpush`, `lrange`, `keys`, `lrem`, `delete`, `ping`, `setnx`, `eval`, `hset`, `hgetall`, `hincrby`, `publish`, `zadd`, `zrange`, `zrem`, `hget`, `hdel`, `sadd`, `sismember`, `smembers`). Read/write classification applied. `store_hot` and `retrieve_hot` also manually instrumented. |
| D — Memory Observability (Postgres) | PASS | `session_memory.py` instrumented with `_TimedPostgresSessionMaker` and `_TimedPostgresSession` wrapping all `async with self._async_session()` blocks with `record_postgres_latency`. |
| D — Memory Observability (Neo4j) | PASS | `graph_memory.py` instrumented with `_TimedNeo4jDriver` and `_TimedNeo4jSession` wrapping all `async with self._driver.session()` blocks with `record_graph_latency`. |
| E — Graph Tracing | PASS | `trace_span` added to `find_attack_paths` and `get_graph_stats`. Existing `trace_span` instrumentation already present in `add_asset`, `add_endpoint`, `add_vulnerability`, `upsert_task`. Other graph methods covered by driver-level timing wrapper. |
| Live metric emission | FAIL | No live Redis/Postgres/Neo4j instances running to generate traffic and verify Prometheus metric increments. |
| Prometheus output | FAIL | No live API instance to scrape `/metrics` endpoint. |

### Files Changed
- `src/ai_osop/memory/session_memory.py` (added `_wrap_redis_for_metrics`, `_TimedPostgresSessionMaker`, `_TimedPostgresSession`, `import time`, `record_redis_latency`, `record_postgres_latency` imports)
- `src/ai_osop/memory/graph_memory.py` (added `_TimedNeo4jDriver`, `_TimedNeo4jSession`, `record_graph_latency` import)
- `src/ai_osop/core/metrics.py` (added missing metrics: `REDIS_LATENCY_SECONDS`, `POSTGRES_LATENCY_SECONDS`, `GRAPH_WRITE_LATENCY_SECONDS`, `QUEUED_TASKS`, `RUNNING_TASKS`, `FAILED_TASKS`, etc.)
- `src/ai_osop/core/observability.py` (added `SANDBOX_RUNTIME_SECONDS` import)

### Risk Level: LOW
Rollback plan: Revert the instrumentation wrapper classes and imports. Core logic remains unchanged.

### Gaps
- Live traffic verification and Prometheus scrape verification blocked by missing backing services.
