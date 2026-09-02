# AI-OSOP Sprint 7 — Runtime Reliability Design Document

**Version:** 1.0
**Date:** 2025-01-18
**Status:** Approved for implementation

---

## 1. Problem Statement

The reports consistently identify:

- **No Dead Letter Queue** — When retries are exhausted, tasks simply fail. No operator review path.
- **MCP circuit breaker too basic** — No half-open state, no recovery tracking, no metrics.
- **Startup is fragile** — If Neo4j/Redis/Postgres is not ready at startup, the platform may start in a degraded state without retry.
- **Agent shutdown leaks** — Event-loop warnings from background task cleanup.
- **Redis recovery gaps** — No automatic reconnection on Redis disconnect.

---

## 2. Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              RELIABILITY LAYER                                 │
│  ┌──────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐   │
│  │ Dead Letter  │  │ MCP Circuit Breaker │  │ Startup Retry            │   │
│  │ Queue (DLQ)  │  │ (v2: half-open)     │  │ (exponential backoff)    │   │
│  └──────────────┘  └─────────────────────┘  └──────────────────────────┘   │
│  ┌──────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐   │
│  │ Agent Shutdown│  │ Redis Reconnect     │  │ Health-Aware Startup     │   │
│  │ (leak fixes) │  │ (auto-recovery)     │  │ (readiness gate)         │   │
│  └──────────────┘  └─────────────────────┘  └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Dead Letter Queue (DLQ)

### 3.1 Design

When a task exhausts its retry budget:

```text
Task
  ↓
Retry 1 → fail
  ↓
Retry 2 → fail
  ↓
Retry 3 → fail (max_retries = 3)
  ↓
DLQ
  ↓
Operator Review (via API / UI)
  ↓
Requeue or Discard
```

### 3.2 Implementation

New module: `ai_osop.reliability.dlq`

```python
class DeadLetterQueue:
    """Store failed tasks that have exhausted their retry budget.

    Backed by Redis (hot) + Postgres (warm) for durability.
    """

    async def enqueue(self, task: Task, reason: str, final_error: str) -> str:
        """Add a failed task to the DLQ. Returns DLQ entry ID."""

    async def list_entries(
        self,
        engagement_id: Optional[str] = None,
        status: Optional[str] = None,  # pending_review, requeued, discarded
    ) -> List[DLQEntry]:
        """List DLQ entries for operator review."""

    async def requeue(self, dlq_entry_id: str) -> Optional[Task]:
        """Requeue a DLQ task back into the normal task queue.
        Resets retry_count to 0."""

    async def discard(self, dlq_entry_id: str, operator_notes: str) -> None:
        """Permanently discard a DLQ entry."""

    async def get_stats(self) -> Dict[str, int]:
        """Return DLQ stats: pending, requeued, discarded counts."""
```

### 3.3 Integration

In `orchestrator._maybe_retry`:
```python
if task.retry_count >= task.max_retries:
    await self.dlq.enqueue(task, reason="retry_budget_exhausted", final_error=...)
    return False
```

In `orchestrator._on_task_failure`:
```python
# If task has exhausted retries and is not already in DLQ
if task.retry_count >= task.max_retries:
    await self.dlq.enqueue(task, reason="terminal_failure", final_error=...)
```

New API endpoint: `GET /dlq` (list), `POST /dlq/{id}/requeue`, `POST /dlq/{id}/discard`

---

## 4. MCP Circuit Breaker v2

### 4.1 Current State

- Binary: open / closed
- Fixed threshold: 5 failures
- Fixed recovery: 30 seconds
- No half-open state
- No recovery attempt tracking

### 4.2 Target State

```
CLOSED  ──[failure_count >= threshold]──>  OPEN
  ↑                                          │
  │                                          │
  │    [recovery_attempt succeeds]           │
  │         (half-open probe)               │
  └────────────── HALF-OPEN <───────────────┘
              [recovery_timeout elapsed]
```

### 4.3 New Fields

```python
class MCPConnection:
    # ... existing ...
    _half_open: bool = False
    _recovery_attempts: int = 0
    _last_success_at: Optional[datetime] = None
    _last_failure_at: Optional[datetime] = None
    _consecutive_successes: int = 0
    CIRCUIT_RECOVERY_SECONDS: int = 30
    CIRCUIT_HALF_OPEN_MAX_ATTEMPTS: int = 3  # max probes in half-open
    CIRCUIT_HALF_OPEN_SUCCESS_REQUIRED: int = 2  # successes to close
```

### 4.4 New Behavior

- **OPEN → HALF-OPEN**: After `CIRCUIT_RECOVERY_SECONDS`, next call transitions to half-open.
- **HALF-OPEN**: Only 1 probe call allowed. If it succeeds, increment `consecutive_successes`.
- **HALF-OPEN → CLOSED**: If `consecutive_successes >= CIRCUIT_HALF_OPEN_SUCCESS_REQUIRED`.
- **HALF-OPEN → OPEN**: If any probe fails, go back to OPEN, reset `consecutive_successes`.
- **Metrics**: Emit `MCP_CIRCUIT_BREAKER_STATE` on every state change.

---

## 5. Startup Retry with Exponential Backoff

### 5.1 Problem

```python
# Current (lifespan):
try:
    await graph_memory.connect()
except Exception as e:
    logger.critical(f"Neo4j connection failed: {e}")
# App continues in degraded state
```

### 5.2 Solution

```python
async def connect_with_retry(
    connector: Callable[[], Awaitable[None]],
    name: str,
    max_retries: int = 10,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> bool:
    """Connect with exponential backoff."""
```

### 5.3 Integration in Lifespan

```python
# Before:
try:
    await session_memory.connect()
except Exception as e:
    logger.critical(...)

# After:
redis_ok = await connect_with_retry(
    session_memory.connect, "redis", max_retries=10
)
if not redis_ok:
    logger.critical("Redis unavailable after retries — halting startup")
    raise RuntimeError("Redis unavailable")
```

### 5.4 Health-Aware Startup

After all connections are established, perform a readiness self-test before marking the app as ready:

```python
async def _startup_self_test() -> Dict[str, str]:
    """Verify all critical paths work end-to-end."""
    # 1. Redis ping
    # 2. Neo4j ping
    # 3. Postgres ping
    # 4. MCP registry has at least 1 healthy server
    # 5. Can create and read a test session
```

---

## 6. Agent Shutdown Leak Fixes

### 6.1 Current Problems

```python
# In shutdown():
for task in self._active_tasks.values():
    task.cancel()  # May raise CancelledError that is not caught

for bg in self._bg_tasks:
    bg.cancel()
for bg in self._bg_tasks:
    try:
        await bg  # This may hang if bg is already done
    except (asyncio.CancelledError, Exception):
        pass
```

### 6.2 Fixes

1. **Shield the cancellation loop** from `CancelledError` propagation
2. **Use `asyncio.shield`** for background tasks that must complete cleanup
3. **Set a timeout** on shutdown cleanup
4. **Track shutdown state** to prevent new tasks during shutdown

```python
async def shutdown(self) -> None:
    if self._shutting_down:
        return
    self._shutting_down = True

    # Cancel active tasks with timeout
    for task in list(self._active_tasks.values()):
        task.cancel()
    
    # Wait for active tasks with timeout
    if self._active_tasks:
        await asyncio.wait(
            [asyncio.create_task(t) for t in self._active_tasks.values()],
            timeout=5.0,
            return_when=asyncio.ALL_COMPLETED,
        )
    
    # Cancel background tasks
    for bg in self._bg_tasks:
        if not bg.done():
            bg.cancel()
    
    # Wait for background tasks with timeout
    if self._bg_tasks:
        await asyncio.wait(
            self._bg_tasks,
            timeout=5.0,
            return_when=asyncio.ALL_COMPLETED,
        )
    self._bg_tasks = []
    
    # ... rest of cleanup
```

---

## 7. Redis Reconnection

### 7.1 Problem

If Redis disconnects during operation, all subsequent Redis operations fail until restart.

### 7.2 Solution

Add a connection health check and auto-reconnect to `SessionMemory`:

```python
class SessionMemory:
    # ...
    async def _ensure_redis(self) -> redis.Redis:
        """Return a healthy Redis connection, reconnecting if needed."""
        if self._redis is None:
            await self.connect()
            return self._redis
        try:
            await self._redis.ping()
            return self._redis
        except Exception:
            logger.warning("Redis connection lost, reconnecting...")
            await self.connect()
            return self._redis
```

Wrap all Redis operations to use `_ensure_redis()`.

---

## 8. Implementation Order

1. **DLQ module** (`reliability/dlq.py`)
2. **DLQ integration** (orchestrator `_maybe_retry`, `_on_task_failure`)
3. **DLQ API endpoints** (`api/routers/dlq.py`)
4. **MCP circuit breaker v2** (`mcp/protocol.py`)
5. **Startup retry** (`api/main.py` lifespan)
6. **Agent shutdown fixes** (`agents/base.py`)
7. **Redis reconnection** (`memory/session_memory.py`)
8. **Tests** (`tests/test_reliability_*.py`)

---

## 9. Rollback Plan

| Feature | Rollback | Risk |
|---------|----------|------|
| DLQ | Skip DLQ enqueue; tasks fail as before | Low — additive only |
| MCP CB v2 | Revert to v1 logic | Medium — test half-open carefully |
| Startup retry | Reduce retry count to 1 | Low |
| Agent shutdown | Revert to old shutdown | Low — but may reintroduce leaks |
| Redis reconnect | Disable auto-reconnect | Low |

---

## 10. Success Criteria

- [ ] Task exhausting retries appears in DLQ within 1 second
- [ ] DLQ task can be requeued and executes successfully
- [ ] MCP circuit breaker enters HALF-OPEN after recovery timeout
- [ ] MCP circuit breaker returns to CLOSED after 2 consecutive successes in HALF-OPEN
- [ ] Platform starts successfully when Redis/Neo4j are initially unavailable but become available within 30 seconds
- [ ] Agent shutdown completes within 5 seconds without event-loop warnings
- [ ] Redis operations survive a Redis restart without platform failure
- [ ] All new code has tests

*End of Design Document*
