# AI-OSOP Patch Summary — Post-Audit Fixes

**Patch Date:** Current session  
**Files Modified:** 9  
**Lines Changed:** +368 / -155  
**Risk After Patch:** All P0 findings addressed; remaining risk is P1/P2 backlog.

---

## Quick Reference Table

| Finding | Severity | File | Lines | What Changed |
|---------|----------|------|-------|--------------|
| P0-008 | P0 | `src/ai_osop/mcp/protocol.py` | 303, 245-265 | `close()` now resets `_initialized`; `execute()` guards against `None` session |
| P0-007 | P0 | `src/ai_osop/mcp/protocol.py` | 157-174 | `_record_failure()` now caps half-open attempts at `CIRCUIT_HALF_OPEN_MAX_ATTEMPTS`; permanent failure state added |
| P0-009 | P0 | `src/ai_osop/orchestrator/task_scheduler.py` | 192-250 | Agent lock leak plugged with `try/except/finally` around persistence + task creation |
| P0-005 | P0 | `src/ai_osop/orchestrator/task_scheduler.py` | 170-190 | Exploit tasks now **fail closed** when scope is unsigned or missing |
| P0-006 | P0 | `src/ai_osop/agents/recon_agent.py` | 145, 250 | Asset IDs now include `engagement_id` to prevent cross-engagement collision |
| P0-006 | P0 | `src/ai_osop/agents/vuln_agent.py` | 133, 147 | Asset + endpoint IDs now include `engagement_id` |
| P0-004 | P0 | `src/ai_osop/agents/exploit_agent.py` | 97-147 | Replaced hardcoded mock with real `SandboxManager` execution; mock mode raises `ApprovalDeniedError` |
| P0-001 | P0 | `src/ai_osop/core/engagement_state_machine.py` | — | **Deleted** (dead stub; real state machine lives in `orchestrator/state_machine.py`) |
| P0-002 | P2 | `src/ai_osop/orchestrator/orchestrator.py` | 153-159 | Duplicate state-machine injection was already absent in working tree |
| P1-014 | P1 | `src/ai_osop/agents/base.py` | 242 | `task.timeout_seconds` already preferred over payload default (no code change needed) |
| P1-010 | P1 | `src/ai_osop/orchestrator/approval_coordinator.py` | 110-129 | `_wait_for_approval` default `max_wait_seconds` changed from `300` to `None`; outer `asyncio.wait_for` now controls timeout |
| P1-019 | P1 | `ui/src/services/api.ts` | 13 | Removed `"dev-token"` fallback; build now throws if `VITE_OSOP_TOKEN` is missing |
| P1-011 | P1 | `src/ai_osop/adapters/burp_mcp.py` | 88-108 | `get_scan_issues` now raises on failure instead of returning `[]` |
| P1-012 | P1 | `src/ai_osop/adapters/burp_mcp.py` | 31-169 | Added `_check_response()` helper; all raw-return methods now validate status |
| P1-018 | P1 | `src/ai_osop/memory/session_memory.py` | 457-514 | HMAC now covers full `action` + `result` JSON; read+write wrapped in single transaction |

---

## Detailed Patch Notes

### 1. MCP Circuit Breaker & Session Safety (`mcp/protocol.py`)

**P0-007: Infinite half-open loop**
- `CIRCUIT_HALF_OPEN_MAX_ATTEMPTS` (defined as `3`) is now actually enforced.
- After 3 failed half-open probes, the circuit enters a **permanent failure** state (`_circuit_opened_at = None`), which disables automatic recovery via `_circuit_breaker_check()`.
- A structured log event `mcp_circuit_permanent_failure` is emitted.

**P0-008: `execute()` crash on `None` session**
- `close()` now sets `self._initialized = False` after closing the session.
- `execute()` adds an explicit guard: `if self._session is None: raise MCPConnectionError(...)`.
- This prevents `AttributeError` during shutdown races.

### 2. Task Scheduler Reliability (`orchestrator/task_scheduler.py`)

**P0-009: Agent lock leak**
- `_assign_task` now wraps the persistence phase (`graph_memory.upsert_task`, `session_memory.store_task`, `coordination_bus.publish`) in a `try/except/finally` block.
- A boolean `started_execution` tracks whether `_execute_via_agent` was actually launched.
- If an exception occurs before the task is started, the `finally` block calls `_release_agent()` to free the Redis lock.

**P0-005: Unsigned scope bypass**
- The scope signature check for exploit-class tasks now has an `else` branch: if the scope has **no signature** or is **unavailable**, the task is immediately rejected with `error_type: "ScopeTamper"`.
- Legacy unsigned scopes are no longer grandfathered in.

### 3. Cross-Engagement Data Integrity (`agents/recon_agent.py`, `agents/vuln_agent.py`)

**P0-006: Asset/endpoint ID collision**
- All deterministic asset IDs changed from `f"asset-{domain}"` to `f"asset-{engagement_id}-{domain}"`.
- Endpoint IDs changed from `f"endpoint-{domain}"` to `f"endpoint-{engagement_id}-{domain}"`.
- This prevents Neo4j `MERGE` from overwriting nodes across engagements.

### 4. Exploit Validation Sandbox (`agents/exploit_agent.py`)

**P0-004: Mocked execution replaced**
- The hardcoded `execution_result = {"success": True, ...}` block is removed.
- New `_execute_in_sandbox()` method:
  1. Creates a `SandboxManager` instance with a unique sandbox ID.
  2. Builds a safe `curl` command inside the sandbox to send the payload to the target.
  3. Executes via `sandbox_mgr.execute_in_sandbox()` with configurable timeout.
  4. Destroys the sandbox in a `finally` block.
- **Mock mode is now gated:** if `settings.sandbox_runtime == "mock"`, `ApprovalDeniedError` is raised with a clear message telling operators to configure a real Docker runtime.

### 5. Approval Timeout Dead Code (`orchestrator/approval_coordinator.py`)

**P1-010: Inner timeout conflict**
- `_wait_for_approval` signature changed: `max_wait_seconds: int = 300` → `max_wait_seconds: Optional[int] = None`.
- The inner loop now only returns early if `max_wait_seconds` is explicitly passed.
- The outer `asyncio.wait_for(timeout=settings.approval_timeout_seconds)` becomes the sole timeout authority, restoring the documented 1800-second approval window.

### 6. Burp Adapter Error Handling (`adapters/burp_mcp.py`)

**P1-011 / P1-012: Silent failures**
- Added `_check_response(response, operation)` helper that raises typed exceptions:
  - `MCPTimeoutError` for `status == "timeout"`
  - `MCPException` for `status == "circuit_open"` or any other failure
- `get_scan_issues()` now calls `_check_response` on non-success, so callers can distinguish "no issues" from "scan failed".
- `scan_target`, `send_to_repeater`, `intruder_attack`, `extension_call` all check response status before returning.

### 7. Audit HMAC Integrity (`memory/session_memory.py`)

**P1-018: Weak HMAC + chain race**
- HMAC payload now includes the full canonical JSON of `action` and `result` (sorted keys, `default=str` for datetime safety).
- The read-last-hash + insert-new-event sequence is now wrapped in a single `session.begin()` transaction, eliminating the race window where two concurrent events could read the same `last_hash`.

### 8. Frontend Security (`ui/src/services/api.ts`)

**P1-019: Hardcoded dev-token**
- Removed `|| "dev-token"` fallback.
- The build will now throw at runtime if `VITE_OSOP_TOKEN` is not set, preventing accidental deployment of a known credential.

### 9. Dead Code Removal (`core/engagement_state_machine.py`)

**P0-001: Stub deletion**
- The 18-line no-op stub was removed from the repository.
- The real `EngagementStateMachine` implementation lives in `src/ai_osop/orchestrator/state_machine.py` and was already imported there.

---

## Remaining Unfixed Findings (Backlog)

These were identified in the audit but not patched in this session due to scope/complexity:

| Finding | Severity | Why Deferred |
|---------|----------|--------------|
| P1-016: MCP startup health check bypass | P1 | Requires adding `critical_mcps` config + readiness probe logic; architectural decision needed on whether MCP should be critical |
| P1-022: `_execute_task_durable` catches `Exception` | P1 | Requires careful design of which exceptions to propagate vs. swallow; needs runtime testing |
| P1-024: `halt_engagement` doesn't release agent locks | P1 | Needs `_release_agent` call in halt path; touches agent lifecycle state machine |
| P1-017: GraphMemory MERGE not engagement-scoped | P1 | Requires Neo4j schema migration (composite constraints) and potentially all MERGE queries rewritten |
| P1-020: K8s secrets hardcoded | P1 | Requires operational process change (Vault/ESO integration), not a code patch |
| P1-021: Sandbox DaemonSet `SYS_ADMIN` | P1 | Requires K8s manifest change + runtime verification |
| P2-025: Adapter incomplete exports | P2 | Documentation-only; no runtime impact |
| P2-026: Widespread `Any` types | P2 | Large refactor; requires Protocol/typing overhaul |
| P2-027: `is_simulated()` string evasion | P2 | Requires schema change (add boolean `is_simulated` field) |
| P2-028: RetentionService has no tests | P2 | Test-only; no production code change |

---

## Verification Checklist

Before deploying these patches to production:

- [ ] **Unit tests:** Run `poetry run pytest` and confirm no regressions.
- [ ] **Sandbox test:** Create an engagement, trigger an exploit validation task, and verify that `SandboxManager.create_sandbox` and `execute_in_sandbox` are called with real Docker containers.
- [ ] **Circuit breaker test:** Simulate an MCP server failure. Verify the circuit opens, half-opens 3 times, then enters permanent failure.
- [ ] **Cross-engagement test:** Create two engagements with the same domain. Verify Neo4j contains two distinct `Asset` nodes.
- [ ] **Approval timeout test:** Set `approval_timeout_seconds = 10`, do NOT approve, and assert the task fails with `status = "timeout"` (not `"pending"`).
- [ ] **Burp error test:** Mock `execute_tool` to return `status="circuit_open"`. Assert `get_scan_issues()` raises `MCPException`.
- [ ] **Audit HMAC test:** Write an audit event, modify the `action` JSON in Postgres directly, and verify a hash verification script flags the tampered row.
- [ ] **UI build test:** Build the UI without `VITE_OSOP_TOKEN` and assert the build fails with a clear error message.
- [ ] **Lint/format:** Run `poetry run black src tests` and `poetry run isort src tests`.
- [ ] **Type check:** Run `poetry run mypy src` and resolve any new type errors introduced by the changes.

---

*End of Patch Summary*
