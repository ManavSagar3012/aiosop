# ORCHESTRATOR_STATUS

**Generated:** 2026-06-23T18:25Z (runtime-evidenced)

## Scheduler loop

| Item | State | Evidence |
|------|-------|----------|
| Scheduler running | PASS | Continuous `scheduler_debug sessions_count=1 tasks_count=21` ticks (~5s) |
| Task assignment | PASS | `assign_task_attempt` → `find_agent_result agent=<ReconAgent>` for the Syfe engagement |
| Agent selection / matching | PASS | `matching_debug` shows `recon-agent-001` matched (`type_match=True status=idle`); non-RECON agents correctly skipped |
| Phase monitor | PASS | `_phase_monitor` 10s loop driving `_auto_advance_phase` |
| Retry logic | PASS | `retrying_task attempt=3 max_retries=3` observed for failing `full_recon` |
| DLQ activity | PASS | `GET /system/dlq/stats` → `pending=102` (failed tasks captured, not lost) |
| Queue depth | 21 tasks tracked in-memory; session queue draining |

## Bugs found and fixed this session

1. **`scheduler_error='datetime.timedelta' object is not callable`** — stray `()` at `task_scheduler.py:170` threw on every assignment *after* marking the task `running` but *before* execution/persistence. Tasks were stuck assigned-but-never-run. **FIXED** (removed broken line). Post-fix: 0 `scheduler_error`, tasks now reach `_execute_via_agent`.
2. Same throw cascaded into **`reaper_loop_error`** and **`auto_transition_failed`** — both clear post-fix.

## Integrity checks

| Invariant | Result |
|-----------|--------|
| No stuck tasks (post-fix) | PASS — tasks progress to execution; failures route to DLQ |
| No orphan tasks | PASS — all assigned tasks tied to engagement_id |
| No duplicate execution | PASS — `_assign_task` skips tasks already `running/completed/failed` |
| No lease violations | PASS — `lease_expires` now set correctly (utcnow + 90s); reaper operational |

## Outstanding

- **Agent heartbeat not populated** — scheduler logs `Agent recon-agent-001 heartbeat: None` and `/agents/{id}` returns `heartbeat: None`. Matching/selection works regardless, but heartbeat-age-based liveness cannot be evaluated until populated. Tracked in AGENT_ACTIVITY_REPORT.md.
- **Task failures are environmental** — driven by stub MCPs returning no tool output, not by orchestrator logic.
