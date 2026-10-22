# AI-OSOP / PentAGI capability comparison (2026-10-13)

This is an implementation audit, not a claim of feature parity. PentAGI reference:
https://github.com/vxcontrol/pentagi. All AI-OSOP assertions below were
checked against the local source tree. Dynamic and deployed behavior still
requires a separate runtime evaluation.

## Implemented in AI-OSOP already

- Multi-agent task scheduling: `src/ai_osop/orchestrator/orchestrator.py`
- Session checkpoints and durable task state: `src/ai_osop/memory/session_memory.py`
- Restart and stalled-task recovery: `src/ai_osop/orchestrator/recovery_service.py`
- Vector and graph memory: `src/ai_osop/memory/`
- Operator approvals, scope gates, MCP integrations and audit records
- Context-summary agent: `src/ai_osop/agents/context_manager_agent.py`
- Tracing and metrics: `src/ai_osop/core/observability.py`

## Findings and implementation priorities

| Priority | Capability | Observed gap / next engineering step |
| --- | --- | --- |
| P0 | Strategic dynamic planning | `engagement_controller.py` contains a syntax error near line 41 and the controller has no observed production caller. Resolve the existing merge/conflict state and integrate the controller with phase scheduling after review. |
| P0 | Reliable Temporal execution | The default worker previously registered an activity that returned a success-shaped queued response without running the task. **Corrected:** the worker now refuses unbound activity registration. The service bootstrap must explicitly pass an orchestrator-backed activity. |
| P1 | Durable hierarchy | `Task` has dependencies, but no native persistent Flow > Task > Subtask > Action model with parent references and per-step tool provenance. Design migrations, ownership, transaction and recovery behavior before rolling out. |
| P1 | Automatic refinement | A subtask-specific Generator/Refiner feedback cycle is not wired into normal orchestration. Add bounded iterations, evidence scoring and human gates. |
| P1 | Context manager integration | `ContextManagerAgent` exists but its summarization task names have no observed production scheduling. Invoke at defined checkpoints and before context limits, preserving provenance. |
| P1 | Engagement diagnostics | Added authenticated `/engagements/{engagement_id}/diagnostics` with live stalled/retry summary and redacted durable audit timeline. Its live task view may be incomplete following a restart. |
| P1 | Sandbox health reporting | Corrected fixed fake metrics in `/system/sandbox/status` to explicit unknowns until live telemetry is connected. Next step: bind to runtime verification and preserve freshness timestamps. |

## Verification

Targeted diagnostics, Temporal and sandbox tests: `12 passed` on this
development workstation. Tests do not establish end-to-end scan efficacy,
target coverage, sandbox isolation or PentAGI parity.

## Source control note

Existing uncommitted changes were present before this audit, including
`engagement_controller.py` and the main orchestrator. Do not overwrite those
changes during subsequent planner and recovery integration.
