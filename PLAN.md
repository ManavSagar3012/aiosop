# Goal
Move _busy_agents from in-memory set to Redis SET.

# Plan
1. Add `add_busy_agent`, `remove_busy_agent`, `is_busy_agent`, `get_all_busy_agents` to `SessionMemory` in `src/ai_osop/memory/session_memory.py`.
2. Update `TaskScheduler` to use `self._orch.session_memory` methods instead of `self._busy_agents`.
3. Remove `self._busy_agents` from `TaskScheduler` and `Orchestrator`.
4. Update tests.

# Status
- Researching: Done.
- Planning: Done.
- Implementation: Done.
- Verification: Done.
