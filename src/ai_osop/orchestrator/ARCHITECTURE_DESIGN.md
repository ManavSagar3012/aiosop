# AI-OSOP Sprint 9 — Architecture Excellence Design Document

**Version:** 1.0  
**Date:** 2025-01-18  
**Status:** Approved for implementation

---

## 1. Problem Statement

The codebase has accumulated significant architecture debt:

| File | Lines | Responsibility Overload |
|------|-------|------------------------|
| `orchestrator.py` | ~1,828 | Scheduling, approvals, phases, engagements, recovery, audit |
| `graph_memory.py` | ~1,077 | Reads, writes, queries, stats, pathfinding |
| `base.py` | ~681 | Agent lifecycle, execution, memory, observation |

Each file violates the Single Responsibility Principle. Future improvements have nowhere clean to live.

---

## 2. Extraction Strategy

**Rule: Do NOT rewrite everything. Extract, delegate, and preserve existing behavior.**

### 2.1 Orchestrator Decomposition

```text
Orchestrator (coordinator/facade)
  ├── TaskScheduler
  │     ├── schedule_task()
  │     ├── _assign_task()
  │     ├── _find_available_agent()
  │     ├── _execute_via_agent()
  │     ├── _maybe_retry()
  │     ├── _on_task_success()
  │     ├── _on_task_failure()
  │     ├── _trigger_downstream_tasks()
  │     ├── _chain_authenticated_surface()
  │     └── _persist_task_dependency()
  ├── ApprovalCoordinator
  │     ├── request_approval()
  │     ├── resolve_approval()
  │     ├── _register_approval()
  │     ├── _raise_approval()
  │     └── _strip_stale_approval()
  ├── PhaseMonitor
  │     ├── _phase_monitor()
  │     └── _auto_advance_phase()
  ├── EngagementManager
  │     ├── create_engagement()
  │     ├── halt_engagement()
  │     ├── _engagement_is_authenticated()
  │     ├── _pick_auth_user_label()
  │     └── claim_auto_discovery()
  └── RecoveryService
        └── (restart recovery, DLQ integration)
```

### 2.2 GraphMemory Decomposition

```text
GraphMemory (facade)
  ├── GraphQueryEngine
  │     ├── find_attack_paths()
  │     ├── get_attack_surface()
  │     └── get_graph_stats()
  ├── GraphWriteEngine
  │     ├── add_asset()
  │     ├── add_endpoint()
  │     ├── add_vulnerability()
  │     └── add_finding()
  └── TaskGraphPersistence
        ├── upsert_task()
        └── task_has_spawned()
```

---

## 3. Implementation Plan

### Phase 1: Extract TaskScheduler

Move all task scheduling, assignment, execution, retry, and lifecycle methods from Orchestrator into a dedicated `TaskScheduler` class.

The Orchestrator retains a `task_scheduler` attribute and delegates all task-related calls to it.

### Phase 2: Extract ApprovalCoordinator

Move all approval-related methods into `ApprovalCoordinator`.

The Orchestrator retains an `approval_coordinator` attribute.

### Phase 3: Extract PhaseMonitor

Move the phase monitor loop and auto-advance logic into `PhaseMonitor`.

### Phase 4: Extract EngagementManager

Move engagement lifecycle methods into `EngagementManager`.

### Phase 5: Extract GraphMemory Sub-components

Create `GraphQueryEngine`, `GraphWriteEngine`, and `TaskGraphPersistence` as internal components of GraphMemory.

---

## 4. Backward Compatibility

The Orchestrator class will maintain all existing public methods but delegate to the new components. No external callers need to change.

```python
class Orchestrator:
    def __init__(self, ...):
        self.task_scheduler = TaskScheduler(self)
        self.approval_coordinator = ApprovalCoordinator(self)
        self.phase_monitor = PhaseMonitor(self)
        self.engagement_manager = EngagementManager(self)
    
    async def schedule_task(self, task: Task) -> Task:
        return await self.task_scheduler.schedule_task(task)
```

---

## 5. Success Criteria

- [ ] `orchestrator.py` < 1,000 lines
- [ ] `graph_memory.py` < 800 lines
- [ ] All existing tests still pass
- [ ] No changes required to external callers
- [ ] New components have dedicated test files

*End of Design Document*
