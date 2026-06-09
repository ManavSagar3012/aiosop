# Improvement Plan for AI-OSOP (P2 Issues)

## Objective
Address the P2 gaps identified in `3-INSPECTION_REPORT.md` to enhance the system's security isolation (eBPF) and workflow durability (Temporal).

## P2 Improvements Breakdown

### 1. Implement eBPF Network Filtering (ISSUE-004)
- **Component**: `safety/ebpf_filter.py`
- **Steps**:
    - Research Cilium Tetragon for runtime security.
    - Define TracingPolicies to restrict network access for the sandbox environment.
    - Implement a mechanism to load/unload these policies when a task starts/ends.

### 2. Implement Temporal Workflow Integration (ISSUE-005)
- **Component**: `orchestrator/temporal_worker.py`
- **Steps**:
    - Research Temporal.io Python SDK.
    - Define workflow and activity interfaces for task execution.
    - Refactor `orchestrator/orchestrator.py` to offload durable task execution to Temporal workflows.

## Verification & Testing
- Validate eBPF policy enforcement by attempting forbidden network connections.
- Verify Temporal workflow durability by restarting the platform during task execution.
