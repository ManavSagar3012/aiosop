# Revised Improvement Plan for AI-OSOP (P2 Issues)

## Objective
Address the P2 gaps. Temporal is being implemented, but Tetragon/eBPF implementation needs a pivot due to dependency issues.

## P2 Improvements Revised Breakdown

### 1. Implement Temporal Workflow Integration (ISSUE-005)
- **Status**: Ready to implement. `temporalio` SDK is installed.
- **Steps**:
    - Define `TaskWorkflow` and `TaskActivity` in `src/ai_osop/orchestrator/temporal_worker.py`.
    - Refactor `Orchestrator.schedule_task` to initiate Temporal workflows.

### 2. Research Alternative eBPF Filtering (ISSUE-004)
- **Status**: Blocked. `tetragon` is not a Python package.
- **Steps**:
    - Research if `cilium/tetragon` provides a CLI or REST API that can be interfaced instead of a Python library.
    - If no suitable interface exists, research alternative eBPF libraries for Python (e.g., `bcc`, `libbpf-python`) to implement similar network filtering policies.

## Next Steps
- Implement Temporal workflows.
- Investigate `libbpf` or alternative interfaces for eBPF networking.
