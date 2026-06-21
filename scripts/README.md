# AI-OSOP Scripts

This directory contains operational, debug, and qualification scripts that were previously scattered across the repository root.

## Directory Structure

| Directory | Purpose | Examples |
|-----------|---------|----------|
| `ops/` | Production operations: audits, scans, seeds, validators | `run_audit.py`, `seed_vuln.py`, `agent_validator.py` |
| `debug/` | Debugging & diagnostics: health checks, probes, tracing | `check_graph.py`, `probe_neo4j.py`, `trace_single_task.py` |
| `qualification/` | Mission qualification & certification tests | `mission_simulator.py`, `validate_field_readiness.py` |

## Port Conventions

All scripts targeting the AI-OSOP API should use **port 8200** (the FastAPI default). Scripts using port 8088 have been updated or removed.

## Usage

Most scripts should be run via the CLI in the future:

```bash
ai-osop audit run          # was: python run_audit.py
ai-osop debug graph        # was: python check_graph.py
ai-osop seed vulns         # was: python seed_vuln.py
```

Until then, run directly from the project root:

```bash
python scripts/ops/run_audit.py
python scripts/debug/check_graph.py
```

## Moving Scripts Here

When adding new scripts:
1. Place in the appropriate subdirectory
2. Add a docstring explaining purpose and usage
3. Prefer adding to `src/ai_osop/cli.py` for frequently-used operations
4. **Remove one-off debug scripts** after use instead of committing them

## Cleanup History

- **2025-06**: Removed 15+ dead scripts (hardcoded task IDs, old ports, one-off tests, "syfe" specific scripts)
- **2025-06**: Moved 9 experimental agents to `src/ai_osop/agents/experimental/`
