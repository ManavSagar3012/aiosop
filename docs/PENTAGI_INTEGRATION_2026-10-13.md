# PentAGI-inspired AI-OSOP integrated upgrade — 13 October 2026

Reference: https://github.com/vxcontrol/pentagi, especially
backend/docs/flow_execution.md and backend/docs/database.md.
The work adapts PentAGI's hierarchy, providers and audit patterns to AI-OSOP.
It is not a claim of complete PentAGI parity or production certification.

## Integrated features and location

| Feature | Files |
| --- | --- |
| Durable Flow / Task / Subtask / Action lineage | src/ai_osop/core/models.py, memory/session_memory.py |
| Versioned database migrations | migrations/versions/0003_execution_lineage.py; memory/schema_migrations.py |
| Operator flow API and scope-checked scheduling | api/routers/flows.py |
| Bounded adaptive planning and recovery | orchestrator/engagement_controller.py, orchestrator/orchestrator.py, recovery_service.py |
| True Temporal worker, scope and persisted approval gates | orchestrator/temporal_worker.py, task_scheduler.py, api/main.py |
| Automatic bounded context reuse | agents/base.py, agents/context_manager_agent.py |
| Sanitized MCP and LLM call evidence | core/call_provenance.py, mcp/protocol.py, core/llm_client.py |
| Real user interface | ui/src/pages/FlowOperations.tsx, ui/src/services/flows.ts |

## Running and operating

Install dependencies through Poetry and start PostgreSQL, Redis and Neo4j before
starting the API. SessionMemory.connect applies Alembic migrations before
database-backed actions; Alembic is included in Poetry dependencies.
An engagement must be explicitly scoped and include an authorization_ref before
subtask dispatch. This reference is metadata and its underlying authorization
must still be verified by the operator.

Open the React app's /flows page; create a Flow and objective, then add up to
15 dependent subtasks per objective. Dispatch is an explicit operator action;
the service verifies engagement ownership, time window, target and dependencies.
Consequential operations require approval through the existing request flow.
Progress and redacted action events are available from:

- GET /engagements/{engagement_id}/diagnostics
- GET /flows/{flow_id}/actions

To enable bounded follow-up planning after task completion, set ROE key
adaptive_planning_enabled to true and optionally adaptive_max_iterations
from 1 to 5. Recon proposed by the planner requires operator approval.

## Verification and limits

The targeted Python regression suite passed 110 tests in a combined run;
two legacy AsyncMock runtime warnings remain. New Flow UI strict TypeScript
checks and a temporary-directory Vite production build passed. Repository-wide
typechecking still reports previously existing errors outside the new modules.
PostgreSQL Alembic offline SQL successfully generated all revisions to 0003.
The Docker Desktop engine was unavailable locally; no live database, Temporal,
or on-target scan qualification is claimed.

PentAGI still offers deeper conversational assistant workers, persisted message
chains, templated flows, multi-provider search orchestration, and a more advanced
interactive refinement UX. Existing unresolved Git paths unrelated to this work
are deliberately preserved. Additional runtime evaluation should test migration
and restart behavior against a real multi-service deployment.
