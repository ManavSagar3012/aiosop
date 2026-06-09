# Copilot Instructions

## Build, test, lint
- `poetry install`
- `cp .env.example .env`
- `docker-compose up -d neo4j postgres redis`
- `poetry run uvicorn ai_osop.api.main:app --reload`
- `poetry run ai-osop --help`
- `poetry run pytest`
- `poetry run pytest tests/test_smoke.py::test_settings_load_mcp_defaults`
- `poetry run black src tests`
- `poetry run isort src tests`
- `poetry run mypy src`
- `docker build -t ai-osop:latest .`
- `npm --prefix ui run dev`
- `npm --prefix ui run build`
- `npm --prefix ui run preview`

## High-level architecture
- **API gateway** (`src/ai_osop/api/main.py`) bootstraps the system in FastAPI lifespan: it builds the Orchestrator with SessionMemory (Redis/Postgres), GraphMemory (Neo4j), MCPRegistry, and LiteLLM, then exposes engagement/task/agent/approval endpoints plus a WebSocket stream.
- **Orchestrator** (`orchestrator/orchestrator.py`) enforces engagement phase transitions, schedules tasks, assigns agents by `AgentType`, and coordinates approval requests; task queues live in Redis via `SessionMemory`.
- **Agent ecosystem** (`agents/`) extends `BaseAgent` to execute tasks; agents delegate tool work through MCP adapters (`adapters/`) and persist findings into GraphMemory or SessionMemory.
- **Memory layers** combine Redis hot state + Postgres audit/session data (`memory/session_memory.py`) with Neo4j attack-graph modeling (`memory/graph_memory.py`).
- **Payload pipeline** (`payload_engine/engine.py` + `adapters/payload_mcp.py`) handles template/LLM payload generation, encoding chains, and fitness evaluation.
- **Approval console UI** (`ui/`) is a Vite React app that calls `/approvals/*` and assumes API port 8080 and UI port 5173.

## Key conventions
- Cross-component data models live in `core/models.py` and use ID prefixes (`asset-`, `ep-`, `vuln-`, `task-`, `apr-`, etc.). Enums for `AgentType`, `VulnClass`, and `Severity` are in `core/config.py`.
- Engagement phase transitions must follow `Orchestrator.VALID_TRANSITIONS` and use the `EngagementPhase` enum.
- MCP server IDs are fixed strings (`burp-mcp`, `recon-mcp`, `payload-mcp`, `nuclei-mcp`, `shodan-mcp`) and are registered on startup; missing servers are skipped rather than crashing. Host/port values come from `OSOP_*` env vars in `.env.example`.
- Task queues are Redis sorted sets keyed as `queue:tasks:{engagement_id}` via `SessionMemory.push_task_queue`, using `Task.priority` (1-10) for ordering.
- UI config uses Vite env vars `VITE_API_BASE` and `VITE_OSOP_TOKEN`; the API CORS allowlist expects `http://localhost:5173`.
- Do not commit `.env` or any target/Burp/Shodan credentials; keep secrets in environment or vault-backed paths referenced by `core/config.py`.
