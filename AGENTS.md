# Repository Guidelines

## Project Structure & Module Organization

This is a Python 3.11 Poetry project using a `src` layout. Application code lives under `src/ai_osop/`:
- `api/` — FastAPI routes + lifespan bootstrap (`main.py`, `routers/`)
- `agents/` — Agent ecosystem extending `BaseAgent` (recon, vuln, payload, exploit, etc.)
- `orchestrator/` — Central orchestrator, task scheduling, approval coordination
- `adapters/` — MCP server integrations (burp, recon, nuclei, shodan, browser, cloud, etc.)
- `mcp/` — MCP protocol layer (client, server abstractions)
- `memory/` — Redis hot state (`session_memory`), Postgres audit, Neo4j graph (`graph_memory`)
- `payload_engine/` — Template/LLM payload generation, encoding chains, fitness evaluation
- `safety/` — Scope enforcement, sandbox management, approval gates, audit integrity, eBPF filtering
- `core/` — Shared models (`models.py`), config (`config.py`), exceptions (`exceptions.py`), LLM client, etc.
- `reporting/` — Report generation
- `auth/` — Authentication (JWT + API token)

Tests live in `tests/` (35+ test files). Deployment: `Dockerfile`, `docker-compose.yml`, `k8s/`. UI: `ui/` (Vite React app).

## High-Level Architecture

- **API gateway** (`api/main.py`) bootstraps the system in FastAPI lifespan: builds the Orchestrator with SessionMemory (Redis/Postgres), GraphMemory (Neo4j), MCPRegistry, and LiteLLM, then exposes engagement/task/agent/approval endpoints plus a WebSocket stream.
- **Orchestrator** (`orchestrator/orchestrator.py`) enforces engagement phase transitions, schedules tasks, assigns agents by `AgentType`, and coordinates approval requests; task queues live in Redis via `SessionMemory`.
- **Agent ecosystem** (`agents/`) extends `BaseAgent` to execute tasks; agents delegate tool work through MCP adapters (`adapters/`) and persist findings into GraphMemory or SessionMemory.
- **Memory layers** combine Redis hot state + Postgres audit/session data (`memory/session_memory.py`) with Neo4j attack-graph modeling (`memory/graph_memory.py`).
- **Payload pipeline** (`payload_engine/engine.py` + `adapters/payload_mcp.py`) handles template/LLM payload generation, encoding chains, and fitness evaluation.
- **Approval console UI** (`ui/`) is a Vite React app that calls `/approvals/*` and assumes API port 8200 and UI port 5173.

## Key Dependencies

| Layer | Packages |
|-------|----------|
| API | `fastapi`, `uvicorn`, `pydantic`, `pydantic-settings` |
| AI/LLM | `litellm`, `langgraph`, `langchain`, `langchain-openai`, `jinja2` |
| Storage | `neo4j`, `redis`, `sqlalchemy[asyncio]`, `asyncpg` |
| Auth | `python-jose[cryptography]`, `passlib[bcrypt]` |
| Observability | `structlog`, `prometheus-client`, `opentelemetry-*` |
| Infra | `docker`, `httpx`, `aiohttp`, `websockets` |

## Commands

### Build / Install
- `poetry install` — install runtime + dev dependencies
- `docker build -t ai-osop:latest .` — build container image

### Configuration
- `cp .env.example .env` — create local config from template (edit values after)

### Infrastructure
- `docker-compose up -d neo4j postgres redis` — start local backing services (Neo4j on 7474/7687, Postgres on 5432, Redis on 6379)

### Run
- `poetry run uvicorn ai_osop.api.main:app --reload --port 8200` — run API locally (hot-reload, port 8200)
- `poetry run ai-osop --help` — inspect the CLI interface (entry: `ai_osop.cli:main`)
- `npm --prefix ui run dev` — start React approval console (port 5173)
- `npm --prefix ui run build` — build UI for production
- `npm --prefix ui run preview` — preview production UI build locally

### Lint & Format
- `poetry run black src tests` — auto-format (line-length 100, py311 target)
- `poetry run isort src tests` — sort imports (black profile, 100 char lines)
- `poetry run mypy src` — static type checking (flags: `warn_return_any`, `warn_unused_configs`, `disallow_untyped_defs`)
- `poetry run flake8 src` — linting

### Test
- `poetry run pytest` — run all tests (src auto-added to `pythonpath`, default `--cov` with `term-missing`)
- `poetry run pytest tests/test_smoke.py` — run a single test file
- `poetry run pytest tests/test_smoke.py::test_settings_load_mcp_defaults -vv` — run a single test function
- `poetry run pytest tests/test_scope.py -k "test_scope_enforcer" -vv` — run tests matching a keyword
- `poetry run pytest --co --durations=5` — show 5 slowest tests
- `poetry run pytest --no-cov` — run without coverage (faster iteration)

### Pre-commit
Before opening a PR, run: `poetry run black src tests && poetry run isort src tests && poetry run mypy src && poetry run pytest`

## Coding Style

### Formatting & Imports
- **Black** with `line-length = 100`, `target-version = py311`
- **isort** with `profile = "black"`, `line_length = 100`
- Group imports: stdlib → third-party → local. Use absolute imports.
- Example:
  ```python
  import hashlib
  from datetime import datetime
  from typing import Any, Dict, Optional

  import httpx
  import pytest
  from pydantic import BaseModel, Field

  from ai_osop.core.config import settings
  from ai_osop.core.exceptions import OutOfScopeError
  ```

### Type Hints
- All function signatures **must** have type annotations (`disallow_untyped_defs = true`)
- Use `Optional[X]` for nullable fields, not `X | None`
- Prefer `list[str]` over `List[str]` for function args (Python 3.11+), but `List[str]` is still used in pydantic `Field(default_factory=list)`
- Use `from __future__ import annotations` in class definitions that need deferred evaluation
- `warn_return_any = true` is enabled — avoid returning `Any` without explicit annotation

### Naming Conventions
- `snake_case` for modules, functions, variables, test names
- `PascalCase` for classes and enums
- `UPPER_CASE` for constants
- ID prefixes for models: `asset-`, `ep-`, `vuln-`, `task-`, `apr-`, `payload-`
- Test files: `test_<unit>.py`, test functions: `def test_<behavior>():`

### Error Handling
- Custom exception hierarchy rooted in `OSOException` (see `core/exceptions.py`):
  ```
  OSOException → MCPException(MCPConnectionError, MCPTimeoutError)
              → ScopeException(OutOfScopeError, ScopeValidationError)
              → AgentException(AgentTaskFailed, AgentHallucinationDetected)
              → SafetyException(ApprovalDeniedError, SandboxEscapeDetected)
              → MemoryException(GraphQueryError)
              → WorkflowException(WorkflowTransitionError)
  ```
- All custom exceptions accept `(message: str, details: dict = None)`
- `pytest.raises(ExpectedException)` for testing error paths
- Avoid bare `except:` — catch specific exception types

### Enums & Config
- Enums inherit from `str, Enum` for JSON serialization
- Settings use `pydantic_settings.BaseSettings` with `SettingsConfigDict(env_file=".env")`
- Environment variable aliases use `validation_alias="OSOP_UPPER_CASE"` pattern
- `AgentType`, `VulnClass`, `Severity`, `LogLevel` enums live in `core/config.py`

### Pydantic Models
- All cross-component models in `core/models.py` use `pydantic.BaseModel`
- Use `Field(default_factory=...)` for mutable defaults (lists, dicts)
- Use `Field(ge=..., le=...)` for numeric constraints
- Use `validator` decorators for cross-field validation
- `datetime.utcnow` is the standard for timestamps

### Async Patterns
- Use `async def` and `await` for I/O (HTTP calls, DB queries, MCP calls)
- Async test functions use the built-in `asyncio_mode = "auto"` (no `@pytest.mark.asyncio` needed)
- Mock async dependencies with `AsyncMock` and `patch`
- Task queues are Redis sorted sets (`queue:tasks:{engagement_id}`) with priority 1-10

### Engagement Phases & MCP
- Phase transitions must follow `Orchestrator.VALID_TRANSITIONS` using `EngagementPhase` enum
- MCP server IDs are fixed strings (`burp-mcp`, `recon-mcp`, `payload-mcp`, `nuclei-mcp`, `shodan-mcp`)
- MCP servers are registered on startup; missing servers are skipped gracefully (not crashed)

### Docstrings
- Module-level docstring: `"""Brief description."""`
- Class docstring: `"""Purpose. Optional details."""`
- Method docstrings: short description, `Raises:` section if applicable (see `safety/scope.py`)

### Security
- Never commit `.env`, API keys, Burp credentials, or target data
- Keep offensive behavior behind scope enforcement (`ScopeEnforcer`) and approval gates (`ApprovalGate`)
- Sandbox all agent tool execution via `SandboxManager`
- Bug-bounty platform sync defaults to `SIMULATION=true` (set `OSOP_BUG_BOUNTY_SIMULATION=false` for live)
- JWT auth (HS256) with fallback to API token shared-secret

### Testing Guidelines
- Write tests in `tests/`, mirroring source structure
- Focus on public behavior, safety boundaries, async workflows
- Use fixtures for shared setup (`@pytest.fixture`)
- Mock external services (MCP servers, Docker, network calls) with `AsyncMock` / `MagicMock`
- Use `pytest.raises` for expected exceptions
- Coverage defaults to `--cov=src/ai_osop --cov-report=term-missing` via pyproject.toml `addopts`

### UI & CORS Configuration
- UI uses Vite env vars `VITE_API_BASE` (default: `http://localhost:8200`) and `VITE_OSOP_TOKEN`
- API CORS allowlist expects `http://localhost:5173` (Vite dev server)
- UI approval console calls `/approvals/*` endpoints

### Logging
- Use `structlog` throughout (configured in settings)
- Log levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `AUDIT` (custom level)
- Structured logging: pass key-value pairs, not f-strings
