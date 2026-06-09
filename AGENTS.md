# Repository Guidelines

## Project Structure & Module Organization

This is a Python 3.11 Poetry project using a `src` layout. Application code lives under `src/ai_osop/`: `api/` exposes FastAPI routes, `agents/` holds agent logic, `orchestrator/` coordinates tasks, `adapters/` integrates MCP services, `memory/` stores state, `payload_engine/` handles payload generation, and `safety/` enforces scope. Tests belong in `tests/`. Deployment assets are in `Dockerfile`, `docker-compose.yml`, and `k8s/`.

## Build, Test, and Development Commands

- `poetry install`: install runtime and development dependencies.
- `cp .env.example .env`: create local configuration, then edit values for your environment.
- `docker-compose up -d neo4j postgres redis`: start local infrastructure services.
- `poetry run uvicorn ai_osop.api.main:app --reload`: run the API locally.
- `poetry run ai-osop --help`: inspect the CLI.
- `poetry run pytest`: run tests with coverage for `src/ai_osop`.
- `docker build -t ai-osop:latest .`: build the container image.

## Coding Style & Naming Conventions

Use Black and isort with the settings in `pyproject.toml`: 100-character lines, Python 3.11 target, and Black-compatible imports. Run `poetry run black src tests` and `poetry run isort src tests` before submitting changes. Use type hints for new functions; mypy has `disallow_untyped_defs = true`. Prefer `snake_case` for modules, functions, variables, and tests; use `PascalCase` for classes and enums.

## Testing Guidelines

Pytest is the test runner, with `pytest-asyncio` in auto mode and coverage from `pytest-cov`. Add tests under `tests/` using names like `test_scope.py` or `test_orchestrator.py`. Focus on public behavior, safety boundaries, and async workflows. Run `poetry run pytest` before opening a PR.

## Commit & Pull Request Guidelines

This workspace has no Git history, so no project-specific pattern can be inferred. Use concise, imperative commit messages such as `Add scope validation tests` or `Fix task scheduling timeout`. PRs should include a summary, test results, configuration notes, and screenshots or API examples when behavior changes. Link related issues when available.

## Security & Configuration Tips

Never commit `.env`, API keys, Burp credentials, or target engagement data. Keep offensive-security behavior behind scope enforcement and approval gates. Use `.env.example` for documented settings and prefer safe defaults for local development.

## Current Integration Priorities

After setup, connect Burp MCP by setting `OSOP_BURP_MCP_HOST` to the Burp extension host. Next priorities are adding MCP servers for tools such as Nuclei and Shodan, wiring LiteLLM into the reasoning layer, and building a React or Vue approval console on top of the existing API.
