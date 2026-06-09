# AI-OSOP: AI Offensive Security Orchestration Platform

AI-OSOP is a production-grade AI-assisted penetration testing ecosystem. It acts as a cognitive offensive security operating system by utilizing multi-agent orchestration, persistent memory, and adaptive payload intelligence to automate and enhance security engagements.

## Architecture

The system is structured into several functional layers:
- **Human Operator Layer**: CLI and reporting interface.
- **Orchestration Layer**: Centralized orchestration and agent coordination bus.
- **Reasoning & Memory Layer**: LLM integration, Vector Memory, Graph Memory, and Session state.
- **Agent Ecosystem**: Specialized agents for Recon, Vulnerability Analysis, Payload generation, Exploitation, Attack chaining, and Human oversight.
- **MCP Integration Layer**: Model Context Protocol servers for Burp Suite, Recon tools, Threat Intel, and Attack Graph data.
- **Execution Sandbox**: Isolated environments using Docker/Kubernetes for safe task execution.

## Key Technologies

- **Language**: Python 3.11+
- **API Framework**: FastAPI
- **Storage/Database**: Neo4j (Graph), PostgreSQL (Relational), Redis (Caching)
- **AI/Orchestration**: LangChain, LangGraph, LiteLLM
- **Packaging/Dependency Management**: Poetry
- **Infrastructure**: Docker, Kubernetes

## Development & Operations

### Build and Run

1.  **Install Dependencies**:
    ```bash
    poetry install
    ```
2.  **Start Infrastructure**:
    ```bash
    docker-compose up -d neo4j postgres redis
    ```
3.  **Run Migrations**:
    ```bash
    poetry run alembic upgrade head
    ```
4.  **Start API Server**:
    ```bash
    poetry run uvicorn ai_osop.api.main:app --reload
    ```

### Testing and Linting

- **Run Tests**:
  ```bash
  poetry run pytest
  ```
- **Formatting and Linting**:
  ```bash
  poetry run black src/
  poetry run isort src/
  poetry run mypy src/
  ```

## Development Conventions

- **Style**: Adhere to PEP 8, enforced by `black`.
- **Imports**: Sorted using `isort`.
- **Typing**: Mandatory type annotations, enforced by `mypy`.
- **Testing**: Use `pytest` with `pytest-asyncio` for async code.
- **Commits**: Follow standard commit message practices.
