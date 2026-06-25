# DEPENDENCY INVENTORY

## 1. Environment Variables & System Settings
- `OSOP_ENV`: Deployment environment (`development` / `production`).
- `OSOP_LOG_LEVEL`: Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `AUDIT`).
- `OSOP_API_TOKEN`: API bearer-token shared secret (Fallback auth: `dev-token`).
- `OSOP_JWT_SECRET`: JWT verification secret (Production auth).

## 2. Databases & Storage
- `OSOP_NEO4J_URI`: `bolt://localhost:7687` (Graph Database).
- `OSOP_NEO4J_USER`: `neo4j` (Default user).
- `OSOP_NEO4J_PASSWORD`: `password` / `change-me-local` (Neo4j password).
- `OSOP_POSTGRES_URI`: `postgresql+asyncpg://osop:osop@localhost:5432/osop` (Relational DB & Session Memory).
- `OSOP_REDIS_URI`: `redis://localhost:6379/0` (Hot-state Cache & Task Queue).

## 3. LLM Configuration
- `OSOP_LLM_PRIMARY`: LiteLLM model provider (e.g. `ollama`, `openai`).
- `OSOP_LLM_PRIMARY_MODEL`: `ollama/llama3` / `gpt-4o`.
- `OSOP_LLM_FALLBACK_MODEL`: fallback model configuration.
- `OSOP_MOCK_LLM`: `false` / `true` (Control mock generation).

## 4. MCP Servers
- `burp-mcp`: `localhost:8081` (Burp Suite Integration).
- `recon-mcp`: `localhost:8082` (Active Recon/Scanning).
- `payload-mcp`: `localhost:8083` (Payload Mutation).
- `nuclei-mcp`: `localhost:8084` (Vulnerability Scans).
- `shodan-mcp`: `localhost:8085` (OSINT Recon).
- `browser-mcp`: `localhost:8091` (Playwright Integration).
- `security-bridge`: `localhost:8087` (Docker Sandbox Control).
- `threat-intel-mcp`: `localhost:8086` (Threat Intelligence).
- `source-map-mcp`: `localhost:8096` (Source Map Audits).
- `cloud-mcp`: `localhost:8097` (Cloud Workloads).
- `turbo-intruder-mcp`: `localhost:8098` (High-speed Fuzzing).
- `session-memory-mcp`: `localhost:8090` (State Synchronization).
- `reporting-mcp`: `localhost:8092` (Report Generation).
- `attack-graph-mcp`: `localhost:8093` (Neo4j Modeling).
