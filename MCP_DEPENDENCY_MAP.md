# MCP DEPENDENCY MAP

## Dependency Graph
- **API Gateway (main.py)**
    - *Dependency*: `MCPRegistry`
    - *Dependency*: `Orchestrator`
    - *Lifecycle*: Registered MCPs -> Orchestrator -> API Ready

## Critical Dependencies
1. **browser-mcp**: Required for DOM capture, navigation, and screenshots.
2. **nuclei-mcp**: Required for vulnerability template execution.
3. **source-map-mcp**: Required for source map auditing.
4. **cloud-mcp**: Required for cloud workload scanning.
5. **turbo-intruder-mcp**: Required for high-speed fuzzing.

## Registration Sequence
- `lifespan` startup -> `register_optional_mcp_servers` -> `registry.register_server` -> `conn.connect` (HTTP Health Check) -> `initialize_server` (HTTP Initialize Call).
