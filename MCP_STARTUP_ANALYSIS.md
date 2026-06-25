# MCP STARTUP ANALYSIS

## Diagnosis
The `browser-mcp` is failing because of **(A) Startup race condition**.

### Evidence
- **Logs**: `ConnectionRefusedError: [WinError 1225] The remote computer refused the network connection` during `mcp_registry.register_server`.
- **Startup Sequence**: The API initiates connections to all critical MCP servers concurrently or sequentially at the very start of the `lifespan` event.
- **Timing**: The MCP Python stubs (using Uvicorn) take several hundred milliseconds to bind their ports and reach a `ready` state, but the API attempts connection immediately upon its own startup.

### Conclusion
The orchestrator attempts to connect to MCP services before they are ready to accept TCP connections. There is zero retry or backoff logic in `MCPConnection.connect()`.
