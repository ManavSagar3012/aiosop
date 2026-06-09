# Go MCP Servers

This directory contains a minimal Go MCP HTTP SDK and starter servers for Nuclei and Shodan.

Run from this directory after installing Go:

```bash
go run ./cmd/nuclei-mcp
go run ./cmd/shodan-mcp
```

The Python API reads these defaults from `.env`:

- `OSOP_NUCLEI_MCP_HOST=localhost`, `OSOP_NUCLEI_MCP_PORT=8084`
- `OSOP_SHODAN_MCP_HOST=localhost`, `OSOP_SHODAN_MCP_PORT=8085`
