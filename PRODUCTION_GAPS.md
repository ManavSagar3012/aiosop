# PRODUCTION GAPS

## 1. Secrets & Credentials
- **No Production Secrets**: `.env` and configuration setting defaults use placeholder development credentials (`password`, `change-me-local`).
- **Encryption Key**: `OSOP_SESSION_ENCRYPTION_KEY` must be generated and set to enable encrypted credential storage in Postgres.
- **JWT Auth**: `OSOP_JWT_SECRET` must be set in production to disable the fallback `dev-token` authentication.

## 2. Infrastructure Gaps
- **Go Binaries**: Compiled Go binaries (`nuclei-mcp.exe`, `payload-mcp.exe`, etc.) are compiled for `windows/amd64`. Production deployment in Linux containers requires compiling these binaries for `linux/amd64`.
- **Kubernetes Networking**: `NetworkPolicy` rules must be updated to route traffic from the API container to the database hostnames instead of `localhost`.
- **Ollama**: Production models (e.g. `llama3`) must be pre-loaded into the Ollama service to avoid latency spikes during initial task reasoning.
