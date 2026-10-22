# Local open-source stack

## Models

The opt-in `.env.opensource` preset selects Ollama on `127.0.0.1:11434`:

- Completion: `qwen2.5:3b`, with `qwen2.5:0.5b` as a pre-dispatch fallback.
- Embeddings: `qwen3-embedding:4b`, requested at 1536 dimensions to match the existing pgvector schema.
- Provider route policy: version 2, so the signed Task, Flow, execution lease, and PostgreSQL usage reservation are still required. No model API key is required.
- Catalog mode reads Ollama's loopback `/api/tags` listing before a reserved call and rejects absent model IDs. A listing does not prove model quality or completion capability.

On Windows, launch the API with the preset loaded into the process environment:

```powershell
poetry run dotenv -f .env.opensource run .venv\Scripts\uvicorn.exe ai_osop.api.main:app --port 8200
```

The base `.env` is unchanged. Starting with plain `poetry run uvicorn` does not apply this preset. The local model can respond, but its output is not independent verification of a security finding.

## Scanner and reconnaissance engines

The free `threat-intel-mcp` service now runs from `mcp-servers/python/threat_intel_mcp.py` on port 8086. It exposes bounded public NVD CVE lookup, ExploitDB reference search, and CISA KEV membership checks. `docker compose up -d threat-intel-mcp` builds and starts it; the API container is configured to reach it as `threat-intel-mcp:8086`. These are public reference data, and every result marks target effect as unverified. A live local registry request fetched CVE-2021-44228 from NVD, and a live KEV request returned membership from CISA on 2026-10-21.

Compose also publishes this public-data endpoint on `127.0.0.1:8086` so the host-side fleet validator can check the same container without exposing it on the LAN. On 2026-10-21, `mcp_validator.py --public-intel-smoke` reported reachable, initialized, and `public_lookup_verified` against that container. Its `end_to_end_verified` field remains false because the lookup is not a signed engagement finding.

- ZAP 2.17.0 was pulled as `ghcr.io/zaproxy/zaproxy:stable` and its local API answered a version request. Its API should be bound to loopback and protected with an operator-generated API key. ZAP is not yet a trusted AI-OSOP MCP provider; no scan action has been enabled.
- Nuclei is installed locally, but the Go MCP server intentionally does not dispatch its registered scan handler until a source-side signed authority path is implemented. Its presence is not a working end-to-end scan.
- The existing Recon MCP advertises Subfinder and Amass tools but currently returns placeholder data through disabled Go handlers. Passive DNS and certificate transparency may replace part of Shodan's discovery workflow; they do not replicate Shodan's global host database.
- Prowler can run locally for cloud accounts after the operator supplies credentials for those accounts. The current Cloud MCP does not invoke Prowler.

## Acceptance gates

### MCP fleet status (2026-10-21)

| MCP | Current execution state | Remaining gate |
| --- | --- | --- |
| Threat Intel | Python service executes NVD, ExploitDB, and CISA KEV public lookups; container and registry paths checked live | Public data does not validate a target finding |
| Browser | Source-signed provider path exists | Provider identity, signed scope, and original capture evidence must be provisioned and verified |
| Source Map | Source-signed reviewed artifact path exists | Original resource offering and signed source authority must be provisioned and verified |
| Nuclei | Go transport and tool declaration exist; handler execution disabled | Extend independent, durable signed grant to this scanner, then verify scope and receipts |
| Recon | Go declarations exist; handler execution disabled | Signed scanner grant and installed open-source tools or safe passive replacements |
| Payload | Go declarations exist; handler execution disabled | Signed grant and provenance for generated payloads |
| Security Bridge | Go declarations exist; handler execution disabled | Tool-specific signed grant, scope, approval, timeout, and evidence fencing |
| Shodan | Go handler disabled; Shodan requires a provider key | Replace specific use cases with free public sources; no equivalent global Shodan database is assumed |
| Burp | Local Burp service was previously observed on 8081 | Verify source-side trust and live tool receipts before treating it as an execution provider |
| Cloud | Optional local Checkov Terraform scan; adapter and `scan_local_iac` agent task wired | Signed engagement execution and stored report evidence; live cloud account scanning remains unsupported |
| Turbo Intruder | Service explicitly reports unavailable | An independently authorized local execution backend and signed source authority |

The Go SDK and central grant issuer currently admit only the inert `authority_status` operation. The registered Go scanner handlers are therefore not executable through MCP. A healthy port or advertised declaration is insufficient evidence of execution.

The disposable local PostgreSQL qualifications were rerun against the current `0040` migration on 2026-10-21. Browser's joined signed-source, one-shot database, and real local Chromium test passed (1 test); its Browser-to-API TLS transport uses an in-process bridge. Source Map's signed original-artifact PostgreSQL qualification passed (2 tests), including one-use and revocation checks. These results strengthen the Browser and Source Map local evidence, but neither result enables the Go scanner handlers or certifies the full API-to-report engagement flow.

On 2026-10-21, a disposable PostgreSQL/Redis stack migrated from a blank database through revision 0040 and the API reached `/health` with PostgreSQL, Redis and Neo4j healthy. `/ready` remained `degraded`: 11 servers registered, one healthy, zero of five critical services initialized or runtime verified. The pre-existing local PostgreSQL container is a separate, inconsistent schema: its revision points past a missing `execution_flows` table. The disposable run does not repair or certify that database.

Run `poetry run python scripts/ops/mcp_validator.py --public-intel-smoke` for a bounded local fleet observation. It never executes arbitrary scanner tools and now exits nonzero if that requested public lookup fails. `--require-critical` exits nonzero while any critical provider lacks end-to-end evidence. A successful public CVE lookup proves only that the free Threat Intel service fetched reference data.

1. Connect ZAP, Nuclei, and recon execution through the existing signed Flow MCP action path, with source-side scope, approval, lease, and receipt checks.
2. Test each provider against an authorized local lab and verify request, tool result, stored evidence, and UI reporting. Keep live target scanning within the signed engagement scope.
3. Verify a signed engagement calls both local model operations and settles usage in PostgreSQL. The direct local model smoke check used a disposable ledger and does not satisfy this gate.
4. Keep `/ready` degraded while critical MCP services are not initialized and runtime verified.

## Running the local services (2026-10-22)

On this workspace, run `poetry run python scripts/ops/start_local_stack.py`.
It starts the existing separate lab PostgreSQL (55435), Redis (6380), and
Threat Intel containers; creates a separate loopback Neo4j lab container
(17687/17474); builds and launches current Go MCP sources on 8082–8085 and
8087; and launches Browser, Source Map, Cloud, Turbo Intruder, the lab target,
API and UI. The API is explicitly a development instance with local Ollama.
It never enables disabled scanner handlers or creates a fake Burp service.
An existing listener is retained and reported with ownership unverified.

The launcher pins Cloud to `tests/fixtures/local_iac` and the isolated installed
Checkov interpreter in `.runtime/checkov-venv`. Its generated bearer and graph
password, child PID files and logs are in `.runtime/local-stack`, outside Git.
It requires that runtime and the named existing Docker containers. It does
not install or configure an independent signing authority.

Run `poetry run python scripts/ops/verify_local_stack.py` for current API,
database readiness, UI, lab and authenticated direct static-IaC observations.
Run `poetry run python scripts/ops/mcp_validator.py --public-intel-smoke` for
all eleven transport/initialize observations. These are diagnostics, not
signed engagement execution or a production readiness certificate.

The live 2026-10-22 run returned API health 200, UI 200, lab 200 and all three
databases healthy. Ten MCP endpoints were reachable. The API initialized
three providers but reported zero runtime-verified providers and degraded
readiness. An authenticated direct Cloud request ran Checkov and returned 11
static findings. Burp has no actual local backend listening on 8081; Go scan
handlers, signed Browser/Source Map execution and Turbo Intruder remain
unverified/unavailable. Restarting their processes does not supply those paths.

The final Cloud adapter/agent/source/HTTP qualification on 2026-10-22 passed
10 tests. An unauthenticated live request to `/engagements` returned 403.
No signed engagement-to-report workflow was executed or certified by this run.
