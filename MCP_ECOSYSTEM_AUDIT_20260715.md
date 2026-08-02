# AI-OSOP MCP Ecosystem Audit

**Audit date:** 2026-07-15  
**Method:** source inspection plus live HTTP-MCP verification of the stack started for this audit.  
**Safety boundary:** destructive scanners and attacks were not pointed at any external target. Live calls used local AI-OSOP endpoints, benign validation inputs, and read-only public vulnerability feeds.

## 1. Executive summary

The MCP fleet is not a uniformly production-ready ecosystem. It contains real implementations and real external integrations, but **no running server meets the strict `REAL` definition in full**: every functional server is missing at least authentication/scope enforcement, correct error signalling, durable state, or full dependency validation.

Three deployed ports are incontrovertible honest stubs. `launch_real.ps1` starts the generic `mcp_stub.py` on 8090, 8092, and 8093; those ports advertise no tools and return a fabricated successful result for arbitrary unknown tool names. The separately committed `session_memory_mcp.py` and `reporting_mcp.py` are also explicit simulations, while the legacy attack-graph implementation cannot speak the HTTP-MCP protocol used by the platform and has a hard-coded Neo4j password.

The highest immediate operational risk is not a stub: browser, source-map, and OAST are listening on all interfaces without authentication; the Go servers listen on an unspecified address (`:port`). Turbo Intruder also accepts malformed targets and attempted ten socket connections instead of rejecting the malformed input. The highest-risk *stub/legacy stub* is attack graph: if its inactive implementation were launched, it exposes arbitrary Cypher with static credentials.

## 2. Evidence and audit limits

### Live platform evidence

| Check | Result |
|---|---|
| API health | `GET /health` returned HTTP 200 / `healthy` |
| Backing stores | Redis `PONG`; PostgreSQL reports `vector` extension; Neo4j `RETURN 1` succeeded |
| Protocol discovery | All 15 listening MCP endpoints returned HTTP 200 to unauthenticated `/health` and accepted unauthenticated `/mcp/initialize` |
| Local recon side effect | `httpx_probe` fetched `http://127.0.0.1:8200/health` (HTTP 200, uvicorn); native `nmap_scan` found local port 8200 open |
| Browser side effect | Playwright navigated to the local health endpoint and wrote a 10,502-byte screenshot to `evidence_vault/eng-audit/wf-audit/` |
| OAST side effect | Registered a token, sent a local callback, then observed it through both `oast_poll` and `oast_drain` |
| External API evidence | Threat Intel returned NVD data and a CISA KEV match for `CVE-2021-44228`; Cloud MCP attempted AWS `ListRoles` and returned the real invalid-token error |

### Important limits

- Burp active audit, Repeater, Intruder, and raw-request tools were not invoked because no authorized target scope was supplied.
- Nuclei `list_templates(limit=1)` did not complete within the client’s 45-second audit budget; therefore a usable Nuclei backend was **not** proved.
- Shodan has no process-visible `OSOP_SHODAN_API_KEY`; its live lookup therefore correctly returned an unavailable/error-shaped empty result. A real Shodan response was not observed.
- Passive internet reconnaissance, crawler, fuzzer, and scanner tools were only code-reviewed or negative-tested where a valid invocation would target external systems.

## 3. Runtime MCP inventory

The launcher is [`launch_real.ps1`](launch_real.ps1). It starts the data tier separately, starts direct processes for the functional servers, and explicitly starts generic stubs on 8090/8092/8093. The API only registers ten servers: Burp, Recon, Payload, Nuclei, Shodan, Browser, Security Bridge, Threat Intel, Cloud, and Turbo Intruder ([`src/ai_osop/api/main.py`](src/ai_osop/api/main.py)). Source Map and OAST are live but not registered; the three stub ports are neither registered nor usable.

| Server / port | Exposed tool(s) | Startup, config, integrations | Health / auth evidence | Classification (confidence) |
|---|---|---|---|---|
| Burp / 8081 | scan_target, history/issues/sitemap, Repeater, Intruder, raw request | Live `BurpSuite.exe` with Montoya extension; local bind defaults to 127.0.0.1 | Read-only history/issues returned real empty Burp collections; unknown tool errored; no auth required | **PARTIALLY IMPLEMENTED (90%)** |
| Recon / 8082 | CT, Amass, TCP scan, HTTP probe, fingerprint, Shodan, Wayback | Go stdlib plus optional Amass/Shodan and public CT/Wayback APIs | Local HTTP probe and TCP connect scan were genuine; missing domain is conveyed inside outer `success` | **PARTIALLY IMPLEMENTED (93%)** |
| Payload / 8083 | generate, mutate, fitness | FastAPI; static templates, encoders, random mutation/fitness; claimed engine is initialized but not used for generation | XSS and SQLi requests returned distinct template sets; unsupported class returned payload-level error inside `success` | **PROTOTYPE (98%)** |
| Nuclei / 8084 | scan, list_templates | Go wrapper around `nuclei` binary | Empty target error observed; template listing exceeded 45 seconds, so backend usability is unproved | **WRAPPER (98%)** |
| Shodan / 8085 | shodan_lookup | Go wrapper around `api.shodan.io`; requires environment key | Missing key/domain returned honest empty/error; no valid provider result observed | **WRAPPER (99%)** |
| Threat Intel / 8086 | cve_lookup, kev_check | Go wrapper around NVD and CISA KEV | NVD response and KEV=true for Log4Shell observed; missing CVE reports a payload error inside outer `success` | **WRAPPER (99%)** |
| Security Bridge / 8087 | sqlmap, nmap, ffuf, masscan, gobuster, nikto, wpscan, katana, JS analysis | Go wrappers over local binaries; JS analyzer is native HTTP/regex | Local JS fetched; unsafe `-` input rejected; missing SQLMap URL ran sqlmap help yet reported outer success | **PARTIALLY IMPLEMENTED (97%)** |
| Session Memory / 8090 | none at runtime | Generic `mcp_stub.py`, not the committed session server | `is_stub=true`, no tools; two arbitrary unknown tools returned `Mock ... executed successfully` | **HONEST STUB (100%)** |
| Browser / 8091 | execute(action) | FastAPI + Playwright; filesystem evidence vault | Local navigation, state capture, and screenshot creation observed; no auth required | **PROTOTYPE (96%)** |
| Reporting / 8092 | none at runtime | Generic `mcp_stub.py`, not the committed reporting server | `is_stub=true`, no tools; arbitrary tool returned fake success | **HONEST STUB (100%)** |
| Attack Graph / 8093 | none at runtime | Generic `mcp_stub.py`, not the committed graph server | `is_stub=true`, no tools; arbitrary tool returned fake success | **HONEST STUB (100%)** |
| Source Map / 8096 | fetch_and_parse_sourcemap | FastAPI + HTTP fetch + regex/JSON parsing | Fetched a local Vite source and parsed raw content; missing URL returned an error | **PROTOTYPE (96%)** |
| Cloud / 8097 | analyze_iam_trust_policies | FastAPI + boto3 AWS IAM only | Azure explicitly `not_implemented`; AWS made real API call and returned invalid-token error; invalid provider error observed | **PARTIALLY IMPLEMENTED (98%)** |
| Turbo Intruder / 8098 | execute_single_packet_attack | Python raw sockets + `threading.Barrier` | Missing target raised error; malformed `not-a-url` was accepted and attempted ten connections | **PROTOTYPE (97%)** |
| OAST / 8099 | register, poll, drain | FastAPI in-memory token/interaction store | Full register → local callback → poll/drain state transition observed | **PROTOTYPE (98%)** |

All initialize and execute calls in this audit omitted `Authorization`. Every tested server accepted them. Bindings were also inconsistent: 8082–8087 listen on `::`; Browser, Source Map, and OAST listen on `0.0.0.0`; only several Python services bind loopback. This invalidates any assumption that the MCP fleet is protected by localhost-only exposure.

## 4. Static code audit

### Functional implementations

- **Burp:** [`BurpMcpMontoyaExtension.java`](burp-extension/src/main/java/com/aiosop/burp/BurpMcpMontoyaExtension.java) calls genuine Montoya APIs: `startAudit`, proxy history, site-map issues, Repeater, Intruder, and `api.http().sendRequest`. It hand-parses JSON strings, advertises all tools with empty parameter schemas, has no authorization middleware, and serializes JSON manually. It is real business logic, but not a safe production protocol implementation.
- **Recon:** [`main.go`](mcp-servers/go/cmd/recon-mcp/main.go) uses `net.DialTimeout`, `http.NewRequestWithContext`, crt.sh, Wayback, optional Amass, and optional Shodan. The previous mock implementation is retained as `main.go.mock.bak`, but the active source is substantive. Scope is metadata only; it is not enforced at the transport boundary.
- **Nuclei:** [`main.go`](mcp-servers/go/cmd/nuclei-mcp/main.go) builds argv and calls `nuclei`; it parses JSONL output. This is genuine but almost entirely delegates to the CLI, hence wrapper classification. `list_templates` has no context timeout.
- **Threat Intel and Shodan:** each uses `http.Get` and decodes the provider response. The audit observed real NVD and CISA responses. Neither validates provider HTTP status before decoding, supplies client timeouts, or enforces caller scope.
- **Security Bridge:** [`main.go`](mcp-servers/go/cmd/security-bridge/main.go) shells out to tools. `js_analyze` is actual native fetching and regex analysis. Most wrappers return `status: success` even when the child command errors or produces non-JSON output; the audit’s missing-URL SQLMap call demonstrated this false-success path.
- **Browser:** [`browser_mcp.py`](mcp-servers/python/browser_mcp.py) controls Chromium and writes screenshots/HAR/DOM evidence. The audit created a real screenshot. It lacks auth, scope validation, retention controls, and durable session/evidence metadata.
- **Source Map:** [`source_map_mcp.py`](mcp-servers/python/source_map_mcp.py) performs actual fetch/parse/regex work. It uses `verify=False`, accepts arbitrary URLs without scope checks, exposes detected secret values verbatim, and returns outer `success` even when its result contains a fetch error.
- **Cloud:** [`cloud_mcp.py`](mcp-servers/python/cloud_mcp.py) makes real boto3 IAM `ListRoles` calls and has an honest unavailable path. It only supports AWS; Azure and GCP intentionally return `not_implemented`. Its wildcard string heuristic is too coarse for production findings.
- **Turbo Intruder:** [`turbo_intruder_mcp.py`](mcp-servers/python/turbo_intruder_mcp.py) constructs raw HTTP/1.1 requests and synchronizes final-byte release. The malformed-target live behavior proves it lacks URL validation and can create unscoped outbound traffic.
- **OAST:** [`oast_mcp.py`](mcp-servers/python/oast_mcp.py) has working in-process correlation and callback capture. State is a process-local dictionary, callback URLs default to local hosting, and no authentication/rate limiting/durable queue exists.

### Explicit stub evidence

- [`launch_real.ps1`](launch_real.ps1) explicitly launches `mcp_stub.py` on 8090, 8092, and 8093.
- [`mcp_stub.py`](mcp-servers/python/mcp_stub.py) labels itself a stub, sets `is_stub: true`, offers no tools for unknown IDs, and returns `Mock {tool} executed successfully` for arbitrary calls.
- [`session_memory_mcp.py`](mcp-servers/python/session_memory_mcp.py) states it would connect to shared memory in a real setup and returns `Operation successful (Simulated)`.
- [`reporting_mcp.py`](mcp-servers/python/reporting_mcp.py) states it is a simulation and manufactures `http://internal/reports/<engagement>`.
- [`attack_graph_mcp.py`](mcp-servers/python/attack_graph_mcp.py) is not HTTP-MCP, hard-codes `AUTH = ("neo4j", "password")`, and exposes arbitrary Cypher if started. It is an inactive, **BROKEN legacy implementation**, while the currently deployed port is an honest stub.

### Protocol and operational defects common to the fleet

1. `scope_check: true` is metadata, not proof of scope enforcement.
2. No tested server verified the API’s bearer token; all accepted unauthenticated calls.
3. Go SDK servers bind `:port` ([`server.go`](mcp-servers/go/sdk/server.go)), exposing IPv6/all-interface listeners by default.
4. The API registration list omits Source Map and OAST and does not include the three stub services. They are therefore live-but-unmanaged or live-but-useless.
5. The launcher’s comments are stale: it calls Cloud a stub while starting `cloud_mcp.py`; it also relies on child-process environment for binary/provider credentials instead of a validated configuration handoff.
6. The project has no direct runtime-server test coverage found by the searched MCP server names; integration behavior is largely asserted by documentation and launch scripts rather than end-to-end tests.

## 5. Classification detail

### Real MCPs

**None under the strict definition.** Recon, Browser, OAST, NVD/CISA enrichment, and several local-binary calls demonstrate real execution, but the authentication, scope, error, or production-state requirements are not satisfied consistently enough to label any complete server `REAL`.

### Honest stubs

| Runtime service | Why it is an honest stub | Risk |
|---|---|---|
| Session Memory / 8090 | Deployed generic stub advertises zero tools; legacy implementation returns a simulated success | Agents cannot retrieve or checkpoint real engagement state, while false success hides the failure |
| Reporting / 8092 | Deployed generic stub advertises zero tools; legacy implementation emits a made-up internal URL | Operators can believe a report was generated when nothing was persisted/exported |
| Attack Graph / 8093 | Deployed generic stub advertises zero tools; legacy alternative is unusable/insecure | Attack-path correlation silently disappears; accidentally launching the legacy server creates a credential and arbitrary-query risk |

### Broken MCPs

No currently listening endpoint is classified `BROKEN`; it either responds honestly as a stub or has a functional path. The inactive `attack_graph_mcp.py` is broken against the platform HTTP-MCP contract. The unused raw-socket `payload_mcp.py`, legacy Python `threat_intel_mcp.py`, and explicit browser/Burp stubs are duplicate/legacy artifacts and should not be deployable.

### Wrapper MCPs

- **Nuclei:** real scanner execution is delegated to `nuclei`; usability remains unproved due the timed-out template call.
- **Shodan:** thin API client; correctly reports absent key but has no credential injection validation.
- **Threat Intel:** thin NVD/CISA client; provider data is real, but resilience/cache/rate-limit behavior is inadequate.

### Prototype MCPs

- **Payload:** static lists plus randomized scoring conflict with deterministic/evidence-backed output; the claimed engine is mostly decorative in the active handler.
- **Browser:** genuine automation/evidence, but no auth/scope/isolation/retention lifecycle.
- **Source Map:** genuine parser with unsafe fetch/TLS/secret disclosure behavior.
- **Turbo Intruder:** genuine socket implementation with unsafe input validation and no authorization gate.
- **OAST:** genuine state machine, but memory-only and only locally reachable without extra deployment.

## 6. Stub-to-production conversion roadmap

The following work converts every honest stub. Do not replace a stub with a synthetic implementation; remove the stub from the launcher only when its replacement passes the success criteria.

### 6.1 Session Memory MCP (8090)

**Current architecture:** generic zero-tool stub is deployed. The alternate FastAPI file returns a simulated message. Existing in-process services already exist in `src/ai_osop/memory/session_memory.py` with Redis/PostgreSQL backing.

**Missing components:** HTTP-MCP server wired to the real service; strict request/response schemas; engagement/tenant authorization; durable checkpoints; Redis/Postgres transaction/error handling; audit events; retention; metrics; idempotency.

**Implementation tasks:**

1. Replace the 8090 launcher entry with `session_memory_mcp_server.py`; delete the generic-stub launch path. Add typed `GetSessionStateRequest`, `CheckpointRequest`, `SessionState`, and `CheckpointReceipt` models.
2. Inject `SessionMemory` with `OSOP_REDIS_URI` and `OSOP_POSTGRES_URI`; use the shared configuration and lifespan instead of a co-located assumption.
3. Implement `get_session_state(session_id)` and `store_checkpoint(session_id, metadata, idempotency_key)` with tenant/engagement ownership checks, Redis hot-state reads, Postgres checkpoint persistence, and an outbox audit event.
4. Add bearer-token verification plus `ScopeController` enforcement before service access. Return outer MCP `error` for validation/authorization/storage failures.
5. Add a Redis/Postgres integration suite using compose, including reconnect/retry, duplicate checkpoint, expiry, concurrent write, and restart recovery tests.

**Files:** modify `launch_real.ps1`, `src/ai_osop/core/config.py`, and `src/ai_osop/memory/session_memory.py`; add `mcp-servers/python/session_memory_mcp_server.py` and `tests/integration/test_session_memory_mcp.py`.

**Success criteria:** two independent authenticated sessions cannot read/write each other; checkpoint survives a server restart; every write produces one audit event; invalid/missing IDs return HTTP/MCP errors; 99% local reads under 200 ms under a defined load test.

### 6.2 Reporting MCP (8092)

**Current architecture:** generic zero-tool stub is deployed. The alternate implementation constructs a fake URL and never invokes a reporting/exporter component.

**Missing components:** verified-findings query; real renderer; artifact storage; report job queue; status/progress model; signed retrieval; reproducible report metadata; authorization and audit trail.

**Implementation tasks:**

1. Define `ReportRequest`, `ReportJob`, and `ReportArtifact` Pydantic/domain models. `compile_findings` must require engagement ID, format, include/exclude evidence, and idempotency key.
2. Query only verified findings and evidence through the existing repositories; reject unverified/synthetic findings by policy.
3. Render Markdown/HTML/JSON through the actual reporting agent/exporters, enqueue long jobs through the platform queue, and persist job state in Postgres.
4. Store generated artifacts in a configured storage backend, return a signed/time-bound URL or artifact ID, and emit audit/outbox events.
5. Test empty engagements, mixed confidence, renderer failure, storage outage, duplicate requests, authorization boundaries, and snapshot determinism.

**Files:** modify `launch_real.ps1`, reporting agent/exporters, and configuration; add `mcp-servers/python/reporting_mcp_server.py`, report persistence migration/models, and end-to-end tests.

**Success criteria:** an authenticated operator can generate a report whose findings/evidence IDs exactly match the database query; identical input produces a byte-stable canonical JSON report; failures never return a success URL; every artifact has retention and access logs.

### 6.3 Attack Graph MCP (8093)

**Current architecture:** generic zero-tool stub is deployed. The alternate raw-socket server is incompatible with HTTP-MCP, uses static credentials, and lets callers submit arbitrary Cypher.

**Missing components:** shared `GraphMemory` integration; configuration-based credentials; typed graph operations; query allowlist; tenant/engagement constraints; parameter validation; graph write audit/outbox; result pagination and redaction.

**Implementation tasks:**

1. Retire `attack_graph_mcp.py` rather than repairing the raw socket protocol. Add an HTTP-MCP server using the same lifespan/configuration as `GraphMemory`.
2. Replace raw `query_graph` with typed tools: `get_asset_neighbors`, `get_attack_paths`, `upsert_verified_finding`, and `get_graph_summary`. Use parameterized repository methods only.
3. Include `engagement_id` in every node/edge query and enforce ownership/scope before any Cypher call. Never expose arbitrary query text to an agent.
4. Add Neo4j transaction retries, pagination/cursors, result size caps, metrics, audit events, and a dead-letter path for write failures.
5. Add Neo4j compose integration tests for cross-engagement isolation, injection attempts, graph-write idempotency, retry behavior, and 100k-node query limits.

**Files:** modify `launch_real.ps1`, `src/ai_osop/memory/graph_memory.py`, models/configuration; add `mcp-servers/python/attack_graph_mcp_server.py` and integration tests; remove/archive the legacy raw-socket file.

**Success criteria:** no static credentials; no raw Cypher tool; a valid graph write/read survives restart and is visible only to its engagement; query limits terminate predictably; 100% of writes create audit records.

### Shared conversion validation

- Unit tests: schemas, authorization, idempotency, error-to-MCP-status mapping, deterministic render/query behavior.
- Integration tests: Redis/Postgres/Neo4j containers, lost connections, retry backoff, migrations, auth failures, and outbox delivery.
- End-to-end tests: API registration initializes each replacement, tool discovery matches adapters, and a full engagement produces a real checkpoint/graph/report trail.
- Failure/performance tests: dependency outage, queue saturation, duplicate request, process restart, credential rotation, P95/P99 latency, and resource caps.

## 7. Engineering priorities and estimate

| Priority | Work | Value / risk reduction | Estimate |
|---|---|---|---|
| P0 | Bind every MCP to loopback or a private authenticated network; add mandatory bearer/mTLS middleware; enforce scope server-side; disable generic stubs | Removes unauthenticated scanner/browser/OAST exposure and fake-success behavior | 1–2 engineer-weeks |
| P0 | Correct MCP status semantics and typed validation; reject malformed URLs/empty mandatory inputs before child process launch | Prevents false positives and unscoped outbound traffic | 1 engineer-week |
| P1 | Stabilize wrappers: provider/binary preflight, bounded context timeouts, child cancellation, structured parser errors, credential injection | Makes Nuclei/Shodan/Security Bridge operationally trustworthy | 2–3 engineer-weeks |
| P1 | Convert Session Memory MCP | Restores durable orchestration state | 2–3 engineer-weeks |
| P1 | Convert Attack Graph MCP | Restores attack-path evidence safely | 2–3 engineer-weeks |
| P2 | Convert Reporting MCP | Produces auditable deliverables | 1–2 engineer-weeks |
| P2 | Harden prototypes (Browser, Source Map, Turbo, OAST, Payload, Cloud) | Reduces false findings, data leakage, and reliability gaps | 4–6 engineer-weeks |
| P3 | Standardized MCP server framework, conformance suite, metrics/tracing, deployment manifests | Prevents future divergence | 3–4 engineer-weeks |

**Optimal order:** exposure/authentication and error semantics → wrapper/binary readiness → Session Memory → Attack Graph → Reporting → prototype hardening → shared framework. Estimated total: **14–22 engineer-weeks**, with 2–3 engineers able to parallelize after the P0 contract is settled.

## 8. Highest-risk stub, quick wins, and long-term improvements

**Highest-risk stub:** the inactive Attack Graph implementation. It combines a hard-coded password, arbitrary Cypher, no auth, no scope, and an incompatible transport. Keep it non-runnable until replaced; do not merely point the current generic stub at it.

**Quick wins:**

1. Remove 8090/8092/8093 from production launch, or make launch fail prominently rather than presenting success.
2. Bind Browser, Source Map, OAST, and Go servers to 127.0.0.1 until authenticated private-network deployment exists.
3. Add a common MCP auth/scope middleware and reject requests without an authenticated engagement.
4. Make outer `status` error/timeout whenever a child tool/provider/result fails; do not encode errors inside a successful envelope.
5. Add strict URL parsing and an egress allowlist before Browser, Source Map, Turbo, Recon, and Security Bridge perform outbound I/O.
6. Fail startup or mark readiness degraded when Nuclei/binary/provider preflight fails. Stop treating registered tools as proof of operational capability.

**Long-term improvements:** one versioned HTTP-MCP framework; JSON Schema/Pydantic request validation; signed evidence and artifact manifests; persistent OAST store and public callback ingress; per-tool approval gates; resource quotas; redacted structured logs; adapter-to-tool contract tests; a live capability test suite that distinguishes "registered", "available", "authorized", and "proved".

## 9. Overall maturity

**3.5 / 10.** The system has meaningful genuine components and demonstrated real side effects, but a production MCP ecosystem needs reliable protocol contracts, authentication, scope enforcement, truthful error semantics, durable state, dependency readiness, and end-to-end conformance tests. Tool registration and a healthy port currently overstate maturity.
