# Eleven configured MCP endpoints: loopback identity qualification

**22 October 2026; original dirty /burp_mcp/ai-osop**

ONLY two new files are owned here:

- tests/qualification/test_mcp_eleven_configured_loopback_identity_20261022.py
- docs/MCP_ELEVEN_CONFIGURED_IDENTITY_20261022.md

Existing application routes, registry, bootstrap, main, UI, native Go code,
Docker state, app databases and listeners are unchanged. Ordinary tests use
httpx.MockTransport and synthetic OS metadata: no actual listener is bound or
contacted. The one actual configured endpoint observation is separately
opted-in and requires an independently pinned executable, one OS-owned
numeric IPv4 loopback listener, no credential and no proxy.

## Actual eleven configured services

The original main.py configured_mcp_server_specs() returns exactly eleven
tuples: service ID, host, port and optional bearer. Literal localhost defaults
are normalized to 127.0.0.1 before the plain HTTP MCP transport.
register_optional_mcp_servers() performs /health then strict /mcp/initialize
for all eleven, records initial registered/initialized state, and fails
production bootstrap if any of the five critical services is unavailable.
These are transport facts and provider schema declarations.

| Service | Default port | Critical | Process/runtime boundary |
| --- | ---: | --- | --- |
| burp-mcp | 8081 | No | Burp bridge, potentially credentialed |
| recon-mcp | 8082 | No | Go-native inert-owned lifecycle exists separately |
| payload-mcp | 8083 | No | Go-native inert-owned lifecycle exists separately |
| nuclei-mcp | 8084 | Yes | Go-native inert-owned lifecycle exists separately |
| shodan-mcp | 8085 | No | Go-native, potential paid upstream; excluded from live test |
| threat-intel-mcp | 8086 | No | Go-native and alternate Python/Docker service; proxy ambiguity |
| security-bridge | 8087 | No | Go-native inert-owned lifecycle exists separately |
| browser-mcp | 8091 | Yes | Python Browser; separately authorized |
| source-map-mcp | 8096 | Yes | Python SourceMap; separately authorized |
| cloud-mcp | 8097 | Yes | Python Cloud; possibly credentialed |
| turbo-intruder-mcp | 8098 | Yes | Python Turbo; active testing excluded |

The six-Go NativeInertProcessFleet checks separately verified executable
SHA-256, owned PID and exact PID-owned numeric-loopback listener. It uses
independently assigned *ephemeral* ports and intentionally returns /health 503.
Its unsafe-port list EXCLUDES ALL eleven fixed configured ports, including
8086. Therefore a current host-owned six-Go process does not prove that the
normal configured 808x/809x registry endpoint belongs to that process.

## Exact port 8086 observation

One read-only Windows OS metadata check on this turn observed:

| Field | Observed |
| --- | --- |
| Local TCP LISTEN | 127.0.0.1:8086 |
| Owning Windows PID | 35352 |
| Owning Windows process | com.docker.backend |
| HTTP requests made | None |
| Docker operations | None |
| Confirmed upstream container/process identity | UNKNOWN |
| Signed native 0033 witness | None |

The Windows-side port belongs to Docker backend/proxy infrastructure, which
does NOT establish whether its upstream is the intended native Go service,
the alternate Python service, or an unrelated listener. Source documentation
contains both the Go command and Python threat-intel implementation. A
claimed server_id in HTTP health or initialization is merely provider
testimony, not signed independently observed host process identity. The test
rejects owner process names containing docker, proxy, wsl, tunnel, vpn or
portproxy even if the supplied digest matches.

## Default unit qualification: NO live network

PowerShell:

    .\.venv\Scripts\python.exe -m pytest tests/qualification/test_mcp_eleven_configured_loopback_identity_20261022.py -q -o addopts=''

Tests require complete exact 11 roster, fixed critical membership and separate
Go process-port boundary; they deny nonnumeric, remappable, remote,
credentialed and paid-risk endpoints, duplicate roster IDs and wrong
credential identity. Injected httpx.MockTransport verifies a fixed numeric
127.0.0.1 GET /health, a separately authorized POST /mcp/initialize
with empty scope and credentials, strict JSON response-body limits, no
redirects or environment proxy, and typed MCPInitializeResponse declaration
with explicit side-effect, approval and scope-check semantics.

It covers no listener, lost connection, redirect, wrong or missing server_id,
HTTP 503 inert service, duplicate JSON members, oversized body, untrusted
tool flags, and a process-owner change between observations. No
/mcp/execute, scan, unknown Action replay, paid API or target is ever called.
Positive simulated metadata has only provider-claimed health/schema status.

**Observed focused result on this checkout:** 20 PASSED, 1 SKIPPED, 20.32s
using the project virtual environment. The single skipped case is the
separately opted-in real configured-port observation; no operator-reviewed
live process executable SHA was supplied. Black --check on the new test file
passed, and Python compileall passed. The 20 passing cases use mock HTTP
transport and simulated OS owner metadata only, with no live socket.

## Separately opt-in, actual configured local endpoint observation

The final test skips unless the operator explicitly sets three independent
settings after reviewing one already-running directly owned local executable:

    $env:OSOP_MCP_ELEVEN_CONFIGURED_IDENTITY_OBSERVE_20261022 = '1'
    $env:OSOP_MCP_ELEVEN_CONFIGURED_IDENTITY_SERVICE_20261022 = 'recon-mcp'
    $env:OSOP_MCP_ELEVEN_CONFIGURED_IDENTITY_SHA256_20261022 = '<reviewed-lowercase-sha256>'
    .\.venv\Scripts\python.exe -m pytest tests/qualification/test_mcp_eleven_configured_loopback_identity_20261022.py -q -o addopts='' -k test_opt_in_real_configured_loopback_observation_only

The digest must be independently verified by an authorized operator; this
test never invents one. Only direct process-owned, exactly one 127.0.0.1
listener, matching executable SHA and stable PID/creation epoch may proceed.
The code checks process identity again between HTTP steps. All remote,
proxy-owned, ambiguous or credentialed endpoints are rejected BEFORE HTTP.
Only these low-risk local service names are supported by the opt-in path:
recon-mcp, payload-mcp, nuclei-mcp, threat-intel-mcp, security-bridge.
Shodan and all externally credentialed or target-active integrations are
excluded. The currently observed Docker proxy on 8086 fails admission.

Without additional authorization, the only live request is GET /health.
If and only if the operator additionally opts in to inert negotiation using:

    $env:OSOP_MCP_ELEVEN_CONFIGURED_IDENTITY_INITIALIZE_20261022 = '1'

then a matching HTTP200 health response with exact claimed service ID,
a still-current independently pinned local process and strict safe service
selection allow one bounded POST /mcp/initialize. This sends only empty scope,
empty auth_credentials, fixed qualification session_id and empty metadata.
Each request is numeric 127.0.0.1, bounded time, no redirects, no proxies,
no ambient bearer, fixed endpoint path, capped health/initialize response
bodies (4096/32768 decoded bytes). A 503 inert health response is NOT
ready, and mismatched or absent claimed name prohibits initialize.

The code classifies provider statements as matching_provider_claim_only and
matching_declared_schema_only, never proof of verified ownership across
Docker/process namespace boundaries. The fields signed_0033_witness_verified,
signed_action_verified, independent_process_witness_verified,
independent_target_effect_verified and production_certified stay False
even on a declared success. This does not verify signed ROE/Task/lease,
flow grants, scanner effects or target-owner readback.

## Prime integration hook and limits

This is a test-only qualification, NOT a production API router. Prime can run
its default deterministic command without contacting any configured service.
Any actual observation is expressly scoped to a separately reviewed
executable pin and opt-in above. Port 8086 requires upstream Docker
container identity proof and original target-side evidence from separately
authorized independent sources; a Windows Docker backend proxy PID,
TCP accept or self-claimed server_id cannot establish that identity.
No app DB, Docker process/container controls, Git mutation or paid calls
occurred in this task.
