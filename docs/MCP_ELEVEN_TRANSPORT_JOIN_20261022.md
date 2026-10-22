# Eleven MCP transport diagnostics: read-only operator join

**Scope:** `src/ai_osop/api/mcp_transport_operator_diagnostics.py` is a new,
mounted-ready senior GET and pure readback helper. This addition does not change
`main.py`, `/system`, an MCP connection, any binary, or a database. **No fleet
runtime or independent target effect is certified by this readback.**

## Source-traced configuration and transport

`src/ai_osop/api/main.py:146-194` is the actual eleven-service transport
roster. `register_optional_mcp_servers()` at lines 197-292 performs real
`MCPRegistry.register_server()` and `initialize_server()` once for **all eleven**
at bootstrap. A critical service's inability to initialize fails strict
production bootstrap; optional services are still attempted. The configured
connection uses MCP's plain HTTP `/health` followed by `/mcp/initialize`.
No scanner, Action, or independent provider signer is proved by this handshake.

| Server ID | Role | Default configured port | Actual bootstrap transport / implementation category |
| --- | --- | ---: | --- |
| burp-mcp | optional | 8081 | HTTP to separately hosted Burp extension/bridge |
| recon-mcp | optional | 8082 | HTTP; Go-native inert host available separately |
| payload-mcp | optional | 8083 | HTTP; Go-native inert host available separately |
| nuclei-mcp | critical | 8084 | HTTP; Go-native inert host available separately |
| shodan-mcp | optional | 8085 | HTTP; Go-native inert host available separately |
| threat-intel-mcp | optional | 8086 | HTTP; Go-native inert host available separately |
| security-bridge | optional | 8087 | HTTP; Go-native inert host available separately |
| browser-mcp | critical | 8091 | HTTP; Python-native endpoint |
| source-map-mcp | critical | 8096 | HTTP; Python-native endpoint |
| cloud-mcp | critical | 8097 | HTTP; Python-native endpoint |
| turbo-intruder-mcp | critical | 8098 | HTTP; Python-native endpoint |

`src/ai_osop/mcp/protocol.py:1261-1379` stores an actual `aiohttp` session,
health negotiation, parsed schema and `_initialized` marker. Its parser
validates declared risk/approval fields before accepting a provider schema;
these declarations originate at the **provider** trust boundary and are not
independently signed execution authorization. `ping()` (1915-1972) makes a
loopback-only health request, but is **not invoked by these diagnostics**.
The shared registry has no application-proved PID identity for every server.

The separate six-Go host controller in
`src/ai_osop/api/native_inert_fleet_control.py` is host-installed only with
independently supplied Go executable digests and explicit opt-in. Its status
method may clean up owned processes on a failed health check. The new GET
reads only its already held, sanitized lifecycle marker (`_state`) and makes
**no PID or socket ownership assertion**. Current PID/listener ownership
requires its dedicated `/system/native-inert-fleet/status` host-bound probe;
even a successful probe does **not** issue a signed 0033 witness, grant,
scanner authority, or independently verified target effect.

## Operator API and exact prime integration

The module provides `router` with one new optional endpoint:

`GET /system/mcp/transport-diagnostics` — requires an existing authenticated
`senior_operator` JWT, a local peer or HTTPS, a complete eleven-row bootstrap
record, and a valid registry. No query-defined target, URL, port, tool, secret,
path, or operation is accepted. The endpoint reads existing
`/system/mcp/health` validation directly, never probing HTTP, reconnecting,
starting Go, or calling a tool. The response is no-store and only includes
fixed server IDs, generic transport classes and safe status labels. It never
publishes the configured host, port, bearer or provider tool names.

At the final worker checkpoint, the prime's `src/ai_osop/api/main.py` already
contains the correct mount of the dedicated GET (near the existing router
mounts). Its exact import/mount form is:

```python
from ai_osop.api.mcp_transport_operator_diagnostics import (
    router as mcp_transport_operator_diagnostics_router,
)

app.include_router(mcp_transport_operator_diagnostics_router)
```

**Recommended single-card UI integration:** The existing
`GET /system/mcp/fleet-readiness` at `routers/system.py:189-203` and the
operator `McpFleetOperatorReadinessPanel` already show exactly the same eleven
services. Do **not** add another fleet card. Enrich that existing endpoint
instead, calling the pure helper after the currently validated `get_mcp_health`:

```python
from ai_osop.api.mcp_transport_operator_diagnostics import (
    build_mcp_eleven_transport_diagnostics,
    _host_lifecycle,
)
from ai_osop.api.native_inert_fleet_control import host_native_inert_control
from ai_osop.api.main import configured_mcp_server_specs

health = await get_mcp_health(operator=operator)
base = mcp_fleet_process_visibility(health)
effective = build_mcp_eleven_transport_diagnostics(
    process_health=health,
    registry=state["orchestrator"].mcp_registry,
    specs=configured_mcp_server_specs(),
    bootstrap=state.get("mcp_bootstrap_readiness"),
    native_host_lifecycle="host_unconfigured",  # replace with _host_lifecycle(request.app) when Request injected
)
by_name = {item["server_id"]: item for item in effective["services"]}
for item in base["services"]:
    item.update({
        "configured_transport": by_name[item["server_id"]]["configured_transport"],
        "http_session_open": by_name[item["server_id"]]["http_session_open"],
        "provider_schema_declared": by_name[item["server_id"]]["provider_schema_declared"],
        "effective_transport_status": by_name[item["server_id"]]["effective_transport_status"],
    })
return base
```

The shown merge preserves the established fleet response structure and its
per-service redacted fields; the UI can display the additional transport state
inside each existing row. `Request` may be added to the endpoint signature and
`_host_lifecycle(request.app)` used when needed. For fail-closed production
integration catch the helper's `ValueError` and return generic HTTP 503, as
the dedicated route already does. The extra router mount is optional if the
existing readiness GET is enriched instead. **Avoid mounting a second fleet
card** in the existing Administration UI.

## Interpreting a response

Each record contains one `effective_transport_status`:

* `not_registered`: no registry connection exists; says nothing about process reachability.
* `registry_identity_mismatch`: live connection does not match exact trusted server ID, host, port and bearer configuration; no addresses are output.
* `no_current_http_session`: connection known, but no open session currently observed.
* `connected_without_valid_current_declaration`: an HTTP session exists, but current registry declaration is missing or invalid.
* `registry_initialized_bootstrap_stale`: live declaration exists, bootstrap is not in the initialized state.
* `initialized_transport_declaration_only`: current session and parsed declared schema are observed, alongside successful bootstrap telemetry.
* `unverified_nonnumeric_or_nonlocal_http`: endpoint is configured outside exact numeric loopback. **No diagnostic request is sent.**

The fields `provider_schema_independently_verified`,
`native_go_current_process_owned_verified`, `current_signed_action_verified`,
`independently_verified_target_effect`, `safe_to_retry_unknown_action`, and
`production_certified` are **always false**. Actual signed engagement/Task
and independent target owner evidence require a separate current verification
path, not a fleet-wide counter. No `mcp/execute`, scan, grant, status/cancel,
retry or provider call is made by the diagnostic.

## Qualification and remaining gaps

`tests/qualification/test_mcp_eleven_transport_operator_diagnostics_20261022.py`
uses isolated senior JWT verification, invalid/junior/expired tokens,
host/query policy denial, the exact roster and spoofed host/credential
redaction, and a real network-bound fixture from
`test_mcp_all_eleven_real_bootstrap_transport_20261021.py` on eleven ephemeral
`127.0.0.1` listeners. A legitimate server fixture supports only inert
`/health` and `/mcp/initialize`; the new GET makes **zero additional HTTP
requests**. These owned fixtures are not independent production signers,
scanner binaries, or verified targets. Report actual execution separately;
no project-wide release status follows from a passing focused test.

**Executed results:** The six focused qualification tests pass, including all
eleven real inert loopback HTTP fixture initializations and zero additional
requests made by the diagnostic. Combined with the existing fleet readiness
unit tests and mounted operator reconciliation test, **14 tests passed** using
the repository virtual environment (`pytest -q -o addopts=''`). `black
--check` also passed for the two new Python files. These checks did not run
the live application lifespan or launch Go binaries.

Further authorization/effect assurance requires original current signed ROE,
Flow-scoped native grants, independent provider proof, target-owner readback,
and durable original Action correlation. The current bootstrap's plain HTTP
transport is not a general remote authenticated/pinned-TLS transport; the
new readback classifies non-loopback configurations as unverified without
network contact. Native inert process lifecycle remains separate from an
MCP client connection and any 0033 signed witness.
