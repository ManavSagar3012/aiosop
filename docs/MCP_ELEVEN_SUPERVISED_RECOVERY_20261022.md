# Eleven MCP services: supervised late transport recovery

## Existing original code

The real startup roster is in src/ai_osop/api/main.py, configured_mcp_server_specs().
All eleven services run HTTP health then strict initialize via
register_optional_mcp_servers(). Five critical services are browser, SourceMap,
Cloud, Turbo Intruder and Nuclei. The other six are Burp, Recon, Payload,
Shodan, Threat Intel and Security Bridge. Startup connection/initialization
never establishes original signed Action authority or independent target effects.

Existing POST /system/mcp/{server_id}/reconcile-local already calls
recover_configured_mcp_transport() and performs a bounded late health/initialize
reconnect with the original registry entry and original request journal.
The NEW supervised bridge therefore reuses that established transport code.

## Meaningful missing guards addressed

1. The existing recovery early-return accepts an initialized bit and matching
   bootstrap label even if the HTTP session is now closed. This bridge checks
   current session and strict parsed tool schema; stale connections have their
   declarations revoked and are **actually reconnected and reinitialized** on
   the same original connection, retaining all historical request IDs.
2. A request may have been reserved in the original seen-ID ledger before an
   active execution handle was installed. This bridge refuses active or malformed
   seen-ID and execution journals before any HTTP, checks identity and journal
   again after awaited calls, and never accepts any request ID or executes a tool.
3. For any of six Go-native names, a host-installed, digest-pinned inert fleet
   must have been manually started and pass its **actual current** status read
   before and after the client handshake. No host-controller installation,
   inactive fleet, lost owned PID, changed executable digest, mismatched owned
   socket or cleanup failure becomes a successful readback. Its existing status()
   owns any required fail-closed stop/cleanup of its **own** process handles.
4. On postflight owner/journal uncertainty, this bridge revokes manifest
   dispatchability, marks bootstrap unavailable and retains the original
   request IDs. No ambiguous Action is retried, no Action started and no
   scanner/native executable launched by the bridge.

The native inert six-Go supervisor creates **ephemeral** owned loopback
listeners and intentionally reports HTTP 503. They do not coincide with the
registry's normal 8082-8087 ports, and neither a PID nor host-owned listener
observation proves that the registry endpoint is the same process.
The response always reports endpoint ownership binding as false. The native
controller status demonstrates only host-local inert PID/socket ownership.

## Prime integration: only the three new files were written

Mount the standalone router in src/ai_osop/api/main.py with:

~~~python
from ai_osop.api.mcp_eleven_supervised_recovery_join_20261022 import (
    router as mcp_eleven_supervised_recovery_router,
)
app.include_router(mcp_eleven_supervised_recovery_router)
~~~

The resulting exact path is POST /system/mcp/{server_id}/supervised-reconcile.
It requires the existing signed senior operator JWT, an actual local host peer
(127.0.0.1 or ::1), exactly one bearer, no browser origin, no request body or
query and one known configured service ID. It takes no port, URL, credential,
grant, original Task, target or request ID from the caller. It refuses any
configured host other than numeric 127.0.0.1 before network contact.
No configured address, bearer, port, binary path or remote tools are serialized.
Responses set Cache-Control no-store.

Keep the existing fleet readiness UI card; optionally expose an explicit
senior operator reconcile action within that card and refetch existing readback
after completion. Avoid a duplicate fleet/status card. No auto-start/retry.

**Existing weak route still mounted:** Until the prime rewires or retires
the older /system/mcp/{server_id}/reconcile-local endpoint, clients can still
call its older, weaker stale-session/journal behavior. The new module cannot
enforce its checks on that older path without a permitted change to system.py.
The intended safe integration is to migrate the existing action to this route
and disable the old route separately.

## Verification and limits

The NEW tests/qualification/test_mcp_eleven_supervised_recovery_join_20261022.py
uses actual isolated local FastAPI signed JWT verification and genuine loopback
aiohttp MCP client health+initialize, including a full 11-listener fleet
fixture. It also uses the actual host controller with an explicitly fake
inert OS process backend: this does NOT exercise real Go binaries.
It tests senior/host/misbound credential denies, no-body/no-query, closed
session positive recovery, active original journal deny, retained unknown-ID
history, native manually started ownership and postflight loss/cleanup.

Every success is qualified only as initialized transport. The returned
fields current_signed_action_verified, signed_0033_witness_verified,
independent_target_effect_verified, unknown_original_action_safe_to_retry,
production_certified, automatic_process_start_performed and
tool_or_scan_executed are false. The separate owned Go process observation
is true only after its host-pinned current health confirms owned inert PIDs;
it never authenticates the registry service endpoint. No app DB, Docker,
real provider, paid API, actual scanner or external target is accessed.
