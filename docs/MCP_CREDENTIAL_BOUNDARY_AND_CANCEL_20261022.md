# 2026-10-22 MCP credential transport and cancelled-handshake hardening

**Scope: original shared `src/ai_osop/mcp/protocol.py`; no configured provider or target process was contacted. Release remains NOT READY.**

## Production effects

1. Every `MCPConnection.connect()` and `MCPRegistry.register_server()` now denies a configured bearer token on a non-numeric-IPv4-loopback plain HTTP endpoint, not only Source Map. This includes literal `localhost`, remappable FQDNs, remote IPs, and alternate loopback addresses. The transport does **not** implement independent pinned HTTPS host verification. Configured externally hosted Burp/Shodan or similar services must instead use an independently authenticated secure host-local relay or a separately implemented and qualified authenticated encrypted transport; this patch does not invent one.
2. `MCPConnection.initialize()` additionally refuses a non-empty `auth_credentials` dictionary when the server host is not exact `127.0.0.1`, even if the connection carries no authorization header. Before this fix such credentials could have been sent in the initialization JSON over remote plaintext HTTP. The previous negotiated tools/manifest are invalidated on a denied reinitialization; no implicit replay follows.
3. A caller cancellation during local `GET /health` now explicitly closes the newly allocated bearer-holding `aiohttp.ClientSession`. Python 3.11 `CancelledError` is not an `Exception`, so prior timeout/general-exception cleanup did not run in that case. The cancel is re-raised, registry registration remains absent, and no Action, budget reservation, scanner or target request is invoked.

## Validation evidence

New `tests/qualification/test_mcp_all_bearers_numeric_loopback_20261022.py` tests the six representative bearer-capable adapter classes across DNS, nonstandard loopback and remote hosts with mocked session creation asserted not called, JSON-credential initialize denial before any connection, and actual harmless ephemeral `127.0.0.1` aiohttp authenticated health route with registration-only state (`_initialized=false`, no executable tools).

New `tests/qualification/test_mcp_cancelled_bearer_handshake_20261022.py` uses actual ephemeral localhost aiohttp server and a held health handler; cancels both a direct `MCPConnection.connect` and `MCPRegistry.register_server`, verifies the cancelled original bearer session closed, the registry did not record the endpoint, and neither path attempted original Action execution. No real configured port, third-party Burp, cloud, Shodan, paid provider, app DB, Docker or target was accessed.

**Observed selections:** first new bearer/adjacent local ping, identity and MCP protocol selection **39 passed**; new combined protocol/loopback/cancellation selection **38 passed**. A separate post-JSON-credential check with protocol+ping selection **39 passed**; these overlap and should not be added as distinct coverage counts. New tests are Black-formatted; existing heavily dirty protocol file was narrowly patched only (full-file Black would reformat unrelated existing code).

**Limitations:** no deployment remote TLS adapter, signed 0027 original Action effects, source-map independently signed native PID/nonroot readonly mount, cloud IAM, externally available Burp or independently authenticated target-owner effects. A local HTTP 200 is still transport-only telemetry. Revocation and cancellation after an actual remote protected Action remain subject to original UNKNOWN one-use nonreplayability.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
