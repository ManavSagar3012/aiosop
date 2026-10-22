# Disabled Turbo Intruder: actual host-owned Python process, 2026-10-22

**Partial operational improvement, NOT an attack integration or release certificate.**

## Production path

- Source: `src/ai_osop/mcp/python_inert_host_supervisor.py`.
- Mounted senior host-only API: `src/ai_osop/api/routers/python_inert_turbo.py`, under `/system/python-inert-turbo/{status,start,stop}` (GET, POST, POST).
- `src/ai_osop/api/main.py` mounts the router and calls `shutdown_host_python_inert_turbo(app)` during lifespan teardown. **Startup never launches a process**.
- `ui/src/pages/Administration.tsx` mounts `PythonInertTurboOperatorPanel`; its service uses only authenticated GET status, never web-based process start/stop, provider tool execution or scanner routes.
- The host installer is `install_host_python_inert_turbo(app, controller)`. It must be called only by trusted host bootstrap, with an explicit `PythonInertHostSupervisor(reviewed_source_sha256=..., reviewed_interpreter_sha256=..., reviewed_runtime_sha256=..., explicitly_opted_in=True)`. All three SHA-256 values originate from independent operator review; the API never accepts them from clients, environment, query, headers or JSON. No host pin is currently enrolled; ordinary requests return `host_unconfigured` and denied start.
- The only allowed script is the fixed repository `mcp-servers/python/turbo_intruder_mcp.py`, which hard-codes HTTP `/health` **503** and `/mcp/execute` **503**. The host supervisor verifies the actual script bytes and both Python executable bytes before any owned process, uses numeric `127.0.0.1` OS-assigned ephemeral port only, rejects configured production ports, sanitizes all inherited OSOP/cloud/provider/proxy credentials, verifies process lineage and independently observed PID/listener, then verifies the exact bounded real 503 health response.
- On Windows, the virtualenv Python launcher may start a child Python process that actually owns the TCP socket. Early testing established that the child PID differs from the launcher PID. The production supervisor now verifies that listener owner is the original OS-owned launcher or its descendant and pins executable paths to current Python/base runtime; teardown reaps verified child/parent PIDs using PID+creation-time checks. A failed or cancelled startup cannot imply process readiness and cleans up owned children. No external host or target is contacted.
- Neither a process PID, signed senior JWT nor disabled-service HTTP exchange implies tool authorization, `0033` supervision, target-owned effects, 11-service availability or production certification. Explicit senior host `POST /start` is a *process-only* operation; it never calls `/mcp/execute`.

## Focused qualifications

1. `tests/qualification/test_python_turbo_inert_host_supervisor_20261022.py`: genuine Windows subprocess+child+owned ephemeral loopback listener, direct `/mcp/execute` 503 denial (synthetic `.invalid` URL is only inert JSON input), offline SHA/source/interpreter negative pins, secret/proxy-free inherited env, cancellation and teardown. Actual `MCPRegistry.register_server` against the owned disabled HTTP 503 child is denied before manifest registration; there is no tool execution. The first implementation incorrectly assumed virtualenv launcher PID owned the socket; a real test failed and private bounded OS PID observations found an owned child. Repaired and reran: **tests passed**.
2. `tests/qualification/test_python_turbo_host_mounted_operator_20261022.py`: real mounted FastAPI operator auth, forged browser origin/query/config rejection, absent host pin denies, explicitly installed fixed host pins, real explicit start/status/stop and non-promotable receipt, no process after teardown. Combined with the supervisor's first six focused tests, **9 passed** after actual registry-denial test added; another joined supervised recovery selection previously **16 passed** after independently pinned interpreter fixes.
3. `ui/tests/python-inert-turbo-operator-20261022.test.mjs` plus existing native Go operator tests: **8 passed**; no web start/stop/execute UI. TypeScript `npm --prefix ui run typecheck` and Vite `npm --prefix ui run build` passed, **2671 modules transformed**.
4. A previously passing but environment-sensitive `test_mcp_eleven_supervised_recovery_join_20261022.py::test_auth_host_body_and_unconfigured_registry_never_open_transport` started receiving HTTP 200 instead of expected 409 when it used the mutable application-configured MCP endpoint. The test now pins a known closed numeric local port 1 and never touches a possibly live configured MCP service. Focused adjacent selection **15 passed**, later pinned interpreter combined selection **16 passed**. This is a test isolation correction, not evidence that real production MCPs are initialized.

## Remaining blockers

Host-provisioned executable SHA pins and independently authenticated senior administration are not installed in a running API; neither configured production port 8098 nor all 11 MCP fleet processes were started here. The disabled Turbo server must **remain disabled** until independent signed current Task/Flow/ROE/Action authorization and authorized target-effect proof exist. The operator startup path does not mint them.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
