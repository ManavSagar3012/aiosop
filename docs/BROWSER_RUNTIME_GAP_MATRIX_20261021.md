# Browser MCP: Current Runtime Qualification and Gaps (2026-10-21)

**Verdict: NOT PRODUCTION CERTIFIED / NOT READY.** This is an inspection of the
current original dirty `/burp_mcp/ai-osop` files, with one new isolated offline
regression. It is not an authorization to browse a live target or an assertion
that all 11 MCP integrations work end to end.

## Current execution and trust chain

1. `src/ai_osop/api/main.py` registers the central
   `native_browser_source_authority.router` at
   `POST /native-browser/source-preflight`. MCP server configuration lists
   `browser-mcp`; the live provider code is
   `mcp-servers/python/browser_mcp.py` (port 8091) and the adapter is
   `src/ai_osop/adapters/browser_mcp.py`. Registration and code are verified;
   actual fleet startup or healthy deployment is **not** verified here.
2. The original 0027 `flow_mcp_action_dispatches`/immutable event history
   prepares, reserves and marks an Action `unknown`. The
   `flow_mcp_action_executor.py` gate admits only the exact reviewed Browser
   `navigate` request with `url`, `action`, `user_label` and optional explicit
   `evidence_mode`. The declaration is `RECON_ACTIVE` with approval and scope
   checks. Signed click, fill, eval, separate capture or replay are not
   independently admitted through this path.
3. Native `/mcp/execute` checks a dedicated bearer, validates the original
   request/task/engagement/server binding, the local signed origin allowlist,
   receipt signer and authenticated HAR mount. Its on-disk
   `RequestJournal.reserve()` performs an exclusive write before it posts to
   central 0034. A retry of that request gets `duplicate_request` even after
   an uncertain outcome or corrupted journal.
4. The central 0034 store uses the **database original** 0027 Action,
   revalidates Flow/Task/current authority/ROE/reviewer/lease/declaration,
   checks exact URL SHA and origin, inserts an immutable source admission in
   one PostgreSQL transaction with unique Action/request indexes, and signs
   22 claims with a distinct Ed25519 issuer. Native verifies the complete
   signed claim set and 10-second expiry; the one source POST has no retry.
   These checks are verified in source. The new test substitutes FakePG for
   actual application PostgreSQL, so its fake authority callbacks are **not**
   independently verified Flow, Task or reviewer decisions.
5. Native Playwright checks final page URL, successful HTTP status and the
   navigation request/redirect chain. On the `screenshot_dom_har` Action it
   writes all three capture artifacts to the pinned tenant mount, rereads
   original bytes, verifies length/SHA, and signs a separate
   `evidence_attestation` joining artifact SHA/size/path, original source
   `preflight_id`, original `action_id`, authorization SHA and request tuple.
   The MCP response returns metadata, not raw screenshot/DOM/HAR content.
6. `/mcp/request/status` reads the native local journal and issues a new
   signed **provider status** assertion only for a matching terminal record.
   Missing, malformed, wrong Task, wrong engagement, wrong request or wrong
   server state returns unsigned `unknown`. The central reconciliation layer
   (`MCPConnection.reconcile_persisted_status`, `FlowMCPActionExecutor.reconcile`)
   separately checks durable original claims and a valid freshly signed
   enrolled provider receipt before settling 0027. A native `succeeded`
   status never itself changes original 0027 `unknown` to `finished`.

## Qualification matrix

| Boundary | Current evidence | Limit / disposition |
|---|---|---|
| 0027 Action identity and one-shot 0034 issuer | Source inspection of migrations `0027`/`0034`, central router and `BrowserSourceAuthorityStore`; FakePG central admission included in new test | No new real PostgreSQL/Alembic migration verification; independent DB ownership/ROE not claimed |
| Wrong original Flow | FakePG original Flow ID mutation invalidates original intent and refuses 0034 | FakePG Row and mock authority, not a live DB Flow mutation |
| Wrong Task and exact URL | Native/source checks and new central ASGI negative checks; same-origin path/query changes require original URL SHA | Synthetic reviewed Action and local address |
| Current revocation | New central ASGI test denies simulated reviewer revocation before admission; pre-existing full capture source/real-PG test also exercises actual reviewer/lease edits | New test uses `MCPActionDenied` callback; no fresh production revocation measured here |
| Native signed original capture | New headless cached Chromium request against an owned `127.0.0.1` listener; actual original PNG, DOM and HAR reread and provider Ed25519 verification | Local Chromium, not an external tenant target or independently reviewed target effect |
| Evidence SHA/identity coupling | New capture verifies original bytes against signed three-artifact digest and 0034 source/action identities | Provider signature is testimony; mount bytes can be altered later unless external immutable retention is enforced |
| Status route and recovery | New ASGI test verifies signed terminal status, forged status fields rejected by independent verifier, cross-tenant/task/request/server status is unsigned unknown, missing bearer is 401 | Signed status contains no SHA/capture evidence and does not itself prove target effect or current authorization |
| Journal poison and replay | New test writes wrong binding, duplicate JSON status key, oversize data and partial JSON into **owned temporary** journal; status is unknown and no browser re-navigation occurs | Local filesystem durability on Windows does not prove power-loss directory fsync; signer/journal compromise outside threat model |
| Source ACK lost after central commit | Existing `tests/qualification/test_browser_full_capture_ack_fence_worker30_20261021.py` covers source ACK loss and invalid signature, original unknown, no new Chromium navigation or reissue | Historical passing evidence in a separate test; no redundant run for new counts |
| Production dispatch integration | Source trace of `MCPConnection` provider receipt parsing, source status route, `FlowMCPActionExecutor.reconcile` | No fleet-wide live operation, app DB state transition, or connected target execution in this worker |

## Outstanding production gaps

- **Evidence retention and recovery:** the status endpoint attests local
  execution state, not the original PNG/DOM/HAR digest or current intact
  artifacts. A later byte mutation leaves the historical status receipt valid.
  A trustworthy completed-capture recovery must independently join signed
  evidence claims with presently retrievable original bytes and central 0034,
  0027, tenant and Action identity before promoting *evidence*.
- **Live central qualification:** the newly added negative Flow, Task, URL and
  reviewer checks use a FakePG original Action and an in-process ASGI hop. A
  real migrated PG 0027→0034 commit, unique-index concurrency, revocation
  racing admission, operator authority and TLS/CA chain remain prerequisites
  to asserting production readiness. There are pre-existing
  `test_browser_real_pg_source_playwright_20261020.py` and
  `test_browser_full_capture_join_20261021.py` qualification files; do not
  equate their presence with verification in this run.
- **Mid-flight revocation:** independent Flow/Task/reviewer revocation is
  evaluated at 0034 admission. It is not continuously observed during a
  Playwright navigation and subsequent screenshot/DOM/HAR; expiry and the
  signed local origin/mount are checked during capture. Do not describe a
  completed 0034 admission as permanent permission.
- **Issuer bearer privilege:** the native Browser currently carries the
  dedicated `OSOP_BROWSER_SOURCE_SERVICE_TOKEN` for central admission. It
  is separate from the inbound Browser bearer but remains a consequential
  bearer available to the native process. A further architecture review
  should consider a host-owned issuance channel with only public trust roots
  in the browser process, while preserving current source proof checks.
- **Deployment:** producer mount provenance (`container_image_sha256`) is
  deployment-declared, not independently measured by this test. Browser
  request/status routes use loopback HTTP. A real deployment must prove the
  intended process isolation, source TLS, operating system file permissions,
  mount provenance, and reader/writer access controls.

## Scope, invocation and evidence class

New owned test:

`tests/qualification/test_browser_hardened_status_recovery_20261021.py`

Invocation (project venv; no Docker or app DB):

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_browser_hardened_status_recovery_20261021.py -q
```

Chromium starts only if an already cached local executable exists. Both
listeners are bound to owned loopback ports; a Playwright request interceptor
allows only the owned site and an independent loopback deny proxy handles
browser background requests. The new test simulates central PostgreSQL and
does **not** exercise actual HTTPS handshakes. Run result and any limitations
are recorded below; absence of external targets is intentional. No changes
were made to production source or protected files.

**Observed 2026-10-21:** `1 passed, 4 warnings in 15.07s` on the repository
`.venv` Python. The four warnings are FastAPI lifespan / `on_event`
deprecations, not failing assertions. An initial attempt with the system
Python failed during collection (`neo4j` missing); the repository `.venv`
run completed successfully. Only this new qualification test was run, so no
historical passing count was added to a fleet-wide total.
