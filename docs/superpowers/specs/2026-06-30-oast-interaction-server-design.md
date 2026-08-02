# OAST Interaction Server — Design Spec

**Date:** 2026-06-30
**Status:** Approved (design) — pending spec review
**Roadmap item:** R1 (highest-ROI gap from `BUG_BOUNTY_PLATFORM_AUDIT.md`)

## Problem

AIOSOP cannot confirm any **blind / out-of-band** vulnerability class — blind SSRF,
blind XSS, blind SQLi, XXE-OOB, blind RCE. These are top-paying, low-duplicate bug
bounty classes, and all of them are invisible to the platform today because there is
no server the target can call back to. Adding an Out-of-band Application Security
Testing (OAST) interaction server unlocks this entire tier, starting with **blind SSRF**.

The platform's invariant is *no finding without active confirmation* (`is_simulated()`,
`reality_gate`). OAST extends that invariant to blind classes: a finding is minted only
when a **real callback is captured**, never on absence of a callback.

## Scope (this build)

In scope:
- A self-hosted OAST interaction server (HTTP capture) as a new MCP server.
- Per-probe correlation tokens; capture of any inbound request keyed by token.
- An `OASTAdapter` and an `ssrf_scan` task in `vuln_agent` as the first consumer.
- Live validation of blind SSRF against OWASP Juice Shop.

Explicitly OUT of scope (follow-ups, noted to avoid scope creep — YAGNI):
- DNS listener / subdomain tokens (HTTP-first; architecture stays DNS-ready).
- `CorrelationEngine` async path for delayed callbacks (synchronous poll for now).
- Cloud-metadata (169.254.169.254) chaining after SSRF confirmation.
- Wiring blind XSS / blind SQLi consumers (the server serves them; agents come later).

## Decisions (from brainstorming)

1. **Reachability:** configurable hybrid — capture host/port/scheme from settings
   (`oast_public_host` default `127.0.0.1`), so local validation works now and a public
   domain can be pointed at it later without code change.
2. **Protocols:** HTTP first; correlation/token layer kept protocol-agnostic so a DNS
   listener drops in later.
3. **First consumer:** blind SSRF, validated against Juice Shop's server-side URL fetch.

## Architecture

Three new components, following existing platform patterns
(`browser_mcp.py` / `turbo_intruder_mcp.py` for the server; `SecurityBridgeAdapter`
for the adapter; the `sqli_scan`/`xss_scan` tasks for the agent consumer).

### Component 1 — `mcp-servers/python/oast_mcp.py` (server, port 8099)

One FastAPI app, two roles on one port:

- **MCP interface:** `/health`, `/mcp/initialize`, `/mcp/execute`. Standard envelope
  `{request_id, status, result}` (the same envelope correction applied to turbo-intruder).
  Tools:
  - `oast_register({label?, ttl_seconds?})` → `{status, token, callback_url}`.
    Mints a unique token (`uuid4().hex[:20]`), stores `ProbeMeta{label, created_at}`.
    `callback_url = f"{scheme}://{public_host}:{port}/{token}"`.
  - `oast_poll({token})` → `{status, token, hit_count, interactions[]}`.
- **Capture listener:** a catch-all route matching every other method/path. It extracts
  the first path segment as the token, and if that token is registered, appends an
  `Interaction{ts, method, path, source_ip, headers(subset), body_snippet}` to that
  token's list. Responds with a benign `200` (1×1 GIF) so `<img>`/fetch beacons succeed.
  Unregistered tokens are ignored (logged, not stored) to bound memory.

State (in-memory, lock-guarded):
- `tokens: dict[str, ProbeMeta]`
- `interactions: dict[str, list[Interaction]]`
- TTL prune: tokens + interactions older than `ttl_seconds` (default 3600) are dropped.

Settings (added to `core/config.py`): `oast_public_host="127.0.0.1"`, `oast_port=8099`,
`oast_scheme="http"`, `oast_mcp_timeout` (reuse existing MCP timeout if present).

### Component 2 — `src/ai_osop/adapters/oast_mcp.py` (`OASTAdapter`)

`SERVER_ID = "oast-mcp"`. Methods:
- `initialize(scope, session_id)` — registry handshake (same as other adapters).
- `register(label) -> (token, callback_url)` — calls `oast_register`.
- `poll(token) -> list[dict]` — calls `oast_poll`, returns interactions.

### Component 3 — `ssrf_scan` task in `vuln_agent`

Input payload (the callback URL can be injected into a query param OR a body field —
both are supported, since real SSRF sinks are often POST body fields like Juice Shop's
profile-image URL):
- `url` — the request URL to send to the target.
- `param` — query parameter to inject into (reuses `_inject_payload` from `xss_scan`,
  including the `OASTINJECT` placeholder form). Use for GET-style URL-fetch sinks.
- `body_field` — name of a JSON body field to set to the callback URL. Use for POST/PUT
  sinks (e.g. Juice Shop profile-image URL). Exactly one of `param`/`body_field` is used.
- `method` (default GET; POST/PUT when `body_field` set), `base_body` (other body fields),
  `token`/`cookie` (auth).
- `engagement_id` (injected by `_execute`).
- `poll_seconds` (default 15), `poll_interval` (default 1.5).

Flow:
1. Initialize `OASTAdapter` for the engagement (scope) if a session exists.
2. `token, callback_url = await oast.register(label=f"ssrf:{url}")`.
3. Inject `callback_url` into `param`/sink; send the request via `httpx` (authed).
4. Poll `oast.poll(token)` every `poll_interval` up to `poll_seconds`.
5. On first interaction → CONFIRMED: mint `Vulnerability(vuln_type=SSRF, cwe="CWE-918",
   severity=HIGH, validated=True, confidence=0.97, tool_source="oast_ssrf",
   evidence=[{provenance:"oast", callback record, injected_param, callback_url}])`,
   persist via `graph_memory.add_vulnerability`.
6. No interaction in window → `{status: success, confirmed: false, findings_count: 0}`
   (honest negative — **no finding**).

## Data flow

```
ssrf_scan
  -> OASTAdapter.register()      -> oast-mcp: mint token + callback_url
  -> inject callback_url, send request (authed) to target
  -> TARGET server fetches callback_url -> oast-mcp catch-all -> Interaction recorded
  -> OASTAdapter.poll(token) loop -> Interaction returned
  -> mint CONFIRMED Vulnerability(SSRF, CWE-918) with callback evidence -> graph_memory
```

## Error handling & honesty invariants

- oast-mcp unreachable → `register` raises `MCPException` → task returns `{status:error}`,
  no finding.
- No callback within the poll window → not confirmed, **no finding** (absence ≠ vuln).
- Only the benign beacon URL is injected — no destructive payloads; in-scope and safe.
- Minted finding satisfies `is_simulated() == False` (real `tool_source`, `provenance:"oast"`).
- TTL prune bounds server memory.

## Token scheme

Path-based: `http://{public_host}:8099/{token}`, `token = uuid4().hex[:20]`. Covers
URL-fetch SSRF sinks (full URL incl. path). Subdomain/DNS-ready form `{token}.{host}`
is a documented later upgrade for host-only sinks; not built now.

## Testing

Offline unit tests (FastAPI `TestClient`, no network):
- `oast_register` returns a unique token + well-formed callback_url.
- catch-all records an interaction keyed by token; `/{token}/extra/path` parses to token.
- `oast_poll` returns recorded hits; unknown token → empty.
- TTL prune drops expired tokens.

Live E2E (vs Juice Shop, requires oast-mcp + Juice Shop up):
- Stand up oast-mcp; authenticate to Juice Shop; set the profile-image URL (server-side
  fetch sink) to the callback_url; assert a callback is captured and `ssrf_scan` mints a
  validated `SSRF` finding with the callback evidence.
- Exact SSRF sink confirmed empirically during build; the OAST mechanism is validated by
  the capture regardless.

Integration: add oast-mcp to `launch_real.ps1` (REAL classification, port 8099).

## Files touched

- New: `mcp-servers/python/oast_mcp.py`, `src/ai_osop/adapters/oast_mcp.py`,
  `tests/test_oast_unit.py`, `.runlogs/validate_ssrf_oast_e2e.py`.
- Edited: `src/ai_osop/agents/vuln_agent.py` (`ssrf_scan` + adapter wiring),
  `src/ai_osop/core/config.py` (oast settings), `launch_real.ps1`.

## Success criteria

1. oast-mcp starts, exposes `oast_register`/`oast_poll`, captures inbound callbacks.
2. A real cross-process callback (target → oast-mcp) is recorded and correlated by token.
3. `ssrf_scan` mints a CONFIRMED, validated SSRF finding ONLY when a callback is captured;
   honest negative otherwise.
4. Live blind-SSRF validation against Juice Shop passes.
5. Offline unit tests pass; no regressions in existing suite.
