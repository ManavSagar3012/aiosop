# Lifecycle repair ledger — 22 October 2026

This ledger tracks repairs against the [24-finding audit](2026-10-22-aiosop-lifecycle-audit.md).
It is not an end-to-end completion or release certificate. The shared checkout
also contains concurrent changes outside this repair set.

## Implemented repairs

| Findings | Changes | Remaining acceptance boundary |
| --- | --- | --- |
| F01–F03 | Preserve Secure, expiry and HttpOnly cookie metadata; pin session credentials to an explicit origin; validate every redirect before transport; persist intermediate cookie rotation and response-directory cookie paths. | Origin pinning is not live signed-ROE validation or DNS/network isolation. Legacy sessions need an explicit imported origin. |
| F04–F05 | Only completed tasks satisfy phase completion. Approval waits, unresolved dispatch, failed and cancelled tasks block progression. Graph outages and malformed statistics block automatic advancement. | Durable phase-generation accounting remains open. |
| F07 | Explicit implemented task declarations replace accept-all agent selection. Unknown agent classes default deny. | Individual MCP source admission can still make declared tasks unavailable. |
| F08 | Vulnerability helper copies its payload. Audit corrected: normal BaseAgent execution already deep-copied the task. | Direct-call mutation was not a demonstrated normal-path signature bypass. |
| F09 | Local Cloud task separates current canonical scheduler metadata from business parameters; forged versions and extra business fields fail. | A full signed orchestration-to-Checkov evidence journey is not established by adapter tests. |
| F10 | Remove fabricated Mobile/Stateful findings and no-op specialist success. Unsupported operations are failures, with no unnecessary model reasoning call for unavailable Mobile/NextJS/Cloud metadata work. | Missing specialist implementations remain missing. |
| F11 | CLI submits the original signed ROE envelope, enforces matching scope, lists actual API engagements, and returns nonzero on API failures without echoing private upstream errors. | Full CLI signed live create/list/halt journey remains to qualify. |
| F12 | Ship migrations and Alembic configuration in the image. Isolate Poetry from the application environment so sync cannot uninstall the installer. Alembic CLI uses the configured application database. | Production deployment and operator enrollment are separate gates. |
| F13–F14 | Unique default report generations; create-only artifact publication, serialized writers, manifest last, no overwrite of original bytes. Configured persistent storage in Compose/Kubernetes and absolute root required in production. | Crash-created partial generations require a new version; no automatic stale-lock takeover. Kubernetes storage provisioning has not been tested. |
| F20–F22 | CI covers all Python tests with per-test limits and UI contracts. Container startup uses real databases. Missing qualification suites/report failures fail. Release workflow uploads a draft instead of writing a fixed PASS certificate. | CI itself has not run on a remote runner. Global lint/type debt and full release qualification remain separate. |
| F23–F24 | Critical extracted scheduler/phase methods delegate to canonical implementations. Neo4j makes one cleaned-up driver attempt; startup coordinates bounded transient retries. Migration logging preserves existing loggers. | Other extracted duplication and all startup outage combinations still require coverage. |

## Verified observations

- Focused core repair suite: 73 passed before the final concurrency test addition.
- Joined fresh PostgreSQL → source admission API → native Browser → actual local
  Chromium test: 1 passed in 58.83 seconds. Browser-to-API TLS is simulated by
  an ASGI bridge; it does not qualify a production HTTPS handshake.
- Fresh image `ai-osop:repair-20261022`: built successfully. Disposable fresh
  PostgreSQL/Redis/Neo4j startup passed and Alembic reported current head.
  Development readiness is deliberately **degraded** for unprovisioned MCPs.
- UI: typecheck passed; 336 contract tests passed; production build passed.
- Full Python regression completed: **6,891 passed, 490 skipped, 1 failed**
  in 457.53 seconds. The remaining failure was a nondeterministic test mutation:
  replacing a signature character with `A` sometimes left it unchanged.
  After making the mutation deterministic, that entire SourceMap module passed:
  **47 passed**. No new complete-suite run was performed after that test-only fix.
- Targeted signed-handoff, release-admission and subscription contracts:
  **60 passed**. Another focused CLI, retry, Temporal and publication run:
  **51 passed**. These selections overlap; do not add their counts to the full run.
- Scoped flake8 exposed existing formatting/import debt. No global lint or
  mypy pass is claimed.

Transient logs and disposable-check evidence are under `.runtime/repair-*` and
`.runtime/fresh-container/`; these are intentionally untracked.

## Open gaps: do not relabel these as completed

1. **F06:** atomic durable phase transition + complete task intents + event
   outbox with cross-replica CAS, idempotent delivery and crash recovery.
   The current phase transition still persists its phase before all phase-entry
   scheduling completes. A superficial in-memory rollback cannot undo effects.
2. **F15–F16:** actual scanner dispatch across the fleet, independently admitted
   signed source authority, one-use redemption, cancellation/status and remote
   outcome reconciliation; deployed Burp/source contract parity. An inert
   authority-status endpoint or process health is not scanner execution.
3. **F17:** deployable production model-provider host enrollment, credential
   resolver, independently bounded budget/usage settlement and restart behavior.
   A local Ollama response alone does not satisfy that admission contract.
4. **F18:** portable service installer and reliable process ownership/configuration
   lifecycle. The existing workspace recovery launcher is not a portable installer.
5. **F19:** classify and execute required opt-in skipped gates. The complete
   suite ran and its final failing module was repaired/rerun, but this is not
   a single complete-suite green result or proof for 490 skipped checks.
6. Run the complete local signed engagement lifecycle, approvals, target-side
   evidence, report generation, independent review, release denial/allow,
   restart and emergency halt. Retain signed ROE, UNKNOWN quarantine and release
   controls throughout. No external scanning is needed for these repairs.

No paid subscription, external scan, fabricated evidence, or disabled safety
gate is part of this repair set.
