# AI-OSOP engagement lifecycle audit

Date: 2026-10-22. Base commit: `1fd93257`, with existing working-tree changes.
Verdict: **not verified end to end; not ready for production release**.

This audit covers onboarding, signed scope, task admission, agent routing,
authenticated replay, MCP execution, phase progression, evidence/report
storage, recovery, packaging and release qualification. It identifies 24
findings: security/correctness defects, operational gaps and maintenance risks.
An intentionally closed authorization gate is labelled as a gap, not an
authorization vulnerability. Each finding has a proposed fix and a testable
acceptance condition. This audit made no product code changes; pre-existing
and concurrent changes were preserved.

The shared checkout was changing during the review, including Burp source,
the API router wiring and reviewed-library import components. Findings refer
to the inspected source plus separately described deployed observations.
This is not a clean-commit certification or a claim that every possible bug
has been found. No external target was scanned during this audit.

## Evidence and current state

| Verification | Result and boundary |
| --- | --- |
| Re-run of pytest's previously failing selection | **58 failed, 7 passed, 54 deselected**, 35.50 seconds. This was not a full-suite run. |
| Focused ROE/scope/execution gates, emergency/durable halt, phase, reporting and differential-auth tests | **110 passed**, 21.77 seconds. |
| Current UI tests | **328 passed**, zero failed. |
| Current UI type checking | Passed. |
| Live API | `/health` 200; `/ready` 200 with body **degraded** in development. |
| Live backing databases | PostgreSQL, Redis and Neo4j healthy. |
| Live fleet | All eleven ports responded; Burp, Browser, Cloud and Threat Intel health endpoints said ready; seven returned 503 unavailable. This does not establish execution authority. |
| API fleet accounting | Eleven registered, three initialized, two of five critical initialized, **zero runtime verified**. The late-started Burp process was not automatically qualified by the API. |
| Packaged `ai-osop:local` image, isolated inspection | `/app/src/.../schema_migrations.py` exists; `/app/alembic.ini` and `/app/migrations` do not. |

The earlier full run is documented in `docs/VALIDATION_20261022.md`: 6,687
passed, 67 failed and 483 skipped at that earlier snapshot. The selected rerun
and UI count above must not be presented as a later full Python pass.

Evidence is local in `.runtime/`:

- `audit-lifecycle-probes-20261022.json`: real lifecycle/agent methods with inert fixture stores.
- `audit-session-probes-20261022.json`: actual SessionClient and synthetic credentials using HTTPX MockTransport; no network.
- `audit-report-runner-probes-20261022.json`: actual report writer in a temporary directory and qualification runner with mocked child processes.
- `audit-cli-probe-20261022.json`: actual Click command and mocked HTTP rejection.
- `audit-live-status-20261022.json`: read-only service observations.
- `audit-source-manifest-20261022.json`: SHA-256 identities of key inspected sources.
- `audit-logging-probe-20261022.json`: isolated migration logging reproduction.
- `audit-last-failed-20261022.log`, `audit-controls-20261022.log`, `audit-ui-tests-20261022.log`, `audit-ui-types-20261022.log`.

## Lifecycle map

| Lifecycle boundary | What works in the reviewed slice | Main failures/gaps |
| --- | --- | --- |
| Install/start | Host-based lab API and databases run | F12, F14, F18, F24 |
| Identify operator / authorize engagement | Signed-ROE and scope tests pass | CLI cannot submit the required envelope: F11 |
| Schedule/approve | Durable authorization and one-shot machinery exist | Agent routing and payload binding: F07–F09; duplicated paths: F23 |
| Authenticate/replay | Session injection and differential engine exist | Credential isolation and rotation: F01–F03 |
| Execute tools/models | Some direct providers run | Inert/missing execution and enrollment: F15–F17 |
| Interpret results | Source/target distinction is preserved in important report controls | Fabricated/no-op specialist outputs: F10 |
| Advance/halt/recover | Focused halt tests pass | Completion and partial transition failures: F04–F06 |
| Persist/review/export | Signed artifact and review gates exist | Overwriting artifact identity and missing storage: F13–F14 |
| Qualify/release | UI tests and selected safety tests pass | Broken regressions, narrow CI, false qualification success and certificate claims: F19–F22 |

Priority definitions: **P1** should block the affected security or release
claim. **P2** is an operations, coverage or maintenance defect that must be
addressed before declaring the complete lifecycle supported. Priorities are
repair priorities, not externally validated CVSS ratings.

## Findings and fixes

### F01 — P1: imported Secure cookies are sent over HTTP

**Reproduced.** `src/ai_osop/auth/session_client.py:76` reconstructs cookies
with `httpx.Cookies.set(name, value, domain, path)` and drops their `secure`
attribute. A synthetic Secure cookie for `allowed.invalid` was included in an
HTTP request to that host. Domain scope alone does not protect the transport.

**Fix:** preserve cookie security attributes in the cookie jar; bind captured
credentials to approved origins, and refuse HTTPS-to-HTTP use unless explicitly
authorized for a separate lab identity. **Acceptance:** Secure cookies never
appear on HTTP; host-only/domain/path/expiry cases have regression coverage.

### F02 — P1: redirects can cross scope and carry custom credentials

**Reproduced.** `session_client.py:67`, `:95`, `:146` default to automatic
redirects and configure CSRF/extra headers globally. An HTTPS redirect from
`allowed.invalid` to `outside.invalid` was followed with synthetic `X-CSRF-Token`
and `X-API-Key` intact. HTTPX correctly removed the scoped cookie in this case;
that did not remove these other credentials. SessionClient has no current
signed-origin/redirect admission check.

**Fix:** disable automatic redirects; follow a bounded chain only after each
hop passes current signed origin, scheme, port and resolved-address checks.
Inject credentials after approval of that exact hop. **Acceptance:** same-host,
cross-host, alternate-port, downgrade, relative redirect and DNS-change cases
are covered; rejected hops produce zero outgoing credential-bearing requests.

### F03 — P2: cookies rotated on intermediate redirects are not persisted

**Reproduced.** `session_client.py:154–158` absorbs Set-Cookie only from the
final response. A cookie set on a 302 existed in the HTTP client's journey but
was absent from `UserSession.cookies` after the request. A later SessionClient
can therefore resume stale authentication.

**Fix:** absorb allowed-hop cookie changes from the full response history, or
from the manual redirect implementation required by F02. Persist rotations
atomically without importing cookies from rejected origins. **Acceptance:** a
302 rotation survives close/reopen of the authenticated session.

### F04 — P1: approval waits and unresolved effects count as completed phases

**Reproduced.** `src/ai_osop/orchestrator/orchestrator.py:3569` considers a
phase complete if no matching task is `pending` or `running`. The actual method
returned true for `awaiting_approval`, `dispatching`, `dispatch_unknown` and
`failed`. It also groups tasks by agent type rather than an explicit phase
execution generation. A phase can advance while operator input or outcome
reconciliation is still required.

**Fix:** define an explicit task-state machine and phase completion predicate.
Approval, dispatch-in-progress and unknown-effect states block advancement.
Failures require an explicit partial/failed outcome; phase membership must be
durable. **Acceptance:** a state-by-state matrix, including restart/replica
observations, proves that none of these states silently advances a phase.

### F05 — P1: graph failure is interpreted as zero vulnerabilities

**Reproduced.** `orchestrator.py:3532` catches `get_graph_stats` failure, assigns
an empty dictionary and reroutes vulnerability discovery to reporting. With
an injected graph error, the actual method returned `reporting`.

**Fix:** distinguish an authoritative empty result from an unavailable result.
Keep the phase blocked/degraded on unavailable data; resume only after a
successful current read. **Acceptance:** an empty healthy graph may select the
documented next phase; an outage may not produce that decision or a clean result.

### F06 — P1: phase state commits before its required work is safely recorded

**Reproduced.** `orchestrator.py:457` mutates the cached phase and persists it
before `_on_phase_enter`. When that dispatch step raised, the phase remained
`reconnaissance`, the durable-state writer had been called, and no successful
transition audit had been written. Retrying the original transition can now
fail its transition precondition; only some phase tasks might exist.

**Fix:** commit the phase CAS, deterministic phase-task intents and audit/outbox
record in one PostgreSQL transaction. Deliver task intents idempotently after
commit. **Acceptance:** crash/fault injection before and after each boundary
leaves either the old phase or a complete recoverable set of new phase intents.

### F07 — P1: generic agents claim specialist task types they cannot execute

**Reproduced.** `src/ai_osop/agents/base.py:121` returns true for every task
type. `api/main.py` registers general vulnerability, GraphQL, JS and mobile
agents under the same `VULN_ANALYSIS` type. The actual orchestrator selector at
`orchestrator.py:1130` picked the first generic vulnerability agent for
`analyze_deep_links` even when the mobile agent was idle; the generic executor
does not implement that task.

**Fix:** make task capabilities explicit and default-deny; register and validate
each `(agent type, task type)` pair before scheduling. **Acceptance:** every
advertised task routes to an implementation, unsupported tasks are rejected
before persistence/approval, and registration order cannot change routing.

### F08 — P2: direct vulnerability helper mutates its input task payload

**Direct-call digest change; scope corrected during repair.** `src/ai_osop/agents/vuln_agent.py:79–90` adds
`engagement_id` directly to `task.payload`. The fingerprint in
`src/ai_osop/safety/approval_binding.py:24` covers that field; only two approval
grant fields are excluded. The same task's digest changed when its real
executor entered a mocked downstream Nuclei helper. However, normal
`BaseAgent.execute` already makes a deep execution copy before calling this
helper. The direct-call reproduction did not demonstrate mutation of the
canonical signed task in the normal execution path or a signature bypass.
The repair also copies helper arguments, covering direct callers.

**Fix:** treat admitted payloads as immutable. Build a separate execution
context or copied helper arguments; keep the canonical signed bytes unchanged.
**Acceptance:** hashes and durable payload equality stay constant before,
during and after every agent execution, failure and retry path.

### F09 — P1: the new local Cloud task rejects real scheduler metadata

**Reproduced; includes recently added wiring.** `orchestrator.py:610` adds
`_authorization_version` to admitted task payloads. The local Cloud handler at
`agents/experimental/cloud_agent.py:52` rejects any nonempty payload. Its real
method rejected a payload containing only that scheduler field. The earlier
empty-payload adapter/agent tests did not test this scheduling boundary.

**Fix:** separate trusted execution metadata from user business parameters.
Validate that the business parameter object is empty; never simply trust or
strip arbitrary caller-supplied authorization fields. **Acceptance:** one real
signed Task reaches the pinned Checkov source, while caller paths/accounts and
forged reserved fields remain denied, with evidence persisted in PostgreSQL.

### F10 — P1: registered specialists still fabricate findings or report no-op success

**Reproduced plus static confirmation.**
`agents/experimental/mobile_agent.py:45` generated a fixed reset-password link
and account-takeover finding solely from an input link containing `reset`.
`nextjs_agent.py:50` reported an audit complete/no direct IDOR for an empty
payload after only a mocked reasoning step. Mobile interception, NextJS
middleware and Cloud metadata paths also return success without implementing
their stated operation. These classes are registered by the API despite stale
comments saying they are not instantiated.

**Fix:** return explicit `unsupported`/`not_executed` outcomes until an actual
implementation exists; keep these states out of clean-result and success
counts. Implement supported slices with original request/response evidence.
**Acceptance:** no finding, interception flag or clean-test result can be
produced without the required target observations; stub agents do not advertise
their unimplemented capabilities.

### F11 — P1: CLI engagement creation cannot satisfy the API and hides failure

**Reproduced.** `src/ai_osop/cli.py:42` sends domain fields without `signed_roe`.
`api/routers/engagements.py:188` requires that envelope. The actual Click
command, given a mocked 403 rejection, printed the error but exited **0**.
The list command is also a placeholder rather than an API listing.

**Fix:** add bounded signed-envelope import using the same schema as the UI;
implement actual listing; raise Click errors/nonzero exit status on failures
and transport timeouts. **Acceptance:** CLI create/list/halt work with the real
local API, invalid signatures fail closed, and shell automation cannot interpret
an HTTP rejection as success.

### F12 — P1: the container image omits required migrations

**Confirmed in the built image and Dockerfile.** `Dockerfile:27–29` copies src,
one MCP and README, but not `alembic.ini` or `migrations/`.
`memory/schema_migrations.py:90` requires both under `/app`. Inspection of
`ai-osop:local` with no network found both absent. The host startup working
does not qualify the container's database startup path.

**Fix:** package and locate the exact migration graph as a versioned runtime
asset. **Acceptance:** the built image initializes a blank disposable database,
upgrades a known prior schema, refuses an inconsistent schema and reaches the
appropriate readiness state without host source mounts.

### F13 — P1: report regeneration overwrites an existing evidence identity

**Reproduced in a temporary directory.** `agents/reporting_agent.py:405`
defaults all generations to `v1.0`; `:642` builds a stable report ID from that
version; `:712` replaces existing artifact files. Running the real writer twice
with changed fixture graph stats produced the same report ID and overwrote its
original JSON bytes. Each file is atomically replaced, but the bundle as a
whole is not atomically published. This undermines immutable report references
and can make concurrent readers see mismatched artifacts.

**Fix:** allocate unique immutable report generations in PostgreSQL, publish a
complete content-addressed bundle once, and expose it only after an atomic
manifest commit. Reject identity reuse with changed bytes. **Acceptance:**
retries, two workers and crashes cannot overwrite or mix a prior report; old
review/signature references continue to verify exactly their original bytes.

### F14 — P1: deployment storage does not support the report writer/reader contract

**Static deployment finding.** The writer uses relative `reports/` at
`reporting_agent.py:695`. `reporting/attested_storage.py:78` requires an absolute
configured `OSOP_ATTESTED_REPORT_ROOT` pointing to those same files.
`k8s/orchestrator-deployment.yaml:41` sets a read-only root filesystem but mounts
no report storage and supplies no report-root setting. It runs two replicas.
The shown deployment cannot rely on local per-process files for generation
and cross-replica retrieval.

**Fix:** use one configured writer/reader storage abstraction with a persistent,
replica-visible immutable artifact store. Keep `/tmp` separate and preserve
path/link/digest validation. **Acceptance:** generate on replica A, restart it,
then read/verify on B under the exact production securityContext.

### F15 — P1 gap: process availability does not supply scanner execution

**Live and static.** `mcp-servers/go/sdk/server.go:128` deliberately never
dispatches registered scanner handlers. The grant issuer in
`memory/native_mcp_execution_grants.py:180` only admits `authority_status`.
Turbo Intruder deliberately returns unavailable. Source Map currently lacks
its required source setup. Thus restarting the fleet cannot produce a real
Nuclei/recon/payload/security-bridge scan. This is correct safety denial, but
missing product functionality.

**Fix:** implement one tool-specific signed execution contract at a time:
current ROE/owner/Flow/Task, approval where required, bounded arguments, source
scope enforcement, one-use durable claim, timeout/cancel/status reconciliation
and original evidence receipts. **Acceptance:** one controlled positive and
one denied/out-of-scope case pass through API → Task → provider → original
evidence → review; UNKNOWN never authorizes an automatic repeat. For no-cost
operation, declare supported free-source capabilities explicitly; do not claim
that an alternative supplies Shodan's entire indexed host database.

### F16 — P1 gap: deployed Burp and current source have different trust contracts

**Live/source mismatch.** The running Burp endpoint still returned ready; the
previous bounded assessment used its old direct request tool. Current dirty
Burp source now denies execution with
`independent_host_burp_authority_not_enrolled` and advertises no executable
tools. Neither version supplies the adapter's complete signed observation and
bound receipt contract. Earlier assessment evidence also demonstrated malformed
JSON from the old body's manual escaping. Current source denial does not prove
that a corrected serializer was deployed or exercised.

**Fix:** version/digest the extension, serialize with a real JSON library,
implement the source authority/receipt contract, provision credentials without
publishing them, reload and reconnect the exact deployed provider.
**Acceptance:** reported build identity matches loaded code; quotes/backslashes
round-trip; unauthorized local calls are denied; one authorized request and its
original response pass the full adapter/executor evidence path. Community-only
operation must advertise only supported tools; professional scanning cannot be
assumed available.

### F17 — P1 gap: production model dispatch has an enrollment hook but no shipped bootstrap

**Static integration gap.** `api/main.py` selects a pending guarded client in
production unless a process-local host runtime was installed before lifespan.
`core/provider_host_runtime_slot_20261022.py:27` defines that installer, but the
reviewed `src/` and `scripts/` contain no caller. The Docker command starts
plain uvicorn. An environment provider key or working local Ollama endpoint
does not install this trust chain. Default production dispatch therefore remains
closed, as intended.

**Fix:** deliver a host-controlled enrollment entrypoint and documented key,
route and durable call-fence provisioning, including the approved local Ollama
profile. Do not add an unauthenticated HTTP/env bypass. **Acceptance:** a real
signed lab task performs completion and embedding through the API with usage
reservation/settlement; revoked enrollment and a second replica cannot bypass
or double-charge its one-use call fence. No paid provider is required.

### F18 — P2: the local launcher is a workspace recovery script, not an installer

**Static; includes newly added operational code.**
`scripts/ops/start_local_stack.py:76` assumes named dated PostgreSQL/Redis
containers, fixed mapped ports, cached images, a preinstalled Checkov venv and
an ignored `.env.opensource`. `_launch` treats any existing socket as an
unverified listener, and a starting process without a bound socket has no
single-instance lock preventing another invocation. It does not provision the
full stack on a clean checkout or manage owned shutdown as one service group.

**Fix:** declare a versioned local stack profile, provision missing dependencies,
validate each listener's configured service identity, and track owned processes
with a supervisor and startup lock. Provide bounded status/stop operations.
**Acceptance:** a clean no-cost install, repeat start during slow startup,
occupied/wrong port, partial crash and owned stop all have deterministic results.

### F19 — P1: regression failures invalidate a full-lifecycle confidence claim

**Fresh selected run: 58 failures.** At least 25 are in report source-provenance
tests and six in differential-auth report-promotion tests. Many fail at the
earlier canonical-manifest loader with `Original report manifest bytes changed`
instead of reaching the intended later assertion. Others parse an old startup
source layout, expect obsolete Cloud stub responses, or pin old migration heads.
These are not automatically 58 production vulnerabilities. They leave intended
boundary checks unproven at the current snapshot.

**Fix:** classify failures by first failing boundary. Rebuild valid canonical
fixtures for positive setup, retain malicious/mutated-byte negative tests,
assert stable machine outcomes rather than source-string layouts, and compare
the migration graph semantically. **Acceptance:** every safety test reaches its
intended gate; full Python suite passes or has explicitly justified environment
skips; no failing security test is simply removed or weakened.

### F20 — P2: the ordinary CI job and container smoke check cover too little

**Static.** `.github/workflows/ci.yml:87` runs only five Python test files;
its UI job omits the browser/service unit tests; `:95` sleeps ten seconds then
checks liveness on a container launched without its required database topology.
The separate release workflow does run a broader Python suite, so this is not
a claim that no full-test job exists. Neither liveness nor YAML parsing proves
production startup or a signed engagement journey.

**Fix:** make full unit/contract tests and UI tests required checks; add a
deadline-based dependency-ready container job and a controlled signed lifecycle
qualification with explicit artifacts. **Acceptance:** a known routing,
cookie-isolation or packaging regression fails the normal required checks;
CI distinguishes liveness from the deployment's required readiness.

### F21 — P1: qualification can report success with missing suites and a failed report

**Reproduced.** `scripts/qualification/run_all.py:28` skips a missing suite
without changing `all_passed`. It also ignores the report subprocess exit code.
With every suite missing and the mocked report process exiting 1, its actual
`main()` returned **0**.

**Fix:** missing required suites and failed report generation must fail the
run. Record executed/expected case counts and bind results to this exact build.
**Acceptance:** zero tests, missing suites, child failure, timeout and malformed
result each cause nonzero exit and no successful qualification artifact.

### F22 — P1: release workflow still writes a fixed PASS certificate

**Static.** `.github/workflows/release.yml:125–141` writes fixed PASS text and
hardcoded counts after shell commands. This bypasses the explicitly noncertified
draft generator and does not read independently verified runtime/release
attestations. Earlier jobs are prerequisites, but their success does not establish
all the assertions written into this certificate.

**Fix:** produce an evidence-bound qualification summary using actual job/case
results. Final production approval must require the existing independent source,
target-effect and human release decisions; fail closed on any missing input.
**Acceptance:** absent target/runtime/reviewer evidence prevents a final
certificate even if every local test is green; counts cannot be constants.

### F23 — P2 latent defect: duplicate scheduler/phase implementations have diverged

**Static, not a demonstrated active bypass.** The canonical orchestrator's
`_execute_task_durable` handles UNKNOWN explicitly, while the duplicate at
`orchestrator/task_scheduler.py:423` can treat `execution_unknown` as completed.
Its agent selector also differs from the canonical distributed selector.
`orchestrator/phase_monitor.py:105` references `_auto_advance_phase`, which that
class does not define, and an `asyncio` name it does not import. The current
main loop uses the canonical orchestrator path, which limits immediate impact.

**Fix:** remove dead implementations or turn them into delegates to one tested
state machine. **Acceptance:** one scheduling/completion/phase authority remains;
every exported alternate entrypoint has the same unknown/approval/lease semantics.

### F24 — P2: nested retries prolong startup and can suppress useful diagnostics

**Static retry analysis; reproduced logger suppression.** `api/main.py:373` wraps graph connection with up to ten attempts;
`memory/graph_memory.py:58` itself makes up to six attempts and retries all
Exceptions, including persistent authentication failures. The composition can
make up to 60 connection attempts before timeout/degradation, with substantial
backoff. Each attempt constructs a driver without an obvious failed-driver close.
Separately, `migrations/env.py:24` calls `fileConfig` with its default
`disable_existing_loggers=True`. In an isolated interpreter, a pre-created
`ai_osop.audit_probe` logger changed from enabled to disabled after loading
the current Alembic logging configuration.

**Fix:** give startup one overall deadline and one retry owner; classify permanent
auth/config failures as nonretryable, close failed drivers, and preserve existing
loggers during migration configuration. **Acceptance:** wrong credentials fail
within the documented bound with a sanitized reason, transient recovery succeeds,
and pre-created application/provenance loggers still emit after migration.

## Repair order and acceptance gates

The recommended order is one complete, controlled lab lifecycle before adding
more breadth. Preserve production denial until each missing authority is actually
implemented. Keep the no-paid-subscription constraint throughout.

| Wave | Work | Release gate |
| --- | --- | --- |
| 1. Protect credentials and truth | F01–F03, F10; add a capability registry and remove false success states | Synthetic credentials cannot escape origin/transport; no unexecuted test yields a finding or clean result |
| 2. Make lifecycle deterministic | F04–F09, F23 | Durable phase CAS/outbox, explicit completion states, correct routing, immutable payload; crash and approval-race tests pass |
| 3. Ship a reproducible runtime | F11–F12, F14, F18, F24 | Clean install and image startup; signed CLI operations; replica-visible report store; bounded startup/stop |
| 4. Enable one real free tool chain | F15–F17 | Explicit host/issuer enrollment; signed local task → one provider → original evidence → reconciliation; denied scope and replay cases pass |
| 5. Preserve report identity | F13 plus existing source/target/review gates | Immutable bundle generations; cross-replica readback; original-byte, ownership, revocation and independent-effect checks all pass |
| 6. Make qualification trustworthy | F19–F22 | Full tests + controlled lifecycle + failure injection; evidence-bound summary; no fabricated PASS certificate |

Suggested owners: credential/session code for Wave 1; orchestration/memory
for Wave 2; runtime/API/CLI for Wave 3; MCP/provider integration for Wave 4;
reporting/storage for Wave 5; QA/release for Wave 6. These are responsibility
boundaries, not authorizations to run parallel edits in the shared checkout.

## Required complete local-lab journey

1. Start the packaged application and pinned free providers against blank
   disposable stores; obtain readiness appropriate to the enabled capability set.
2. Authenticate an operator; import independently signed, expiring local-only
   scope; create the engagement through both UI and CLI.
3. Create a supported Task/Flow; verify durable owner, phase, dependency,
   budget and approval binding. Reject changed payloads and reserved-field forgery.
4. Capture two lab identities without leaking their cookies/headers; exercise
   a known allowed resource and a known denied resource with ownership mapping.
5. Execute exactly one admitted provider action; correlate request ID, one-use
   grant, source receipt, original bytes and stored immutable evidence.
6. Verify a known lab flaw against a controlled target-side oracle. Keep a
   scanner issue without independent corroboration as a candidate.
7. Halt/revoke during execution; simulate a timeout after acceptance, a provider
   crash, PostgreSQL/Redis/graph disruption and worker restart. Reconcile UNKNOWN
   without blindly repeating the target-side action.
8. Resume permitted work, make an explicit partial/failed/successful coverage
   decision, and advance phases only when that decision is durably justified.
9. Generate a uniquely identified report bundle; independently verify original
   bytes and provenance; obtain separate human review and release approval.
10. Read the same immutable report from another replica, regenerate a new
    version without altering the original, and verify that revocation blocks
    further release/dispatch. Restore a disposable backup and repeat the readback.

The final gate is a recorded run of this sequence with both positive and
negative controls. Passing isolated transport, UI, model or unit tests cannot
replace that evidence.

## Controls to retain

The focused passing tests and code inspection support keeping signed ROE,
owner isolation, canonical manifest validation, independent source/target
verification, one-use dispatch quarantine, approval binding and halt/revocation
checks. The reviewed report writer already sanitizes display text; this audit
does not claim an exploitable report XSS merely because the generic exporter
accepts raw Markdown. Development HTTP 200/degraded readiness is intentional;
the production readiness fence is stricter. Do not fix availability by removing
those checks, interpreting unavailable as clean, or relabelling static IaC/public
reference data as target-effect proof.
