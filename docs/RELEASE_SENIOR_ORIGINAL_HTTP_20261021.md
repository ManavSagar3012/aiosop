# Original v3 report HTTP readback vs. independent senior RELEASE — 2026-10-21

**Decision: NOT PRODUCTION CERTIFIED.** The original report attestation is
readable as an authenticated signed **report-generation snapshot**. That is
not a signed target effect, independent senior release admission, completed
one-use release transaction, or production release certificate. All
demonstrations in this note use disposable test artifacts and identity/DB
doubles. They do not exercise a real target, JWT verifier, PostgreSQL database,
host, independently enrolled signer, or deployment.

## Actual mounted route and original-source trust chain

The original `src/ai_osop/api/main.py:612-617` registers
`report_attestations.router`. Its original implementation is at
`src/ai_osop/api/routers/report_attestations.py`, with prefix
`/engagements` (line 49):

| Method/path | Original handler and required trust | Intended non-certified outcome |
| --- | --- | --- |
| `GET /engagements/{session_id}/attestations/{report_id}` | `get_signed_report_attestation` at lines 1321–1406: current durable owner/role, `guard_sql` current signed ROE, original storage, independent graph evidence, Ed25519 report signature, durable Task+Flow report-generation SHA receipt. | `signed_report_task_snapshot_verified` with `independent_target_authority_verified=false`, `finding_release_eligible=false`, `operator_approval_verified=false`; **not** external release. |
| `POST /engagements/{session_id}/attestations/{report_id}/release` | `approve_signed_report_release` at lines 1034–1148: senior JWT, signed current authorization and original owner, `_verified_final_release_candidate`, independently authenticated source and target-owner evidence, immutable `report.human_release_approved` event if *all* checks succeed. Nonempty reports are reverified after event append under the same transaction. | A human signoff event for one snapshot, **not** an independently signed senior RELEASE certificate. With absent original target-owner current witness, return 503 and do not append. |
| `GET /engagements/{session_id}/attestations/{report_id}/release` | `get_signed_report_release_status` at lines 1151–1254: same `_verified_final_release_candidate` then lookup exact `report-release:{sha256(engagement:report:version:attestation_digest)}` event, confirm historical signing actor still equals original durable owner and event fields still match. | Historical event alone is not current authority. With target-owner absent, fail before event lookup (503), **not** `human_release_approved`. Ambiguous ACK cannot be reinterpreted as committed. |
| `GET /engagements/{session_id}/attestations/{report_id}/artifacts/{artifact_kind}` | `download_verified_signed_report_artifact` at lines 1257–1318: same candidate verification followed by original artifact SHA verification; respond as a sandboxed attachment, never inline arbitrary HTML. | Without independent source and current owner proof, fail before returning report bytes (503). |

`_report_operator` (lines 629–657) in the **actual mounted app** requires
a bearer credential, separately trusted expiring JWT/OIDC identity and role.
This suite explicitly **does not** claim that JWT verification was tested:
the isolated ASGI harness supplies only a test dependency representing an
already-authenticated identity.

## Original-byte chain, not a reserialized manifest

- `src/ai_osop/agents/reporting_agent.py:428-483` ties v3 detached
  attestation to original Task, authorization version/digest, Flow ID and
  revision; lines 642–716 write original `md`, `html`, `graph.html`,
  `json`, `attestation`, `manifest` with per-file SHA-256 and binary
  atomic replacement.
- `src/ai_osop/reporting/attestation.py:25-29,188-293,326-446`
  verifies independently configured *report* Ed25519 public key, signed
  original artifact hashes, provenance and evidence snapshots. Explicit
  `attestation_scope` forbids inferring exploit success, source
  authenticity, report completeness or human release from that signature.
- `src/ai_osop/reporting/attested_storage.py:52-123` loads only fixed
  file names under an administrator-selected absolute root. **Current
  canonical original-manifest fix at lines 100–114** reconstructs the
  writer's exact compact sorted `json.dumps(ensure_ascii=False,
  sort_keys=True,separators=(',',':'))` bytes and refuses reordered,
  indented, whitespace-mutated, or other noncanonical original bytes during
  `load_attested_bundle`, before a parsed snapshot is returned.
  `verify_loaded_bundle` at lines 126–184 then verifies the reporter's
  detached signature, manifest fields and current trusted report key.
- `src/ai_osop/api/routers/report_attestations.py:469-626` still independently
  joins the original **completed** `generate_report` Task, active Flow
  revision, signed authorization and original **all-six-artifact** SHA
  receipt using shared read locks. The canonical loader does **not** replace
  this Task SHA proof. A syntactically canonical *but wrong* manifest SHA
  receipt fails on that latter check.

**HTTP evidence:** the exact original handler code returns 200 for a test-only
Ed25519-signed report as a `signed_report_task_snapshot_verified` record
with approval/target-effect flags `false`. It returns 503 for mutated
canonical manifest, JSON artifact, reporter signature and altered original
Task hash. It does not return actual raw graph evidence, a release event ID,
or a production certificate.

## Independent signed target-owner vs. separately signed senior release

There are **two distinct signing boundaries**. They must not be conflated:

1. The original report's signer proves the artifact snapshot only. A stored
   `VERIFIED` finding flag does not independently prove the target. Original
   target authority is from `0016` signed assertion/one-shot nonce,
   `0021` historical `UNKNOWN` qualification and `0022` independent
   signed dual observer/owner target-effect verdict with current challenge,
   witness trust registry, ROE, reviewer, source Task, original per-finding
   evidence, and short expiry. Source:
   `src/ai_osop/api/routers/report_attestations.py:179-453,740-916`;
   `src/ai_osop/memory/independent_target_effect_verifications.py:1518-1737`;
   `migrations/versions/0016_target_authority_nonce_receipts.py`,
   `0021_target_verified_promotions.py`,
   `0022_independent_target_effect_verifications.py`.
   Missing current independent owner or forged graph-only evidence **denies**
   the original nonempty release candidate.
2. `src/ai_osop/safety/independent_release_authority.py:690-1303`
   separately verifies an independently *enrolled* senior **RELEASE** Ed25519
   claim, true host current signed authority, exact original report and
   target-owner 0016/0021/0022 chain, current replica qualifications and
   one-use senior release ledger. It remains **unmounted**.
   `src/ai_osop/safety/production_release_admission.py:246-392`
   additionally checks original attestation/manifest bytes, one-use
   committed/ACK-confirmed, not consumed/replayed/revoked senior receipt,
   revalidates reporter and external roots after await, and returns a
   *read-only*, not-executable result if all genuine requirements exist.
   There is **no mounted external senior release host service and no
   independently enrolled senior/host/replica release tables** in the
   original migrations. The test's ephemeral Ed25519 senior signature is
   **not enrolled** and cannot substitute for those records.

The HTTP release routes do **not** accept an `X-Independent-Senior-Release`
header as an independent signed release authority. The qualification
deliberately provides either a test-only correctly signed, stale or forged
senior envelope out of band and confirms that none changes the mounted
human-signoff GET readback. This is a **negative boundary check**: adding a
header does not verify the source, and its absence does not authorize release.

## Read-only qualification (new test)

**File:** `tests/qualification/test_release_senior_original_http_readback_20261021.py`

The local Python interpreter lacks `sqlalchemy`, `neo4j`,
`python-jose` and `prometheus_client`, preventing a genuine
`ai_osop.api.main:app` import. Therefore this test:

- Parses the **current original router source**, executes the *unchanged*
  decorators, `FinalReportSignoff` model, route bodies, original
  `_verified_final_release_candidate`,
  `_verify_signed_finding_sources`,
  `_verify_generation_release`, source-claim checks and release-key
  function as Python AST, and registers them on an **isolated FastAPI ASGI
  app**.
- Calls real HTTP with `httpx.ASGITransport`. Its mocked identity represents
  only the authenticated operator state; the session/Flow/Task store is
  SELECT-ONLY, enforcing `FOR SHARE` queries and recording attempted writes.
  The original disk artifacts live only under pytest's `tmp_path` and are
  genuinely verified with the production loader/report signer code.
- Uses pre-existing ephemeral test-only **report** and **senior** Ed25519
  fixtures with different keys. No test creates a live independently enrolled
  signed owner observation or valid host/replica release authority, and no
  success path for human release is mocked.
- Qualifies route registration, valid signed snapshot GET (non-certified),
  absent owner proof on POST/GET release and artifact GET, manifest whitespace
  and reorder rejection at loader, report JSON/attestation signature tamper,
  original Task digest corruption, revoked report key, revoked signed ROE,
  changed Flow revision, wrong owner and wrong role.
- Requires forged reporter-as-senior, expired senior, missing target receipt,
  correctly signed but unenrolled senior claim, absent host ledger and
  repeated readback/lost-ACK ambiguity to remain denied. At no point is
  an original release event appended or report artifact served following a
  missing 0022 witness.

**Observed command:**

```powershell
python -m pytest -q -o addopts='' tests/qualification/test_release_senior_original_http_readback_20261021.py --tb=short
```

**Result: 21 passed**, one environment warning (the local pytest
installation does not recognize `asyncio_mode`). No genuine PostgreSQL,
OIDC/JWT, hosted senior service, independent signed 0022 target owner,
crash/restart, replica/current ledger or positive one-use CAS was qualified.
Consequently **neither human release nor independent production release is
certified**.

## Remaining production prerequisites

An external protected service must independently enroll and revoke senior
release, host, observer/owner and at least two replica public signing roots.
It must atomically store a one-use release decision bound to the exact
original Task/Flow/ROE, original report SHA, 0016/0021/0022 current dual
target-owner witness and independently qualified current replicas. Its
host-only readback must prove acknowledged committed state after crashes,
lost ACK, replay, rollback and external key revocation. A real disposable
PostgreSQL ASGI test with authorized independently enrolled signing roots
and a separate host process is still needed. Until those prerequisites are
genuinely implemented, **the correct outcome is fail closed**.
