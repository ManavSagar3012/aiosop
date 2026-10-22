# Original report custody and independent release trust joins — 2026-10-21

**Qualification outcome: release certificate DENIED / not independently
certified.** The original v3 report bytes can be retrieved and authenticated
through existing read-only reporting APIs. The present human report signoff is
an authenticated supervision event, **not** a cryptographically independent
senior release certificate. A final senior release still lacks separately
enrolled and current signing authority, a durable admission ledger, and
independent multi-replica qualification records. Nothing in this qualification
was mounted, signed as a senior, or sent to an external system.

## Traced original-byte custody

| Trust boundary | Reachable source contract and evidence | Implication |
| --- | --- | --- |
| Original producer | `src/ai_osop/agents/reporting_agent.py:428-485` requires the persisted reporting Task and signed ROE and signs its exact Task ID, original authorization version/hash, and Flow ID/revision for v3. `src/ai_osop/agents/reporting_agent.py:642-718` writes **md, html, graph.html, json, attestation, manifest** to `reports/<engagement>/<report-id>.*` with UTF-8 binary writes, fsync and atomic replacement, and hashes the exact serialized attestation and manifest bytes. `src/ai_osop/agents/reporting_agent.py:732-749` returns the per-file SHA-256 Task receipt. | Files are original producer outputs, but the filesystem and its administrator-selected root are not themselves an independent proof of target effects. |
| Read-only original loader | `src/ai_osop/reporting/attested_storage.py:39-49,52-108` permits only server-derived report IDs and an absolute configured `OSOP_ATTESTED_REPORT_ROOT`, refuses symlink file paths, bounds reads and returns **original binary artifacts** plus parsed attestation/manifest and SHA-256 of their original raw bytes. | No caller path or unsigned fallback exists in this loader. Root/provenance and concurrent filesystem mutation still depend on protected deployment and the downstream Task hash join. |
| Detached report signature | `src/ai_osop/reporting/attestation.py:25-29,39-72,126-185,188-241,244-293,326-446` checks a separately configured report-signing Ed25519 public key, exact artifact digest set, canonical signed payload, original independent evidence snapshots and signed Flow/ROE/Task binding. The signature declares source authenticity, operator approval, completeness and exploit effects **false**. | A valid report signature authenticates archived content, not a finding, owner-side observation, senior approval or release certificate. |
| Manifest original SHA | `src/ai_osop/reporting/attested_storage.py:111-169` checks the parsed manifest fields, signed artifact hashes and signed attestation SHA. **It does not independently bind the manifest's exact original serialization.** `src/ai_osop/api/routers/report_attestations.py:469-626` separately verifies the completed original reporting Task and compares its durable `artifact_sha256` receipt to all four artifacts **and the original attestation/manifest digests**. | **Observed regression boundary:** adding one whitespace byte to the manifest passes the lower-level `verify_loaded_bundle` but is rejected by the genuine Task receipt check in `_verify_generation_release`. Consumers must retain this latter join; a standalone lower-level verification result is not a release verdict. |
| Live authenticated read | `src/ai_osop/api/routers/report_attestations.py:1321-1406` checks current signed authorization under a PostgreSQL shared lock, reads the configured original report root, retrieves independent graph evidence and invokes the two verifiers. It returns `signed_report_task_snapshot_verified` only after the original Task/Flow receipt check, and explicitly sets independent target authority and finding release eligibility to **false**. | Attestation GET is a read of the authentic draft/task snapshot, with no production release authority. |
| Release candidate and downloads | `src/ai_osop/api/routers/report_attestations.py:936-1031` performs the original custody and per-finding source checks inside one caller-owned transaction, then rechecks the signed ROE after awaited verifiers. `src/ai_osop/api/routers/report_attestations.py:1258-1318` reuses that candidate check before returning exact artifact bytes as attachment with another SHA-256 comparison. | A stale, altered, revoked or unverified report cannot become a distribution artifact through this path. Actual mounted ASGI verification was **not run** in this bounded task. |

## The existing 0016 → 0021 → 0022 target-owner chain

1. `migrations/versions/0016_target_authority_nonce_receipts.py:16-46,73-135`
   defines immutable, engagement/Flow-bound target-owner assertions and
   duplicate-nonce receipts. It proves an admission record exists, subject to
   independent current signature verification. Neither table authorizes release.
2. `migrations/versions/0021_target_verified_promotions.py:20-134`
   persists only `UNKNOWN` qualification attempts and constrains
   `independent_effect_verified=false`,
   `finding_verified=false` and `report_release_approved=false`.
   A provider self-report or legacy graph `validated` flag cannot promote it.
3. `migrations/versions/0022_independent_target_effect_verifications.py:22-61,63-226`
   defines a separate, immutable finding/Flow/ROE/reviewer/challenge/qualification
   witness ledger, allows `VERIFIED` only with qualifying signed evidence and
   requires `report_release_approved=false`; the signed verdict lifetime is
   at most 60 seconds. `src/ai_osop/memory/independent_target_effect_verifications.py:1518-1737`
   readback rechecks immutable row references, independently signed outer and
   nested owner claims, original Tasks, current ROE, replay receipts, current
   witness key registry/revocation and nonce freshness. Missing or stale current
   authority returns `UNKNOWN`.
4. `src/ai_osop/api/routers/report_attestations.py:179-453,740-916`
   requires current signed provider-source lineage and the exact current
   0022 target-owner evidence for every finding before a human report release.
   The helper `_independent_target_authority_available` at lines 163-176
   deliberately remains false for older self-reported sources.

The release report joins *all* of the above. An isolated `VERIFIED` database
flag cannot replace external owner authority or report-original provenance.

## Human release, ambiguous ACK and external senior release

`src/ai_osop/api/routers/report_attestations.py:1034-1148` appends
`report.human_release_approved` with the exact original attestation digest and
ROE version. For nonempty findings it rechecks independent authority after the
awaited append and rolls back the transaction if any authority changed. The
event idempotency key derives deterministically from engagement ID, report ID,
authorization version and attestation SHA
(`src/ai_osop/api/routers/report_attestations.py:919-921`). PostgreSQL's
`(engagement_id, idempotency_key)` uniqueness is declared by
`src/ai_osop/memory/supervision_store.py:35-49`. The read-only status handler
(`src/ai_osop/api/routers/report_attestations.py:1151-1254`) recomputes the
key, rechecks the original source candidate and signed owner before presenting
an existing human event.

**An ACK loss does not mean the release committed.** A retry identifies the
same candidate/event key, but a real PostgreSQL transaction readback must
resolve whether an event committed, was rolled back, or became stale after
revocation. The qualification suite tested deterministic key stability and
release-domain separation only; it did not issue an event, retry a database
write, simulate a real ACK loss, or certify PostgreSQL cross-replica behavior.
Reusing a human event cannot provide the separate independent senior claim.

`src/ai_osop/safety/independent_release_authority.py:690-1303` contains an
**unmounted** read-only independent senior release verifier. It requires a
domain-separated independent senior signature, original report/task/owner/Flow
binding, current external host authority, signed target-owner evidence and
separately signed, independent replica qualification/run receipts with current
revocation and a durable one-use release receipt. It does **not** issue any
signature, key, approval or certificate. The existing migration history has no
`independent_senior_release_key_enrollments`,
`independent_release_host_key_enrollments`,
`independent_release_replica_key_enrollments`,
`independent_release_replica_qualifications`,
`independent_release_qualification_run_receipts`, or
`independent_senior_release_receipts` tables. There is no mounted independent
senior current-release host service. **Production senior approval must DENY.**

## New read-only qualification and scope

`tests/qualification/test_release_report_original_custody_20261021.py`
passes **36 focused tests** in the available Windows Python environment:

- Uses the actual report storage and signature verifier with a **disposable
  report-signing fixture key only** and exact original bytes written to an
  isolated temporary directory. Exercises all four artifact types, attestation
  and manifest tampering, equivalent-JSON original-byte changes, current
  reporter-key revocation and independently fetched evidence substitution.
- Executes the **unchanged original AST function bodies** for
  `_verified_final_release_candidate`,
  `_verify_generation_release`,
  `_refuse_unsupported_target_promotion`,
  `_verify_signed_finding_sources` and `_release_key` against an isolated,
  SELECT-only DB double. Exercises durable Task receipt and Flow/owner revision
  changes, 0016/0021/0022 source unavailability, and signed ROE revocation
  between awaited source verification and its mandatory final reread.
- Executes the **actual 0022 readback function body** with bounded negative
  SQL doubles: wrong tenant/Flow/finding/digest, a fabricated `VERIFIED` row,
  missing original signature, nonce mismatch and unavailable independent
  current signer all return `UNKNOWN`. The test never fabricates a working
  owner/observer private signer.
- Exercises the independent release verifier with an **unsigned senior
  envelope and public-only placeholders**, proving denial before any release
  SQL call. The real replica SELECT helper refuses a missing current
  qualification row. Checks that the independently required tables are absent
  from the migration corpus and the human-status API does not call the
  standalone independent senior verifier.

Command: `python -m pytest -q -o addopts='' tests/qualification/test_release_report_original_custody_20261021.py --tb=short`.
Result: **36 passed** (plus one pytest environment warning:
`asyncio_mode` is unknown because the interpreter lacks `pytest-asyncio`).
`python -m compileall -q tests/qualification/test_release_report_original_custody_20261021.py`
passed.

**Qualification limits:** The local interpreter lacks `sqlalchemy` and
`neo4j`, so neither mounted FastAPI nor true PostgreSQL row locks, signed
0022 owner observations, external key enrollment, multi-replica current
qualifications, host callbacks or actual network/report distribution were
tested. AST body execution exercises live source functions with mocked
dependencies; it does not prove actual mounted runtime behavior. No fake
independent senior signer, live provider, target, Docker container,
application DB or Git operation was used.

The next independently qualified prerequisite is a reviewed host-only
readback that joins signed 0016/0021/0022 records, the exact original v3
Task/report receipts and real durable signed senior/replica release ledgers
under current ROE, current trust roots and a one-use CAS. Until that exists
and is qualified with a disposable PostgreSQL and independently enrolled
authorities, **the only supported interpretation is an authenticated report
snapshot or human signoff, never an independent release certificate**.
