# Independent senior release approval: verifier and production gaps (2026-10-21)

**Current decision: DENY / NOT PRODUCTION CERTIFIED.** The isolated module
`src/ai_osop/safety/independent_release_authority.py` is deliberately **not
mounted** in the API, release script, CI, or signing paths. It creates no key,
certificate, claim, approval, target effect, or database record. No active host
authority is configured or assumed to exist. Offline cryptographic unit tests
do not qualify the product for release.

## What actually exists

| Source | Verified scope | Missing production senior release |
| --- | --- | --- |
| `reporting/attestation.py` v3 and `reporting/attested_storage.py` | Detached report Ed25519 signature; four report artifacts, report manifest and original graph evidence snapshots; generation Task, Flow and ROE reference | Signature explicitly asserts **no operator approval, source authenticity or completeness**. Artifacts are stored under the configured local report root; no independent release ledger is attached to the bundle |
| `api/routers/report_attestations.py` POST `/{session_id}/attestations/{report_id}/release` | JWT human `senior_operator` who owns engagement, current signed ROE, report Task and evidence rechecks; event `report.human_release_approved` with attestation SHA, authorization version | Event is **not** an independent senior Ed25519 release signature, durable independent release nonce, or external senior root enrollment. A human report signoff is narrower than product release certification |
| `migrations/versions/0016_target_authority_nonce_receipts.py` | Immutable target owner `target_authority_assertions` and nonce receipts scoped to engagement/Flow, proof SHA | Does not join an entire report or independently authorize production release |
| `migrations/versions/0021_target_verified_promotions.py` | UNKNOWN-only attempted effects, no production effect approval | Cannot promote UNKNOWN to released |
| `migrations/versions/0022_independent_target_effect_verifications.py` and `memory/independent_target_effect_verifications.py` | Immutable, finding-scoped independently signed effect verdicts; original Task/Flow, candidate review, current observer registry, challenge and nonce revalidation | Enforces `report_release_approved=false` and `finding_release_eligible=false`; 0022's VERIFIED row is only a locator. The final release consumer must freshly rerun current owner/access, signed Task, reviewer, and ROE checks |
| `scripts/qualification/generate_release_certificate.py` | Noncertified readiness draft, nonzero release gate exit | Intentionally does not create production certificates or final senior release |
| `migrations/versions/0023_immutable_evidence_ledger.py` | Hashes of request/response and replay recipes | Does not supply a signed senior final release, qualified multi-replica run, or one-shot release transaction |

## New verifier contract

The separate senior release claim must carry an exact schema, one independently
enrolled external senior Ed25519 public key ID, original report attestation,
manifest and report JSON SHA-256, generation Task ID, tenant and owner identity,
Flow ID and revision, signed ROE ID/version/hash, the set of target-owner
verification/challenge/qualification IDs and hashes, target assertion and nonce
receipt IDs and hashes, and distinct multi-replica run IDs and qualification
hashes. It also requires a one-use durable senior release receipt ID/digest,
senior identity and a maximum five-minute signature lifetime.

The signature covers
`AI-OSOP-INDEPENDENT-SENIOR-RELEASE-APPROVAL-V1\\0 || canonical_json(claim)`.
The host supplies trust roots out of band: **one** external senior key, distinct
report, provider, target owner and host authority keys, each with separate
revocation management. Same public-key bytes reused in any roles are denied.
No key supplied by the claim or client is accepted as an enrollment root.

The verifier initiates a 32-byte random challenge and sends its SHA-bound claim
over a host-only HTTPS endpoint at exactly `/release/current-authority`, using
HTTPS port 443, a validated nonlocal DNS host, a separate service bearer,
disabled environment proxy use, bounded bytes, and no redirects. Its exclusive
CA PEM must be an immutable in-memory SSL trust context loaded from a host/root
owned, nonsymlinked regular file beneath non-writable ancestors; inode, mode
and ownership are checked under `O_NOFOLLOW`. The present implementation
deliberately refuses Windows host CA admission until a separately verified
Windows DACL validator is implemented. That makes the current Windows
workspace unable to configure a production host authority. The
host signs an exact canonical JSON response under a **different pinned Ed25519
root**, with the signature domain
`AI-OSOP-HOST-CURRENT-RELEASE-AUTHORITY-V1\\0`. Its response binds the
fresh challenge, senior claim digest, report/scope/receipt identifiers, and a
maximum ten-second current-authority window. A boolean, caller-supplied
`verified` field, cached 0022 row, or provider self-attestation cannot satisfy
that signature. Signature verification alone makes no truth claim about its
sources; the host-side authority must independently establish them.

## Missing integrations that **must** fail closed

1. **Independent key enrollment.** There is no verified, protected enrollment
   source here providing a single external senior public root plus distinct
   report/provider/owner/host roots, current revocation generation, and
   authenticated senior identity. Keys must be independently provisioned; the
   existing report signer private key must never double as the senior key.
2. **Signed report and tenant join.** A host-only transaction must retrieve the
   exact archived v3 attestation, all signed artifact bytes (MD/HTML/graph/JSON),
   manifest, independently retrieved evidence by finding, signed current ROE,
   generation Task, Flow revision, durable tenant/owner, and the senior's
   authenticated current session. Verify the original signatures and hashes,
   and reject revocation or changes at commit/readback. The current verifier
   receives three original hashes but leaves full v3 report verification to
   that separate authoritative host.
3. **Target-owner chain.** Re-verify the 0022 challenge, signed independent LIVE
   witness verdict, original signed 0016 `target_authority_assertions`,
   `target_authority_nonce_receipts`, immutable finding review, report-source
   digest, current independently enrolled verifier registry, actual target
   owner identity and one-use nonce. Calculate full receipt row hashes under a
   documented canonical rule. The 0022 table has no direct release receipt or
   report-wide immutable foreign-key join; it remains release-ineligible.
4. **Multi-replica qualification.** No durable independently verifiable table
   was identified proving distinct actual replica process identities, same
   exact candidate and signed Flow/ROE revision, failure/ACK-loss/recovery,
   resulting immutable test run receipts, committed freshness and signing
   provenance. A pair of operator-supplied host names or local unit tests
   cannot supply the requirement. Add an independent qualification recorder
   and current readback before enabling host approval.
5. **One-use release CAS.** No immutable `srelease-*` admission transaction or
   separate release nonce/receipt store presently binds the signed senior
   claim to report SHA, owner/tenant, Flow and all 0022/multi-replica receipts.
   Require a cross-process atomic uniqueness fence, rollback/ACK-loss
   readback, revocation fence, and release validity window.
6. **Host authority service.** No authenticated server currently offers the
   pinned current-release challenge protocol with the above complete DB joins,
   signed reply and current revocation checks. Deploy as a separate privileged
   host process with its own public key and CA chain only after these ledgers
   exist; never provision its private signer in the application/native/provider.
7. **Release consumer and distribution.** Do not connect this read-only verifier
   to `approve_signed_report_release`, status GET, download, report export,
   release generator or deployment gates until a complete production release
   schema and authenticated host authority are verified. A verified senior
   claim at that future boundary should authorize only its exact snapshot and
   remain invalid on any change to the owner, signed ROE, witness trust or run
   qualification.

## Focused verification

`python -m pytest -q -o addopts='' tests/test_independent_release_authority_20261021.py`
passed **36 tests (one symlink test skipped on Windows)** in the current
interpreter. `-o addopts=''` is necessary
because the local pytest environment lacks `pytest-cov`; the tests run through
AnyIO since it also lacks `pytest-asyncio`. These tests use ephemeral
**synthetic fixture keys**, an in-memory stand-in for the signed host response
and exact original byte samples. They prove parsing, Ed25519 domain separation,
role-key exclusion, report-byte binding, receipt shape, replica uniqueness,
request scope, nonce freshness, bounded host HTTPS stream, redirect refusal,
disabled proxy use, and adversarial denial. They do **not** establish
an independently provisioned external senior, running current host authority,
actual 0016/0022 ledger joins, multi-replica production qualification, or
any valid production release.
