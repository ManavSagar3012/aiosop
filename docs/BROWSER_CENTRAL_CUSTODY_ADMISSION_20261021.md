# Browser central CURRENT authority → original-byte custody admission

**Qualification date:** 2026-10-21  
**Disposition:** **NOT PRODUCTION CERTIFIED / NOT READY.**

## Decision: no mounted central custody-admission path

**No.** The existing, mounted
`POST /native-browser/current-authority/readback` can independently
revalidate the original 0027 Action, committed 0034 source, original signed
ROE, current Flow/Task/approval/reviewer/lease and the signed source/provider
evidence *metadata*. It **cannot** read the Browser provider's presently
owned screenshot/DOM/HAR bytes, authenticate a provider file-access
capability, acquire a durable custody lock or authorize a target-owner effect.
This is a deliberately limited read-only authority service, not an
artifact-custody admission interface.

The actual source has two distinct endpoints:

1. **Central host-only:** `src/ai_osop/api/routers/native_browser_current_authority.py`
   exposes one POST route. Its accepted JSON shape contains exactly
   `source_proof` and `provider_evidence`. After a READ ONLY authority
   transaction it signs a **five-second** `current_authority_readback_only`
   Ed25519 certificate. The certificate expressly contains
   `artifact_bytes_verified=false`, `target_effect_verified=false`;
   the response additionally says
   `original_browser_artifact_bytes_verified=false`,
   `independent_target_effect_verified=false`,
   `automatic_retry_authorized=false` and
   `production_release_certified=false`.
   There is **no** original-byte retrieval RPC, file descriptor, lease,
   signed custody grant, byte stream, or callback to the native side.
2. **Provider-local:** `mcp-servers/python/browser_mcp.py` exposes
   `POST /mcp/request/evidence/readback`, protected by the distinct
   `OSOP_BROWSER_MCP_BEARER_TOKEN`. It rereads the one-shot
   `RequestJournal`, independently signed sidecar and the original local
   screenshot/DOM/HAR files from the pinned test/tenant mount, checking
   length/SHA/path and a provider signature. A successful local result
   explicitly sets `current_authorization_verified=false`,
   `independent_target_effect_verified=false` and
   `safe_to_automatically_retry=false`. It does not accept a central
   CURRENT certificate as authorization or emit an independent target
   owner-of-record attestation.

The independent source issuer, provider signer and central current-authority
signer have separately enrolled roots. A certificate from one is not a
capability issued by another. Combining two individually signed readbacks
in a report would **not** establish an atomic present-state join, nor even
prove that the client accessed the provider files under central authority.

## New disjoint qualification and evidence class

New test:
`tests/qualification/test_browser_central_custody_current_admission_20261021.py`

The test calls **actual mounted central FastAPI ASGI** and **actual native
Browser ASGI** with no sockets or external targets. It uses genuine
Ed25519 source/provider/central certificates, a real signed ROE verifier,
the original RequestJournal/sidecar/byte-reread logic and the current
central read-only SQL. The original PNG/DOM/HAR here are **synthetic
test-owned bytes**, not new Chromium captures or target evidence.
Original 0027/0034/Flow/Task/reviewer/lease records come from the
existing **in-memory SELECT-only FakePG** fixture, **not** application
PostgreSQL or a real signed approval service. The fixture's query log is
cleared between independent transaction simulations. Source claims are
locally reissued to meet the source's short validity window. Neither action
is a real production enrollment/issuance decision.

| Probe against current production routes | Observed boundary |
|---|---|
| Fresh genuine central proof with valid synthetic local originals | Central does **not** call the provider's `current_evidence`; it performs SELECT-only authority checks and produces no original byte or custody grant. |
| Host CURRENT token, source token or central certificate signature used at native original readback | All refused **HTTP 401** before the original file reader runs; a native-specific bearer is required. |
| Native-specific bearer with original request tuple | Returns provider-local current SHA/size/path metadata for the three private original fixtures; still refuses current authorization, target effect and automatic retry. |
| Attempt to send `read_original_bytes`, `reconcile_to_target_owner`, or a fabricated custody grant through central POST | **HTTP 422** before any central DB query; no alternate byte-admission request shape is mounted. |
| Try central proof as native original-file request JSON, even with native bearer | **HTTP 422**; central certificate is not a RequestJournal identity or readable file. |
| Foreign source `owner_id` or `approval_id` re-signed by the **legitimate enrolled source key** | **HTTP 503** from original durable source/Action identity revalidation. A valid signature over a made-up owner is still not original authority. |
| Provider `target_effect_verified=true` newly signed by the **legitimate enrolled provider key** | **HTTP 503**; the provider cannot add independent target/effect claims to the exact signed evidence schema. |
| Current central certificate after five-second expiry, removed trusted current root, or revoked authorization row | Verifier rejects expired or revoked root; new central issuance fails **HTTP 503**, without producing a custody grant. |
| Original request after every attempted admission | One-shot native RequestJournal reservation remains unavailable; original central 0027 Action stays `unknown`; no original navigation, provider execution, reconciliation, or retry occurs. |

### Reproduction

```powershell
poetry run pytest -o addopts='' tests/qualification/test_browser_central_custody_current_admission_20261021.py -q --disable-warnings --maxfail=1
poetry run black --check tests/qualification/test_browser_central_custody_current_admission_20261021.py
```

**Observed after formatting:** **9 passed, 24 warnings in 14.26 seconds** for the new isolated
test only. The warning categories were suppressed by this invocation and
not independently triaged; they are not additional passing cases. Prior
nine-test Browser original-custody qualification and previous genuine
offline Chromium capture tests were inspected but **not added to this count**.

## Exact blocker to additional original-byte admission proof

A new host-owned, independently authenticated **original-custody admission
consumer/service** would be required before central CURRENT authorization
could mediate any provider-owned byte readback. No such production component
exists in the mounted route inspected. It would need:

- Original immutable identity pinned at *every* boundary:
  `request_id`, engagement, Task, Flow, subtask, Action, owner, source
  `preflight_id`, signed ROE and authorization SHA, 0027 intent SHA,
  native attestation SHA, and each currently observed file SHA/size/path.
- Independent operator/host ownership of the actual provider producer
  process and mount; a separately enrolled custody-readback signing key
  **not issued or controlled by the Browser provider**. A native signature
  over its own files is valuable forensic testimony, not independent owner
  verification.
- Fresh central current authority **before and after** actual original
  byte consumption, with current key revocation/Task/reviewer/ROE/lease
  checks and a durable loss-of-ACK/cancellation disposition. The observation
  cannot be promoted if any source changed or the outcome is UNKNOWN.
- A production-controlled readback transport (bounded, distinct
  service credential, host-only TLS/CA, no redirects/proxies) and a durable
  custody ACK/receipt tied to the exact originals; neither a copied signed
  certificate nor a provider caller-supplied path can grant a read.
- Immutable original retention and clear non-atomic snapshot limitations:
  without a custody lock, artifact mutations can race both successful
  independent reads. No readback in this architecture alone proves an
  external target-side effect.

The current architecture therefore supports **two independent read-only
observations** and must not relabel them as a signed custody lifecycle,
original target-owner evidence, verified exploit, reporting promise or
production-release certification. If a later consumer cannot verify every
necessary durable original and current authorization fact, the safe
operator-facing result is **UNKNOWN / NOT VERIFIED / NO AUTO RETRY**.

No production source, existing tests, application DB, Docker, Git history,
live Browser provider, Chromium profile, real scan or external target was
modified or contacted by this qualification.
