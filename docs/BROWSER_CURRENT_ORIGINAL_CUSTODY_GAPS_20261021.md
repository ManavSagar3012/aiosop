# Browser original artifact custody × central current-authority join

**Date:** 2026-10-21  
**Disposition:** **NOT PRODUCTION CERTIFIED / NOT READY**; no independent
target-owner effect, release authorization or original-request replay is
established here.

## What was actually qualified

New disjoint qualification:
`tests/qualification/test_browser_current_original_custody_join_20261021.py`.
The test uses **actual production** native Browser `RequestJournal`,
`commit_evidence`, `current_evidence`, `/mcp/request/evidence/readback`,
`/mcp/request/status`, `_signed_coupled_evidence`, the **mounted production**
`POST /native-browser/current-authority/readback`, and real cryptographic
Ed25519 signing and verification with independently generated/enrolled source,
native provider and central current-authority keys. The central current readback
executes its actual read-only SQL and original signed ROE/authorization checks.

**Fixture-only—not independently demonstrated:** the central 0027 original
Action, 0034 source admission, Flow/Task/reviewer/lease, and owner authorization
are supplied by existing SELECT-only `FakeReadOnlyPG` fixture
`tests/qualification/test_browser_current_central_state_join_20261021.py`.
Its real SQL paths run but its records are synthetic, not current application
PostgreSQL. Before each independent HTTP read, its *in-memory statement list*
is cleared because this fixture models a single fresh transaction. No DB
operation or application file is reset. The signed original source admission
claims are reissued inside the fixture to keep the short 10-second time window
valid; **these are not independently enrolled production admission decisions**.

The original local screenshot/DOM/HAR files in this new test are **synthetic
test-owned bytes**, not actual browser captures. They are written to an isolated
`tmp_path` tenant mount with a test-pinned mount descriptor and examined by
the real source readback implementation. The test never invokes Playwright,
opens Chromium, drives a browser, navigates a target, or calls
`/mcp/execute`. This deliberately avoids duplicating prior **real local
Chromium** evidence:
`tests/test_browser_current_evidence_readback_20261021.py`,
`tests/qualification/test_browser_full_evidence_source_contract_20261020.py`
and `tests/qualification/test_browser_hardened_status_recovery_20261021.py`.
Those earlier tests cover real offline Chromium original PNG/DOM/HAR; their
presence is referenced, **not claimed as a new run or added to this result**.

## The custody and authority boundaries

| Boundary | Qualifying observation | What it **does not** establish |
|---|---|---|
| One original RequestJournal reservation | `reserve()` writes the one-shot local journal; repeated reservation returns False, including after damaged or uncertain evidence. | No provider navigation retry is granted, no central ACK becomes a fresh original Action. |
| Provider-local original bytes | Three original test artifact files, their exact SHA-256/length/relative path, an original signed provider sidecar and terminal journal are independently re-read by `current_evidence()` and provider ASGI. | Does not establish current signed Task, ROE, reviewer, lease, target owner, target effect or reporting truth. |
| Independent central current authority | Production central ASGI independently verifies signed source + signed provider attestation, original 0027/0034, signed ROE, Task, Flow, reviewer and lease in a READ ONLY snapshot and issues a 5-second central Ed25519 certificate. | Response explicitly sets `original_browser_artifact_bytes_verified=false` and `independent_target_effect_verified=false`. It does **not** access or lock the producer's actual files. |
| Signed central current before any local journal | A valid central current certificate can be issued from independent recorded attestations while local `RequestJournal`/sidecar is missing. | Merely joining two signatures or statuses is **not** proof of current local custody. |
| Missing screenshot / DOM / HAR | Removing any one of the three original test files makes provider-local current readback `unknown`; a previously signed central current certificate remains authentic until expiry but **never** asserts artifact bytes verified. | Cannot show complete immutable evidence or promote a report. |
| Captured HAR modified after central proof | Provider-local readback returns `unknown`; historical provider status may remain independently signed `succeeded`; previously issued central proof remains signed but is explicitly not byte proof. | No single atomic snapshot of provider files and central PostgreSQL; a TOCTOU gap remains. |
| Provider key revocation / stale sidecar | Removing trusted provider public key or re-signing an expired native sidecar denies current local proof. Revocation denies central new proof; previously signed current certificate still expires normally. | Signed provider status is not an independent target-owner statement. |
| Forged central authority/effect | Provider-signing key cannot produce acceptable central current certificate, and changing `target_effect_verified` to true invalidates current verifier. | No actor may mint an operator/target-owner grant via the native provider. |
| Current Task / ROE / reviewer revoked | Central current readback denies when the relevant synthetic authoritative row is revoked even when original files still match locally. | Provider bytes cannot replace the central present authorization decision. |
| Lost readback ACK | The test deliberately discards a successfully issued read-only central reply, then removes the signing capability for the next read. New readback fails; one-shot journal never reopens. | This **simulates a lost client acknowledgment**, not a real network partition, process crash or application DB rollback. |

All routes and local file access remain read-only **after** the fixture's initial
own private reservation and synthetic capture setup. No native RequestJournal
condition or signed central response is converted into a provider/target retry.

## Current production gap and safe integration recommendation

**The missing operation is an independently authenticated, durable,
post-commit join of the *same* original Action, the present producer-owned
bytes, a fresh central 0027/0034/ROE/Task/reviewer/lease snapshot and target
owner/effect if a report would assert any.** The current provider-local readback
and central authority endpoint are independent observations. They provide no
atomic read/lock across host mount and PostgreSQL. An attacker/process can
modify the HAR after a central signed snapshot, or its local signed sidecar can
be missing while a valid central current certificate is separately obtainable.

An integration must require exact `request_id`, engagement, Task, Flow,
subtask, Action, owner, preflight, authorization SHA, original intent SHA,
provider signed evidence SHA and **all three currently reread SHA/size/path
values**, and independently verify separately enrolled keys with fresh,
bounded expiry and current revocation. Use post-commit durable custody receipts
and a fresh second authority/byte check immediately before reporting, while
clearly labeling any remaining race as UNKNOWN. **Do not** elevate an HTTP 200,
provider `succeeded`, a signed status, a source admission or central
`authority_current` to original-target effect or release certification.
Provider-local forensic bytes should remain private and must not be copied into
ordinary UI/logs/reporting; absent immutable source ownership evidence,
return **UNKNOWN**.

Deployment evidence still required: independently witnessed owner of record,
immutable original byte retention and host mount access, isolated producer
process identity and TLS/CA, replica crash/failover recovery, real current
PostgreSQL transactions and revocation races, source-authorized real browser
navigation, and target-owner effect verification independent from the provider.

## Execution

```powershell
poetry run pytest -o addopts='' tests/qualification/test_browser_current_original_custody_join_20261021.py -q --disable-warnings
poetry run black --check tests/qualification/test_browser_current_original_custody_join_20261021.py
```

**Observed result, 2026-10-21:** **9 passed, 36 warnings** in 21.30 seconds
using the repository Poetry environment, executing only the newly assigned
qualification file. The warning categories were suppressed by the focused
invocation and were not independently triaged; no test failed. This test does
not assert live fleet
readiness, real signed reviewer enrollment, application DB state transition or
physical target-side effect.
