# Browser four-original host CURRENT readback join — 2026-10-22

**Status: mounted-ready, not production certified.** This optional operator
readback exposes no new Browser execution or evidence creation. It can return a
bounded four-file **original-byte digest observation** only after independently
signed enrollment, native Browser custody and fresh central CURRENT authority
all agree. It does **not** establish independently witnessed target effects,
confirm delivery of an original HTTP response, settle a lost Action ACK,
authorize automatic retries or approve a production release.

## Actual traced boundary

The original API in `src/ai_osop/api/main.py` already mounts:

- `POST /system/browser/custody/readback` through
  `create_browser_current_custody_router()`: default denies until
  `install_host_browser_original_enrollment(app, enrollment)` is explicitly
  called with a separately enrolled `BrowserHostOriginalEnrollment`.
- `POST /native-browser/current-authority/readback`, a host-authenticated,
  **READ ONLY** centrally issued Ed25519 five-second CURRENT Flow/Task/ROE
  proof based on the original PostgreSQL action/source/authorization rows.
- Browser-native `POST /mcp/request/evidence/readback` verifies the original
  screenshot/DOM/HAR artifact SHA and size under the enrolled Browser provider
  key, but is **provider testimony only** and never proves target effects.

`browser_host_original_enrollment_20261022.py` already binds independently
enrolled `http_raw`, `screenshot`, `dom`, `har` original bytes to the exact
signed engagement, request, Flow, Task, subtask, action, owner, preflight,
authorization and original intent/URI hash. It rejects mutable, linked,
symlink/reparse, nonregular or out-of-root file descriptors and compares
bounded exact SHA-256 bytes. Host enrollment keys must be distinct from the
custody signer and the source/current/provider signing authorities; it never
generates any of those keys.

## Added reusable join

**New:** `src/ai_osop/api/browser_original_host_join_20261022.py`

- `BrowserOriginalHostJoin(enrollment, enabled=True).readback(engagement_id,
  request_id, actor_id, *, cancellation_check=None)`
- `create_browser_original_host_join_router(join)`, which exposes
  **`POST /system/browser/original-host/readback`** when explicitly mounted.
  With no join or `enabled=False`, it returns `503 UNVERIFIED`.
- `install_browser_original_host_join(app, join)`, a **host-only synchronous
  one-time admission** for an already mounted default-deny router. The default
  route reads `request.app.state` on every authorized request, checks a
  separately maintained process-local installed-object registry, and denies
  if no exact enabled `BrowserOriginalHostJoin` and exact enrolled
  `BrowserHostOriginalEnrollment` have been installed.

The installer validates that the supplied object has the exact expected types,
the independent roots and signed host enrollment manifest exist, and the
preexisting native custody service is truly configured. It refuses apps
without exactly one `POST /system/browser/original-host/readback` mounted in
the unconfigured/default-deny mode. A process-wide host-only lock makes the
`app.state` / registry check-and-insert atomic against simultaneous bootstrap
threads: the same or another join cannot be installed twice. Failed
installation leaves the app default-deny and eligible for a later valid host
installation. Even a direct overwrite of the `app.state` slot does not
replace its registry-verified join. This is an in-process bootstrap invariant,
**not** a cross-process attestation or protection against a privileged
process administrator changing application code.

The join verifies independently pinned enrollment roots and snapshots original
enrollment, source, provider envelopes and scope identities. It then uses the
existing custody service to execute the original provider/central
read-only checks **twice each**, reading all four originals and separately
verifying the custody Ed25519 signature. The custody signature covers the
original provider's three-file manifest, not a newly invented raw-HTTP
provider attestation. The join independently opens/hash-checks all four host
originals again, including `http_raw`, obtains **a third fresh signed central
CURRENT** check after this final host read, and then re-verifies:

- Signed host enrollment and identical unchanged original source/provider
  envelopes, manifest, Flow/Task/owner/ROE/intent/URL hashes
- Same independently pinned enrollment/custodian roots before and after,
  including revocation and rotation; no key supplied by the HTTP request
- Third central CURRENT evidence/authorization and the original action
  identity, rejecting revocation, mismatch, expiry or lost ACK
- Cancellation/disconnect before entry, after the custody join, after the
  final byte read and after the last signed central read; no replay

The **only success** is `CURRENT_HOST_ORIGINAL_FOUR_DIGEST_READBACK`,
containing fixed four `{sha256,size_bytes}` descriptors, original opaque
engagement/request IDs, SHA digests of verified signed enrollment/custody
claims, and three non-effect flags explicitly `false`. No raw HTTP,
screenshot, DOM, HAR body, path, URI, bearer, signer key or provider command
is returned. An HTTP 200 proves a scoped *readback snapshot*, not ongoing
authority or target-owner testimony; authorization may revoke immediately
after the final check.

The server returns `503` with a bounded `UNVERIFIED` detail and
`current_original_artifact_bytes_verified=false`,
`raw_http_original_bytes_verified=false`,
`independent_target_effect_verified=false`,
`automatic_retry_authorized=false` and
`production_release_certified=false` on all admission/readback denials.

## Prime mounting hook — no existing routes edited here

The independent host must supply a real, previously enrolled configuration;
do **not** construct signer roots from operator HTTP or synthesize signatures:

```python
from ai_osop.api.browser_original_host_join_20261022 import (
    BrowserOriginalHostJoin,
    create_browser_original_host_join_router,
    install_browser_original_host_join,
)
from ai_osop.api.browser_host_original_enrollment_20261022 import (
    BrowserHostOriginalEnrollment,
)

host_enrollment = BrowserHostOriginalEnrollment(
    host_root=host_sealed_originals_root,
    records=host_enrolled_signed_original_records,
    enrollment_roots=host_pinned_distinct_enrollment_public_keys,
    custody_roots=host_pinned_separate_custody_public_keys,
    custody_signer=separately_authenticated_host_custodian_signer,
    central_client=independently_pinned_central_readback_client,
    provider_client=independently_pinned_native_browser_readback_client,
    central_bearer=host_only_central_service_bearer,
    provider_bearer=distinct_host_native_service_bearer,
    enabled=True,
)
# Prime owns the only old-file main.py edit: import and mount ONCE at startup.
# Safe to mount at import time before host provisioning.
app.include_router(create_browser_original_host_join_router())

# Separately trusted host bootstrap, after real independent enrollment,
# before serving requests. NOT a REST endpoint, env flag, or caller input.
install_browser_original_host_join(
    app, BrowserOriginalHostJoin(host_enrollment, enabled=True)
)
```

This is a **separate nonconflicting endpoint**; do not duplicate or replace
the existing `/system/browser/custody/readback` route. Mount its **default
router first**, and install the preconfigured host join separately afterwards
(and only once). No production signing root is configured by importing the
module or by creating this default router. The prebound
`create_browser_original_host_join_router(join)` form is retained for
isolated tests/explicit legacy wiring but is **not** eligible for the
late host installer. Only a currently signed, server-authenticated
`senior_operator` may make the request:

```json
{"engagement_id":"eng-original","request_id":"req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

All other fields, including user-supplied URI, manifest, proof, file paths or
effect/approval flags, are rejected before original-byte access. Transport
is HTTPS or numeric-loopback HTTP as enforced by the existing route parser;
dedicated central/provider bearer and nofollow original mount never derive
from the caller. The host must provision independently pinned central and
Browser-native HTTP clients, keys and read-only storage, outside this code.

## Verification

Command (test-generated Ed25519 roots, synthetic original HTTP/PNG/DOM/HAR,
existing mounted FastAPI central/native routes, isolated FakePG only):

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_browser_original_host_join_20261022.py -q --disable-warnings --tb=short
# 23 passed, 92 existing FastAPI warnings
```

Positive fixture checks three signed central CURRENT and two provider-native
readbacks, distinct enrolled custody signer, exact four SHA/size summaries,
unchanged original UNKNOWN, no target/provider execution or private bytes.
Negative fixtures check unsigned configuration and roles, unapproved request
fields, forged independently signed enrollment issuer, expired enrollment,
foreign tenant/Flow, all four original byte mutations, original ROE revoke
before and during the final central read, host root rotation during the join,
raw HTTP mutation immediately after the genuine custody signature, and
pre/post request cancellation with no retries.

Additional mounted FastAPI tests cover: default-unconfigured 503 before any
native/CURRENT I/O, valid late host installation without another route, two
successive **read-only** original readbacks (without Action replay or retry),
forged HTTP body attempts to set path/roots/signer before and after install,
invalid/downgraded root or disabled configuration not poisoning the slot,
duplicate/prebound/nonexistent route rejection, tampered `app.state` after
installation and eight concurrent host installer calls with exactly **one**
winner.

**Unresolved real-world blockers:** no independently enrolled physical
owner-owned WORM/snapshot originals; host byte reader immutable-mount
attestation is not a target-owner effect signature; the provider still has no
first-class separately signed original *raw HTTP* artifact; no installed
production host roots/custodian identity/pinned transport verified here; no
live current PostgreSQL/multi-replica cancellation/revocation qualification.
The combined four-file digest result is **not one new atomic Ed25519
signature over all four bytes**: it is a read-only join of independently
enrolled four-file host claims, existing signed three-file custody, and
current central ROE/Flow authority. Do not claim atomic HTTP-client receipt
or definitive target-effect evidence.
