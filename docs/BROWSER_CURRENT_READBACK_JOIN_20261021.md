# Browser CURRENT original-byte custody: operator mount (2026-10-21)

**Qualification: NOT READY for production.** This is an optional read-only host
operator mount, not registered in `api/main.py`. It produces a signed witness
of the *three original Browser artifact bytes* only after a separately owned
custodian independently rereads them and the existing central CURRENT authority
and provider-original readback both succeed before and after the read. It never
proves target effects, settles an UNKNOWN Action, creates a new navigation
grant, or authorizes retries or release.

## Existing traced sources

- `memory/browser_source_authority.py`: original 0027 dispatch source,
  committed original source preflight, signed original action and URL digest.
- `orchestrator/browser_current_authority_readback.py`: central READ ONLY
  snapshot verifies original Action/attempt/source, signed ROE, current owner,
  reviewer and lease, current Flow revision/Task/subtask, full original URI,
  scope, approval and user controls; emits independent five-second Ed25519
  current-authority envelope and explicitly sets `artifact_bytes_verified=false`.
- `api/routers/native_browser_current_authority.py`: dedicated bearer
  `POST /native-browser/current-authority/readback`.
- Native Browser provider: `POST /mcp/request/evidence/readback` performs a
  provider-local read of immutable screenshot PNG, DOM HTML, and HAR; provider
  evidence attestation is a provider assertion and never the host custody
  witness.
- `adapters/native_browser_current_original_bridge.py`: independent host
  join sequence: central CURRENT -> provider original -> independent owner
  raw-byte reader with SHA-256 match -> provider original -> central CURRENT
  again -> separate custodian signature verified against enrolled root.

## New operator API

`src/ai_osop/api/browser_current_custody_readback.py` exposes:

```python
from ai_osop.api.browser_current_custody_readback import (
    BrowserCurrentCustodyReadback,
    OriginalBrowserHostRecord,
    create_browser_current_custody_router,
)

# Construct these in an independently configured host custodial service:
# - host_record_resolver(engagement_id, request_id, senior_subject) -> record
# - NativeBrowserCurrentOriginalBridge(...), with independent reader, signer,
#   enrolled distinct custodian roots and pinned host-provisioned HTTP clients.
# The resolver obtains signed 0027/0034 originals, original full URI and exact
# source/flow/owner/ROE/preflight/authorization/intent SHA from a host ledger.
service = BrowserCurrentCustodyReadback(
    enabled=True,
    independent_host_enrolled=True,  # only after external enrollment verified
    bridge=host_configured_bridge,
    host_record_resolver=host_record_resolver,
)
app.include_router(create_browser_current_custody_router(service))
```

The imported `router` exists for deliberate fail-closed compatibility and is
**always unconfigured**. No environment flag, provider response, UI control,
arbitrary path, test signer or caller-supplied proof enables independent custody.
`independent_host_enrolled=True` is a host operator assertion; the module
cannot inspect host process identities, storage mounts or signing key
enrollment by itself. A real host must implement and attest these dependencies
outside the Browser provider and enroll a separate cryptographic trust root.

The mounted route is senior-JWT-only `POST /system/browser/custody/readback`.
Request body (exact keys, bounded):

```json
{"engagement_id":"eng-...", "request_id":"req-..."}
```

Authentication flows through existing `require_role("senior_operator")`, so
the normal JWT signature, expiration and configured credential-revocation
behavior apply. Credentials must appear in the single Authorization header,
with HTTPS or numeric-loopback HTTP transport, and no query string. The signed
central read still independently checks current original owner, reviewer, ROE,
Task, Flow revision, approval, lease, source token, URL origin and full URL SHA.
The host resolver supplies the **original full URI** to compare with its signed
digest; the operator never supplies a URI/path/port or artifact bytes.

With an actually enrolled independent host custodian, successful read-only
result has `status=CURRENT_ORIGINAL_CUSTODY_VERIFIED`, a domain-separated
Ed25519 `custody_proof` and a bounded SHA/size manifest for PNG/HTML/HAR.
`current_original_artifact_bytes_verified=true` means only the original
readback comparison, not authenticity of page content, target-side changes,
permission to use an HTTP session, original action outcome or release. The
response contains no raw file bytes, URI, bearer, or filesystem location.

Any absent host enrollment/reader/signer/record, changed original URI/identity,
bad or expired current signature, signer revocation, changed original bytes,
ROE/owner/Flow mismatch, or missing provider/central readback gives HTTP 503:

```json
{
  "detail": {
    "status": "UNVERIFIED",
    "reason": "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED",
    "current_original_artifact_bytes_verified": false,
    "independent_target_effect_verified": false,
    "automatic_retry_authorized": false,
    "production_release_certified": false
  }
}
```

The closed set of reason codes includes
`INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED`,
`ORIGINAL_HOST_RECORD_UNAVAILABLE`,
`ORIGINAL_HOST_RECORD_UNVERIFIED`,
`ORIGINAL_HOST_IDENTITY_MISMATCH`,
`CURRENT_ORIGINAL_CUSTODY_UNVERIFIED` and
`CURRENT_ORIGINAL_READBACK_UNAVAILABLE`. Invalid user requests return
`INVALID_OPERATOR_REQUEST` (422); missing/unsafe transport or query credentials
return their corresponding machine-readable denial.
No provider-originated HTML, screenshot, HAR, forged signature or lost ACK
can be promoted to host independent original-byte proof by this route.

## Qualification evidence and limitations

`tests/qualification/test_browser_custody_readback_join_20261021.py`
exercises the mounted route, authentic senior JWT dependency, real independent
Ed25519 source/provider/central/custody paths, provider ASGI and central ASGI
readback, and existing isolated FakePG signed current ROE test fixtures.
Cases include no host enrollment, role denial, exact Flow/owner/authorization/
source-preflight/URI mismatch, original PNG/DOM/HAR tampering, revocation
during byte read, signer withdrawal, malformed/duplicate JSON and lost ACK.

Command and observed result:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_browser_custody_readback_join_20261021.py tests/test_native_browser_current_original_bridge_20261021.py -q --disable-warnings
# 47 passed, 188 warnings (existing Browser MCP startup/shutdown deprecations)
```

The assets are fixture bytes, **not real Chromium evidence**. FakePG only
simulates the schema and SELECT read transaction. No disposable real
PostgreSQL instance, host process isolation proof, independently configured
production roots/keys, real custody reader mount, or real target-side effect
has been qualified by this file. The 0035/0037 SourceMap provenance and any
other independently signed effect-admission fences remain separate. The
original HTTP request/response information is embedded in the HAR only:
no separate independently preserved raw-HTTP Browser artifact/witness was
found in these Browser custody endpoints. A separate original HTTP proof,
if required for effect reporting, needs its own independently attested
producer and current host readback and is **not certified here**.

Mount only after separate host procurement, distinct custodian signing roots,
real original-byte mount ownership/immutable read guarantees, production JWT
revocation, provider and central transport pinning, PostgreSQL qualification
and operator verification. The prime integrator should keep this component
unmounted until those preconditions are independently established.
