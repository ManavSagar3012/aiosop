# Browser ORIGINAL host enrollment and read-only custody admission — 2026-10-22

**Release: NOT READY.** A newly implemented, explicitly configured host
enrollment class safely binds original raw HTTP, screenshot PNG, DOM HTML and
HAR bytes to the existing Browser CURRENT read-only custody bridge. It does
not start a Browser, issue a target request, retry an UNKNOWN Action, settle
target effects or certify release.

## Traced mounted contracts

- `src/ai_osop/api/main.py` mounts
  `create_browser_current_custody_router()` with **no host service**; the
  mounted `POST /system/browser/custody/readback` is senior-JWT-only and
  returns machine-readable `503 UNVERIFIED` until explicitly configured.
- `src/ai_osop/api/browser_current_custody_readback.py` accepts precisely
  `engagement_id` and `request_id`, then resolves the host-enrolled original
  URI, original source/provider signed envelopes and exact source identity.
- `src/ai_osop/adapters/native_browser_current_original_bridge.py` checks
  original central CURRENT 0027/0034 source, persisted Flow/Task/ROE/owner,
  human approval, lease and revocation using independent signed trust roots
  and a PostgreSQL read-only snapshot, plus the native Browser's original
  provider-local artifact readback. It then invokes a host-owned byte reader
  for screenshot, DOM and HAR; repeats provider and central CURRENT readback;
  demands a **different**, externally enrolled custody Ed25519 signature.
- The Browser provider currently attests **three** file artifacts (PNG,
  HTML and HAR). There is no fourth raw-HTTP Browser evidence artifact
  in its signed proof or external bridge result.

## New enrollment factory

`src/ai_osop/api/browser_host_original_enrollment_20261022.py` exports:

- `EnrolledBrowserOriginal(original, signed_enrollment)`: host-controlled
  record combining the existing source/Flow binding with a distinct signed
  four-artifact enrollment manifest.
- `BrowserHostOriginalEnrollment(...).service()`: independently configured
  `BrowserCurrentCustodyReadback` service, with
  `host_record_resolver` and `original_reader` bound to the approved
  original host record and pinned private mount. **It creates no signing key,
  root, enrollment record, or Browser side effect.**
- `ENROLLMENT_DOMAIN`: dedicated Ed25519 domain
  `ai-osop/browser-host-original-immutable-enrollment/v1\0`.

The independently provided signed enrollment claims must contain exact
original request/engagement/Flow/Task/subtask/action/owner/preflight and
authorization/intent/full-URI SHA identities; enrollment version and ID;
sealed host-root path SHA; issued/expiry with maximum one-day lifetime;
and all four `{path,sha256,size_bytes}` artifact descriptions.

The host enrollment root key and final custody witness root key are two
**separate, pre-enrolled Ed25519 public-key maps**. Neither can overlap
each other, the central CURRENT issuer, the 0034 original source issuer or
the Browser provider's signing key. Missing/revoked/changed roots fail
closed. The only permitted paths are exact signed
`captures/<32-lowercase-hex>.http|png|html|har` leaf names beneath
`<host_root>/<original_engagement_id>/captures/`. Neither arbitrary
filepaths nor any URI are accepted through the HTTP request.

The host reader opens **all four original files** and hashes their raw bytes
with SHA-256. Three must also match the exact preverified Browser-native
attestation; independently host-enrolled `http_raw` is mandatory and
never substituted with a claimed HAR response. The existing bridge accepts
only the three native filenames, so raw HTTP is a **local extra prerequisite**,
not a new independent target-effect witness or an additional raw-HTTP API
return. No raw bytes/path/token/URI reach the signer or UI.
Once the bridge has completed its second provider and central CURRENT checks,
the factory rereads **all four** immutable originals before delegating to
the externally installed custody signer. A raw-HTTP mutation between the
first reader callback and the last authority snapshot therefore also denies
the witness.

Path safety uses component-by-component read-only descriptors:

- On POSIX: from the filesystem root, `openat`-style directory-relative
  `O_DIRECTORY|O_NOFOLLOW` for each directory and `O_NOFOLLOW` for a
  regular final file. Reject nonregular files, multiple links, writable
  mode and changing inode/length/timestamps during the bounded read.
- On Windows: `CreateFileW` with
  `FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS` for every
  ancestor and file, holding ancestor handles with read-only sharing until
  finished. Check reparse flags, directory attributes, hard-link count and
  read-only attribute. Read directly via the final handle and compare
  immutable size/timestamps. UNC/network shares and alternate streams
  are denied.
- Unsupported platforms fail closed. The host still must independently
  establish that this root is an owner-controlled sealed mount, with
  reliable file immutability and no privileged outside writer or revoked
  issuer. File attributes alone are not a substitute for WORM/snapshot
  control or host process custody attestation.

## Prime integration hook

**Server app mount:** the existing `main.py` registration currently
constructs the deny-only service. The prime may replace that router
registration at its own disjoint integration stage **only after** provision
of independently trusted host enrollment keys, separate custody keys,
host-owned sealed original files/record resolver, and pinned central/provider
transport clients. Concrete constructor usage:

```python
from ai_osop.api.browser_host_original_enrollment_20261022 import (
    BrowserHostOriginalEnrollment,
    EnrolledBrowserOriginal,
)
from ai_osop.api.browser_current_custody_readback import (
    create_browser_current_custody_router,
)

enrolled = BrowserHostOriginalEnrollment(
    host_root=host_configured_absolute_private_original_root,
    records=host_loaded_original_enrollment_records,   # (engagement, request)
    enrollment_roots=preinstalled_enrollment_public_roots,
    custody_roots=separate_custody_public_roots,
    custody_signer=external_independent_host_custodian_signer,
    central_client=host_pinned_current_authority_client,
    provider_client=host_pinned_browser_original_readback_client,
    central_bearer=host_current_authority_service_bearer,
    provider_bearer=host_provider_original_readback_bearer,
    enabled=True,
)
app.include_router(create_browser_current_custody_router(enrolled.service()))
```

The operator must send **only**:

```json
{"engagement_id":"eng-original","request_id":"req-<48 lowercase hex>"}
```

Missing enrollment, forged or revoked enrollment signer, wrong owner/Flow/
ROE/source, missing or writable raw file, unexpected symlink/reparse point,
hardlink, modified SHA or lost CURRENT readback keep `UNVERIFIED`. No key
material is generated or automatically enrolled by this code.

## Qualification and limits

Executed:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_browser_host_original_enrollment_20261022.py -q --disable-warnings --tb=short
# 13 passed, 1 skipped (Windows unprivileged symlink creation unavailable)

.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_browser_host_original_enrollment_20261022.py tests/qualification/test_browser_custody_readback_join_20261021.py tests/test_native_browser_current_original_bridge_20261021.py -q --disable-warnings --tb=short
# 60 passed, 1 skipped, 244 warnings (existing FastAPI startup deprecations)
```

Tests use actual independently generated **test-only** enrollment and
custodian Ed25519 signers, real local Windows file handles, real Browser
native and central ASGI readback endpoints, a mounted senior operator route
and prior FakePG current-source/ROE/approval fixtures. They verify normal
four-byte-source admission, enrollment signer forgery/key overlap, original
raw HTTP and all three Browser artifact mutations, hardlinks, writable files,
late raw HTTP modification between initial and final central CURRENT reads,
stale/revoked current ROE, no private path leaks and strict path manifest.

**Remaining release blockers:** no real independently enrolled host records,
physical WORM/immutable mount/custodian identity, pinned runtime network
transport or production PostgreSQL; synthetic offline original HTTP and
Browser PNG/DOM/HAR fixture bytes; no standalone signed original raw-HTTP
producer/provider contract; no independent target-owner effect; and no
multi-replica CURRENT/ACK-loss qualification. An unprivileged symlink
creation test was skipped on this Windows fixture environment; the production
Windows reader still rejects reparse handles explicitly.
