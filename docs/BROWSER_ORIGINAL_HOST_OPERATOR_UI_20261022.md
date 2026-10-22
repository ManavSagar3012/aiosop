# Browser four-original senior host readback — mounted operator workflow

**Date:** 2026-10-22. **Workspace:** original shared dirty AI-OSOP. **Release:** NOT PRODUCTION CERTIFIED / NOT READY.

## Production routes and explicit host enrollment

The original FastAPI application mounts exactly one new default-deny readback endpoint through `create_browser_original_host_join_router()`:

`POST /system/browser/original-host/readback`

It remains 503/UNVERIFIED until a trusted host Python bootstrap separately provisions independently enrolled signer/custody material and calls:

```python
from ai_osop.api.browser_original_host_join_20261022 import (
    BrowserOriginalHostJoin,
    install_browser_original_host_join,
)

# enrollment must already be externally host-enrolled, independently signed,
# and host-owned; it cannot be created or requested through HTTP.
install_browser_original_host_join(
    app, BrowserOriginalHostJoin(enrollment, enabled=True)
)
```

The installer uses an exact typed host-only single-use registry; no replacement or client-installed signer/root/path is possible through the new endpoint. The join rechecks four immutable original SHA/size sets: raw HTTP response, screenshot PNG, DOM and HAR, plus host custody roots, separate signed native custody and an additional signed central CURRENT Flow/Task/owner/ROE read after final original byte examination. A currently signed target-owner effect is **not** claimed.

## Operator-facing implementation

The read-only Administration view now includes `BrowserHostOriginalPanel`, backed by `ui/src/services/browserHostOriginalReadback.ts`. It requires a current `senior_operator` JWT in memory, secure frontend/API origins, exact bounded engagement ID and request ID, and sends only those two identifiers to the mounted endpoint.

It uses a single `fetch` POST with `credentials:'omit'`, `cache:'no-store'`, `redirect:'error'`, `referrerPolicy:'no-referrer'`. Response handling requires a bounded <=8192-byte strict UTF-8 JSON, **exact** success keys/status and all four SHA-256/size pairs, and the explicit flags `independent_target_effect_verified=false`, `automatic_retry_authorized=false`, `production_release_certified=false`. The client rejects 503, forged flag escalation, unexpected original-text or path fields, invalid hashes, wrong request identities, expired operator session/signout, malformed content type and arbitrary response fields.

Only truncated digest prefixes and sizes are displayed, not original HTTP/PNG/DOM/HAR content, URLs, paths, keys or bearer. Results are cleared after five seconds or on session changes because the host response is **not a separately signed, independently reverified client receipt**. The panel cannot execute Browser navigation/scanning, authenticate a target effect, restart an UNKNOWN action, or approve a release.

## Verification

- New `ui/tests/browser-host-original-readback-20261022.test.mjs`: **5 passed** (single signed senior request and two IDs; default 503/forged effects/extra fields/bad hashes; invalid identifiers/non-senior; signout response race; static no-execution panel).
- New plus prior Browser custody Node tests: **13 passed**, 0 failed.
- `npm --prefix ui run typecheck`: PASS.
- `npm --prefix ui run build`: Vite 7.3.3 PASS, **2674 transformed modules**.
- Browser host backend join worker: **23 passed**, plus existing custody bridge and original enrollment suites **85 passed / 1 Windows symlink privilege skip**; joined Browser+SourceMap+eleven MCP identity selection **55 passed / 2 skips**. Test-only signer roots are **not deployed host trust**.

No real Browser external target, scanner, provider billing, application database, Docker control, agent prompt, or release approval was contacted/modified by this frontend workflow. Actual independent host key/WORM enrollment, target-owner effects, physical ASGI socket/client receipts and separately signed senior release remain blockers.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
