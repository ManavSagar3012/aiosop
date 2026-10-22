# SourceMap original host witness: senior operator readback

**Date:** 2026-10-22. **Scope:** a new, unmounted, read-only operator API module and isolated qualification tests. This work was performed in the original shared `/burp_mcp/ai-osop` tree without application database, Docker, native process, real external verifier, scanner, mount, provider, target or deployment access.

## Current original admission chain

The existing contracts are distinct authorities. A positive status requires their **same-original, current, independently signed** join; a signed receipt, process PID or mount status in isolation is insufficient.

| Boundary | Original source and enforced facts |
| --- | --- |
| `0013` reviewed source | `SourceMapSourceAuthorityStore._source` checks current original PostgreSQL artifact `BYTEA`, exact byte SHA and metadata manifest; `0015` requires a distinct senior reviewer approval. A client-supplied path/URI cannot stand in for original bytes. |
| `0026` virtual folders and `0030`/`0031` staging | `NativeMCPWorkerSupervisionStore._current_folder`, resource offer and staging SHA must bind the current Task/Flow folder and the redeemed grant. Offered metadata is not independently witnessed native filesystem custody. |
| `0027` Action | Original unknown Action, lease and Task/Flow/owner/signed ROE must match across evidence and persisted records. The original is irreversibly `UNKNOWN` before crossing the provider boundary. A lost acknowledgment is not permission to retry. |
| `0029` native grant | One-use exact signed token, grant, redemption, current authorization and resource hash are checked together. **Present operational `_require_operational_pair` only accepts the six Go `authority_status` pairs; `source-map-mcp/inspect_local_original_sourcemap` remains denied.** A SourceMap `0035` preflight is a different authority. |
| `0033` supervisor | Fresh signed running ledger with original `grant_id`, worker/container/epoch and exact last CAS transition/event digest. Persisted `updated_at` is historical, not a current heartbeat, live PID or mount. |
| `0035` original preflight + current STATUS | Single issued source preflight and signed short-lived current STATUS; no minting another proof or replaying an original Action to recover from UNKNOWN. Both must refer to the same reviewed original. |
| `0036` finite schema pair + `0037` binding | A database representation and immutable `bound_only` provenance binding do not independently authorize execution or establish source bytes/process; `0037` must agree with original 0027/0029/0035 evidence. |
| Separate Linux host observers | `sourcemap_supervisor_process_witness.py` reads signed PID with `pidfd` and `/proc` checks (PID start ticks, fsuid, namespace and cgroup); `sourcemap_native_mount_observer.py` validates a separately signed SourceMap process binding and **read-only, nonroot native mount** under protected `/run/osop-sourcemap/sourcemap-originals`. They are distinct producer roots, not a `0033` self-attestation. |

The existing `SourceMap0033CurrentWitness.corroborate(...)` is the mandatory read-only verifier used by this API. It rejects absent/stale/forged separate 0033, STATUS, 0035 preflight, source-specific supervisor, live process and native mount signatures, then checks matching original `0013`/`0015`, `0027`, `0029`, `0030`/`0031`, `0033` and `0037` database state within one read transaction. It requires concrete current process PID/start/namespace/fsuid and read-only mount proof; `signed original available` or a Go-owned PID cannot substitute. Its positive response is `corroborated_read_only`, explicitly `authorizes_execution: false` and `authorizes_mount_or_replay: false`.

## New host readback and its mount hook

`src/ai_osop/api/source_map_host_witness_operator.py` exposes a **mount-ready**, default-unconfigured `router` and factory `create_source_map_host_witness_router(service)`. The precise operator endpoint is:

```http
POST /system/source-map/host-witness/readback
Authorization: Bearer <signed senior-operator JWT>
Content-Type: application/json

{"engagement_id":"eng-...","request_id":"req-<48 lowercase hex>"}
```

Only `engagement_id` and original `request_id` are accepted. Reject query strings, extra root/path/URI/PID/namespace/credential/grant/capability/target/source-proof input, duplicate JSON members, oversized/malformed input, browser Origin headers, duplicate/missing authorization headers and plaintext HTTP outside numeric loopback. Existing `require_role("senior_operator")` authenticates signed HMAC/OIDC JWT; the route additionally demands a nonempty signed subject and unexpired integer JWT `exp`. Headers use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

The prime's host-side initialization hook is:

```python
from ai_osop.api.source_map_host_witness_operator import (
    SourceMapHostWitnessOperator,
    HostPinnedSourceMapReadback,
    create_source_map_host_witness_router,
)
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore

# Independently review and install `read_only_host_source` in the trusted
# host startup code. Its only inputs are original engagement/request and
# authenticated operator identity. It reads an already persisted host
# record; it returns HostPinnedSourceMapReadback(original_identity, signed_proofs).
# It may not stage, start processes, issue proofs, produce signatures, retry
# UNKNOWN, fetch arbitrary caller paths or reach a live target.
actions = FlowMCPActionStore(orchestrator.session_memory, orchestrator.mcp_registry)
host_operator = SourceMapHostWitnessOperator(
    independently_enrolled=True,
    host_pinned_reader=read_only_host_source,
    actions=actions,
)
app.include_router(create_source_map_host_witness_router(host_operator))
```

`HostPinnedSourceMapReadback.original_identity` must be an exact dictionary of the original `request_id`, `engagement_id`, `flow_id`, `task_id`, `subtask_id`, `action_id`, `owner_id`, `approval_id`, `lease_id`, `artifact_sha256`, `manifest_sha256`, and `authorization_sha256`. The `signed_proofs` exact keys are `supervisor_observation`, `source_status`, `source_preflight_proof`, `native_grant_token`, `live_process_witness`, `signed_supervisor_source`, and `native_mount_witness`. Each must be an original independently produced signed envelope where required by the existing verifier. The untrusted request provides none of them. The resolver must check actor access to its host-held record; the source/core verifier independently binds the result to signed persisted original state.

Host enrollment pins the immutable fingerprints of all five independent existing **public** SourceMap verifier roots at service construction and rereads them before each operation. Missing, duplicate-across-domains or rotated keys fail closed. This module never creates/enrolls roots, takes root configuration from a request, or treats a `host_enrolled` flag as cryptographic evidence: the core verifier still checks all actual Ed25519 signatures and current rows. The existing original `0029` signer and authorization verifier remain additionally mandatory; this API does not expand them.

A conforming positive result contains only booleans, with `status: CURRENT_ORIGINAL_HOST_WITNESS_VERIFIED`, and proves a *current read-only original custody/ledger join only*. It omits tokens, signatures, public key IDs, PIDs, namespace, private mount path, source payload and artifact bytes. It explicitly sets `original_action_replayed`, `authorizes_execution`, `target_effect_verified`, `automatic_retry_authorized`, and `production_certified` to `false`. Every unavailable, mismatched, stale or partially trusted check returns sanitized HTTP **503** with `status: UNVERIFIED` and all proof booleans false. There is no issuance, auto-retry, external provider/tool invocation, stage mutation or scanner path in this router.

## Verification and limits

Offline checks in `tests/qualification/test_source_map_host_witness_operator_20261022.py` use real signed local JWT handling through FastAPI/ASGI, separate synthetic test-only *public* enrollment roots and inert host reader records. Scenarios include signed ordinary operator, bad/expired/signed senior tokens, request ambiguity/injection, browser-origin/transport/header controls, no host enrollment, changed pins, host original identity mismatches, fabricated unsigned SourceMap evidence, unsupported existing SourceMap 0029 operational pair and response secrecy. A synthetic final-verifier stub tests that a **previously verified** response maps safely to only minimal operator output; it is explicitly **not** cryptographic or production 0033 verification.

No actual enrolled Linux host verifier, signed SourceMap-specific 0029 grant or redeemed running 0033 SourceMap worker was available in this run. The original source grant issuer and worker contract still rule out positive end-to-end SourceMap current witness in the deployed original until the centrally reviewed paired native SourceMap issuance/redemption and authentic externally enrolled process/mount observer chain exists. The default mounted router must therefore report `UNVERIFIED` 503, with no production certification. A successful fixture, an `HTTP 200` from another provider, test-only Ed25519 signatures or a bare PID can never substitute for the original independent witness.
