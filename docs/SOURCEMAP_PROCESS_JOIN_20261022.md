# Original SourceMap: independently signed host PID and read-only mount join

**22 October 2026 — worker 57, original shared `/burp_mcp/ai-osop`.** The implementation is confined to three new files: `src/ai_osop/orchestrator/sourcemap_host_process_join_20261022.py`, `tests/qualification/test_sourcemap_host_process_join_20261022.py` and this document. No original migration, API/router, Go binary, Action, database, Docker, host `/proc`, actual host mount, provider, target or Git operation was performed.

## Original path and source of truth

| Revision | Actual existing mechanism | What the host process join must preserve |
| --- | --- | --- |
| **0013 / 0015** | `SourceMapSourceAuthorityStore._source` recomputes the original PostgreSQL artifact BYTEA SHA, exact metadata manifest and distinct senior reviewer approval in a current source transaction | Signed 0035 artifact/manifest digests must identify the one reviewed original; a path, copy or user-provided SHA is insufficient |
| **0026** | `NativeMCPWorkerSupervisionStore._current_folder` checks the current Task-approved virtual folder revision | SourceMap host stage cannot bypass Task authority or treat mount inode alone as a resource grant |
| **0027** | Original signed Flow MCP Action and immutable dispatch transition | Original is `unknown` before crossing the tool boundary; **never send, issue or retry the same UNKNOWN Action** |
| **0029** | The one-use native grant issuer/redeemer and original Action binding | A source preflight is not a grant. Current `_require_operational_pair` still rejects `source-map-mcp/inspect_local_original_sourcemap` |
| **0030 / 0031** | One offer per grant and exact approved folder staging hash | Signed ledger `resource_sha256`/staging provenance must bind the original reviewed manifest and live Task; the host witness does not create a resource offer |
| **0033** | Signed supervisor running observation, redeemed grant and committed latest event; signed `expected_revision = r` corresponds to durable row revision `r + 1` | Ledger must match separately signed current-DB witness, worker ID, container ID and epoch. Historical `updated_at` is not a heartbeat/PID proof |
| **0035** | Unique original SourceMap preflight and short-lived non-consuming signed STATUS | One original `preflight_id` and STATUS bind reviewed artifact, Task, Flow, ROE, lease, owner and source signature; no reissue to fix lost ACK |
| **0036** | PostgreSQL finite CHECK adds the exact SourceMap grant *schema pair* | No operational grant issuer/redemption extension is installed merely by migrating the CHECK |
| **0037** | Immutable `bound_only` provenance row after separately committed/verified 0035 and 0029 | The host prerequisite cannot mint a binding, claim a committed 0037 row or invoke a provider |

The existing `SourceMapSupervisorCurrentDBWitness.issue` signs the **CURRENT_DB_DOMAIN** only after one PostgreSQL read transaction checks original `_source` (including original artifact bytes, Task, current Flow, signed ROE, senior reviewer and lease), original 0035 preflight and STATUS, 0029 redeemed grant, 0026 folder/0030/0031 resource offer, latest signed 0033 running row/event, global epoch and CAS revision. The checked facts expire in at most five seconds. The currently operational native 0029 issuer remains incompatible with SourceMap, so a genuine current-DB proof cannot presently be produced in the deployed original merely by enabling this helper.

The existing Linux host components `IndependentSourceMapSupervisorProcessWitness` and `IndependentSourceMapNativeMountObserver` are **separate** private-key owners. The process witness checks the signed 0033/PID binding against kernel PID start ticks, live cgroup, mount namespace and nonzero fsuid; the mount observer checks read-only native `mountinfo`, the same live PID, cgroup and namespace, nonzero fsuid, file system inode against the host stage and repeats the observation for race detection. This new module only **verifies already signed output**; it does not recreate or impersonate those system calls.

## New reusable host-only entry point

`SourceMapHostProcessJoin` is a pure read-only verifier that compares **seven** original signed proof envelopes from six separately trusted Ed25519 producer domains:

1. `supervisor_observation`: signed 0033 lifecycle ledger;
2. `source_status` and `source_preflight_proof`: distinct signed domains under the enrolled original 0035 source issuer;
3. `current_db_witness`: signed, current, transaction-checked 0013–0035 original state;
4. `live_process_witness`: signed live PID/process identity and cgroup;
5. `signed_supervisor_source`: signed SourceMap-specific PID/ROE/lease binding;
6. `native_mount_witness`: independently signed read-only nonroot native mount and host directory inode.

The helper loads only the existing six protected environment **public-key** enrollment mappings using `_roots`. It requires nonempty, distinct keys across all domains, pins their SHA fingerprints when constructed, then checks them before and after every join. Any missing, reused or changed signer identity denies. Test-only private keys never enter the production module.

The host must also independently resolve two immutable inputs, neither accepted from an operator request:

- `HostPinnedOriginalSourceMapTask`, the original engagement, Flow, Task, subtask, Action, owner, approval, lease, artifact SHA, manifest SHA, signed ROE SHA and authorization version from a trusted host original record.
- `HostPinnedSourceMapMountRoot`, the actual host-owned original-stage `st_dev`/`st_ino` obtained through the existing secure host stage verification, and the fixed `/run/osop-sourcemap/sourcemap-originals` native root. A signed but substituted, mismatched mount inode denies.

All original identities must match by both **type and value** across pinned original, current signed DB, 0035 status, original preflight, supervisor source and read-only mount. Independently signed current-DB `status_proof_sha256` and `supervisor_observation_sha256` must match their exact original signatures. SourceMap-specific grant/worker/container/epoch and 0033 `expected_revision+1` must be identical across ledger, current DB and process witness; live PID, PID start ticks, namespace, fsuid, cgroup digest, source mount and inode must match across independent host sources. Revoked reviewer/lease/ROE/source flags, expiry, nonroot/readonly violations or a changed root deny.

Example integration into an **already trusted host**:

```python
from ai_osop.orchestrator.sourcemap_host_process_join_20261022 import (
    HostPinnedOriginalSourceMapTask,
    HostPinnedSourceMapMountRoot,
    SourceMapHostProcessJoin,
)

# These objects are obtained independently from the original protected host
# journal and existing secure original host directory stat. Never use request
# JSON or an unverified caller claim to supply either object.
host_join = SourceMapHostProcessJoin(
    pinned_mount_root=HostPinnedSourceMapMountRoot(
        root_dev=trusted_original_dir_st_dev,
        root_ino=trusted_original_dir_st_ino,
    )
)

joined = host_join.verify(
    original=trusted_original_task,  # HostPinnedOriginalSourceMapTask
    supervisor_observation=already_signed_0033,
    source_status=already_signed_current_0035,
    source_preflight_proof=already_issued_signed_0035,
    current_db_witness=already_signed_current_postgresql_readback,
    live_process_witness=already_signed_linux_pid_observation,
    signed_supervisor_source=already_signed_source_supervisor_binding,
    native_mount_witness=already_signed_readonly_mount_observation,
)

# `joined` is a short-lived host prerequisite. A central consumer must still
# perform the original 0029/0037/current DB source checks before ANY operation.
# It cannot treat this value as a provider capability or proof of target effect.
```

The result is a frozen `VerifiedSourceMapHostProcessMount`, including the exact original request/Flow/Task/Action/lease, grant/worker/container/epoch/revision, signed PID/start ticks/namespace/nonroot fsuid, pinned original host directory device/inode and conservative expiry. Its `authorizes_execution`, `authorizes_mount_or_replay`, `native_grant_redemption_verified_here`, `durable_0037_binding_verified_here` and `target_effect_verified` are **always false**. It carries no credential, original bytes, private key or arbitrary pathname. It must remain inside the trusted host; do not serialize PID or process metadata to browser/operator APIs.

This is a narrow **host process and mount prerequisite**, beyond an unbound status display. It does **not** certify current 0037 provenance or Action admission. The separate existing `SourceMap0033CurrentWitness.corroborate` checks the live original 0037 binding and 0029 signed token against PostgreSQL in a single read-only transaction; it remains required before interpreting any SourceMap original custody as completely verified. None of these checks retries UNKNOWN.

## Evidence and remaining blocker

`tests/qualification/test_sourcemap_host_process_join_20261022.py` builds exact original claim formats and signs each domain with a different deterministic **test-only** Ed25519 private key. The suite covers a positive signed **host-layer** join and negative cases for altered original Task/Flow/owner/lease/tenant/ROE, stale or revoked signed current-DB source, 0033 CAS revision, grant/worker identity, signature tampering and cross-domain replay, PID start/namespace, fsuid zero, changed source mount inode/path/PID, writable mount, expired source signatures and mismatched/reused/rotated enrollment. The positive fixture is deliberately not a live kernel, app DB, 0029 redemption or production 0033/0037 proof.

**Release blocker:** Original SourceMap native operational issuance/redemption remains restricted by `src/ai_osop/memory/native_mcp_execution_grants.py` and the original executor. The 0036 migration makes the database able to *represent* the SourceMap pair, and 0037 can represent bound-only evidence, but neither creates current independent process/mount testimony or grants permission. Real positive integration still requires owner-approved existing original source, the separately protected Linux producer keys, current signed PostgreSQL source, authentic 0029/0033 SourceMap worker lifecycle and original 0037 corroboration. Until then runtime must fail closed.
