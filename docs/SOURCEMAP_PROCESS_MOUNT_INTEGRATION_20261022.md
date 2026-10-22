# SourceMap original process + read-only mount: mounted integration qualification

**22 October 2026. Scope:** original heavily dirty `/burp_mcp/ai-osop`. New qualification-only file `tests/qualification/test_sourcemap_process_mount_integration_20261022.py` and this report. No production source, router, main, Go, migration, application database, Docker, target or Git modification.

## Actual mounted path and authority

Inspected the real `src/ai_osop/api/main.py` import and `app.routes`: the current mounted production FastAPI app contains exactly one POST route each for:

| Mounted original endpoint | Role | Qualification |
| --- | --- | --- |
| `/native-sourcemap/source-preflight` | 0035 one-use original source preflight, distinct SourceMap service bearer; `SourceMapSourceAuthorityStore.admit` additionally requires current 0013 BYTEA original, 0015 reviewer, 0027 original Action, current Task/Flow/ROE/lease | Real route enforces dedicated bearer, refuses an ordinary signed operator/JWT without issuer credentials; no source preflight was issued |
| `/native-sourcemap/status-preflight` | 0035 bounded, non-consuming signed current-status proof; **different** bearer from source issuer and native MCP | Real route refuses missing/ordinary JWT issuer; no UNKNOWN Action was retried |
| `/system/source-map/host-witness/readback` | Signed `senior_operator` JWT and optional separately enrolled **host-owned** reader, after which the original `SourceMap0033CurrentWitness.corroborate` must recheck 0029 grant and all signed current original 0013–0037 rows | Actual mounted default returns `503 UNVERIFIED / INDEPENDENT_HOST_VERIFIER_UNAVAILABLE`; no client can supply private signer, PID, trust roots, mount path, or approvals |

The only mount hook for the **existing** route is already implemented in `source_map_host_witness_operator.py`:

```python
from ai_osop.api.source_map_host_witness_operator import (
    HostPinnedSourceMapReadback,
    SourceMapHostWitnessOperator,
    install_host_source_map_witness_operator,
)
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.orchestrator.sourcemap_host_process_join_20261022 import (
    HostPinnedOriginalSourceMapTask,
    HostPinnedSourceMapMountRoot,
    SourceMapHostProcessJoin,
)

# Trusted Linux host startup only, AFTER independent trust provisioning.
# Obtain the inode from the existing securely opened original stage directory.
process_join = SourceMapHostProcessJoin(
    pinned_mount_root=HostPinnedSourceMapMountRoot(
        root_dev=existing_verified_original_dir_st_dev,
        root_ino=existing_verified_original_dir_st_ino,
    )
)

# read_current_original_from_enrolled_host is a trusted, read-only host reader,
# not an HTTP-supplied callback. It must read the already committed original
# host journal and all seven independently signed original source proofs.
async def original_reader(engagement_id, request_id, operator_sub):
    original, evidence, native_grant_token = (
        await read_current_original_from_enrolled_host(
            engagement_id, request_id, operator_sub
        )
    )
    process_join.verify(
        original=original,  # HostPinnedOriginalSourceMapTask
        supervisor_observation=evidence["supervisor_observation"],
        source_status=evidence["source_status"],
        source_preflight_proof=evidence["source_preflight_proof"],
        current_db_witness=evidence["current_db_witness"],
        live_process_witness=evidence["live_process_witness"],
        signed_supervisor_source=evidence["signed_supervisor_source"],
        native_mount_witness=evidence["native_mount_witness"],
    )
    # This helper establishes only current host PID/mount prerequisite evidence;
    # real 0029 one-use signed native grant and 0037 original DB join remain
    # mandatory in SourceMap0033CurrentWitness. Never mint/retry a grant here.
    return HostPinnedSourceMapReadback(
        original_identity={
            key: getattr(original, key)
            for key in (
                "request_id", "engagement_id", "flow_id", "task_id",
                "subtask_id", "action_id", "owner_id", "approval_id",
                "lease_id", "artifact_sha256", "manifest_sha256",
                "authorization_sha256",
            )
        },
        signed_proofs={
            "supervisor_observation": evidence["supervisor_observation"],
            "source_status": evidence["source_status"],
            "source_preflight_proof": evidence["source_preflight_proof"],
            "native_grant_token": native_grant_token,
            "live_process_witness": evidence["live_process_witness"],
            "signed_supervisor_source": evidence["signed_supervisor_source"],
            "native_mount_witness": evidence["native_mount_witness"],
        },
    )

actions = FlowMCPActionStore(
    existing_orchestrator.session_memory,
    existing_orchestrator.mcp_registry,
)
service = SourceMapHostWitnessOperator(
    independently_enrolled=True,
    host_pinned_reader=original_reader,
    actions=actions,
)
install_host_source_map_witness_operator(app, service)
# Main already registered create_source_map_host_witness_router() once.
# DO NOT include another router: this installs the host verifier into the
# existing app.state slot used by that one mounted endpoint.
```

This is an **integration contract**, not an executed host startup. The `original_reader` is intentionally undefined until a real independently enrolled host-only original evidence reader is supplied. No HTTP caller may specify roots, private signer, process metadata, original bytes or new Action authority. The installed service requires authentic separately controlled keys. Before any downstream action, the original 0029 redeemed-grant, 0037 immutable binding and signed/current Task/Flow/reviewer/ROE/lease readback remain mandatory.

## What is verified and what is blocked

The latest original 0013–0037 source reads show:

- Original 0013 artifacts are PostgreSQL BYTEA with a current-byte digest and a distinct 0015 senior review. Original 0027 Action becomes `unknown` before crossing the provider boundary; no lost ACK implies replay permission.
- Original 0026 current Task folder, 0030 resource offer and 0031 staging manifest bind only the existing reviewed original and existing redeemed grant.
- Original 0033 supervisor signature alone lacks live kernel PID/cgroup/mount. The `sourcemap_supervisor_process_witness` producer checks Linux `pidfd`, `/proc` PID start ticks, cgroup, mount namespace and nonzero fsuid; the distinct `sourcemap_native_mount_observer` verifies the native process' read-only original mount, original host inode, and repeats kernel checks before signing.
- The new `SourceMapHostProcessJoin` can independently cryptographically join six controlled trust domains and seven envelopes including the independently signed current-DB witness, exact Task/Flow/owner/approval/current ROE/lease and 0033 CAS revision + PID + read-only mount. The result's execution, replay, native redemption, 0037 and target-effect flags remain **false**.
- The actual `SourceMap0033CurrentWitness.corroborate` verifies signed external facts and then calls native `_verify` **before any database access**. Current Python 0029 `_require_operational_pair` still rejects `source-map-mcp/inspect_local_original_sourcemap`. Migration 0036 permits the schema pair, but does not add operational grant issuance/redemption or authentic 0033 process evidence. The current API must therefore remain `503 UNVERIFIED`, even when independently signed *test-only* host evidence passes its pure verifier.

## Local runtime feasibility and evidence boundaries

The connected coding host is **Windows**, with WSL `Ubuntu` and `docker-desktop` visible, but the running Python test process is Windows. The current session contains **no demonstrated independently enrolled production Linux SourceMap supervisor current-DB/PID-binding private signer**, verified original Action/0033/0029 chain, protected original host journal, or matching read-only `/run/osop-sourcemap/sourcemap-originals` mount in the required native namespace. Creating an arbitrary WSL process or signing a synthetic PID/mount record would not prove an original tenant-approved SourceMap. No WSL/Docker container was started; no process or filesystem mount was created. The optional Linux live-host test is consequently skipped on this host. A positive real host process/mount test requires a separately provisioned Linux host with those protected sources and an existing authorized original Action, and must remain read-only and non-consuming.

The mounted ASGI tests use the **actual** `ai_osop.api.main.app` routes without lifespan startup, network port, database or external services. A signed test-only senior JWT exercises the real auth dependency; the temporary host trust demonstration uses six independently controlled disposable Ed25519 test keys and the *existing* cryptographic verifier, then deliberately omits a native grant to require the **real mounted** original `503`. It patches the DB session factory solely to fail if a bug proceeds to DB before the native grant denial, so no app DB is accessed. Test-only host enrollment is removed from `app.state` after the test. It does not prove a live original PID or actual read-only mount.

The mounted result must never be described as production-ready, as a target effect, or as a new 0033 receipt. The dedicated service routes and the host-only verifier cannot be used to repair or replay `UNKNOWN`.

## Verification command

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts= tests/qualification/test_sourcemap_process_mount_integration_20261022.py -q -rs --tb=short
```

**Executed:** new mounted test alone: **12 passed, 1 skipped**. Combined with the existing independently signed host process verifier tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts= tests/qualification/test_sourcemap_process_mount_integration_20261022.py tests/qualification/test_sourcemap_host_process_join_20261022.py -q -rs --tb=short
```

**Combined result: 59 passed, 1 skipped, 0 failed** (23.01 seconds). Black, Ruff and targeted mypy on the new test file passed. The one skipped test is the real Linux `pidfd`/nonroot read-only SourceMap mount producer test because the current test process runs on Windows.

**Interpretation:** passing tests show mounted authorization, issuer isolation, test-only Ed25519 process/mount proof checking and actual mounted fail-closed behavior. The Linux skip means no real nonroot read-only host observation was available, never a successful kernel mount qualification.
