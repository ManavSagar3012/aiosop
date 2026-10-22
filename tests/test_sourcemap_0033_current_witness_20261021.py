"""Adversarial read-only SourceMap current-0033 witness qualification.

Cryptographic fixture keys/claims are TEST-ONLY vectors: made-up numeric PID,
filesystem and mount fields are deliberately NOT actual kernel observations or
evidence a native process exists. Tests never authorize a process, stage,
grant, preflight, live target, or application database action.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import time
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.orchestrator import sourcemap_0033_current_witness as witness
from ai_osop.orchestrator.sourcemap_native_mount_observer import (
    IndependentSourceMapNativeMountObserver,
    MOUNT_DOMAIN,
    MOUNT_FIELDS,
    SUPERVISOR_FIELDS,
    SUPERVISOR_SOURCE_DOMAIN,
    _observe_proc,
)
from ai_osop.orchestrator.sourcemap_original_stage import _canonical
from ai_osop.orchestrator.sourcemap_supervisor_source_issuer import (
    LEDGER_DOMAIN,
    PROCESS_DOMAIN,
    SOURCE_STATUS_DOMAIN,
    _LEDGER_FIELDS,
    _PROCESS_FIELDS,
    _STATUS_FIELDS,
)
from ai_osop.memory.sourcemap_source_authority import CLAIM_FIELDS, DOMAIN as PREFLIGHT_DOMAIN


S = "a" * 64
M = "b" * 64
CONTAINER = "c" * 64
CGROUP = "d" * 64
FOLDER = "e" * 64
ROOT = "/run/osop-sourcemap/sourcemap-originals"


def _signed(
    claims: dict[str, Any], kid: str, private: Ed25519PrivateKey, domain: bytes
) -> dict[str, Any]:
    encoded = base64.urlsafe_b64encode(private.sign(domain + _canonical(claims)))
    return {"claims": claims, "kid": kid, "signature": encoded.decode("ascii").rstrip("=")}


def _digest(proof: dict[str, Any], domain: bytes) -> str:
    raw = base64.urlsafe_b64decode(proof["signature"] + "==")
    return hashlib.sha256(domain + _canonical(proof["claims"]) + raw).hexdigest()


def _vectors(now: int | None = None) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Independent ephemeral signatures for *negative* contract tests only."""
    now = int(time.time()) if now is None else now
    keys = {
        name: Ed25519PrivateKey.generate()
        for name in ("ledger", "status", "process", "supervisor", "mount")
    }
    roots = {
        name: {"kid-" + name: keys[name].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}
        for name in keys
    }
    identity = {
        "request_id": "req-" + "1" * 48,
        "engagement_id": "eng-fixture",
        "flow_id": "flow-fixture",
        "task_id": "task-fixture",
        "subtask_id": "subtask-fixture",
        "action_id": "action-" + "2" * 32,
        "owner_id": "owner-fixture",
        "approval_id": "approval-fixture",
        "lease_id": "lease-fixture",
        "authorization_sha256": S,
        "artifact_sha256": S,
        "manifest_sha256": M,
    }
    status = {
        "version": 1,
        **identity,
        "preflight_id": "nsp-" + "3" * 32,
        "status_id": "nss-" + "4" * 32,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "authorization_version": 3,
        "issued_at": now - 1,
        "expires_at": now + 4,
    }
    assert set(status) == _STATUS_FIELDS
    source = {key: value for key, value in status.items() if key != "status_id"}
    assert set(source) == CLAIM_FIELDS
    ledger = {
        "version": 1,
        "grant_id": "ngr-" + "5" * 32,
        "request_id": status["request_id"],
        "server_id": "source-map-mcp",
        "worker_id": "worker-fixture",
        "container_id": CONTAINER,
        "epoch": 8,
        "expected_revision": 4,
        "state": "running",
        "observed_at": now - 1,
        "evidence_sha256": S,
        "resource_sha256": M,
        "folder_staging_sha256": FOLDER,
        "readback_sha256": None,
    }
    assert set(ledger) == _LEDGER_FIELDS
    ledger_proof = _signed(ledger, "kid-ledger", keys["ledger"], LEDGER_DOMAIN)
    process = {
        "version": 1,
        "grant_id": ledger["grant_id"],
        "request_id": ledger["request_id"],
        "worker_id": ledger["worker_id"],
        "container_id": CONTAINER,
        "epoch": 8,
        "supervisor_observation_sha256": _digest(ledger_proof, LEDGER_DOMAIN),
        # These are syntactic TEST VECTORS, NOT observations from Linux /proc.
        "pid": 4242,
        "pid_start_ticks": 5555,
        "mount_namespace_inode": 6666,
        "native_fsuid": 1000,
        "cgroup_sha256": CGROUP,
        "native_stage_root": ROOT,
        "observed_at": now - 1,
        "expires_at": now + 3,
    }
    assert set(process) == _PROCESS_FIELDS
    supervisor = {
        "version": 1,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        **identity,
        "signed_roe_sha256": S,
        "container_id": CONTAINER,
        "epoch": 8,
        **{
            k: process[k]
            for k in (
                "pid",
                "pid_start_ticks",
                "mount_namespace_inode",
                "native_fsuid",
                "cgroup_sha256",
                "native_stage_root",
            )
        },
        "status": "running",
        "source_current": True,
        "lease_active": True,
        "approval_current": True,
        "issued_at": now - 1,
        "expires_at": now + 3,
    }
    assert set(supervisor) == SUPERVISOR_FIELDS
    supervisor_proof = _signed(
        supervisor, "kid-supervisor", keys["supervisor"], SUPERVISOR_SOURCE_DOMAIN
    )
    mount = {
        "version": 1,
        "server_id": "source-map-mcp",
        "mode": "host-stage-v1",
        "native_stage_root": ROOT,
        "root_dev": 100,
        "root_ino": 200,
        "read_only": True,
        "observer_id": "observer-fixture",
        "issued_at": now - 1,
        "expires_at": now + 2,
        **{
            k: supervisor[k]
            for k in (
                "pid",
                "pid_start_ticks",
                "mount_namespace_inode",
                "native_fsuid",
                "container_id",
                "epoch",
                "request_id",
                "engagement_id",
                "task_id",
                "flow_id",
                "subtask_id",
                "owner_id",
                "approval_id",
                "action_id",
                "lease_id",
                "artifact_sha256",
                "manifest_sha256",
                "authorization_sha256",
            )
        },
        "supervisor_source_sha256": _digest(supervisor_proof, SUPERVISOR_SOURCE_DOMAIN),
    }
    assert set(mount) == MOUNT_FIELDS
    proofs = {
        "supervisor_observation": ledger_proof,
        "source_status": _signed(status, "kid-status", keys["status"], SOURCE_STATUS_DOMAIN),
        "source_preflight_proof": _signed(source, "kid-status", keys["status"], PREFLIGHT_DOMAIN),
        "live_process_witness": _signed(process, "kid-process", keys["process"], PROCESS_DOMAIN),
        "signed_supervisor_source": supervisor_proof,
        "native_mount_witness": _signed(mount, "kid-mount", keys["mount"], MOUNT_DOMAIN),
    }
    return proofs, roots, keys


def _check(proofs: dict[str, Any], roots: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    return witness._verify_external_proofs(
        **proofs, roots=roots, now=int(time.time()) if now is None else now
    )


def test_ephemeral_signatures_only_test_contract_not_real_process() -> None:
    proofs, roots, _ = _vectors()
    readback = _check(proofs, roots)
    assert readback["status"]["preflight_id"] == readback["source"]["preflight_id"]
    assert readback["mount"]["read_only"] is True
    assert readback["process"]["pid_start_ticks"] == readback["mount"]["pid_start_ticks"]
    assert "native_grant_token" not in readback
    # Never interpret the made-up process IDs as actual /proc or mounted proof.
    assert "grant_id" not in readback


@pytest.mark.parametrize(
    "missing",
    [
        "supervisor_observation",
        "source_status",
        "source_preflight_proof",
        "live_process_witness",
        "signed_supervisor_source",
        "native_mount_witness",
    ],
)
def test_missing_independent_external_producer_denied(missing: str) -> None:
    proofs, roots, _ = _vectors()
    proofs[missing] = {}
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        _check(proofs, roots)


@pytest.mark.parametrize(
    "changed",
    [
        "supervisor_observation",
        "source_status",
        "source_preflight_proof",
        "live_process_witness",
        "signed_supervisor_source",
        "native_mount_witness",
    ],
)
def test_broken_signed_evidence_denied(changed: str) -> None:
    proofs, roots, _ = _vectors()
    proofs[changed]["signature"] = "A" * 86
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        _check(proofs, roots)


@pytest.mark.parametrize(
    ("which", "field", "value", "signer", "domain"),
    [
        ("source_status", "lease_id", "lease-revoked", "status", SOURCE_STATUS_DOMAIN),
        ("source_preflight_proof", "approval_id", "approval-replaced", "status", PREFLIGHT_DOMAIN),
        ("supervisor_observation", "epoch", 9, "ledger", LEDGER_DOMAIN),
        ("supervisor_observation", "resource_sha256", S, "ledger", LEDGER_DOMAIN),
        ("live_process_witness", "pid", 4321, "process", PROCESS_DOMAIN),
        ("live_process_witness", "pid_start_ticks", 9999, "process", PROCESS_DOMAIN),
        ("live_process_witness", "mount_namespace_inode", 9999, "process", PROCESS_DOMAIN),
        ("live_process_witness", "cgroup_sha256", S, "process", PROCESS_DOMAIN),
        ("signed_supervisor_source", "lease_active", False, "supervisor", SUPERVISOR_SOURCE_DOMAIN),
        (
            "signed_supervisor_source",
            "source_current",
            False,
            "supervisor",
            SUPERVISOR_SOURCE_DOMAIN,
        ),
        (
            "signed_supervisor_source",
            "approval_current",
            False,
            "supervisor",
            SUPERVISOR_SOURCE_DOMAIN,
        ),
        ("native_mount_witness", "read_only", False, "mount", MOUNT_DOMAIN),
        ("native_mount_witness", "root_ino", -1, "mount", MOUNT_DOMAIN),
        ("native_mount_witness", "pid_start_ticks", 9999, "mount", MOUNT_DOMAIN),
        ("native_mount_witness", "manifest_sha256", S, "mount", MOUNT_DOMAIN),
    ],
)
def test_distinct_but_correctly_signed_identity_drift_denied(
    which: str, field: str, value: Any, signer: str, domain: bytes
) -> None:
    proofs, roots, keys = _vectors()
    corrupt = deepcopy(proofs[which]["claims"])
    corrupt[field] = value
    proofs[which] = _signed(corrupt, "kid-" + signer, keys[signer], domain)
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        _check(proofs, roots)


@pytest.mark.parametrize("expiry", [-30, -6, -4])
def test_expired_status_revocation_or_lost_ack_not_replayed(expiry: int) -> None:
    baseline = int(time.time())
    proofs, roots, keys = _vectors(baseline)
    claims = deepcopy(proofs["source_status"]["claims"])
    claims["issued_at"] = baseline + expiry
    claims["expires_at"] = claims["issued_at"] + 5
    proofs["source_status"] = _signed(claims, "kid-status", keys["status"], SOURCE_STATUS_DOMAIN)
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        _check(proofs, roots, baseline)


def test_ledger_revision_and_signature_current_event_are_required() -> None:
    source = inspect.getsource(witness._verify_current_rows)
    for required in (
        'worker["revision"] != ledger.get("expected_revision", -10) + 1',
        '"claims_sha256": hashlib.sha256(_canonical(ledger)).hexdigest()',
        '"signature_sha256": hashlib.sha256(sig).hexdigest()',
        '"status": "corroborated_read_only"',
        '"authorizes_execution": False',
        '"authorizes_mount_or_replay": False',
        'binding.get("status") != "bound_only"',
        'binding.get("resource_manifest_sha256") != manifest',
    ):
        assert required in source


@pytest.mark.asyncio
async def test_no_bundled_real_process_or_native_grant_can_open_db(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actions = object.__new__(FlowMCPActionStore)

    def forbidden_session() -> Any:
        raise AssertionError("No app DB or unknown Action replay")

    monkeypatch.setattr(actions, "_sessions", forbidden_session)
    instance = object.__new__(witness.SourceMap0033CurrentWitness)
    instance._actions = actions
    proofs, roots, _ = _vectors()
    instance._roots = roots
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        await instance.corroborate(**proofs, native_grant_token={})


@pytest.mark.asyncio
async def test_missing_trust_roots_fail_closed_before_db(monkeypatch: pytest.MonkeyPatch) -> None:
    for env in (
        "OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON",
    ):
        monkeypatch.delenv(env, raising=False)
    actions = object.__new__(FlowMCPActionStore)
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        witness.SourceMap0033CurrentWitness(actions)


@pytest.mark.parametrize("case", ["revoked", "resource_changed", "lost_ack", "missing_0037"])
def test_current_db_join_fails_closed_on_revocation_and_unknown(case: str) -> None:
    # Deliberately incomplete, NON-AUTHORITATIVE rows. It is impossible to
    # make a positive 0033 process/mount claim out of local fixture mappings.
    proofs, roots, _ = _vectors()
    signed = _check(proofs, roots)
    original = {
        "status": "unknown",
        "cancel_requested": False,
        "receipt_sha256": None,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "side_effect_class": "READ_ONLY",
    }
    if case == "revoked":
        original["cancel_requested"] = True
    if case == "lost_ack":
        original["status"] = "unknown"
        original["receipt_sha256"] = S
    binding = {} if case == "missing_0037" else {"status": "bound_only"}
    manifest = S if case == "resource_changed" else M
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        witness._verify_current_rows(
            original=original,
            manifest=manifest,
            preflight={},
            binding=binding,
            grant={},
            offer={},
            worker={},
            events=[],
            signed=signed,
            folder_sha=None,
            now=int(time.time()),
            current_task={},
            review={},
        )


def _comparison_rows() -> dict[str, Any]:
    """ONLY structural test vectors. Not original approved DB or live PID."""
    now = int(time.time())
    proofs, roots, _ = _vectors(now)
    signed = _check(proofs, roots, now)
    signed["ledger_signature"] = proofs["supervisor_observation"]["signature"]
    action = {
        "action_id": signed["status"]["action_id"],
        "request_id": signed["status"]["request_id"],
        "engagement_id": signed["status"]["engagement_id"],
        "flow_id": signed["status"]["flow_id"],
        "task_id": signed["status"]["task_id"],
        "subtask_id": signed["status"]["subtask_id"],
        "owner_id": signed["status"]["owner_id"],
        "approval_id": signed["status"]["approval_id"],
        "lease_id": signed["status"]["lease_id"],
        "lease_owner_id": "worker-owner-fixture",
        "flow_revision": 2,
        "authorization_id": "auth-fixture",
        "authorization_version": 3,
        "authorization_sha256": S,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "side_effect_class": "READ_ONLY",
        "declaration_sha256": "6" * 64,
        "parameters_sha256": "7" * 64,
        "intent_sha256": "8" * 64,
        "status": "unknown",
        "receipt_sha256": None,
        "cancel_requested": False,
    }
    pf = {
        **signed["source"],
        "kid": signed["source_kid"],
        "claims_sha256": hashlib.sha256(witness.source_canonical(signed["source"])).hexdigest(),
        "signature_sha256": signed["source_signature_sha256"],
        "committed_at": object(),
    }
    binding = {
        "binding_id": "snb-" + "1" * 32,
        "grant_id": signed["ledger"]["grant_id"],
        "preflight_id": pf["preflight_id"],
        "artifact_id": "artifact-" + "2" * 32,
        **{
            field: action[field]
            for field in (
                "action_id",
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "lease_owner_id",
                "flow_revision",
                "authorization_id",
                "authorization_version",
                "authorization_sha256",
            )
        },
        "reviewer_id": "reviewer-distinct",
        "artifact_sha256": S,
        "resource_manifest_sha256": M,
        "declaration_sha256": action["declaration_sha256"],
        "parameters_sha256": action["parameters_sha256"],
        "preflight_claims_sha256": pf["claims_sha256"],
        "preflight_signature_sha256": pf["signature_sha256"],
        "grant_claims_sha256": "9" * 64,
        "grant_signature_sha256": "a" * 64,
        "status": "bound_only",
    }
    binding["join_sha256"] = hashlib.sha256(
        witness.source_canonical(
            {
                key: value
                for key, value in binding.items()
                if key not in {"binding_id", "join_sha256"}
            }
        )
    ).hexdigest()
    grant = {
        **action,
        "grant_id": binding["grant_id"],
        "status": "redeemed",
        "issued_at": now - 1,
        "expires_at": now + 20,
        "resource_sha256": M,
        "manifest_sha256": action["declaration_sha256"],
        "claims_sha256": binding["grant_claims_sha256"],
        "signature_sha256": binding["grant_signature_sha256"],
    }
    offer = {
        **{
            field: grant[field]
            for field in (
                "grant_id",
                "request_id",
                "engagement_id",
                "flow_id",
                "action_id",
                "server_id",
            )
        },
        "status": "offered",
        "manifest_sha256": M,
        "claims_sha256": grant["claims_sha256"],
        "folder_staging_sha256": FOLDER,
    }
    worker = {
        **{
            field: action[field]
            for field in (
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "lease_owner_id",
                "server_id",
                "authorization_version",
                "authorization_sha256",
            )
        },
        "grant_id": grant["grant_id"],
        "state": "running",
        "resource_sha256": M,
        "folder_staging_sha256": FOLDER,
        "grant_claims_sha256": grant["claims_sha256"],
        "worker_id": signed["ledger"]["worker_id"],
        "container_id": CONTAINER,
        "epoch": 8,
        "supervisor_kid": "kid-ledger",
        "supervisor_id": "supervisor-fixture",
        "revision": signed["ledger"]["expected_revision"] + 1,
    }
    event = {
        "grant_id": grant["grant_id"],
        "epoch": 8,
        "revision": worker["revision"],
        "state": "running",
        "kid": "kid-ledger",
        "supervisor_id": worker["supervisor_id"],
        "observed_at": signed["ledger"]["observed_at"],
        "evidence_sha256": signed["ledger"]["evidence_sha256"],
        "claims_sha256": hashlib.sha256(_canonical(signed["ledger"])).hexdigest(),
        "signature_sha256": hashlib.sha256(
            base64.urlsafe_b64decode(signed["ledger_signature"] + "==")
        ).hexdigest(),
    }
    review = {
        "reviewer_sub": "reviewer-distinct",
        "reviewer_role": "senior_operator",
        "decision": "approve",
        "artifact_id": binding["artifact_id"],
        "artifact_sha256": S,
        **{
            field: action[field]
            for field in (
                "engagement_id",
                "flow_id",
                "flow_revision",
                "authorization_id",
                "authorization_version",
                "authorization_sha256",
            )
        },
    }
    task = {
        "resource_artifact_id": binding["artifact_id"],
        "resource_artifact_sha256": S,
        "resource_manifest_sha256": M,
        "resource_command_sha256": action["parameters_sha256"],
        "resource_authorization_sha256": S,
    }
    return {
        "original": action,
        "manifest": M,
        "preflight": pf,
        "binding": binding,
        "grant": grant,
        "offer": offer,
        "worker": worker,
        "events": [event],
        "signed": signed,
        "folder_sha": FOLDER,
        "now": now,
        "current_task": task,
        "review": review,
    }


def test_synthetic_stored_row_comparison_is_explicitly_non_authoritative() -> None:
    rows = _comparison_rows()
    comparison = witness._verify_current_rows(**rows)
    assert comparison["status"] == "corroborated_read_only"
    assert comparison["authorizes_execution"] is False
    assert comparison["authorizes_mount_or_replay"] is False
    # This test did NOT call corroborate(): there was no PostgreSQL/current
    # source check or real kernel process observation.


@pytest.mark.parametrize(
    ("section", "field", "mutated"),
    [
        ("original", "status", "completed"),
        ("original", "cancel_requested", True),
        ("original", "receipt_sha256", S),
        ("original", "lease_id", "lease-revoked"),
        ("preflight", "signature_sha256", CGROUP),
        ("preflight", "claims_sha256", CGROUP),
        ("binding", "preflight_id", "nsp-" + "9" * 32),
        ("binding", "artifact_sha256", CGROUP),
        ("binding", "resource_manifest_sha256", CGROUP),
        ("binding", "join_sha256", CGROUP),
        ("binding", "status", "authorized"),
        ("grant", "status", "unknown"),
        ("grant", "expires_at", 1),
        ("grant", "resource_sha256", CGROUP),
        ("grant", "claims_sha256", CGROUP),
        ("offer", "status", "unknown"),
        ("offer", "folder_staging_sha256", CGROUP),
        ("worker", "state", "terminated"),
        ("worker", "epoch", 9),
        ("worker", "revision", 4),
        ("worker", "container_id", CGROUP),
        ("worker", "supervisor_kid", "attacker"),
        ("current_task", "resource_artifact_sha256", CGROUP),
        ("current_task", "resource_command_sha256", CGROUP),
        ("review", "reviewer_sub", "owner-fixture"),
        ("review", "decision", "revoke"),
    ],
)
def test_stale_current_rows_and_revoked_identity_denied(
    section: str, field: str, mutated: Any
) -> None:
    rows = _comparison_rows()
    rows[section][field] = mutated
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        witness._verify_current_rows(**rows)


def test_missing_or_replayed_0033_event_denied() -> None:
    rows = _comparison_rows()
    rows["events"] = []
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        witness._verify_current_rows(**rows)
    rows = _comparison_rows()
    rows["events"].append(dict(rows["events"][0]))
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        witness._verify_current_rows(**rows)


def test_independent_root_principals_must_not_share_one_signing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, roots, _ = _vectors()
    repeated = base64.b64encode(roots["ledger"]["kid-ledger"]).decode("ascii")
    for env in (
        "OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON",
    ):
        monkeypatch.setenv(env, json.dumps({"kid-shared": repeated}))
    actions = object.__new__(FlowMCPActionStore)
    with pytest.raises(witness.SourceMap0033CurrentWitnessDenied):
        witness.SourceMap0033CurrentWitness(actions)


def test_only_read_only_post_status_corrob_no_issuance_or_replay() -> None:
    source = inspect.getsource(witness.SourceMap0033CurrentWitness.corroborate)
    assert "self._sources._source(db, request)" in source
    assert "_verify_native(native_grant_token)" in source
    assert "_verify_issued(" in source
    assert "native_sourcemap_grant_bindings" in source
    assert "native_mcp_worker_supervision_events" in source
    assert "self._folder_plan(db, grant)" in source
    assert "final_now = await self._sources._now(db)" in source
    assert 'for name in ("status", "source", "process", "supervisor", "mount")' in source
    for forbidden in (
        "INSERT INTO ",
        "UPDATE ",
        "DELETE FROM ",
        "await self._sources.admit(",
        "issue_grant(",
        "mark_dispatched(",
        "mount(",
        "os.kill(",
    ):
        assert forbidden not in source
    # The *real* native observer reads /proc twice, uses pidfd and verifies
    # mountinfo VFS flags, not an arbitrary caller's pid or mount assertion.
    proc = inspect.getsource(_observe_proc)
    assert "os.pidfd_open(pid, 0)" in proc
    assert "_mount_options(" in proc
    assert "_process_start_ticks(" in proc
    assert "_native_dir_stat(" in proc
    assert "verify_supervisor_source(" in inspect.getsource(
        IndependentSourceMapNativeMountObserver.observe
    )
