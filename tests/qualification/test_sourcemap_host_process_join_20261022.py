"""Offline source-authentic SourceMap PID/readonly-mount join qualifications.

All six Ed25519 private keys belong to this disposable fixture. No tests use
production signers, database, host /proc, containers, mounts or MCP services.
The successful result is a signed-host-layer prerequisite, not real runtime
0033 supervision, 0029 redemption, 0037 durable binding or Action admission.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import time
from dataclasses import replace
from dataclasses import FrozenInstanceError
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.memory.sourcemap_source_authority import (
    CLAIM_FIELDS,
    DOMAIN as PREFLIGHT_DOMAIN,
)
from ai_osop.orchestrator import sourcemap_host_process_join_20261022 as join
from ai_osop.orchestrator.sourcemap_native_mount_observer import (
    MOUNT_DOMAIN,
    MOUNT_FIELDS,
    SUPERVISOR_FIELDS,
    SUPERVISOR_SOURCE_DOMAIN,
)
from ai_osop.orchestrator.sourcemap_original_stage import _canonical
from ai_osop.orchestrator.sourcemap_supervisor_source_issuer import (
    CURRENT_DB_DOMAIN,
    LEDGER_DOMAIN,
    PROCESS_DOMAIN,
    SOURCE_STATUS_DOMAIN,
    _DB_FIELDS,
    _LEDGER_FIELDS,
    _PROCESS_FIELDS,
    _STATUS_FIELDS,
)

NATIVE_ROOT = "/run/osop-sourcemap/sourcemap-originals"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
PRIVATE_PATH = "/private/credentials/do-not-expose"
DOMAIN_FOR = {
    "ledger": LEDGER_DOMAIN,
    "status": SOURCE_STATUS_DOMAIN,
    "process": PROCESS_DOMAIN,
    "supervisor": SUPERVISOR_SOURCE_DOMAIN,
    "mount": MOUNT_DOMAIN,
    "current_db": CURRENT_DB_DOMAIN,
}


def signed(
    group: str,
    claims: dict[str, Any],
    secrets: dict[str, Ed25519PrivateKey],
    *,
    domain: bytes | None = None,
) -> dict[str, Any]:
    token_domain = domain if domain is not None else DOMAIN_FOR[group]
    signature = secrets[group].sign(token_domain + _canonical(claims))
    return {
        "claims": claims,
        "kid": "Signer" + group.replace("_", "").title(),
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def digest(group: str, token: dict[str, Any], *, domain: bytes | None = None) -> str:
    from hashlib import sha256

    token_domain = domain if domain is not None else DOMAIN_FOR[group]
    signature = base64.urlsafe_b64decode(token["signature"] + "==")
    return sha256(token_domain + _canonical(token["claims"]) + signature).hexdigest()


def proof_fixture(now: int, secrets: dict[str, Ed25519PrivateKey]) -> dict[str, Any]:
    original = join.HostPinnedOriginalSourceMapTask(
        request_id="req-" + "1" * 48,
        engagement_id="eng-original",
        flow_id="flow-original",
        task_id="task-original",
        subtask_id="subtask-original",
        action_id="action-" + "2" * 32,
        owner_id="owner-original",
        approval_id="approval-original",
        lease_id="lease-original",
        artifact_sha256=SHA_A,
        manifest_sha256=SHA_B,
        authorization_sha256=SHA_C,
        authorization_version=3,
    )
    source = vars(original).copy()
    source.pop("authorization_version")
    ledger = {
        "version": 1,
        "grant_id": "ngr-" + "3" * 32,
        "request_id": original.request_id,
        "server_id": "source-map-mcp",
        "worker_id": "worker-original",
        "container_id": SHA_D,
        "epoch": 11,
        "expected_revision": 6,
        "state": "running",
        "observed_at": now,
        "evidence_sha256": SHA_E,
        "resource_sha256": SHA_B,
        "folder_staging_sha256": SHA_F,
        "readback_sha256": SHA_E,
    }
    assert set(ledger) == _LEDGER_FIELDS
    ledger_proof = signed("ledger", ledger, secrets)
    ledger_digest = digest("ledger", ledger_proof)
    status_common = {
        "version": 1,
        **source,
        "preflight_id": "nsp-" + "4" * 32,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "authorization_version": original.authorization_version,
        "issued_at": now,
        "expires_at": now + 4,
    }
    preflight_claims = dict(status_common)
    assert set(preflight_claims) == CLAIM_FIELDS
    preflight = signed("status", preflight_claims, secrets, domain=PREFLIGHT_DOMAIN)
    status_claims = {**status_common, "status_id": "nss-" + "5" * 32}
    assert set(status_claims) == _STATUS_FIELDS
    status = signed("status", status_claims, secrets)
    process_claims = {
        "version": 1,
        "grant_id": ledger["grant_id"],
        "request_id": original.request_id,
        "worker_id": ledger["worker_id"],
        "container_id": ledger["container_id"],
        "epoch": ledger["epoch"],
        "supervisor_observation_sha256": ledger_digest,
        "pid": 18101,
        "pid_start_ticks": 927,
        "mount_namespace_inode": 45002,
        "native_fsuid": 1101,
        "cgroup_sha256": SHA_F,
        "native_stage_root": NATIVE_ROOT,
        "observed_at": now,
        "expires_at": now + 4,
    }
    assert set(process_claims) == _PROCESS_FIELDS
    process = signed("process", process_claims, secrets)
    current_db_claims = {
        "version": 1,
        "grant_id": ledger["grant_id"],
        "worker_id": ledger["worker_id"],
        "container_id": ledger["container_id"],
        "epoch": ledger["epoch"],
        "revision": ledger["expected_revision"] + 1,
        "supervisor_observation_sha256": ledger_digest,
        "status_proof_sha256": digest("status", status),
        **source,
        "signed_roe_sha256": original.authorization_sha256,
        "status": "running",
        "source_current": True,
        "lease_active": True,
        "approval_current": True,
        "reviewer_current": True,
        "roe_current": True,
        "observed_at": now,
        "expires_at": now + 4,
    }
    assert set(current_db_claims) == _DB_FIELDS
    current_db = signed("current_db", current_db_claims, secrets)
    supervisor_claims = {
        "version": 1,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        **source,
        "signed_roe_sha256": original.authorization_sha256,
        **{
            field: process_claims[field]
            for field in (
                "container_id",
                "epoch",
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
        "issued_at": now,
        "expires_at": now + 4,
    }
    assert set(supervisor_claims) == SUPERVISOR_FIELDS
    supervisor = signed("supervisor", supervisor_claims, secrets)
    mount_claims = {
        "version": 1,
        "server_id": "source-map-mcp",
        "mode": "host-stage-v1",
        "native_stage_root": NATIVE_ROOT,
        "root_dev": 201,
        "root_ino": 902,
        "read_only": True,
        "observer_id": "observer-original",
        "issued_at": now,
        "expires_at": now + 4,
        **{
            field: process_claims[field]
            for field in (
                "pid",
                "pid_start_ticks",
                "mount_namespace_inode",
                "native_fsuid",
                "container_id",
                "epoch",
            )
        },
        **source,
        "supervisor_source_sha256": digest("supervisor", supervisor),
    }
    assert set(mount_claims) == MOUNT_FIELDS
    mount = signed("mount", mount_claims, secrets)
    return {
        "original": original,
        "supervisor_observation": ledger_proof,
        "source_status": status,
        "source_preflight_proof": preflight,
        "current_db_witness": current_db,
        "live_process_witness": process,
        "signed_supervisor_source": supervisor,
        "native_mount_witness": mount,
    }


@pytest.fixture
def host_setup(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    secrets = {
        group: Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
        for index, group in enumerate(join._ROOT_ENVS, 1)
    }
    for group, variable in join._ROOT_ENVS.items():
        public = (
            secrets[group]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        kid = "Signer" + group.replace("_", "").title()
        monkeypatch.setenv(variable, json.dumps({kid: base64.b64encode(public).decode("ascii")}))
    now = int(time.time())
    return {
        "keys": secrets,
        "proofs": proof_fixture(now, secrets),
        "join": join.SourceMapHostProcessJoin(
            pinned_mount_root=join.HostPinnedSourceMapMountRoot(root_dev=201, root_ino=902)
        ),
        "now": now,
        "monkeypatch": monkeypatch,
    }


def _resign(
    host: dict[str, Any], proof: str, *, group: str | None = None, domain: bytes | None = None
) -> None:
    bundle = host["proofs"]
    key = (
        group
        if group is not None
        else {
            "supervisor_observation": "ledger",
            "source_status": "status",
            "source_preflight_proof": "status",
            "current_db_witness": "current_db",
            "live_process_witness": "process",
            "signed_supervisor_source": "supervisor",
            "native_mount_witness": "mount",
        }[proof]
    )
    if proof == "source_preflight_proof":
        domain = PREFLIGHT_DOMAIN
    bundle[proof] = signed(key, bundle[proof]["claims"], host["keys"], domain=domain)


def test_six_distinct_signed_host_sources_join_original_pid_and_ro_mount(
    host_setup: dict[str, Any],
) -> None:
    result = host_setup["join"].verify(**host_setup["proofs"])
    assert isinstance(result, join.VerifiedSourceMapHostProcessMount)
    assert result.status == "host_process_readonly_mount_correlated_only"
    assert result.request_id == host_setup["proofs"]["original"].request_id
    assert result.task_id == host_setup["proofs"]["original"].task_id
    assert result.lease_id == host_setup["proofs"]["original"].lease_id
    assert (result.epoch, result.revision) == (11, 7)
    assert (result.pid, result.pid_start_ticks, result.native_fsuid) == (18101, 927, 1101)
    assert (result.root_dev, result.root_ino) == (201, 902)
    assert result.expires_at > result.observed_at
    assert result.authorizes_execution is False
    assert result.authorizes_mount_or_replay is False
    assert result.native_grant_redemption_verified_here is False
    assert result.durable_0037_binding_verified_here is False
    assert result.target_effect_verified is False
    assert PRIVATE_PATH not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.authorizes_execution = True
    with pytest.raises(TypeError):
        replace(result, authorizes_execution=True)


@pytest.mark.parametrize(
    ("proof", "field", "value"),
    [
        ("source_status", "task_id", "task-other"),
        ("source_status", "lease_id", "lease-other"),
        ("source_preflight_proof", "owner_id", "owner-foreign"),
        ("source_preflight_proof", "approval_id", "approval-foreign"),
        ("current_db_witness", "engagement_id", "eng-other"),
        ("current_db_witness", "authorization_sha256", SHA_D),
        ("current_db_witness", "signed_roe_sha256", SHA_D),
        ("current_db_witness", "reviewer_current", False),
        ("current_db_witness", "source_current", False),
        ("current_db_witness", "lease_active", False),
        ("current_db_witness", "roe_current", False),
        ("current_db_witness", "status_proof_sha256", SHA_A),
        ("current_db_witness", "supervisor_observation_sha256", SHA_A),
        ("current_db_witness", "revision", 6),
        ("current_db_witness", "grant_id", "ngr-" + "9" * 32),
        ("live_process_witness", "pid_start_ticks", 928),
        ("live_process_witness", "native_fsuid", 0),
        ("live_process_witness", "mount_namespace_inode", 95001),
        ("live_process_witness", "supervisor_observation_sha256", SHA_A),
        ("signed_supervisor_source", "cgroup_sha256", SHA_A),
        ("signed_supervisor_source", "lease_id", "lease-other"),
        ("native_mount_witness", "read_only", False),
        ("native_mount_witness", "root_ino", 903),
        ("native_mount_witness", "root_dev", 202),
        ("native_mount_witness", "native_stage_root", PRIVATE_PATH),
        ("native_mount_witness", "pid", 19101),
        ("native_mount_witness", "native_fsuid", 0),
    ],
)
def test_independently_signed_foreign_or_unsafe_host_claims_rejected(
    host_setup: dict[str, Any],
    proof: str,
    field: str,
    value: Any,
) -> None:
    host_setup["proofs"][proof]["claims"][field] = value
    _resign(host_setup, proof)
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        host_setup["join"].verify(**host_setup["proofs"])


@pytest.mark.parametrize(
    "field",
    ["engagement_id", "flow_id", "task_id", "lease_id", "authorization_sha256", "artifact_sha256"],
)
def test_host_pinned_original_scope_changed_is_rejected(
    host_setup: dict[str, Any], field: str
) -> None:
    original = host_setup["proofs"]["original"]
    new = (
        SHA_D
        if field.endswith("sha256")
        else (
            "eng-other"
            if field == "engagement_id"
            else (
                "task-other"
                if field == "task_id"
                else "lease-other" if field == "lease_id" else "flow-other"
            )
        )
    )
    bundle = dict(host_setup["proofs"])
    bundle["original"] = replace(original, **{field: new})
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        host_setup["join"].verify(**bundle)


def test_signature_tamper_cross_domain_replay_and_missing_proof_rejected(
    host_setup: dict[str, Any],
) -> None:
    for key in (
        "source_preflight_proof",
        "source_status",
        "current_db_witness",
        "live_process_witness",
        "signed_supervisor_source",
        "native_mount_witness",
        "supervisor_observation",
    ):
        case = copy.deepcopy(host_setup["proofs"])
        case[key]["signature"] = "A" + case[key]["signature"][1:]
        with pytest.raises(join.SourceMapHostProcessJoinDenied):
            host_setup["join"].verify(**case)
    forged = copy.deepcopy(host_setup["proofs"])
    forged["native_mount_witness"] = signed(
        "mount",
        forged["native_mount_witness"]["claims"],
        host_setup["keys"],
        domain=PROCESS_DOMAIN,
    )
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        host_setup["join"].verify(**forged)
    lost = dict(host_setup["proofs"])
    lost["current_db_witness"] = {}
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        host_setup["join"].verify(**lost)


@pytest.mark.parametrize(
    ("proof", "field", "value"),
    [
        ("current_db_witness", "observed_at", 0),
        ("current_db_witness", "expires_at", 0),
        ("source_status", "expires_at", 0),
        ("source_preflight_proof", "issued_at", 0),
        ("live_process_witness", "expires_at", 0),
        ("signed_supervisor_source", "expires_at", 0),
        ("native_mount_witness", "expires_at", 0),
    ],
)
def test_expired_or_historical_signed_witness_rejected(
    host_setup: dict[str, Any],
    proof: str,
    field: str,
    value: int,
) -> None:
    host_setup["proofs"][proof]["claims"][field] = value
    _resign(host_setup, proof)
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        host_setup["join"].verify(**host_setup["proofs"])


def test_missing_duplicate_or_rotated_host_signer_enrollment_rejected(
    host_setup: dict[str, Any],
) -> None:
    variable = join._ROOT_ENVS["mount"]
    host_setup["monkeypatch"].setenv(variable, "{}")
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        host_setup["join"].verify(**host_setup["proofs"])
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        join.SourceMapHostProcessJoin(
            pinned_mount_root=join.HostPinnedSourceMapMountRoot(root_dev=201, root_ino=902)
        )

    ledger_variable = join._ROOT_ENVS["ledger"]
    host_setup["monkeypatch"].setenv(variable, os.environ[ledger_variable])
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        join.SourceMapHostProcessJoin(
            pinned_mount_root=join.HostPinnedSourceMapMountRoot(root_dev=201, root_ino=902)
        )


def test_wrong_signed_supervisor_digest_denied_even_when_mount_resigned(
    host_setup: dict[str, Any],
) -> None:
    # Replacing the independent source signature requires an exact read-only
    # mount testimony referring to that exact original signature as well.
    case = host_setup["proofs"]
    case["native_mount_witness"]["claims"]["supervisor_source_sha256"] = SHA_A
    _resign(host_setup, "native_mount_witness")
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        host_setup["join"].verify(**case)


def test_no_signature_can_be_replayed_as_an_action_grant_or_0033_issuer(
    host_setup: dict[str, Any],
) -> None:
    # An independent signed SourceMap PID/mount has no scope to execute.
    result = host_setup["join"].verify(**host_setup["proofs"])
    assert result.authorizes_execution is False
    assert result.authorizes_mount_or_replay is False
    assert result.native_grant_redemption_verified_here is False
    assert result.durable_0037_binding_verified_here is False
    assert not hasattr(host_setup["join"], "issue")
    assert not hasattr(host_setup["join"], "redeem")
    assert not hasattr(host_setup["join"], "stage")
    assert not hasattr(host_setup["join"], "dispatch")


def test_root_pin_requires_verified_host_inode_not_caller_flags(
    host_setup: dict[str, Any],
) -> None:
    for pin in (
        join.HostPinnedSourceMapMountRoot(root_dev=0, root_ino=902),
        join.HostPinnedSourceMapMountRoot(root_dev=201, root_ino=0),
        join.HostPinnedSourceMapMountRoot(root_dev=True, root_ino=902),
        join.HostPinnedSourceMapMountRoot(
            root_dev=201, root_ino=902, native_stage_root=PRIVATE_PATH
        ),
    ):
        with pytest.raises(join.SourceMapHostProcessJoinDenied):
            join.SourceMapHostProcessJoin(pinned_mount_root=pin)
    wrong = join.SourceMapHostProcessJoin(
        pinned_mount_root=join.HostPinnedSourceMapMountRoot(root_dev=201, root_ino=903)
    )
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        wrong.verify(**host_setup["proofs"])


def test_host_trust_rotation_during_valid_signature_join_denied(
    host_setup: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authentic = join._verify_external_proofs

    def rotate_after_valid_proof(**proofs: Any) -> dict[str, Any]:
        verified = authentic(**proofs)
        monkeypatch.setenv(join._ROOT_ENVS["current_db"], "{}")
        return verified

    monkeypatch.setattr(join, "_verify_external_proofs", rotate_after_valid_proof)
    with pytest.raises(join.SourceMapHostProcessJoinDenied):
        host_setup["join"].verify(**host_setup["proofs"])
