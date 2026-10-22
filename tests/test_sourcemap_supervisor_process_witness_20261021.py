"""Host SourceMap process attestation tests. No app DB/Docker/targets/network.

Positive path is SYNTHETIC: five separate test-only Ed25519 keys sign the
historical 0033, current DB and supervisor PID binding; the kernel checker is
mocked ONLY for this case. There is NO production PID-binding producer today.
Negative /proc checks use the real Linux kernel with no mount/exec effects.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1] / "src" / "ai_osop"
ORCH = ROOT / "orchestrator"
ENG = "eng-original"
REQUEST = "req-" + "a" * 48
GRANT = "ngr-" + "b" * 32
CONTAINER = "c" * 64
SHA = "d" * 64


def _module(qualified: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(qualified, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified] = module
    spec.loader.exec_module(module)
    return module


def _public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


@pytest.fixture
def case(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> dict[str, Any]:
    for name, root in (("ai_osop", ROOT), ("ai_osop.orchestrator", ORCH)):
        package = types.ModuleType(name)
        package.__path__ = [str(root)]
        monkeypatch.setitem(sys.modules, name, package)
    names = (
        "sourcemap_original_stage",
        "sourcemap_native_mount_observer",
        "sourcemap_supervisor_source_issuer",
        "sourcemap_supervisor_process_witness",
    )
    loaded: dict[str, Any] = {}
    for name in names:
        fullname = "ai_osop.orchestrator." + name
        loaded[name] = _module(fullname, ORCH / (name + ".py"))
    stage = loaded["sourcemap_original_stage"]
    issuer = loaded["sourcemap_supervisor_source_issuer"]
    witness = loaded["sourcemap_supervisor_process_witness"]
    keys = {label: Ed25519PrivateKey.generate() for label in ("ledger", "db", "binder", "process")}
    enrollment = {
        "ledger": "OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON",
        "db": "OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON",
        "binder": "OSOP_SOURCEMAP_SUPERVISOR_PID_BINDING_TRUSTED_PUBLIC_KEYS_JSON",
        "process": "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON",
    }
    for name, env in enrollment.items():
        monkeypatch.setenv(
            env,
            json.dumps({name + "-trusted": base64.b64encode(_public(keys[name])).decode()}),
        )
    signfile = tmp_path / "process-signer.key"
    signfile.write_bytes(
        keys["process"].private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    signfile.chmod(0o600)
    monkeypatch.setenv("OSOP_SOURCEMAP_SUPERVISOR_PROCESS_SIGNING_KID", "process-trusted")
    monkeypatch.setenv("OSOP_SOURCEMAP_SUPERVISOR_PROCESS_SIGNING_KEY_FILE", str(signfile))
    journal = tmp_path / "sourcemap-originals"
    journal.mkdir(mode=0o700)
    journal.chmod(0o700)
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(journal))

    def sign(name: str, claims: dict[str, Any], domain: bytes) -> dict[str, Any]:
        return {
            "claims": copy.deepcopy(claims),
            "kid": name + "-trusted",
            "signature": base64.urlsafe_b64encode(
                keys[name].sign(domain + stage._canonical(claims))
            )
            .decode("ascii")
            .rstrip("="),
        }

    now = int(time.time())
    ledger = {
        "version": 1,
        "grant_id": GRANT,
        "request_id": REQUEST,
        "server_id": "source-map-mcp",
        "worker_id": "worker-approved",
        "container_id": CONTAINER,
        "epoch": 7,
        "expected_revision": 6,
        "state": "running",
        "observed_at": now,
        "evidence_sha256": SHA,
        "resource_sha256": SHA,
        "folder_staging_sha256": None,
        "readback_sha256": None,
    }
    token = sign("ledger", ledger, issuer.LEDGER_DOMAIN)
    _, digest = issuer._verified(
        token,
        {"ledger-trusted": _public(keys["ledger"])},
        issuer.LEDGER_DOMAIN,
        issuer._LEDGER_FIELDS,
    )
    db = {
        "version": 1,
        "grant_id": GRANT,
        "worker_id": "worker-approved",
        "container_id": CONTAINER,
        "epoch": 7,
        # Genuine 0033 transition: durable post-commit revision is CAS + 1.
        "revision": 7,
        "supervisor_observation_sha256": digest,
        "status_proof_sha256": SHA,
        "request_id": REQUEST,
        "engagement_id": ENG,
        "flow_id": "flow-current",
        "task_id": "task-current",
        "subtask_id": "subtask-current",
        "owner_id": "owner-current",
        "approval_id": "approval-current",
        "action_id": "action-" + "e" * 32,
        "lease_id": "lease-current",
        "artifact_sha256": SHA,
        "manifest_sha256": SHA,
        "authorization_sha256": SHA,
        "signed_roe_sha256": SHA,
        "status": "running",
        "source_current": True,
        "lease_active": True,
        "approval_current": True,
        "reviewer_current": True,
        "roe_current": True,
        "observed_at": now,
        "expires_at": now + 5,
    }
    binding = {
        "version": 1,
        "grant_id": GRANT,
        "request_id": REQUEST,
        "worker_id": "worker-approved",
        "container_id": CONTAINER,
        "epoch": 7,
        "supervisor_observation_sha256": digest,
        "pid": 12345,
        "pid_start_ticks": 67890,
        "mount_namespace_inode": 424242,
        "native_fsuid": 1000,
        "cgroup_sha256": SHA,
        "cmdline_sha256": SHA,
        "native_stage_root": "/run/osop-sourcemap/sourcemap-originals",
        "observed_at": now,
        "expires_at": now + 5,
    }
    proofs = {
        "supervisor_observation": token,
        "current_db_witness": sign("db", db, issuer.CURRENT_DB_DOMAIN),
        "signed_supervisor_pid_binding": sign("binder", binding, witness.PID_BINDING_DOMAIN),
    }
    yield {
        "mod": witness,
        "issuer": issuer,
        "keys": keys,
        "sign": sign,
        "proofs": proofs,
        "root": journal,
        "signfile": signfile,
        "ledger": ledger,
        "db": db,
        "binding": binding,
    }
    for name in names:
        monkeypatch.delitem(sys.modules, "ai_osop.orchestrator." + name, raising=False)


def _issue(case: dict[str, Any], proofs: dict[str, Any] | None = None) -> dict[str, Any]:
    producer = case["mod"].IndependentSourceMapSupervisorProcessWitness()
    return producer.issue(**(case["proofs"] if proofs is None else proofs))


@pytest.mark.skipif(sys.platform != "linux", reason="host-only Linux")
def test_simulated_signed_sources_kernel_observation_and_one_shot(
    case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Explicitly synthetic positive: *not* a real live SourceMap PID binding.
    calls = []

    def simulated_kernel(data: dict[str, Any]) -> dict[str, Any]:
        calls.append(data["pid"])
        assert data == case["binding"]
        return {"pid": data["pid"]}

    monkeypatch.setattr(case["mod"], "_live_kernel_identity", simulated_kernel)
    produced = _issue(case)
    process_roots = {"process-trusted": _public(case["keys"]["process"])}
    signed, _digest = case["issuer"]._verified(
        produced,
        process_roots,
        case["issuer"].PROCESS_DOMAIN,
        case["issuer"]._PROCESS_FIELDS,
    )
    assert calls == [12345]
    assert signed["grant_id"] == GRANT
    assert signed["container_id"] == CONTAINER
    assert signed["epoch"] == 7
    assert case["db"]["revision"] == case["ledger"]["expected_revision"] + 1
    assert signed["pid_start_ticks"] == 67890
    assert signed["native_fsuid"] == 1000
    assert set(signed) == case["issuer"]._PROCESS_FIELDS
    assert len(list(case["root"].glob(".supervisor-process-*.used"))) == 2
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        _issue(case)
    assert calls == [12345, 12345]  # no second signed witness or journal success


@pytest.mark.skipif(sys.platform != "linux", reason="host-only Linux")
@pytest.mark.parametrize(
    "missing",
    [
        "supervisor_observation",
        "current_db_witness",
        "signed_supervisor_pid_binding",
    ],
)
def test_no_unsigned_or_absent_source_can_select_process(
    case: dict[str, Any],
    missing: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        case["mod"], "_live_kernel_identity", lambda _: pytest.fail("kernel accessed without trust")
    )
    proofs = dict(case["proofs"])
    proofs.pop(missing)
    with pytest.raises((case["mod"].SourceMapProcessWitnessDenied, TypeError)):
        _issue(case, proofs)
    assert not list(case["root"].glob(".supervisor-process-*"))


@pytest.mark.skipif(sys.platform != "linux", reason="host-only Linux")
@pytest.mark.parametrize(
    "which,field,value",
    [
        ("supervisor_observation", "server_id", "recon-mcp"),
        ("supervisor_observation", "state", "unknown"),
        ("supervisor_observation", "epoch", 0),
        ("current_db_witness", "lease_active", False),
        ("current_db_witness", "reviewer_current", False),
        ("current_db_witness", "roe_current", False),
        ("current_db_witness", "revision", 6),
        ("signed_supervisor_pid_binding", "pid", 22222),
        ("signed_supervisor_pid_binding", "container_id", "f" * 64),
    ],
)
def test_modified_signed_evidence_denied_without_kernel_access(
    case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    which: str,
    field: str,
    value: Any,
) -> None:
    monkeypatch.setattr(
        case["mod"],
        "_live_kernel_identity",
        lambda _: pytest.fail("untrusted identity touched kernel"),
    )
    proofs = copy.deepcopy(case["proofs"])
    proofs[which]["claims"][field] = value  # unchanged signature!
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        _issue(case, proofs)


@pytest.mark.skipif(sys.platform != "linux", reason="host-only Linux")
@pytest.mark.parametrize(
    "which,field,value",
    [
        ("supervisor_observation", "server_id", "recon-mcp"),
        ("supervisor_observation", "epoch", 8),
        ("current_db_witness", "lease_active", False),
        ("current_db_witness", "revision", 6),  # equal == uncommitted CAS
        ("current_db_witness", "revision", 5),  # stale prior revision
        ("current_db_witness", "revision", 8),  # skipped revision
        ("current_db_witness", "supervisor_observation_sha256", "f" * 64),
        ("signed_supervisor_pid_binding", "pid", 0),
        ("signed_supervisor_pid_binding", "epoch", 8),
        ("signed_supervisor_pid_binding", "native_stage_root", "/tmp/caller-mount"),
    ],
)
def test_independently_resigned_conflicting_sources_denied(
    case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    which: str,
    field: str,
    value: Any,
) -> None:
    monkeypatch.setattr(
        case["mod"],
        "_live_kernel_identity",
        lambda _: pytest.fail("invalid source must fail before kernel"),
    )
    proofs = copy.deepcopy(case["proofs"])
    old = proofs[which]
    claims = {**old["claims"], field: value}
    signer, domain = {
        "supervisor_observation": ("ledger", case["issuer"].LEDGER_DOMAIN),
        "current_db_witness": ("db", case["issuer"].CURRENT_DB_DOMAIN),
        "signed_supervisor_pid_binding": ("binder", case["mod"].PID_BINDING_DOMAIN),
    }[which]
    proofs[which] = case["sign"](signer, claims, domain)
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        _issue(case, proofs)
    assert not list(case["root"].glob(".supervisor-process-*"))


@pytest.mark.skipif(sys.platform != "linux", reason="host-only Linux")
def test_missing_or_overlapping_roots_and_bad_host_signer_fail_closed(
    case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OSOP_SOURCEMAP_SUPERVISOR_PID_BINDING_TRUSTED_PUBLIC_KEYS_JSON")
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        _issue(case)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SUPERVISOR_PID_BINDING_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"binder-trusted": base64.b64encode(_public(case["keys"]["ledger"])).decode()}),
    )
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        _issue(case)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SUPERVISOR_PID_BINDING_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"binder-trusted": base64.b64encode(_public(case["keys"]["binder"])).decode()}),
    )
    case["signfile"].chmod(0o644)
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        _issue(case)


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux /proc only")
def test_real_proc_self_pid_and_host_namespace_denied(
    case: dict[str, Any],
) -> None:
    # GENUINE /proc access: self PID is not a supervised SourceMap container.
    pid = os.getpid()
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    ticks = case["mod"]._start_ticks(raw, pid)
    cgroup = Path(f"/proc/{pid}/cgroup").read_bytes()
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        case["mod"]._live_kernel_identity(
            {
                **case["binding"],
                "pid": pid,
                "pid_start_ticks": ticks,
                "native_fsuid": os.getuid(),
                "mount_namespace_inode": os.stat("/proc/self/ns/mnt").st_ino,
                "cgroup_sha256": hashlib.sha256(cgroup).hexdigest(),
            }
        )
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        case["mod"]._live_kernel_identity({**case["binding"], "pid": 0})


def test_actual_cgroup_ownership_and_start_parsing_fail_closed(
    case: dict[str, Any],
) -> None:
    checker = case["mod"]._cgroup_container_bound
    assert checker(f"0::/system.slice/docker-{CONTAINER}.scope\n".encode(), CONTAINER)
    assert checker(f"11:memory:/docker/{CONTAINER}\n".encode(), CONTAINER)
    assert not checker(b"0::/\n", CONTAINER)
    assert not checker(f"0::/docker/{CONTAINER}f\n".encode(), CONTAINER)
    assert not checker(f"0::/docker/{'f'*64}\n".encode(), CONTAINER)
    assert not checker(b"unparseable", CONTAINER)
    if sys.platform == "linux":
        pid = os.getpid()
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        assert case["mod"]._start_ticks(raw, pid) > 0
        assert case["mod"]._fsuid(Path(f"/proc/{pid}/status").read_bytes()) == os.getuid()
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        case["mod"]._start_ticks(b"fake PID stat", 1)
    with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
        case["mod"]._fsuid(b"Uid:\tbad")


def test_windows_never_mints_linux_process_witness(case: dict[str, Any]) -> None:
    if sys.platform != "linux":
        with pytest.raises(case["mod"].SourceMapProcessWitnessDenied):
            _issue(case)
