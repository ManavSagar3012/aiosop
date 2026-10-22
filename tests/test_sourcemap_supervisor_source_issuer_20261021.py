"""Narrow adversarial qualification of the not-yet-wired SourceMap issuer.

All positive input witnesses are synthetic, signed by test-only independent
Ed25519 keys; they DO NOT represent actual 0033 PostgreSQL current-readback,
live supervisor PID observations, or a live central 0035 status service.
There are no DB, Docker, network, target, or migration operations.
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ORCH = Path(__file__).resolve().parents[1] / "src" / "ai_osop" / "orchestrator"
ENG = "eng-auth"
FLOW = "flow-auth"
TASK = "task-auth"
ACTION = "action-" + "a" * 32
REQUEST = "req-" + "b" * 48
GRANT = "ngr-" + "c" * 32
CONTAINER = "d" * 64
SHA = "e" * 64


def _load_module(name: str, file: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, file)
    assert spec is not None and spec.loader is not None
    obj = importlib.util.module_from_spec(spec)
    sys.modules[name] = obj
    spec.loader.exec_module(obj)
    return obj


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1] / "src" / "ai_osop"
    for name, folder in (("ai_osop", root), ("ai_osop.orchestrator", ORCH)):
        package = types.ModuleType(name)
        package.__path__ = [str(folder)]
        monkeypatch.setitem(sys.modules, name, package)
    loaded = {}
    for name, file in (
        ("sourcemap_original_stage", ORCH / "sourcemap_original_stage.py"),
        ("sourcemap_native_mount_observer", ORCH / "sourcemap_native_mount_observer.py"),
        ("sourcemap_supervisor_source_issuer", ORCH / "sourcemap_supervisor_source_issuer.py"),
    ):
        qualified = "ai_osop.orchestrator." + name
        loaded[name] = _load_module(qualified, file)
    issuer = loaded["sourcemap_supervisor_source_issuer"]
    observer = loaded["sourcemap_native_mount_observer"]
    root_dir = tmp_path / "sourcemap-originals"
    root_dir.mkdir(mode=0o700)
    root_dir.chmod(0o700)
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(root_dir))
    secrets: dict[str, Ed25519PrivateKey] = {
        name: Ed25519PrivateKey.generate()
        for name in ("issuer", "ledger", "status", "db", "process")
    }
    for short, env in (
        ("issuer", "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"),
        ("ledger", "OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON"),
        ("status", "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"),
        ("db", "OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON"),
        ("process", "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON"),
    ):
        public = (
            secrets[short]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        monkeypatch.setenv(env, json.dumps({short + "-trusted": base64.b64encode(public).decode()}))
    signing_file = tmp_path / "source-issuer-private.key"
    signing_file.write_bytes(
        secrets["issuer"].private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    signing_file.chmod(0o600)
    monkeypatch.setenv("OSOP_SOURCEMAP_SUPERVISOR_SOURCE_SIGNING_KEY_FILE", str(signing_file))
    monkeypatch.setenv("OSOP_SOURCEMAP_SUPERVISOR_SOURCE_SIGNING_KID", "issuer-trusted")

    def sign(kind: str, data: dict[str, Any], domain: bytes) -> dict[str, Any]:
        return {
            "claims": dict(data),
            "kid": kind + "-trusted",
            "signature": base64.urlsafe_b64encode(
                secrets[kind].sign(domain + loaded["sourcemap_original_stage"]._canonical(data))
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
        "worker_id": "worker-live",
        "container_id": CONTAINER,
        "epoch": 19,
        "expected_revision": 8,
        "state": "running",
        "observed_at": now,
        "evidence_sha256": SHA,
        "resource_sha256": SHA,
        "folder_staging_sha256": None,
        "readback_sha256": None,
    }
    status = {
        "version": 1,
        "preflight_id": "nsp-" + "1" * 32,
        "status_id": "nss-" + "2" * 32,
        "request_id": REQUEST,
        "engagement_id": ENG,
        "flow_id": FLOW,
        "task_id": TASK,
        "subtask_id": "subtask-ok",
        "action_id": ACTION,
        "owner_id": "owner-a",
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": SHA,
        "manifest_sha256": SHA,
        "approval_id": "approval-a",
        "lease_id": "lease-a",
        "authorization_version": 5,
        "authorization_sha256": SHA,
        "issued_at": now,
        "expires_at": now + 5,
    }
    ledger_proof = sign("ledger", ledger, issuer.LEDGER_DOMAIN)
    status_proof = sign("status", status, issuer.SOURCE_STATUS_DOMAIN)
    _, ledger_digest = issuer._verified(
        ledger_proof,
        {
            "ledger-trusted": secrets["ledger"]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        },
        issuer.LEDGER_DOMAIN,
        issuer._LEDGER_FIELDS,
    )
    _, status_digest = issuer._verified(
        status_proof,
        {
            "status-trusted": secrets["status"]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        },
        issuer.SOURCE_STATUS_DOMAIN,
        issuer._STATUS_FIELDS,
    )
    db = {
        "version": 1,
        "grant_id": GRANT,
        "worker_id": "worker-live",
        "container_id": CONTAINER,
        "epoch": 19,
        "revision": 9,
        "supervisor_observation_sha256": ledger_digest,
        "status_proof_sha256": status_digest,
        **{field: status[field] for field in issuer._IDENTITY},
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
    process = {
        "version": 1,
        "grant_id": GRANT,
        "request_id": REQUEST,
        "worker_id": "worker-live",
        "container_id": CONTAINER,
        "epoch": 19,
        "supervisor_observation_sha256": ledger_digest,
        "pid": 12345,
        "pid_start_ticks": 123456,
        "mount_namespace_inode": 12345678,
        "native_fsuid": 1000,
        "cgroup_sha256": SHA,
        "native_stage_root": "/run/osop-sourcemap/sourcemap-originals",
        "observed_at": now,
        "expires_at": now + 5,
    }
    proofs = {
        "supervisor_observation": ledger_proof,
        "source_status": status_proof,
        "current_db_witness": sign("db", db, issuer.CURRENT_DB_DOMAIN),
        "live_process_witness": sign("process", process, issuer.PROCESS_DOMAIN),
    }
    yield {
        "issuer": issuer,
        "observer": observer,
        "proofs": proofs,
        "sign": sign,
        "secrets": secrets,
        "root": root_dir,
        "key_file": signing_file,
    }
    for key in loaded:
        monkeypatch.delitem(sys.modules, "ai_osop.orchestrator." + key, raising=False)


def _issue(case: dict[str, Any], proofs: dict[str, Any] | None = None) -> dict[str, Any]:
    source = case["issuer"].SourceMapSupervisorSourceIssuer()
    return source.issue(**(proofs if proofs is not None else case["proofs"]))


@pytest.mark.skipif(
    sys.platform != "linux", reason="Linux protected key and O_EXCL journal required"
)
def test_synthetic_separate_signed_sources_join_and_durable_one_use(
    host: dict[str, Any],
) -> None:
    signed = _issue(host)
    observed, proof_digest = host["observer"].verify_supervisor_source(
        signed,
        {
            "issuer-trusted": host["secrets"]["issuer"]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        },
        "/run/osop-sourcemap/sourcemap-originals",
    )
    assert len(proof_digest) == 64
    assert set(observed) == host["observer"].SUPERVISOR_FIELDS
    assert observed["request_id"] == REQUEST
    assert observed["action_id"] == ACTION
    assert observed["pid"] == 12345
    assert observed["epoch"] == 19
    assert observed["native_fsuid"] == 1000
    assert observed["source_current"] is True
    assert len(list(host["root"].glob(".supervisor-source-*.used"))) == 2
    with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
        _issue(host)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux host-only signer")
def test_current_cas_revision_must_be_one_after_signed_transition(
    host: dict[str, Any],
) -> None:
    # Real 0033 verifies signed expected_revision against the old row, then
    # UPDATEs revision = revision + 1 before persisting this observation.
    # A CURRENT_DB witness at the old revision is stale even if properly
    # signed by its own key, not evidence of a committed running transition.
    proofs = copy.deepcopy(host["proofs"])
    ledger_revision = proofs["supervisor_observation"]["claims"]["expected_revision"]
    assert proofs["current_db_witness"]["claims"]["revision"] == ledger_revision + 1
    stale = proofs["current_db_witness"]["claims"]
    stale["revision"] = ledger_revision
    proofs["current_db_witness"] = host["sign"]("db", stale, host["issuer"].CURRENT_DB_DOMAIN)
    with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
        _issue(host, proofs)
    assert not list(host["root"].glob(".supervisor-source-*"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux host-only signer")
@pytest.mark.parametrize(
    "missing",
    [
        "supervisor_observation",
        "source_status",
        "current_db_witness",
        "live_process_witness",
    ],
)
def test_missing_independent_proof_denies_without_journal(
    host: dict[str, Any],
    missing: str,
) -> None:
    proofs = dict(host["proofs"])
    proofs.pop(missing)
    with pytest.raises((host["issuer"].SourceMapSupervisorIssuerDenied, TypeError)):
        _issue(host, proofs)
    assert not list(host["root"].glob(".supervisor-source-*"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux host-only signer")
@pytest.mark.parametrize(
    "proof, field, changed",
    [
        ("supervisor_observation", "server_id", "recon-mcp"),
        ("supervisor_observation", "state", "unknown"),
        ("supervisor_observation", "epoch", 0),
        ("supervisor_observation", "request_id", "req-" + "f" * 48),
        ("source_status", "owner_id", "owner-foreign"),
        ("source_status", "server_id", "recon-mcp"),
        ("current_db_witness", "reviewer_current", False),
        ("current_db_witness", "lease_active", False),
        ("current_db_witness", "roe_current", False),
        ("current_db_witness", "revision", 7),
        ("live_process_witness", "pid", 999),
        ("live_process_witness", "epoch", 20),
        ("live_process_witness", "native_stage_root", "/tmp/forged"),
        ("live_process_witness", "native_fsuid", 0),
    ],
)
def test_forged_or_conflicting_signed_evidence_fails_closed(
    host: dict[str, Any],
    proof: str,
    field: str,
    changed: Any,
) -> None:
    proofs = copy.deepcopy(host["proofs"])
    proofs[proof]["claims"][field] = changed
    # Mutating a signed claim without signature is always refused.
    with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
        _issue(host, proofs)
    assert not list(host["root"].glob(".supervisor-source-*"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux host-only signer")
def test_independently_resigned_conflicting_lease_or_process_denied(
    host: dict[str, Any],
) -> None:
    for proof, field, wrong in (
        ("current_db_witness", "action_id", "action-" + "f" * 32),
        ("current_db_witness", "reviewer_current", False),
        ("live_process_witness", "pid", -1),
        ("live_process_witness", "container_id", "9" * 64),
        ("supervisor_observation", "server_id", "recon-mcp"),
    ):
        proofs = copy.deepcopy(host["proofs"])
        token = proofs[proof]
        token["claims"][field] = wrong
        kind, domain = {
            "current_db_witness": ("db", host["issuer"].CURRENT_DB_DOMAIN),
            "live_process_witness": ("process", host["issuer"].PROCESS_DOMAIN),
            "supervisor_observation": ("ledger", host["issuer"].LEDGER_DOMAIN),
        }[proof]
        proofs[proof] = host["sign"](kind, token["claims"], domain)
        with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
            _issue(host, proofs)
    assert not list(host["root"].glob(".supervisor-source-*"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux host-only signer")
def test_unsigned_rows_and_missing_or_shared_signers_deny(
    host: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proofs = copy.deepcopy(host["proofs"])
    proofs["current_db_witness"] = {"lease_active": True}
    with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
        _issue(host, proofs)
    monkeypatch.delenv("OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON")
    with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
        _issue(host)
    db_key = (
        host["secrets"]["ledger"]
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"db-trusted": base64.b64encode(db_key).decode()}),
    )
    with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
        _issue(host)
    assert not list(host["root"].glob(".supervisor-source-*"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux host-only signer")
def test_private_key_mode_wrong_key_or_missing_signer_denied(
    host: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = host["key_file"]
    key.chmod(0o644)
    with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
        _issue(host)
    key.chmod(0o600)
    monkeypatch.setenv("OSOP_SOURCEMAP_SUPERVISOR_SOURCE_SIGNING_KID", "not-enrolled")
    with pytest.raises(host["issuer"].SourceMapSupervisorIssuerDenied):
        _issue(host)
    assert not list(host["root"].glob(".supervisor-source-*"))


def test_no_host_signing_on_windows_and_no_inferred_live_producer(
    host: dict[str, Any],
) -> None:
    issuer = host["issuer"]
    assert "current_db_witness" in issuer.SourceMapSupervisorSourceIssuer.issue.__code__.co_varnames
    assert (
        "live_process_witness" in issuer.SourceMapSupervisorSourceIssuer.issue.__code__.co_varnames
    )
    if sys.platform != "linux":
        with pytest.raises(issuer.SourceMapSupervisorIssuerDenied):
            _issue(host)
