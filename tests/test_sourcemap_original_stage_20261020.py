"""Offline host SourceMap staging tests; no issuer, DB, target or Docker."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# This standalone host process deliberately has no app/SQLAlchemy dependency.
# Load its leaf module without importing orchestrator.__init__ and the app DB.
_MODULE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "ai_osop"
    / "orchestrator"
    / "sourcemap_original_stage.py"
)
_SPEC = importlib.util.spec_from_file_location("sourcemap_original_stage_host_test", _MODULE)
assert _SPEC is not None and _SPEC.loader is not None
stage = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(stage)


MAP = b'{"version":3,"sources":["src.js"],"sourcesContent":["const x = 1;"]}'
DIGEST = hashlib.sha256(MAP).hexdigest()


def public_b64(private: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode("ascii")


def signed(claims: dict[str, Any], signer: Ed25519PrivateKey, domain: bytes, kid: str) -> dict:
    signature = signer.sign(domain + stage._canonical(claims))
    return {
        "claims": claims,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


@pytest.fixture
def authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    original_key = Ed25519PrivateKey.generate()
    host_key = Ed25519PrivateKey.generate()
    root = tmp_path / "sourcemap-originals"
    root.mkdir(mode=0o700)
    if os.name == "posix":
        root.chmod(0o700)
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(root))
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"central-issuer": public_b64(original_key)}),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"host-provision": public_b64(host_key)}),
    )
    now = int(time.time())
    source_claims = {
        "version": 1,
        "preflight_id": "nsp-" + "a" * 32,
        "request_id": "req-" + "b" * 48,
        "engagement_id": "eng-review",
        "flow_id": "flow-review",
        "task_id": "task-review",
        "subtask_id": "subtask-review",
        "action_id": "action-" + "c" * 32,
        "owner_id": "owner-review",
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": DIGEST,
        "manifest_sha256": "d" * 64,
        "approval_id": "approved-by-independent-reviewer",
        "lease_id": "lease-current",
        "authorization_version": 4,
        "authorization_sha256": "e" * 64,
        "issued_at": now,
        "expires_at": now + 10,
    }
    source = signed(source_claims, original_key, stage.SOURCE_DOMAIN, "central-issuer")
    digest = hashlib.sha256(
        stage.SOURCE_DOMAIN
        + stage._canonical(source["claims"])
        + base64.urlsafe_b64decode(source["signature"] + "==")
    ).hexdigest()
    provision_claims = {
        **source_claims,
        "stage_id": "sms-" + "f" * 32,
        "source_proof_sha256": digest,
    }
    provision = signed(
        provision_claims, host_key, stage.PROVISION_DOMAIN, "host-provision"
    )
    return {
        "root": root,
        "source": source,
        "provision": provision,
        "original_key": original_key,
        "host_key": host_key,
        "now": now,
    }


def resign_provision(fixture: dict, claims: dict[str, Any]) -> dict:
    return signed(claims, fixture["host_key"], stage.PROVISION_DOMAIN, "host-provision")


def verify(fixture: dict, source: Any = None, provision: Any = None) -> dict:
    return stage.verify_original_stage_proofs(
        fixture["source"] if source is None else source,
        fixture["provision"] if provision is None else provision,
        {"central-issuer": base64.b64decode(public_b64(fixture["original_key"]))},
        {"host-provision": base64.b64decode(public_b64(fixture["host_key"]))},
        now=fixture["now"],
    )


def test_independent_authority_exact_original_signatures(authority: dict) -> None:
    claims = verify(authority)
    assert claims["action_id"] == "action-" + "c" * 32
    assert claims["artifact_sha256"] == hashlib.sha256(MAP).hexdigest()
    assert claims["manifest_sha256"] == "d" * 64

    for field, other in (
        ("task_id", "task-other"),
        ("flow_id", "flow-other"),
        ("owner_id", "owner-other"),
        ("action_id", "action-" + "1" * 32),
        ("lease_id", "lease-other"),
        ("approval_id", "approval-other"),
        ("artifact_sha256", "1" * 64),
        ("manifest_sha256", "1" * 64),
        ("authorization_sha256", "1" * 64),
        ("authorization_version", 5),
        ("preflight_id", "nsp-" + "1" * 32),
        ("request_id", "req-" + "1" * 48),
    ):
        mutated = copy.deepcopy(authority["provision"]["claims"])
        mutated[field] = other
        with pytest.raises(stage.OriginalSourceMapStageDenied):
            verify(authority, provision=resign_provision(authority, mutated))


def test_reject_signature_forgery_and_unsigned_claims(authority: dict) -> None:
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        verify(authority, source=authority["source"]["claims"])
    for key in ("source", "provision"):
        fake = copy.deepcopy(authority[key])
        fake["signature"] = "A" * 86
        with pytest.raises(stage.OriginalSourceMapStageDenied):
            verify(
                authority,
                source=fake if key == "source" else None,
                provision=fake if key == "provision" else None,
            )
    extra = copy.deepcopy(authority["provision"])
    extra["claims"]["scope_from_caller"] = "anything"
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        verify(authority, provision=extra)
    spoofed = copy.deepcopy(authority["provision"])
    spoofed["kid"] = "central-issuer"
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        verify(authority, provision=spoofed)


def test_signed_stage_must_bind_original_source_signature(authority: dict) -> None:
    altered = copy.deepcopy(authority["source"]["claims"])
    altered["approval_id"] = "approved-by-another-reviewer"
    changed_source = signed(
        altered, authority["original_key"], stage.SOURCE_DOMAIN, "central-issuer"
    )
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        verify(authority, source=changed_source)
    wrong = copy.deepcopy(authority["provision"]["claims"])
    wrong["source_proof_sha256"] = "0" * 64
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        verify(authority, provision=resign_provision(authority, wrong))


def test_expiry_bad_clock_and_wrong_purpose_signing(authority: dict) -> None:
    proof = authority["provision"]
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        stage.verify_original_stage_proofs(
            authority["source"],
            proof,
            {"central-issuer": base64.b64decode(public_b64(authority["original_key"]))},
            {"host-provision": base64.b64decode(public_b64(authority["host_key"]))},
            now=authority["now"] + 10,
        )
    forged = signed(
        authority["source"]["claims"],
        authority["original_key"],
        stage.PROVISION_DOMAIN,
        "central-issuer",
    )
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        verify(authority, provision=forged)
    extended = copy.deepcopy(proof["claims"])
    extended["expires_at"] = authority["now"] + 11
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        verify(authority, provision=resign_provision(authority, extended))
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        stage.verify_original_stage_proofs(
            authority["source"],
            authority["provision"],
            {"central-issuer": base64.b64decode(public_b64(authority["original_key"]))},
            {"host-provision": base64.b64decode(public_b64(authority["original_key"]))},
            now=authority["now"],
        )


def test_unenrolled_host_trust_or_wrong_root_denies(
    authority: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON")
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        stage.OriginalSourceMapHostStage()
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"host-provision": public_b64(authority["host_key"])}),
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(authority["root"].parent))
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        stage.OriginalSourceMapHostStage()


@pytest.mark.skipif(os.name != "posix", reason="secure POSIX dir-fd staging; Windows denies closed")
def test_stage_original_once_readonly_fsync_and_replay_denied(authority: dict) -> None:
    host = stage.OriginalSourceMapHostStage()
    path = host.stage(
        original_bytes=MAP,
        source_proof=authority["source"],
        provision_proof=authority["provision"],
    )
    assert path == authority["root"] / (DIGEST + ".map")
    assert path.read_bytes() == MAP
    assert stat.S_ISREG(path.lstat().st_mode)
    assert path.stat().st_nlink == 1
    assert path.stat().st_mode & 0o222 == 0
    assert sorted(p.name for p in authority["root"].iterdir()).count(DIGEST + ".map") == 1
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        host.stage(
            original_bytes=MAP,
            source_proof=authority["source"],
            provision_proof=authority["provision"],
        )


@pytest.mark.skipif(os.name != "posix", reason="secure POSIX dir-fd staging; Windows denies closed")
def test_modified_original_rejected_without_consuming_action(authority: dict) -> None:
    host = stage.OriginalSourceMapHostStage()
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        host.stage(
            original_bytes=MAP + b"tampered",
            source_proof=authority["source"],
            provision_proof=authority["provision"],
        )
    assert not list(authority["root"].iterdir())


@pytest.mark.skipif(os.name != "posix", reason="secure POSIX dir-fd staging; Windows denies closed")
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "regular"])
def test_preexisting_path_never_overwritten(authority: dict, kind: str) -> None:
    target = authority["root"] / (DIGEST + ".map")
    outside = authority["root"].parent / "existing.map"
    outside.write_bytes(b"original untouched")
    if kind == "symlink":
        target.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, target)
    else:
        target.write_bytes(b"preexisting original")
    host = stage.OriginalSourceMapHostStage()
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        host.stage(
            original_bytes=MAP, source_proof=authority["source"],
            provision_proof=authority["provision"],
        )
    assert outside.read_bytes() == b"original untouched"
    assert target.read_bytes() in (b"original untouched", b"preexisting original")
    # Failed stage has durably consumed Action; it cannot be retried.
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        host.stage(
            original_bytes=MAP, source_proof=authority["source"],
            provision_proof=authority["provision"],
        )
    assert outside.read_bytes() == b"original untouched"


@pytest.mark.skipif(os.name != "posix", reason="secure POSIX dir-fd staging; Windows denies closed")
def test_lost_ack_or_failed_readback_remains_consumed(
    authority: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = stage.OriginalSourceMapHostStage()
    def fail_readback(_fd: int, _name: str, _digest: str, _size: int) -> None:
        raise OSError("simulated post-write readback failure")
    monkeypatch.setattr(stage, "_readback", fail_readback)
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        host.stage(
            original_bytes=MAP, source_proof=authority["source"],
            provision_proof=authority["provision"],
        )
    monkeypatch.undo()
    assert (authority["root"] / (DIGEST + ".map")).read_bytes() == MAP
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        host.stage(
            original_bytes=MAP, source_proof=authority["source"],
            provision_proof=authority["provision"],
        )


@pytest.mark.skipif(os.name != "posix", reason="secure POSIX dir-fd staging; Windows denies closed")
def test_reparse_or_symlink_root_and_nonprivate_root_deny(
    authority: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = authority["root"]
    root.chmod(0o777)
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        stage.OriginalSourceMapHostStage()
    root.chmod(0o700)
    root.rmdir()
    root.symlink_to(root.parent, target_is_directory=True)
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        stage.OriginalSourceMapHostStage()


@pytest.mark.skipif(os.name == "posix", reason="POSIX has atomic dir-fd stage")
def test_windows_native_handle_required_fail_closed(authority: dict) -> None:
    host = stage.OriginalSourceMapHostStage()
    with pytest.raises(stage.OriginalSourceMapStageDenied):
        host.stage(
            original_bytes=MAP, source_proof=authority["source"],
            provision_proof=authority["provision"],
        )
    assert not list(authority["root"].iterdir())
