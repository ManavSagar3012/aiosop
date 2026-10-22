"""Real POSIX original SourceMap staging and proof sidecar publication.

Only the SQLAlchemy import is stubbed: no central server, application DB,
Docker, supervised mount, native execution or authorized target is contacted.
Actual production stage/provisioner filesystem functions and Ed25519 signatures
are exercised against private test-owned POSIX directories.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import stat
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2] / "src" / "ai_osop"
ORCH = ROOT / "orchestrator"
CONTENT = b'{"version":3,"sources":["file.ts"],"sourcesContent":["const one = 1;"]}'
SHA = hashlib.sha256(CONTENT).hexdigest()


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    obj = importlib.util.module_from_spec(spec)
    sys.modules[name] = obj
    spec.loader.exec_module(obj)
    return obj


def _public(private: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode("ascii")


def _signed(stage: Any, signer: Ed25519PrivateKey, domain: bytes, claims: dict, kid: str) -> dict:
    return {
        "claims": claims,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(signer.sign(domain + stage._canonical(claims)))
        .decode("ascii")
        .rstrip("="),
    }


@pytest.fixture
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("requires Linux/POSIX protected dir_fd and nofollow handles")

    # Standalone WSL qualification deliberately does not depend on SQLAlchemy.
    for name, folder in (
        ("ai_osop", ROOT),
        ("ai_osop.orchestrator", ORCH),
        ("ai_osop.memory", ROOT / "memory"),
    ):
        package = types.ModuleType(name)
        package.__path__ = [str(folder)]
        monkeypatch.setitem(sys.modules, name, package)

    sqlalchemy = types.ModuleType("sqlalchemy")
    sqlalchemy.text = lambda query: query
    monkeypatch.setitem(sys.modules, "sqlalchemy", sqlalchemy)
    dispatcher = types.ModuleType("ai_osop.memory.flow_mcp_action_dispatch")
    dispatcher.FlowMCPActionStore = type("FlowMCPActionStore", (), {})
    monkeypatch.setitem(sys.modules, dispatcher.__name__, dispatcher)

    stage = _load(
        "ai_osop.orchestrator.sourcemap_original_stage", ORCH / "sourcemap_original_stage.py"
    )
    authority = types.ModuleType("ai_osop.memory.sourcemap_source_authority")
    authority.SourceMapSourceAuthorityStore = type("SourceMapSourceAuthorityStore", (), {})
    authority.canonical = stage._canonical
    monkeypatch.setitem(sys.modules, authority.__name__, authority)
    provisioner = _load(
        "ai_osop.orchestrator.sourcemap_original_readonly_provisioner",
        ORCH / "sourcemap_original_readonly_provisioner.py",
    )

    root = tmp_path / "sourcemap-originals"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    source_key = Ed25519PrivateKey.generate()
    host_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(root))
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"source-key": _public(source_key)}),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"host-key": _public(host_key)}),
    )
    now = int(time.time())
    claims = {
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
        "artifact_sha256": SHA,
        "manifest_sha256": "d" * 64,
        "approval_id": "reviewer-independent",
        "lease_id": "lease-current",
        "authorization_version": 4,
        "authorization_sha256": "e" * 64,
        "issued_at": now,
        "expires_at": now + 10,
    }
    source = _signed(stage, source_key, stage.SOURCE_DOMAIN, claims, "source-key")
    source_signature = base64.urlsafe_b64decode(source["signature"] + "==")
    source_sha = hashlib.sha256(
        stage.SOURCE_DOMAIN + stage._canonical(claims) + source_signature
    ).hexdigest()
    host_claims = {**claims, "stage_id": "sms-" + "f" * 32, "source_proof_sha256": source_sha}
    host = _signed(stage, host_key, stage.PROVISION_DOMAIN, host_claims, "host-key")
    return {
        "stage": stage,
        "provisioner": provisioner,
        "root": root,
        "source": source,
        "host": host,
    }


def _stage_original(world: dict[str, Any]) -> tuple[Any, Path]:
    host_stage = world["stage"].OriginalSourceMapHostStage()
    path = host_stage.stage(
        original_bytes=CONTENT,
        source_proof=world["source"],
        provision_proof=world["host"],
    )
    return host_stage, path


def test_actual_posix_signed_original_sidecar_commit(environment: dict[str, Any]) -> None:
    world = environment
    host, staged = _stage_original(world)
    root_info = world["root"].stat()
    root_identity = (root_info.st_dev, root_info.st_ino)
    sidecar = world["provisioner"]._publish_proof_sidecar(
        host, staged, len(CONTENT), root_identity, world["source"], world["host"]
    )
    assert sidecar == world["root"] / (SHA + ".proof.json")
    result = json.loads(sidecar.read_bytes())
    assert set(result) == {"version", "source_proof", "provision_proof"}
    assert result == {
        "version": 1,
        "source_proof": world["source"],
        "provision_proof": world["host"],
    }
    assert sidecar.read_bytes() == world["provisioner"]._proof_sidecar_bytes(
        world["source"], world["host"]
    )
    info = sidecar.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_mode & 0o222 == 0
    assert staged.read_bytes() == CONTENT
    assert staged.stat().st_mode & 0o222 == 0
    for field in ("action_id", "request_id", "preflight_id", "stage_id"):
        digest = hashlib.sha256(world["host"]["claims"][field].encode("ascii")).hexdigest()
        marker = world["root"] / (".used-" + field + "-" + digest)
        assert marker.read_bytes() == b"consumed\n"
        assert marker.stat().st_mode & 0o222 == 0
    assert not list(world["root"].glob(".proof-*.tmp"))
    with pytest.raises(ValueError):
        world["provisioner"]._publish_proof_sidecar(
            host, staged, len(CONTENT), root_identity, world["source"], world["host"]
        )
    with pytest.raises(ValueError):
        _stage_original(world)


@pytest.mark.parametrize("poison", ["symlink", "hardlink"])
def test_existing_sidecar_link_never_overwritten(
    environment: dict[str, Any], tmp_path: Path, poison: str
) -> None:
    world = environment
    host, staged = _stage_original(world)
    target = tmp_path / "unrelated-proof"
    target.write_bytes(b"original unrelated bytes")
    sidecar = world["root"] / (SHA + ".proof.json")
    if poison == "symlink":
        sidecar.symlink_to(target)
    else:
        os.link(target, sidecar)
    root_info = world["root"].stat()
    with pytest.raises(ValueError):
        world["provisioner"]._publish_proof_sidecar(
            host,
            staged,
            len(CONTENT),
            (root_info.st_dev, root_info.st_ino),
            world["source"],
            world["host"],
        )
    assert target.read_bytes() == b"original unrelated bytes"
    assert staged.read_bytes() == CONTENT
    with pytest.raises(ValueError):
        _stage_original(world)


def test_post_stage_original_byte_corruption_denies_signed_publication(
    environment: dict[str, Any],
) -> None:
    world = environment
    host, staged = _stage_original(world)
    # The test controls its isolated original directory, and simulates an
    # out-of-band write after stage commit but before proof publication.
    staged.chmod(0o600)
    staged.write_bytes(b"X" + CONTENT[1:])
    staged.chmod(0o400)
    root_info = world["root"].stat()
    with pytest.raises(ValueError):
        world["provisioner"]._publish_proof_sidecar(
            host,
            staged,
            len(CONTENT),
            (root_info.st_dev, root_info.st_ino),
            world["source"],
            world["host"],
        )
    assert not (world["root"] / (SHA + ".proof.json")).exists()
    with pytest.raises(ValueError):
        _stage_original(world)
