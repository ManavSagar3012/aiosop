"""Native SAME-0035 SourceMap proof handoff, offline with FAKE central PostgreSQL.

The fixture models a separately issued and committed 0035 Ed25519 proof and a
host provision proof, plus host-staged immutable .map, four consumed markers
and fsynced .proof.json. It does NOT qualify real PostgreSQL, the host
provisioner's producer wiring, TLS, supervisor UID mapping, or a live lease.
Only native verification, journal one-shot and the ASGI transport are real.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.test_source_map_signed_original_intake_20261020 import (
    ACTION,
    APPROVAL,
    DIGEST,
    DOCUMENT,
    ENGAGEMENT,
    REQUEST_ID,
    SECRET,
    TASK,
    _REAL_HTTPX_CLIENT,
    call,
    configure,
    request,
)

_ISSUER_KID = "independent-original-source-issuer"
_HOST_KID = "independent-host-supervisor"
_STATUS_SERVICE = "dedicated-central-status-token-20261021"
_LINUX = pytest.mark.skipif(os.name != "posix", reason="Trusted host stage is POSIX only")


def _public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


def _signed(
    module: Any,
    claims: dict[str, Any],
    key: Ed25519PrivateKey,
    kid: str,
    domain: bytes,
) -> dict[str, Any]:
    sig = key.sign(domain + module._canonical(claims))
    return {
        "claims": claims,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(sig).decode("ascii").rstrip("="),
    }


def _file(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o400 if os.name == "posix" else stat.S_IREAD)


def _setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    module, original_file, journal, original_traffic = configure(monkeypatch, tmp_path)
    # Native host-stage-v1 consumes an already committed source preflight. The
    # central SOURCE issuer URL/bearer must never be provisioned to the native
    # worker; only enrolled issuer public roots and a separate STATUS channel
    # are required. Keeping these from legacy configure() now fails closed.
    monkeypatch.delenv("OSOP_SOURCEMAP_SOURCE_URL", raising=False)
    monkeypatch.delenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", raising=False)
    assert "OSOP_SOURCEMAP_SOURCE_URL" not in os.environ
    assert "OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN" not in os.environ
    root = tmp_path / "sourcemap-originals"
    root.mkdir(mode=0o700)
    original_file.replace(root / (DIGEST + ".map"))
    source_key = Ed25519PrivateKey.generate()
    host_key = Ed25519PrivateKey.generate()
    assert _public(source_key) != _public(host_key)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({_ISSUER_KID: _public(source_key)}),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({_HOST_KID: _public(host_key)}),
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_ORIGINAL_READONLY_ROOT", str(root))
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(root))
    monkeypatch.setenv("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE", "host-stage-v1")
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_STATUS_URL",
        "https://authority.example.org/native-sourcemap/status-preflight",
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", _STATUS_SERVICE)

    now = int(time.time())
    source = {
        **request()["execution_binding"],
        "version": 1,
        "preflight_id": "nsp-" + "1" * 32,
        "flow_id": "flow-original",
        "subtask_id": "subtask-original",
        "action_id": ACTION,
        "owner_id": "owner-original",
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": DIGEST,
        "manifest_sha256": "b" * 64,
        "approval_id": APPROVAL,
        "lease_id": "lease-current",
        "authorization_version": 3,
        "authorization_sha256": "c" * 64,
        "issued_at": now,
        "expires_at": now + 10,
    }
    source_proof = _signed(module, source, source_key, _ISSUER_KID, module._SOURCE_DOMAIN)
    source_sig = base64.urlsafe_b64decode(source_proof["signature"] + "==")
    source_hash = hashlib.sha256(
        module._SOURCE_DOMAIN + module._canonical(source) + source_sig
    ).hexdigest()
    stage = {
        **source,
        "stage_id": "sms-" + "2" * 32,
        "source_proof_sha256": source_hash,
        "expires_at": now + 8,
    }
    provision = _signed(module, stage, host_key, _HOST_KID, module._HOST_STAGE_DOMAIN)
    proof_file = root / (DIGEST + ".proof.json")
    proof = {"version": 1, "source_proof": source_proof, "provision_proof": provision}
    _file(proof_file, module._canonical(proof))

    markers = {}
    for name in ("action_id", "request_id", "preflight_id", "stage_id"):
        digest = hashlib.sha256(stage[name].encode("ascii")).hexdigest()
        path = root / (".used-" + name + "-" + digest)
        _file(path, b"consumed\n")
        markers[name] = path

    status_traffic: list[dict[str, Any]] = []
    state = {"live": True, "invalid_status": False}

    def central_status(req: httpx.Request) -> httpx.Response:
        assert (
            req.url.path == "/native-sourcemap/status-preflight"
        ), "Native attempted second 0035 issuance"
        assert req.headers["Authorization"] == "Bearer " + _STATUS_SERVICE
        assert req.headers["Cache-Control"] == "no-store"
        posted = json.loads(req.content)
        status_traffic.append(posted)
        assert posted == {
            "request_id": REQUEST_ID,
            "engagement_id": ENGAGEMENT,
            "task_id": TASK,
            "server_id": "source-map-mcp",
            "tool_name": "inspect_local_original_sourcemap",
            "artifact_sha256": DIGEST,
        }
        if not state["live"]:
            return httpx.Response(409, json={"status": "reviewer_revoked"})
        current = int(time.time())
        signed = _signed(
            module,
            {
                **source,
                "status_id": "nss-" + "3" * 32,
                "issued_at": current,
                "expires_at": current + 5,
            },
            source_key,
            _ISSUER_KID,
            module._SOURCE_DOMAIN if state["invalid_status"] else module._STATUS_DOMAIN,
        )
        return httpx.Response(200, json=signed)

    def http_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        assert kwargs.get("trust_env") is False
        assert kwargs.get("follow_redirects") is False
        assert kwargs.get("verify") == os.environ["OSOP_SOURCEMAP_SOURCE_CA_BUNDLE"]
        return _REAL_HTTPX_CLIENT(*args, transport=httpx.MockTransport(central_status), **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", http_client)
    return {
        "module": module,
        "original": root / (DIGEST + ".map"),
        "root": root,
        "journal": journal,
        "proof_path": proof_file,
        "markers": markers,
        "source": source,
        "host": stage,
        "source_key": source_key,
        "host_key": host_key,
        "traffic": status_traffic,
        "legacy_issuer_traffic": original_traffic,
        "state": state,
    }


@_LINUX
@pytest.mark.asyncio
async def test_handoff_consumes_preissued_0035_once_without_reissuing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world = _setup(monkeypatch, tmp_path)
    module = world["module"]
    assert (await call(module, request())).status_code == 200
    first = await call(module, request())
    assert first.status_code == 503
    result = json.loads(next(world["journal"].glob("completed-*.json")).read_text(encoding="utf-8"))
    assert result["artifact_sha256"] == DIGEST
    assert result["preflight_id"] == world["source"]["preflight_id"]
    assert provider_receipt_is_signed(
        result["provider_receipt"], "source-map-mcp", REQUEST_ID, ENGAGEMENT, TASK
    )
    assert len(world["traffic"]) == 1
    assert not world["legacy_issuer_traffic"]
    assert world["original"].read_bytes() == DOCUMENT
    assert len(list(world["journal"].glob("action_id-*.used"))) == 1
    assert len(list(world["journal"].glob("request_id-*.used"))) == 1
    assert SECRET not in json.dumps(result)


@pytest.mark.asyncio
async def test_portable_preissued_dual_signature_marker_and_status_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cryptographic handoff contract, without asserting Windows host staging."""
    world = _setup(monkeypatch, tmp_path)
    module = world["module"]
    config = module._local_original_config()
    roots = {_HOST_KID: base64.b64decode(_public(world["host_key"]))}
    bound = request()["execution_binding"]
    admitted = module._preissued_source_handoff(bound, DIGEST, config, roots)
    assert admitted == world["source"]
    permit = await module._central_original_status(bound, admitted, config)
    assert permit["action_id"] == ACTION
    assert permit["artifact_sha256"] == DIGEST
    assert world["original"].read_bytes() == DOCUMENT
    assert world["traffic"] == [
        {**bound, "tool_name": "inspect_local_original_sourcemap", "artifact_sha256": DIGEST}
    ]
    assert not world["legacy_issuer_traffic"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alteration",
    [
        "missing",
        "source_signature",
        "host_signature",
        "wrong_task",
        "wrong_sha",
        "swapped_issuer",
        "missing_marker",
        "forged_marker",
        "sidecar_hardlink",
        "sidecar_symlink",
    ],
)
async def test_handoff_adversarial_provenance_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, alteration: str
) -> None:
    world = _setup(monkeypatch, tmp_path)
    module = world["module"]
    proof = world["proof_path"]
    payload = json.loads(proof.read_text())
    if alteration == "missing":
        if os.name == "nt":
            proof.chmod(stat.S_IREAD | stat.S_IWRITE)
        proof.unlink()
    elif alteration == "source_signature":
        payload["source_proof"]["signature"] = "A" * 86
    elif alteration == "host_signature":
        payload["provision_proof"]["signature"] = "A" * 86
    elif alteration == "wrong_task":
        payload["source_proof"]["claims"]["task_id"] = "task-forged"
    elif alteration == "wrong_sha":
        payload["provision_proof"]["claims"]["artifact_sha256"] = "0" * 64
    elif alteration == "swapped_issuer":
        payload["source_proof"]["kid"] = _HOST_KID
    elif alteration == "missing_marker":
        if os.name == "nt":
            world["markers"]["stage_id"].chmod(stat.S_IREAD | stat.S_IWRITE)
        world["markers"]["stage_id"].unlink()
    elif alteration == "forged_marker":
        marker = world["markers"]["stage_id"]
        marker.chmod(0o600)
        _file(marker, b"unverified")
    elif alteration == "sidecar_hardlink":
        try:
            os.link(proof, proof.with_name("hardlink.proof.json"))
        except OSError:
            pytest.skip("Hardlinks unavailable")
    elif alteration == "sidecar_symlink":
        another = proof.with_name("real.proof.json")
        proof.rename(another)
        try:
            proof.symlink_to(another)
        except OSError:
            pytest.skip("Symlink creation unavailable")
    if alteration in {
        "source_signature",
        "host_signature",
        "wrong_task",
        "wrong_sha",
        "swapped_issuer",
    }:
        proof.chmod(0o600)
        _file(proof, module._canonical(payload))
    config = module._local_original_config()
    roots = {_HOST_KID: base64.b64decode(_public(world["host_key"]))}
    with pytest.raises(module.SourceMapDenied):
        module._preissued_source_handoff(request()["execution_binding"], DIGEST, config, roots)
    assert not world["traffic"]
    assert not world["legacy_issuer_traffic"]
    assert not list(world["journal"].iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["revoked", "wrong_domain"])
async def test_portable_revoked_or_wrong_domain_status_cannot_authorize_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: str
) -> None:
    world = _setup(monkeypatch, tmp_path)
    module = world["module"]
    if state == "revoked":
        world["state"]["live"] = False
    else:
        world["state"]["invalid_status"] = True
    with pytest.raises(module.SourceMapUnavailable):
        await module._central_original_status(
            request()["execution_binding"],
            world["source"],
            module._local_original_config(),
        )
    assert len(world["traffic"]) == 1
    assert not world["legacy_issuer_traffic"]
    assert not list(world["journal"].iterdir())


@_LINUX
@pytest.mark.asyncio
@pytest.mark.parametrize("current", ["revoked", "invalid_signature", "status_missing"])
async def test_handoff_live_0035_status_required_before_original_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, current: str
) -> None:
    world = _setup(monkeypatch, tmp_path)
    if current == "revoked":
        world["state"]["live"] = False
    elif current == "invalid_signature":
        world["state"]["invalid_status"] = True
    else:
        monkeypatch.delenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN")
    original = world["module"]._read_original_bytes
    called = []

    def blocked_read(*args: Any) -> bytes:
        called.append(True)
        return original(*args)

    monkeypatch.setattr(world["module"], "_read_original_bytes", blocked_read)
    output = await call(world["module"], request())
    assert output.status_code == 503
    assert not called
    assert not list(world["journal"].iterdir())
    assert not world["legacy_issuer_traffic"]


@pytest.mark.asyncio
async def test_host_staged_root_without_handoff_never_issues_second_proof(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world = _setup(monkeypatch, tmp_path)
    monkeypatch.delenv("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE")
    response = await call(world["module"], request())
    assert response.status_code == 503
    assert not world["legacy_issuer_traffic"]
    assert not world["traffic"]
    assert not list(world["journal"].iterdir())


@pytest.mark.asyncio
async def test_unavailable_host_provenance_windows_denied_without_issuer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world = _setup(monkeypatch, tmp_path)
    if os.name == "posix":
        pytest.skip("Windows unsafe stage guard; real POSIX host tested above")
    response = await call(world["module"], request())
    assert response.status_code == 503
    assert not world["legacy_issuer_traffic"]
    assert not world["traffic"]
    assert not list(world["journal"].iterdir())
