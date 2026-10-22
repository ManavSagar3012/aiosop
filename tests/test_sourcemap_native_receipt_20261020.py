"""Native SourceMap provider status attestation over a real local SHA-pinned map.

The central authorization here is a signed in-memory HTTP fixture; no live
PostgreSQL reviewer state, external network, target effect or deployment claim.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.test_source_map_signed_original_intake_20261020 import (
    ACTION,
    DIGEST,
    DOCUMENT,
    ENGAGEMENT,
    REQUEST_ID,
    SECRET,
    TASK,
    call,
    configure,
    request,
)

NATIVE_SIGNER_KID = "enrolled-native-sourcemap"
STATUS_FIELDS = {
    "request_id",
    "engagement_id",
    "task_id",
    "server_id",
    "status",
    "verified",
    "stopped",
    "issued_at",
}


def _enroll_receipt_signer(monkeypatch, tmp_path: Path) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    identity_root = tmp_path / "operator-receipt-identity"
    identity_root.mkdir(mode=0o700)
    key_file = identity_root / "native-ed25519.key"
    key_file.write_bytes(private)
    key_file.chmod(0o600 if os.name == "posix" else stat.S_IREAD)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KID", NATIVE_SIGNER_KID)
    monkeypatch.setenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps(
            {
                "source-map-mcp": {
                    NATIVE_SIGNER_KID: base64.b64encode(public).decode("ascii"),
                },
            }
        ),
    )
    return key


def _verify_status(receipt: dict) -> bool:
    return provider_receipt_is_signed(
        receipt,
        "source-map-mcp",
        REQUEST_ID,
        ENGAGEMENT,
        TASK,
    )


@pytest.mark.asyncio
async def test_real_immutable_original_is_processed_and_native_receipt_persisted(
    monkeypatch, tmp_path
):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    _enroll_receipt_signer(monkeypatch, tmp_path)
    response = await call(mod, request())
    assert response.status_code == 200, response.text
    envelope = response.json()
    assert set(envelope) == {"request_id", "status", "result", "provider_receipt"}
    assert envelope["request_id"] == REQUEST_ID
    assert envelope["status"] == "success"
    assert envelope["result"]["source_original_bytes_sha256_verified"] is True
    assert envelope["result"]["source_side_signed_authorization_verified"] is True
    assert envelope["result"]["findings"][0]["secret_type_counts"]["aws_access_key"] == 1
    receipt = envelope["provider_receipt"]
    assert set(receipt) == STATUS_FIELDS | {"attestation"}
    assert receipt["status"] == "succeeded"
    assert receipt["verified"] is True
    assert receipt["stopped"] is False
    assert receipt["attestation"]["kid"] == NATIVE_SIGNER_KID
    assert _verify_status(receipt)
    assert SECRET not in response.text
    assert "private-test-password" not in response.text
    assert original.read_bytes() == DOCUMENT
    assert len(traffic) == 1
    assert len(list(ledger.glob("*.used"))) == 2
    completed = list(ledger.glob("completed-*.json"))
    assert len(completed) == 1
    evidence = json.loads(completed[0].read_text())
    assert evidence["action_id"] == ACTION
    assert evidence["artifact_sha256"] == DIGEST
    assert evidence["metadata"] == envelope["result"]
    assert evidence["provider_receipt"] == receipt
    assert SECRET not in completed[0].read_text()
    assert "private-test-password" not in completed[0].read_text()
    assert not list(tmp_path.glob("**/native-ed25519.key.*"))


@pytest.mark.asyncio
async def test_missing_native_signer_refuses_before_central_and_source_read(monkeypatch, tmp_path):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    # The shared original-intake fixture now provisions a distinct native
    # receipt signer for its positive 0027 tests. Explicitly revoke it here.
    monkeypatch.delenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KID")
    assert mod._approved_original_transport_configured() is False
    read_calls = []

    def refuse_read(*args):
        read_calls.append(args)
        raise AssertionError("A missing receipt signer must never read the original")

    monkeypatch.setattr(mod, "_read_original_bytes", refuse_read)
    denied = await call(mod, request())
    assert denied.status_code == 503
    assert "provider_receipt" not in denied.json()
    assert not traffic
    assert not read_calls
    assert not list(ledger.iterdir())
    assert original.read_bytes() == DOCUMENT


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["untrusted", "swapped", "writable", "same_issuer"])
async def test_wrong_or_insecure_provider_signer_cannot_mint_success(
    monkeypatch, tmp_path, invalid
):
    mod, _, ledger, traffic = configure(monkeypatch, tmp_path)
    _enroll_receipt_signer(monkeypatch, tmp_path)
    signing_path = Path(os.environ["OSOP_SOURCEMAP_RECEIPT_SIGNING_KEY_FILE"])
    if invalid == "untrusted":
        monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "{}")
    elif invalid == "swapped":
        changed = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        signing_path.chmod(0o600 if os.name == "posix" else stat.S_IREAD | stat.S_IWRITE)
        signing_path.write_bytes(changed)
        signing_path.chmod(0o600 if os.name == "posix" else stat.S_IREAD)
    elif invalid == "writable":
        if os.name != "posix":
            pytest.skip("Owner-only mode check uses POSIX file permission bits")
        signing_path.chmod(0o644)
    else:
        public = (
            Ed25519PrivateKey.from_private_bytes(signing_path.read_bytes())
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
            json.dumps({"conflicted-issuer": base64.b64encode(public).decode("ascii")}),
        )
    response = await call(mod, request())
    assert response.status_code == 503
    assert "provider_receipt" not in response.json()
    assert not traffic
    assert not list(ledger.iterdir())


@pytest.mark.asyncio
async def test_original_one_shot_replay_cannot_create_second_receipt(monkeypatch, tmp_path):
    mod, _, ledger, traffic = configure(monkeypatch, tmp_path)
    _enroll_receipt_signer(monkeypatch, tmp_path)
    first = await call(mod, request())
    assert first.status_code == 200
    replay = await call(mod, request())
    assert replay.status_code == 503
    assert "provider_receipt" not in replay.json()
    assert len(list(ledger.glob("completed-*.json"))) == 1
    assert len(traffic) == 2


@pytest.mark.asyncio
async def test_unsigned_central_proof_cannot_generate_signed_native_receipt(monkeypatch, tmp_path):
    mod, _, ledger, traffic = configure(monkeypatch, tmp_path, corrupted=True)
    _enroll_receipt_signer(monkeypatch, tmp_path)
    response = await call(mod, request())
    assert response.status_code == 503
    assert "provider_receipt" not in response.json()
    assert len(traffic) == 1
    assert not list(ledger.iterdir())


@pytest.mark.asyncio
async def test_native_receipt_never_precedes_durable_evidence_persistence(monkeypatch, tmp_path):
    mod, _, ledger, traffic = configure(monkeypatch, tmp_path)
    _enroll_receipt_signer(monkeypatch, tmp_path)
    invoked = []

    def broken_persist(*args):
        invoked.append(True)
        raise OSError("deliberately unavailable one-shot outcome storage")

    monkeypatch.setattr(mod, "_persist_native_receipt", broken_persist)
    first = await call(mod, request())
    assert first.status_code == 503
    assert first.json()["status"] == "error"
    assert "provider_receipt" not in first.json()
    assert invoked == [True]
    assert len(list(ledger.glob("*.used"))) == 2
    assert not list(ledger.glob("completed-*.json"))
    replay = await call(mod, request())
    assert replay.status_code == 503
    assert len(traffic) == 2


@pytest.mark.asyncio
async def test_client_can_neither_override_identity_nor_reuse_signed_status(monkeypatch, tmp_path):
    mod, _, ledger, traffic = configure(monkeypatch, tmp_path)
    _enroll_receipt_signer(monkeypatch, tmp_path)
    wrong = request()
    wrong["execution_binding"]["task_id"] = "task-foreign"
    denied = await call(mod, wrong)
    assert denied.status_code == 503
    assert not list(ledger.iterdir())
    completed = await call(mod, request())
    assert completed.status_code == 200
    receipt = completed.json()["provider_receipt"]
    assert not provider_receipt_is_signed(
        receipt, "source-map-mcp", REQUEST_ID, ENGAGEMENT, "task-foreign"
    )
    assert not provider_receipt_is_signed(
        receipt, "source-map-mcp", "req-" + "f" * 48, ENGAGEMENT, TASK
    )
    assert not provider_receipt_is_signed(receipt, "other-mcp", REQUEST_ID, ENGAGEMENT, TASK)
    assert len(traffic) == 2
