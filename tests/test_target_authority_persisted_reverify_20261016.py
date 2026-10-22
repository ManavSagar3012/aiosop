"""Immutable signed target proof can be checked later, without nonce reissue."""

import base64
import hashlib
from types import SimpleNamespace

import pytest

from ai_osop.core import target_authority_proof as proof
from ai_osop.memory.target_authority_receipts import (
    PersistedTargetAuthorityReceiptGuard,
    TargetAuthorityNonceUnavailable,
)
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


class ReadOnlyRecordedNonce:
    """SQL stand-in: verify SELECT identity, never insert or mutate."""

    def __init__(self, present=True):
        self.present = present
        self.reads = []

    async def execute(self, statement, params):
        sql = str(statement).upper()
        assert "SELECT" in sql and "INSERT" not in sql and "DELETE" not in sql
        self.reads.append(params)
        expected_id = params["id"] if self.present else None
        return SimpleNamespace(scalar_one_or_none=lambda: expected_id)


@pytest.mark.asyncio
async def test_reverify_historical_proof_against_recorded_sql_nonce(proof_case, monkeypatch):
    case = proof_case
    claim_bytes, signature = case.signed_bytes()
    original = await proof.verify_target_authority_proof(
        claims_json=claim_bytes, signature_b64url=signature, **case.context
    )
    recorded_epoch = case.claims["issued_at"] + 1
    monkeypatch.setattr(proof, "_now_epoch", lambda: recorded_epoch + 7200)
    db = ReadOnlyRecordedNonce()
    guard = PersistedTargetAuthorityReceiptGuard(
        db, original.proof_sha256, proof_received_at_epoch=recorded_epoch
    )
    result = await proof.verify_target_authority_proof(
        claims_json=claim_bytes,
        signature_b64url=signature,
        **{**case.context, "replay_guard": guard},
    )
    assert result.proof_sha256 == original.proof_sha256
    assert result.finding_verified is False
    assert len(db.reads) == 1
    assert db.reads[0]["proof"] == original.proof_sha256
    assert db.reads[0]["nonce"] == hashlib.sha256(case.claims["nonce"].encode()).hexdigest()


@pytest.mark.asyncio
async def test_missing_recorded_nonce_cannot_reverify(proof_case, monkeypatch):
    case = proof_case
    claim_bytes, signature = case.signed_bytes()
    digest = hashlib.sha256(
        proof._DOMAIN + claim_bytes + base64.urlsafe_b64decode(signature + "==")
    ).hexdigest()
    epoch = case.claims["issued_at"] + 1
    monkeypatch.setattr(proof, "_now_epoch", lambda: epoch + 7200)
    db = ReadOnlyRecordedNonce(present=False)
    with pytest.raises(proof.TargetAuthorityDenied, match="replayed or unconfirmed"):
        await proof.verify_target_authority_proof(
            claims_json=claim_bytes,
            signature_b64url=signature,
            **{
                **case.context,
                "replay_guard": PersistedTargetAuthorityReceiptGuard(
                    db, digest, proof_received_at_epoch=epoch
                ),
            },
        )


def test_untrusted_or_missing_immutable_received_time_denied():
    db = ReadOnlyRecordedNonce()
    with pytest.raises(TargetAuthorityNonceUnavailable):
        PersistedTargetAuthorityReceiptGuard(db, "a" * 64, proof_received_at_epoch=0)
    with pytest.raises(TargetAuthorityNonceUnavailable):
        PersistedTargetAuthorityReceiptGuard(db, "a" * 64, proof_received_at_epoch=True)


@pytest.mark.asyncio
async def test_future_durable_receipt_time_is_not_valid_history(proof_case, monkeypatch):
    case = proof_case
    blob, sig = case.signed_bytes()
    real_now = case.claims["issued_at"]
    monkeypatch.setattr(proof, "_now_epoch", lambda: real_now)
    with pytest.raises(proof.TargetAuthorityDenied, match="admission time untrusted"):
        await proof.verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **{
                **case.context,
                "replay_guard": PersistedTargetAuthorityReceiptGuard(
                    ReadOnlyRecordedNonce(),
                    "a" * 64,
                    proof_received_at_epoch=real_now + 1000,
                ),
            },
        )
