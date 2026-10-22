"""Admission/replay tests never contact the target or application database."""

import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.target_authority_receipts import (
    TargetAuthorityNonceUnavailable,
    TargetAuthorityReplayGuard,
)


def identity():
    return {
        "engagement_id": "eng-test",
        "flow_id": "flow-test",
        "key_id": "oracle-1",
        "nonce": "abcdefghijklmnopqrstuvwx",
        "proof_sha256": "a" * 64,
    }


@pytest.mark.asyncio
async def test_exact_pg_insert_is_atomic_one_use_without_payload() -> None:
    receipts = set()
    values = []

    async def execute(stmt, params):
        assert "ON CONFLICT DO NOTHING RETURNING id" in str(stmt)
        assert "signature" not in params and "body" not in params
        assert params["nonce_sha256"] == hashlib.sha256(identity()["nonce"].encode()).hexdigest()
        values.append(params)
        if params["id"] in receipts:
            return SimpleNamespace(scalar_one_or_none=lambda: None)
        receipts.add(params["id"])
        return SimpleNamespace(scalar_one_or_none=lambda: params["id"])

    guard = TargetAuthorityReplayGuard(SimpleNamespace(execute=execute))
    assert await guard.claim_once(**identity()) is True
    assert await guard.claim_once(**identity()) is False
    assert len(values) == 2 and values[0] == values[1]


@pytest.mark.asyncio
async def test_unavailable_store_denies_and_does_not_claim_success() -> None:
    db = SimpleNamespace(execute=AsyncMock(side_effect=RuntimeError("private details")))
    with pytest.raises(TargetAuthorityNonceUnavailable, match="ledger unavailable"):
        await TargetAuthorityReplayGuard(db).claim_once(**identity())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key,value",
    [
        ("engagement_id", "eng-foreign/../../"),
        ("flow_id", "flow-newline\n"),
        ("key_id", "secret key"),
        ("nonce", "short"),
        ("proof_sha256", "B" * 64),
        ("proof_sha256", None),
    ],
)
async def test_invalid_nonce_identity_no_database_call(key, value) -> None:
    db = SimpleNamespace(execute=AsyncMock())
    fields = identity()
    fields[key] = value
    with pytest.raises(TargetAuthorityNonceUnavailable):
        await TargetAuthorityReplayGuard(db).claim_once(**fields)
    db.execute.assert_not_called()


def test_missing_transaction_is_rejected() -> None:
    with pytest.raises(TargetAuthorityNonceUnavailable):
        TargetAuthorityReplayGuard(None)
