"""One-use PostgreSQL admission for independent target-authority attestations.

This store does NOT decide whether the target-side assertion is true. Its only
job is to prevent a valid signed oracle nonce from being accepted a second time
across ASGI processes, while the caller holds the signed Flow/ROE transaction.
No external action, target request, provider call, or mutable evidence is made.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from sqlalchemy import text

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_INSERT = text(
    "INSERT INTO target_authority_nonce_receipts "
    "(id, engagement_id, flow_id, key_id, nonce_sha256, proof_sha256) "
    "VALUES (:id, :engagement_id, :flow_id, :key_id, :nonce_sha256, :proof_sha256) "
    "ON CONFLICT DO NOTHING RETURNING id"
)


class TargetAuthorityNonceUnavailable(RuntimeError):
    """No durable, unambiguous one-use target proof admission was confirmed."""


class TargetAuthorityReplayGuard:
    """Use inside an existing authoritative SQL transaction, never autocommit.

    The caller must lock current signed engagement/Flow/Task provenance in the
    same transaction. Rollback on any later refusal also discards this claim.
    """

    def __init__(self, db: Any) -> None:
        if db is None or not callable(getattr(db, "execute", None)):
            raise TargetAuthorityNonceUnavailable("PostgreSQL transaction required")
        self._db = db

    async def claim_once(
        self,
        *,
        engagement_id: str,
        flow_id: str,
        key_id: str,
        nonce: str,
        proof_sha256: str,
    ) -> bool:
        if (
            type(engagement_id) is not str
            or _ID.fullmatch(engagement_id) is None
            or not engagement_id.startswith("eng-")
            or type(flow_id) is not str
            or _ID.fullmatch(flow_id) is None
            or not flow_id.startswith("flow-")
            or type(key_id) is not str
            or _ID.fullmatch(key_id) is None
            or type(nonce) is not str
            or _NONCE.fullmatch(nonce) is None
            or type(proof_sha256) is not str
            or _SHA.fullmatch(proof_sha256) is None
        ):
            raise TargetAuthorityNonceUnavailable("Invalid signed proof admission identity")
        nonce_sha256 = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        digest = hashlib.sha256(
            (engagement_id + "\0" + flow_id + "\0" + key_id + "\0" + nonce_sha256).encode("utf-8")
        ).hexdigest()
        try:
            result = await self._db.execute(
                _INSERT,
                {
                    "id": "tauth-" + digest[:32],
                    "engagement_id": engagement_id,
                    "flow_id": flow_id,
                    "key_id": key_id,
                    "nonce_sha256": nonce_sha256,
                    "proof_sha256": proof_sha256,
                },
            )
            claimed = result.scalar_one_or_none()
        except Exception as exc:
            raise TargetAuthorityNonceUnavailable(
                "Independent proof replay ledger unavailable"
            ) from exc
        return claimed == "tauth-" + digest[:32]


class PersistedTargetAuthorityReceiptGuard:
    """Reverify one *already admitted* nonce, without a second insert.

    This adapter is for an independent later review of immutable PostgreSQL
    receipts, NOT for initial admission. It implements the verifier's existing
    ``claim_once`` interface by checking a known receipt. Callers must require
    a matching immutable target_authority_assertions row and hold current
    signed Task/Flow/ROE locks before invoking it.
    """

    def __init__(
        self,
        db: Any,
        expected_proof_sha256: str,
        *,
        proof_received_at_epoch: int,
    ) -> None:
        if (
            db is None
            or not callable(getattr(db, "execute", None))
            or type(expected_proof_sha256) is not str
            or _SHA.fullmatch(expected_proof_sha256) is None
            or type(proof_received_at_epoch) is not int
            or proof_received_at_epoch < 1
        ):
            raise TargetAuthorityNonceUnavailable("Existing signed proof receipt required")
        self._db = db
        self._expected = expected_proof_sha256
        # Supplied ONLY from an immutable PostgreSQL target_authority_assertions
        # row under the current signed authority transaction, never the client.
        self.verification_epoch = proof_received_at_epoch

    async def claim_once(
        self,
        *,
        engagement_id: str,
        flow_id: str,
        key_id: str,
        nonce: str,
        proof_sha256: str,
    ) -> bool:
        if (
            type(engagement_id) is not str
            or _ID.fullmatch(engagement_id) is None
            or not engagement_id.startswith("eng-")
            or type(flow_id) is not str
            or _ID.fullmatch(flow_id) is None
            or not flow_id.startswith("flow-")
            or type(key_id) is not str
            or _ID.fullmatch(key_id) is None
            or type(nonce) is not str
            or _NONCE.fullmatch(nonce) is None
            or proof_sha256 != self._expected
        ):
            return False
        nonce_sha = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        receipt_hash = hashlib.sha256(
            (engagement_id + "\0" + flow_id + "\0" + key_id + "\0" + nonce_sha).encode("utf-8")
        ).hexdigest()
        receipt_id = "tauth-" + receipt_hash[:32]
        try:
            record = await self._db.execute(
                text(
                    "SELECT id FROM target_authority_nonce_receipts "
                    "WHERE id=:id AND engagement_id=:eng AND flow_id=:flow "
                    "AND key_id=:key AND nonce_sha256=:nonce AND proof_sha256=:proof FOR SHARE"
                ),
                {
                    "id": receipt_id,
                    "eng": engagement_id,
                    "flow": flow_id,
                    "key": key_id,
                    "nonce": nonce_sha,
                    "proof": self._expected,
                },
            )
        except Exception as exc:
            raise TargetAuthorityNonceUnavailable(
                "Durable prior proof receipt unavailable"
            ) from exc
        return record.scalar_one_or_none() == receipt_id
