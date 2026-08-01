"""ReceiptStore: persists HMAC-chained ExploitReceipts and artifact blobs.

DB access is SQLAlchemy Core against an injected AsyncEngine (same engine
SessionMemory builds; do NOT use asyncpg directly — see memory/session_memory.py).
"""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict

from sqlalchemy import insert, select

from ai_osop.evidence.migrations import exploit_receipts
from ai_osop.evidence.models import ExploitReceipt


def _canonical_payload(receipt_fields: Dict[str, Any]) -> str:
    return json.dumps(receipt_fields, sort_keys=True, default=str, separators=(",", ":"))


def _sign_receipt_fields(
    signing_key: bytes, prev_hash: str, receipt_fields: Dict[str, Any]
) -> str:
    data = f"{prev_hash}:{_canonical_payload(receipt_fields)}"
    return hmac.new(signing_key, data.encode(), hashlib.sha256).hexdigest()


def _receipt_signing_fields(receipt: "ExploitReceipt") -> Dict[str, Any]:
    """Subset of fields covered by the HMAC chain (tamper-relevant only)."""
    return {
        "receipt_id": receipt.receipt_id,
        "engagement_id": receipt.engagement_id,
        "vuln_id": receipt.vuln_id,
        "approval_id": receipt.approval_id,
        "verdict": receipt.verdict,
        "confidence": receipt.confidence,
        "scope_hash": receipt.scope_hash,
        "oracle_signals": receipt.oracle_signals,
    }


class ReceiptStore:
    """Persists signed exploit receipts.

    `integrity` is an AuditIntegrity instance; we reuse its HMAC signing key but
    maintain a separate per-engagement chain (AuditIntegrity._last_hash is NOT
    shared with the audit ledger).
    """

    def __init__(self, sa_engine, integrity, evidence_root: Path):
        self._engine = sa_engine
        self._integrity = integrity
        self._root = Path(evidence_root)
