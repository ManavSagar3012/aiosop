"""ReceiptStore: persists HMAC-chained ExploitReceipts and artifact blobs.

DB access is SQLAlchemy Core against an injected AsyncEngine (same engine
SessionMemory builds; do NOT use asyncpg directly — see memory/session_memory.py).
"""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import insert, select

from ai_osop.evidence.migrations import exploit_receipts
from ai_osop.evidence.models import ExploitReceipt, ReceiptArtifact


def _canonical_payload(receipt_fields: Dict[str, Any]) -> str:
    return json.dumps(receipt_fields, sort_keys=True, default=str, separators=(",", ":"))


def _sign_receipt_fields(signing_key: bytes, prev_hash: str, receipt_fields: Dict[str, Any]) -> str:
    data = f"{prev_hash}:{_canonical_payload(receipt_fields)}"
    return hmac.new(signing_key, data.encode(), hashlib.sha256).hexdigest()


def _receipt_signing_fields(receipt: "ExploitReceipt") -> Dict[str, Any]:
    """Subset of fields covered by the HMAC chain (tamper-relevant only).

    Timestamps are normalised to ISO strings so that naive-vs-aware datetimes
    round-tripping through ``DateTime(timezone=True)`` columns never break the
    chain.
    """
    ts = receipt.timestamp
    return {
        "receipt_id": receipt.receipt_id,
        "engagement_id": receipt.engagement_id,
        "vuln_id": receipt.vuln_id,
        "approval_id": receipt.approval_id,
        "verdict": receipt.verdict,
        "confidence": receipt.confidence,
        "scope_hash": receipt.scope_hash,
        "oracle_signals": receipt.oracle_signals,
        "hop_idx": receipt.hop_idx,
        "chain_id": receipt.chain_id,
        "confirmation_note": receipt.confirmation_note,
        "request_summary": receipt.request_summary,
        "response_summary": receipt.response_summary,
        "timestamp": ts.isoformat() if ts is not None else "",
        "simulated": receipt.simulated,
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

    def _blob_for_content(self, engagement_id: str, kind: str, content: str) -> "ReceiptArtifact":
        """Redact then persist content; return its content-addressed artifact."""
        from ai_osop.evidence.models import ReceiptArtifact
        from ai_osop.evidence.redaction import redact_text

        scrubbed = redact_text(content)
        digest = hashlib.sha256(scrubbed.encode()).hexdigest()
        artifact_id = f"art-{digest[:12]}"
        rel = Path(engagement_id) / artifact_id
        target = self._root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(scrubbed)
        return ReceiptArtifact(
            artifact_id=artifact_id, kind=kind, sha256=digest, blob_path=str(rel)
        )

    async def record(self, receipt: "ExploitReceipt") -> str:
        prev = await self._last_receipt_hash(receipt.engagement_id)
        sig = _sign_receipt_fields(
            self._integrity.signing_key, prev, _receipt_signing_fields(receipt)
        )
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(exploit_receipts).values(
                    receipt_id=receipt.receipt_id,
                    engagement_id=receipt.engagement_id,
                    vuln_id=receipt.vuln_id,
                    approval_id=receipt.approval_id,
                    hop_idx=receipt.hop_idx,
                    chain_id=receipt.chain_id,
                    verdict=receipt.verdict,
                    confidence=receipt.confidence,
                    confirmation_note=receipt.confirmation_note,
                    oracle_signals=receipt.oracle_signals,
                    artifacts=[a.model_dump(mode="json") for a in receipt.artifacts],
                    request_summary=receipt.request_summary,
                    response_summary=receipt.response_summary,
                    scope_hash=receipt.scope_hash,
                    prev_receipt_hash=prev,
                    integrity_sig=sig,
                    simulated=receipt.simulated,
                    created_at=receipt.timestamp,
                )
            )
        return sig

    async def _last_receipt_hash(self, engagement_id: str) -> str:
        async with self._engine.connect() as conn:
            row = await conn.execute(
                select(exploit_receipts.c.integrity_sig)
                .where(exploit_receipts.c.engagement_id == engagement_id)
                .order_by(exploit_receipts.c.created_at.desc())
                .limit(1)
            )
            val = row.scalar_one_or_none()
        return val or ""

    async def get(self, receipt_id: str) -> "Optional[ExploitReceipt]":
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        select(exploit_receipts).where(exploit_receipts.c.receipt_id == receipt_id)
                    )
                )
                .mappings()
                .first()
            )
        if not row:
            return None
        data = dict(row)
        # Table column is created_at; model field is timestamp.
        data["timestamp"] = data.pop("created_at")
        return ExploitReceipt(**data)

    async def verify_chain(self, engagement_id: str) -> bool:
        async with self._engine.connect() as conn:
            rows = (
                (
                    await conn.execute(
                        select(exploit_receipts)
                        .where(exploit_receipts.c.engagement_id == engagement_id)
                        .order_by(exploit_receipts.c.created_at)
                    )
                )
                .mappings()
                .all()
            )
        prev = ""
        for row in rows:
            payload = {
                "receipt_id": row["receipt_id"],
                "engagement_id": row["engagement_id"],
                "vuln_id": row["vuln_id"],
                "approval_id": row["approval_id"],
                "verdict": row["verdict"],
                "confidence": row["confidence"],
                "scope_hash": row["scope_hash"],
                "oracle_signals": row["oracle_signals"],
                "hop_idx": row["hop_idx"],
                "chain_id": row["chain_id"],
                "confirmation_note": row["confirmation_note"],
                "request_summary": row["request_summary"],
                "response_summary": row["response_summary"],
                "timestamp": row["created_at"].isoformat() if row["created_at"] is not None else "",
                "simulated": row["simulated"],
            }
            if (
                _sign_receipt_fields(self._integrity.signing_key, prev, payload)
                != row["integrity_sig"]
            ):
                return False
            prev = row["integrity_sig"]
        return True

    async def _fetch_where(self, clause) -> "List[ExploitReceipt]":
        async with self._engine.connect() as conn:
            rows = (
                (
                    await conn.execute(
                        select(exploit_receipts)
                        .where(clause)
                        .order_by(exploit_receipts.c.created_at)
                    )
                )
                .mappings()
                .all()
            )
        return [ExploitReceipt(**dict(r)) for r in rows]

    async def for_vulnerability(self, vuln_id: str) -> "List[ExploitReceipt]":
        return await self._fetch_where(exploit_receipts.c.vuln_id == vuln_id)

    async def for_engagement(self, engagement_id: str) -> "List[ExploitReceipt]":
        return await self._fetch_where(exploit_receipts.c.engagement_id == engagement_id)

    async def export_bundle(self, vuln_id: str, redact_secrets: bool = True) -> Dict[str, Any]:
        """Bounty-grade export. Redaction is capture-time; export never re-emits
        originals and never submits — caller hands `markdown` to BugBountyAdapter."""
        receipts = await self.for_vulnerability(vuln_id)
        manifest: List[Dict[str, Any]] = []
        for r in receipts:
            manifest.extend(a.model_dump() for a in r.artifacts)
        markdown = f"## Exploit receipts for {vuln_id}\n\n" + "\n\n".join(
            f"- **{r.receipt_id}** verdict={r.verdict} confidence={r.confidence:.2f} "
            f"note={r.confirmation_note} scope_hash={r.scope_hash}"
            for r in receipts
        )
        return {
            "markdown": markdown,
            "manifest": manifest,
            "receipts": [r.model_dump(mode="json") for r in receipts],
            "receipt_count": len(receipts),
            "submitted": False,
            "redact_secrets": redact_secrets,
        }
