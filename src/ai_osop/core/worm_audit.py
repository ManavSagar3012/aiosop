"""WORM (Write Once Read Many) audit log.

Hash-chained append-only table: each audit entry's `entry_hash` covers its
content plus the previous entry's hash. Edits to history break the chain at the
tampered row, so `verify_chain()` detects rollback/modification without any
external notarization service.

Persistence goes through the existing SessionMemory Postgres layer. This is the
"immutability" piece of Step E — every approval / auth / destructive decision
can now be anchored in a row that cannot be silently rewritten.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

WORM_TABLE = "ai_osop_audit_log_worm"
GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    id: str
    tenant_id: str
    prev_hash: str
    entry_hash: str
    payload: Dict[str, Any]
    created_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
        }


def _canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(
    tenant_id: str, prev_hash: str, payload: Dict[str, Any], created_at: datetime
) -> str:
    """Deterministic SHA-256 over the normalized entry fields."""
    block = "|".join([tenant_id, prev_hash, _canonical_json(payload), created_at.isoformat()])
    return hashlib.sha256(block.encode("utf-8")).hexdigest()


class WormAuditLog:
    """Append-only audit log with a hash chain per tenant."""

    def __init__(self, session_memory: Any):
        self.session_mem = session_memory
        self._mem = session_memory  # test hook for in-memory fakes

    async def initialize(self) -> None:
        q = f"""
            CREATE TABLE IF NOT EXISTS {WORM_TABLE} (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                payload JSONB NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """
        await self.session_mem.run_write(q)

    async def append(
        self,
        payload: Dict[str, Any],
        tenant_id: str = "default",
        entry_id: Optional[str] = None,
    ) -> AuditEntry:
        """Append an audit entry, anchored to the last entry's hash for this tenant."""
        entry_id = entry_id or f"audit-{uuid.uuid4().hex[:12]}"
        created_at = datetime.utcnow()
        prev_hash = await self._last_hash(tenant_id)
        entry_hash = compute_entry_hash(tenant_id, prev_hash, payload, created_at)
        q = f"""
            INSERT INTO {WORM_TABLE}
            (id, tenant_id, prev_hash, entry_hash, payload, created_at)
            VALUES ($1, $2, $3, $4, $5::jsonb, $6)
        """
        await self.session_mem.run_write(
            q, entry_id, tenant_id, prev_hash, entry_hash, _canonical_json(payload), created_at
        )
        return AuditEntry(
            id=entry_id,
            tenant_id=tenant_id,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            payload=payload,
            created_at=created_at,
        )

    async def _last_hash(self, tenant_id: str) -> str:
        q = f"""
            SELECT entry_hash FROM {WORM_TABLE}
            WHERE tenant_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT 1
        """
        rows = await self.session_mem.run_read(q, tenant_id)
        if rows:
            return rows[0]["entry_hash"]
        return GENESIS_HASH

    async def read_chain(self, tenant_id: str) -> List[Dict[str, Any]]:
        q = f"""
            SELECT id, tenant_id, prev_hash, entry_hash, payload, created_at
            FROM {WORM_TABLE}
            WHERE tenant_id = $1
            ORDER BY created_at ASC, id ASC
        """
        return await self.session_mem.run_read(q, tenant_id)

    async def verify_chain(self, tenant_id: Optional[str] = None) -> bool:
        """Recompute the chain for a tenant; return False on any inconsistency."""
        q_all = f"""
            SELECT id, tenant_id, prev_hash, entry_hash, payload, created_at
            FROM {WORM_TABLE}
            {"WHERE tenant_id = $1" if tenant_id else ""}
            ORDER BY tenant_id, created_at ASC, id ASC
        """
        rows = (
            await self.session_mem.run_read(q_all, tenant_id)
            if tenant_id
            else await self.session_mem.run_read(q_all)
        )
        # Group by tenant, verify each chain in order
        by_tenant: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            by_tenant.setdefault(r["tenant_id"], []).append(r)
        for _tenant, chain_rows in by_tenant.items():
            expected_prev = GENESIS_HASH
            for r in chain_rows:
                if r["prev_hash"] != expected_prev:
                    return False
                payload = r["payload"]
                if isinstance(payload, str):
                    payload = json.loads(payload)
                created_at = r["created_at"]
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                recomputed = compute_entry_hash(r["tenant_id"], r["prev_hash"], payload, created_at)
                if recomputed != r["entry_hash"]:
                    return False
                expected_prev = r["entry_hash"]
        return True
