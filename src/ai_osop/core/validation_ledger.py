"""ValidationLedger: durable tracking of every finding's journey.

Tracks state transitions (detected -> validated -> manual_review -> escalated ->
chain_executed) so the platform measures its own precision without external ground truth.

Persistence goes through Postgres SessionMemory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


@dataclass
class ValidatedFindingEvent:
    id: str
    vuln_id: str
    endpoint_id: str
    state: str  # detected | validated | manual_review | escalated | chain_executed | chain_failed
    evidence_summary: str = ""
    trust_score: float = 0.0
    triggered_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ValidationLedger:
    """PostgreSQL-backed running log of every finding's lifecycle and outcomes."""

    TABLE_NAME = "ai_osop_validation_ledger"

    def __init__(self, session_memory: Any):
        self.session_mem = session_memory

    async def initialize(self) -> None:
        """Ensure the table exists with the right schema; no-op if already present."""
        q = f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_NAME} (
                id TEXT PRIMARY KEY,
                vuln_id TEXT NOT NULL,
                endpoint_id TEXT NOT NULL,
                state TEXT NOT NULL,
                evidence_summary TEXT,
                trust_score REAL,
                triggered_at TIMESTAMP DEFAULT NOW(),
                metadata JSONB
            )
        """
        await self.session_mem.run_write(q)

    async def record(self, finding: ValidatedFindingEvent) -> ValidatedFindingEvent:
        q = f"""
            INSERT INTO {self.TABLE_NAME}
            (id, vuln_id, endpoint_id, state, evidence_summary, trust_score, triggered_at, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
        """
        await self.session_mem.run_write(
            q,
            finding.id,
            finding.vuln_id,
            finding.endpoint_id,
            finding.state,
            finding.evidence_summary,
            finding.trust_score,
            finding.triggered_at,
            _jsonb(finding.metadata),
        )
        return finding

    async def transition(self, event_id: str, to_state: str, reason: str = "") -> None:
        """Move an event to a new state and append audit metadata about the change."""
        _meta = {"change_reason": reason, "changed_at": datetime.utcnow().isoformat()}
        q = f"""
            UPDATE {self.TABLE_NAME}
            SET state = $2,
                metadata = metadata || $3::jsonb,
                triggered_at = NOW()
            WHERE id = $1
        """
        await self.session_mem.run_write(
            q,
            event_id,
            to_state,
            _jsonb(_meta),
        )

    async def summarize(
        self, engagement_id: Optional[str] = None, since: Optional[timedelta] = None
    ) -> Dict[str, Any]:
        """Aggregate the ledger into counts by state and trend over time."""
        where = []
        params: list[Any] = []
        if engagement_id:
            where.append("endpoint_id LIKE $1 || '%'")
            params.append(engagement_id)
        if since:
            where.append("triggered_at >= NOW() - $2")
            params.append(since)
        wc = " WHERE " + " AND ".join(where) if where else ""
        q = f"""
            SELECT state,
                   COUNT(*) as count,
                   AVG(trust_score) as avg_trust,
                   array_agg(id) FILTER (WHERE state='manual_review') as suspicious_ids
            FROM {self.TABLE_NAME}
            {wc}
            GROUP BY state
        """
        rows = await self.session_mem.run_read(q, *params)
        return {
            "states": [
                (r["state"], r["count"], r["avg_trust"] or 0.0) for r in rows
            ],
            "needs_review_sample": next(
                (r["suspicious_ids"] for r in rows if r["state"] == "manual_review"), []
            ),
        }


def _jsonb(value: Any) -> str:
    """Serialize to PostgreSQL JSONB string."""
    import json as _json

    if isinstance(value, dict):
        return _json.dumps(value)
    return _json.dumps({"value": value})
