"""ValidationLedger: durable tracking of every finding's journey.

Tracks state transitions (detected -> validated -> manual_review -> escalated ->
chain_executed) so the platform measures its own precision without external ground truth.

Persistence goes through Postgres SessionMemory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from ai_osop.core.exceptions import WorkflowTransitionError

LEGAL_TRANSITIONS = {
    "detected": {"validated", "manual_review", "rejected"},
    "validated": {"chain_executed", "escalated", "manual_review"},
    "manual_review": {"validated", "rejected"},
    "chain_executed": {"successful_chain", "chain_failed"},
    "escalated": {"validated"},
    "chain_failed": {"detected"},
    "successful_chain": set(),
    "rejected": set(),
}


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

    def can_transition(self, from_state: str, to_state: str) -> bool:
        return to_state in LEGAL_TRANSITIONS.get(from_state, set())

    def ensure_transition(self, from_state: str, to_state: str) -> None:
        if not self.can_transition(from_state, to_state):
            raise WorkflowTransitionError(
                f"illegal ledger transition: {from_state} -> {to_state}",
                details={"from_state": from_state, "to_state": to_state},
            )

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
        """Move an event to a new state, enforcing the legal lifecycle funnel."""
        rows = await self.session_mem.run_read(
            f"SELECT state FROM {self.TABLE_NAME} WHERE id = $1", event_id
        )
        if rows and rows[0].get("state"):
            # Enforce the legal funnel against the ledger's current recorded state.
            self.ensure_transition(rows[0]["state"], to_state)
        elif rows:
            # Row exists but state column read back empty — treat as corrupt, keep
            # the audit trail honest by refusing the transition rather than
            # writing an unvalidated state change on top of it.
            raise WorkflowTransitionError(
                "ledger row has no readable state; refusing transition",
                details={"event_id": event_id, "to_state": to_state},
            )
        else:
            # No prior row: only 'detected' is a legal entry point into the funnel
            if to_state != "detected":
                raise WorkflowTransitionError(
                    "first ledger event for a finding must be 'detected'",
                    details={"event_id": event_id, "to_state": to_state},
                )
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
            "states": [(r["state"], r["count"], r["avg_trust"] or 0.0) for r in rows],
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
