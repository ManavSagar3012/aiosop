"""Findings Ledger (2026-08-29) — pipeline visibility.

The "0 findings" problem is a black box: an engagement can run recon -> scan ->
exploit and produce nothing, with no record of WHY. This ledger makes the
findings funnel explicit by recording every lifecycle transition a finding
undergoes, with the reason:

    proposed -> validated | rejected | inconclusive   (ValidationEngine)
              -> emitted | escalated | dropped | needs_poc   (TriagerGate)
              -> persisted (Vulnerability node)

Components write to it via the module-level singleton (same pattern as
playbook_registry) so ValidationEngine / TriagerGate / base.py need no coupling
to the orchestrator. A router endpoint + the dashboard can read the funnel.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FindingLedgerEntry:
    """One recorded transition in a finding's lifecycle."""

    event_id: str = field(default_factory=lambda: f"fl-{uuid.uuid4().hex[:10]}")
    engagement_id: str = ""
    finding_id: str = ""  # CandidateVulnerability id / Vulnerability id
    finding_title: str = ""
    stage: str = ""  # proposed | validated | triaged | persisted
    status: str = ""  # PROPOSED | VALIDATED | REJECTED | INCONCLUSIVE | EMIT | ESCALATE | DROP | NEEDS_POC | PERSISTED
    reason: str = ""  # human-readable: why this transition
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    actor: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FindingsLedger:
    """Append-only record of every finding lifecycle transition."""

    def __init__(self) -> None:
        self._entries: List[FindingLedgerEntry] = []
        self._max_entries = 20000

    def record(
        self,
        engagement_id: str,
        finding_id: str,
        stage: str,
        status: str,
        reason: str = "",
        finding_title: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        actor: str = "system",
    ) -> FindingLedgerEntry:
        """Append one transition record. Bounded in memory (oldest dropped)."""
        entry = FindingLedgerEntry(
            engagement_id=engagement_id,
            finding_id=finding_id,
            finding_title=finding_title,
            stage=stage,
            status=status,
            reason=reason,
            evidence=evidence or {},
            actor=actor,
        )
        self._entries.append(entry)
        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries :]
        return entry

    def funnel_for(self, engagement_id: str) -> Dict[str, Any]:
        """Aggregate the funnel for one engagement: counts per stage/status.

        This is the visibility primitive: how many findings were proposed,
        how many survived validation, how many were emitted, how many rejected
        and with what top reasons.
        """
        by_status: Dict[str, int] = {}
        reasons: Dict[str, int] = {}
        for e in self._entries:
            if e.engagement_id != engagement_id:
                continue
            by_status[e.status] = by_status.get(e.status, 0) + 1
            if e.reason:
                reasons[e.reason] = reasons.get(e.reason, 0) + 1

        return {
            "engagement_id": engagement_id,
            "total_transitions": sum(by_status.values()),
            "by_status": by_status,
            "top_reasons": sorted(reasons.items(), key=lambda kv: kv[1], reverse=True)[:10],
        }

    def entries_for(self, engagement_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        return [
            e.to_dict()
            for e in self._entries
            if e.engagement_id == engagement_id
        ][-limit:]

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


# Global singleton (same pattern as playbook_registry) so the validation engine,
# triager gate, and agent loop can all write without coupling.
_ledger: Optional[FindingsLedger] = None


def get_findings_ledger() -> FindingsLedger:
    global _ledger
    if _ledger is None:
        _ledger = FindingsLedger()
    return _ledger


def record_finding_event(
    engagement_id: str,
    finding_id: str,
    stage: str,
    status: str,
    reason: str = "",
    finding_title: str = "",
    evidence: Optional[Dict[str, Any]] = None,
    actor: str = "system",
) -> FindingLedgerEntry:
    """Convenience wrapper: record a finding lifecycle event."""
    return get_findings_ledger().record(
        engagement_id=engagement_id,
        finding_id=finding_id,
        stage=stage,
        status=status,
        reason=reason,
        finding_title=finding_title,
        evidence=evidence,
        actor=actor,
    )
