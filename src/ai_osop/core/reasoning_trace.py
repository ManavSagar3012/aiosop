"""Reasoning Trace — explainable cognition for the reasoning loop.

The assessment's next maturity level: 'Can it explain why it abandoned
one hypothesis in favor of another?' 'Can independent experts understand
and reproduce its reasoning process?'

This module records every decision the reasoning loop makes as a
structured trace entry:
  - What hypothesis was selected and WHY (confidence, novelty, prior)
  - What action was dispatched and WHY (task type, target, rationale)
  - What the result was (confirmed, refuted, inconclusive)
  - What follow-up was generated and WHY (chain, dead-end recovery, pivot)
  - What the system learned (new finding, new endpoint, new technique)

The trace is queryable so an operator (or the CriticAgent) can ask:
  'Why did you test endpoint X instead of endpoint Y?'
  'Why did you abandon the SQLi hypothesis?'
  'What did you learn from the SSRF confirmation?'

This is the 'self-evaluation' + 'explainability' cognitive capability
the assessment says is missing — the system can now introspect on and
explain its own reasoning process.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TraceEntry:
    """One step in the reasoning trace."""
    timestamp: str = ""
    engagement_id: str = ""
    step: str = ""  # observe, orient, hypothesize, select, dispatch, evaluate, critique, learn, pivot
    decision: str = ""  # what was decided
    rationale: str = ""  # WHY this decision was made
    hypothesis_id: str = ""
    task_id: str = ""
    result: str = ""  # confirmed, refuted, inconclusive, dispatched, skipped
    confidence: float = 0.0
    alternatives_considered: List[str] = field(default_factory=list)
    alternatives_rejected: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "engagement_id": self.engagement_id,
            "step": self.step,
            "decision": self.decision,
            "rationale": self.rationale,
            "hypothesis_id": self.hypothesis_id,
            "task_id": self.task_id,
            "result": self.result,
            "confidence": self.confidence,
            "alternatives_considered": self.alternatives_considered,
            "alternatives_rejected": self.alternatives_rejected,
            "metadata": self.metadata,
        }


class ReasoningTrace:
    """Records and queries the reasoning trace for an engagement.

    Maintains an in-memory trace of every decision the reasoning loop
    makes. The trace is queryable by step type, hypothesis id, or result,
    enabling explainability and self-evaluation.

    The trace is also published as reasoning.trace events on the
    coordination bus so the dashboard + CriticAgent can observe the
    reasoning process in real time.
    """

    def __init__(self):
        self._entries: List[TraceEntry] = []
        self._by_hypothesis: Dict[str, List[TraceEntry]] = {}

    def record(
        self,
        engagement_id: str,
        step: str,
        decision: str,
        rationale: str = "",
        hypothesis_id: str = "",
        task_id: str = "",
        result: str = "",
        confidence: float = 0.0,
        alternatives_considered: Optional[List[str]] = None,
        alternatives_rejected: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TraceEntry:
        """Record a reasoning step in the trace."""
        entry = TraceEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            engagement_id=engagement_id,
            step=step,
            decision=decision,
            rationale=rationale,
            hypothesis_id=hypothesis_id,
            task_id=task_id,
            result=result,
            confidence=confidence,
            alternatives_considered=alternatives_considered or [],
            alternatives_rejected=alternatives_rejected or [],
            metadata=metadata or {},
        )
        self._entries.append(entry)
        if hypothesis_id:
            self._by_hypothesis.setdefault(hypothesis_id, []).append(entry)
        logger.info(
            "reasoning_trace",
            engagement_id=engagement_id,
            step=step,
            decision=decision[:100],
            rationale=rationale[:100],
            result=result,
            confidence=confidence,
        )
        return entry

    def get_trace(self, engagement_id: str = "", *aliases: str) -> List[Dict[str, Any]]:
        """Get the full reasoning trace for an engagement.

        Matches any provided id form (session_id / scope.engagement_id) — same
        split-brain fix as GraphMemory.get_vulnerabilities_by_engagement
        (AIOSOP-FINDINGS-KEY). Entries are recorded under whichever id the
        reasoning loop was passed, which isn't always the same form the API
        caller queries with.
        """
        ids = {i for i in (engagement_id, *aliases) if i}
        if ids:
            return [e.to_dict() for e in self._entries if e.engagement_id in ids]
        return [e.to_dict() for e in self._entries]

    def get_hypothesis_trace(self, hypothesis_id: str) -> List[Dict[str, Any]]:
        """Get the reasoning trace for a specific hypothesis.

        Answers: 'Why did you test this hypothesis? What happened? What
        did you do next?'
        """
        return [e.to_dict() for e in self._by_hypothesis.get(hypothesis_id, [])]

    def get_abandoned_hypotheses(self, engagement_id: str = "") -> List[Dict[str, Any]]:
        """Get all hypotheses that were abandoned (refuted or inconclusive).

        Answers: 'Why did you abandon this hypothesis?'
        """
        return [
            e.to_dict() for e in self._entries
            if e.result in ("refuted", "inconclusive")
            and (not engagement_id or e.engagement_id == engagement_id)
        ]

    def get_confirmed_hypotheses(self, engagement_id: str = "") -> List[Dict[str, Any]]:
        """Get all confirmed hypotheses with their rationale."""
        return [
            e.to_dict() for e in self._entries
            if e.result == "confirmed"
            and (not engagement_id or e.engagement_id == engagement_id)
        ]

    def explain_decision(self, hypothesis_id: str) -> str:
        """Generate a human-readable explanation of the reasoning for a hypothesis.

        Answers: 'Why did you test this? Why did you abandon/confirm it?
        What did you learn?'
        """
        trace = self._by_hypothesis.get(hypothesis_id, [])
        if not trace:
            return f"No reasoning trace found for hypothesis {hypothesis_id}."

        lines = [f"=== Reasoning trace for hypothesis {hypothesis_id} ==="]
        for entry in trace:
            lines.append(f"\n[{entry.timestamp}] {entry.step.upper()}")
            lines.append(f"  Decision: {entry.decision}")
            if entry.rationale:
                lines.append(f"  Rationale: {entry.rationale}")
            if entry.result:
                lines.append(f"  Result: {entry.result}")
            if entry.confidence:
                lines.append(f"  Confidence: {entry.confidence:.2f}")
            if entry.alternatives_rejected:
                lines.append(f"  Rejected alternatives: {', '.join(entry.alternatives_rejected)}")

        return "\n".join(lines)

    def get_summary(self, engagement_id: str = "", *aliases: str) -> Dict[str, Any]:
        """Get a summary of the reasoning process for an engagement.

        Matches any provided id form (session_id / scope.engagement_id) — same
        split-brain fix as get_trace (AIOSOP-FINDINGS-KEY).
        """
        ids = {i for i in (engagement_id, *aliases) if i}
        entries = [e for e in self._entries if not ids or e.engagement_id in ids]
        return {
            "total_steps": len(entries),
            "hypotheses_selected": len([e for e in entries if e.step == "select"]),
            "hypotheses_confirmed": len([e for e in entries if e.result == "confirmed"]),
            "hypotheses_refuted": len([e for e in entries if e.result == "refuted"]),
            "hypotheses_inconclusive": len([e for e in entries if e.result == "inconclusive"]),
            "chains_generated": len([e for e in entries if e.step == "chain"]),
            "pivots": len([e for e in entries if e.step == "pivot"]),
            "dead_ends": len([e for e in entries if e.step == "deadend"]),
            "critique_issues": len([e for e in entries if e.step == "critique"]),
        }

    def clear(self, engagement_id: str = "") -> None:
        """Clear the trace for an engagement (or all if empty)."""
        if engagement_id:
            self._entries = [e for e in self._entries if e.engagement_id != engagement_id]
            self._by_hypothesis = {
                k: [e for e in v if e.engagement_id != engagement_id]
                for k, v in self._by_hypothesis.items()
            }
        else:
            self._entries.clear()
            self._by_hypothesis.clear()
