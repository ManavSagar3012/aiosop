"""Effort Budget Tracker (T2.2)

Tracks how many agent-iterations, LLM tokens, and wall-clock time go
into each finding. High-cost low-confidence findings are flagged for
human review rather than continued burning.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai_osop.core.effort_tracker")


@dataclass
class FindingEffort:
    """Effort tracking for a single finding."""

    finding_id: str
    engagement_id: str
    agent_id: str
    task_id: str
    iterations: int = 0
    tokens_used: int = 0
    tool_calls: int = 0
    wall_clock_seconds: float = 0.0
    llm_calls: int = 0
    tools_used: List[str] = field(default_factory=list)
    confidence_start: float = 0.0
    confidence_current: float = 0.0
    confidence_peak: float = 0.0
    start_time: float = field(default_factory=time.monotonic)
    status: str = "active"  # active, completed, abandoned, flagged

    @property
    def cost_efficiency(self) -> float:
        """Confidence gained per 1000 tokens. Higher is better."""
        if self.tokens_used == 0:
            return 0.0
        delta = self.confidence_current - self.confidence_start
        return (delta / self.tokens_used) * 1000

    @property
    def time_efficiency(self) -> float:
        """Confidence gained per minute. Higher is better."""
        minutes = self.wall_clock_seconds / 60
        if minutes == 0:
            return 0.0
        delta = self.confidence_current - self.confidence_start
        return delta / minutes

    @property
    def is_over_budget(self) -> bool:
        """Check if this finding exceeds effort budgets."""
        return (
            self.iterations > MAX_ITERATIONS
            or self.tokens_used > MAX_TOKENS
            or self.wall_clock_seconds > MAX_WALL_CLOCK
        )

    @property
    def should_flag_for_review(self) -> bool:
        """High cost + low confidence = should be flagged."""
        return (
            self.is_over_budget
            and self.confidence_current < MIN_CONFIDENCE_FOR_AUTO
        )


# Effort budgets
MAX_ITERATIONS = 15
MAX_TOKENS = 50000
MAX_WALL_CLOCK = 300  # 5 minutes
MIN_CONFIDENCE_FOR_AUTO = 0.6


class EffortTracker:
    """Tracks effort budgets across all findings in an engagement."""

    def __init__(self) -> None:
        self._effort: Dict[str, FindingEffort] = {}
        self._engagement_totals: Dict[str, FindingEffort] = {}

    def start_tracking(
        self,
        finding_id: str,
        engagement_id: str,
        agent_id: str,
        task_id: str,
        initial_confidence: float = 0.0,
    ) -> FindingEffort:
        """Start tracking effort for a finding."""
        effort = FindingEffort(
            finding_id=finding_id,
            engagement_id=engagement_id,
            agent_id=agent_id,
            task_id=task_id,
            confidence_start=initial_confidence,
            confidence_current=initial_confidence,
            confidence_peak=initial_confidence,
        )
        self._effort[finding_id] = effort
        return effort

    def record_iteration(
        self,
        finding_id: str,
        tool_name: str,
        tokens: int = 0,
        confidence: float = 0.0,
    ) -> FindingEffort:
        """Record one iteration of work on a finding."""
        effort = self._effort.get(finding_id)
        if not effort:
            return FindingEffort(finding_id=finding_id, engagement_id="", agent_id="", task_id="")

        effort.iterations += 1
        effort.tokens_used += tokens
        effort.tool_calls += 1
        effort.llm_calls += 1
        effort.confidence_current = confidence
        effort.confidence_peak = max(effort.confidence_peak, confidence)
        effort.wall_clock_seconds = time.monotonic() - effort.start_time

        if tool_name not in effort.tools_used:
            effort.tools_used.append(tool_name)

        # Check budget and flag if needed
        if effort.is_over_budget:
            effort.status = "flagged"
            logger.warning(
                "effort_budget_exceeded finding_id=%s iterations=%d tokens=%d wall_clock=%.1f confidence=%.2f",
                finding_id,
                effort.iterations,
                effort.tokens_used,
                effort.wall_clock_seconds,
                confidence,
            )

        return effort

    def complete_tracking(self, finding_id: str, final_confidence: float = 0.0) -> Optional[FindingEffort]:
        """Mark tracking as completed."""
        effort = self._effort.get(finding_id)
        if effort:
            effort.status = "completed"
            effort.confidence_current = final_confidence
            effort.wall_clock_seconds = time.monotonic() - effort.start_time
        return effort

    def abandon_tracking(self, finding_id: str, reason: str = "") -> Optional[FindingEffort]:
        """Mark tracking as abandoned."""
        effort = self._effort.get(finding_id)
        if effort:
            effort.status = "abandoned"
            effort.wall_clock_seconds = time.monotonic() - effort.start_time
            logger.info(
                "effort_abandoned finding_id=%s reason=%s iterations=%d tokens=%d",
                finding_id,
                reason,
                effort.iterations,
                effort.tokens_used,
            )
        return effort

    def get_effort(self, finding_id: str) -> Optional[FindingEffort]:
        """Get effort for a finding."""
        return self._effort.get(finding_id)

    def get_engagement_summary(self, engagement_id: str) -> Dict[str, Any]:
        """Get effort summary for an engagement."""
        findings = [e for e in self._effort.values() if e.engagement_id == engagement_id]
        if not findings:
            return {"finding_count": 0}

        total_tokens = sum(e.tokens_used for e in findings)
        total_iterations = sum(e.iterations for e in findings)
        total_time = sum(e.wall_clock_seconds for e in findings)
        flagged = [e for e in findings if e.status == "flagged"]
        completed = [e for e in findings if e.status == "completed"]

        return {
            "finding_count": len(findings),
            "total_tokens": total_tokens,
            "total_iterations": total_iterations,
            "total_wall_clock_seconds": total_time,
            "flagged_count": len(flagged),
            "completed_count": len(completed),
            "avg_cost_efficiency": (
                sum(e.cost_efficiency for e in completed) / len(completed)
                if completed else 0.0
            ),
            "most_expensive_finding": (
                max(findings, key=lambda e: e.tokens_used).finding_id
                if findings else None
            ),
        }

    def get_flagged_findings(self, engagement_id: str) -> List[FindingEffort]:
        """Get all findings flagged for human review."""
        return [
            e for e in self._effort.values()
            if e.engagement_id == engagement_id and e.status == "flagged"
        ]
