"""Tool Effectiveness Tracker (T3.1 + T3.2)

Tracks which tool+target_type+technique combinations historically
produce validated findings. Feeds into task scheduling to prioritize
high-yield combinations and deprioritize low-yield ones.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ai_osop.core.effectiveness_tracker")


@dataclass
class ToolEffectivenessRecord:
    """One execution record for effectiveness tracking."""

    tool_name: str
    target_type: str  # "web", "api", "ssh", "cloud", etc.
    technique: str  # "xss", "sqli", "ssrf", etc.
    engagement_id: str
    timestamp: float = field(default_factory=time.time)
    yielded_finding: bool = False
    finding_validated: bool = False
    finding_rejected: bool = False
    confidence: float = 0.0
    tokens_used: int = 0
    wall_clock_seconds: float = 0.0


@dataclass
class EffectivenessScore:
    """Aggregated effectiveness score for a combination."""

    tool_name: str
    target_type: str
    technique: str
    total_runs: int = 0
    findings_yielded: int = 0
    findings_validated: int = 0
    findings_rejected: int = 0
    avg_confidence: float = 0.0
    avg_tokens: float = 0.0
    yield_rate: float = 0.0
    validation_rate: float = 0.0
    composite_score: float = 0.0

    @property
    def is_high_yield(self) -> bool:
        return self.composite_score >= 0.6

    @property
    def is_low_yield(self) -> bool:
        return self.composite_score < 0.2 and self.total_runs >= 5


class EffectivenessTracker:
    """Tracks and queries tool effectiveness across engagements.

    Persists records in-memory (could be backed by DB for durability).
    Used by the task scheduler to make informed scheduling decisions.
    """

    def __init__(self) -> None:
        self._records: List[ToolEffectivenessRecord] = []
        self._score_cache: Dict[Tuple[str, str, str], EffectivenessScore] = {}
        self._cache_dirty = True

    def record_execution(
        self,
        tool_name: str,
        target_type: str,
        technique: str,
        engagement_id: str,
        yielded_finding: bool = False,
        finding_validated: bool = False,
        finding_rejected: bool = False,
        confidence: float = 0.0,
        tokens_used: int = 0,
        wall_clock_seconds: float = 0.0,
    ) -> None:
        """Record a tool execution result."""
        record = ToolEffectivenessRecord(
            tool_name=tool_name,
            target_type=target_type,
            technique=technique,
            engagement_id=engagement_id,
            yielded_finding=yielded_finding,
            finding_validated=finding_validated,
            finding_rejected=finding_rejected,
            confidence=confidence,
            tokens_used=tokens_used,
            wall_clock_seconds=wall_clock_seconds,
        )
        self._records.append(record)
        self._cache_dirty = True

        # Keep memory bounded
        if len(self._records) > 10000:
            self._records = self._records[-5000:]

    def get_effectiveness(
        self,
        tool_name: str,
        target_type: str,
        technique: str,
    ) -> EffectivenessScore:
        """Get effectiveness score for a specific combination."""
        key = (tool_name, target_type, technique)

        if self._cache_dirty:
            self._rebuild_cache()

        if key in self._score_cache:
            return self._score_cache[key]

        # No data — return neutral score
        return EffectivenessScore(
            tool_name=tool_name,
            target_type=target_type,
            technique=technique,
        )

    def get_recommendations(
        self,
        target_type: str,
        techniques: List[str],
        max_results: int = 5,
    ) -> List[EffectivenessScore]:
        """Get top tool recommendations for a target type and techniques."""
        if self._cache_dirty:
            self._rebuild_cache()

        candidates = []
        for (tool, ttype, tech), score in self._score_cache.items():
            if ttype == target_type and tech in techniques:
                candidates.append(score)

        # Sort by composite score descending
        candidates.sort(key=lambda s: s.composite_score, reverse=True)
        return candidates[:max_results]

    def should_skip_tool(
        self,
        tool_name: str,
        target_type: str,
        technique: str,
        min_runs: int = 5,
    ) -> bool:
        """Check if a tool should be skipped based on historical low yield."""
        score = self.get_effectiveness(tool_name, target_type, technique)
        return score.total_runs >= min_runs and score.is_low_yield

    def get_engagement_summary(self, engagement_id: str) -> Dict[str, Any]:
        """Get effectiveness summary for an engagement."""
        records = [r for r in self._records if r.engagement_id == engagement_id]
        if not records:
            return {"record_count": 0}

        tools = set(r.tool_name for r in records)
        techniques = set(r.technique for r in records)
        validated = sum(1 for r in records if r.finding_validated)

        return {
            "record_count": len(records),
            "unique_tools": len(tools),
            "unique_techniques": len(techniques),
            "validated_findings": validated,
            "overall_yield_rate": validated / len(records) if records else 0,
        }

    def _rebuild_cache(self) -> None:
        """Rebuild the effectiveness score cache."""
        self._score_cache.clear()

        # Group records by (tool, target_type, technique)
        groups: Dict[Tuple[str, str, str], List[ToolEffectivenessRecord]] = defaultdict(list)
        for record in self._records:
            key = (record.tool_name, record.target_type, record.technique)
            groups[key].append(record)

        for key, records in groups.items():
            total = len(records)
            findings = sum(1 for r in records if r.yielded_finding)
            validated = sum(1 for r in records if r.finding_validated)
            rejected = sum(1 for r in records if r.finding_rejected)
            avg_conf = sum(r.confidence for r in records) / total if total else 0
            avg_tokens = sum(r.tokens_used for r in records) / total if total else 0

            yield_rate = findings / total if total else 0
            validation_rate = validated / findings if findings else 0

            # Composite: yield rate × validation rate × (1 - rejection penalty)
            rejection_penalty = rejected / findings if findings else 0
            composite = yield_rate * validation_rate * (1 - rejection_penalty * 0.5)

            self._score_cache[key] = EffectivenessScore(
                tool_name=key[0],
                target_type=key[1],
                technique=key[2],
                total_runs=total,
                findings_yielded=findings,
                findings_validated=validated,
                findings_rejected=rejected,
                avg_confidence=avg_conf,
                avg_tokens=avg_tokens,
                yield_rate=yield_rate,
                validation_rate=validation_rate,
                composite_score=composite,
            )

        self._cache_dirty = False
