from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.models import DiffAuthFinding
from ai_osop.memory.graph_memory import GraphMemory

logger = structlog.get_logger("ai_osop.submission_intelligence")


class SubmissionIntelligenceEngine:
    """
    Sprint 7: Submissions Intelligence Engine.
    Prioritizes findings based on historical acceptance outcomes,
    confidence, and business impact.
    """

    def __init__(self, graph_memory: GraphMemory):
        self.graph_memory = graph_memory

    async def get_historical_outcome_stats(self, category: str) -> Dict[str, int]:
        """Query historical outcome stats for a given finding category."""
        cypher = """
        MATCH (d:DiffAuthFinding {category: $category})
        RETURN d.outcome as outcome, count(d) as count
        """
        records = await self.graph_memory.run_read_query(cypher, {"category": category})
        stats = {"accepted": 0, "duplicate": 0, "informative": 0, "na": 0}
        for record in records:
            outcome = record.get("outcome")
            if outcome in stats:
                stats[outcome] = record.get("count", 0)
        return stats

    async def calculate_acceptance_probability(self, finding: DiffAuthFinding) -> float:
        """Calculate acceptance probability based on historical category performance."""
        stats = await self.get_historical_outcome_stats(finding.category)
        total = sum(stats.values())
        if total == 0:
            return 0.5  # Neutral baseline

        # Bayesian-inspired simple probability
        acceptance_prob = stats.get("accepted", 0) / total

        # Adjust by confidence
        return acceptance_prob * finding.confidence

    async def recommend_submission(self, finding: DiffAuthFinding) -> Dict[str, Any]:
        """Generate a submission recommendation for an operator."""
        prob = await self.calculate_acceptance_probability(finding)

        recommendation = "monitor"
        if prob > 0.7:
            recommendation = "submit"
        elif prob > 0.4:
            recommendation = "verify_manually"

        return {
            "acceptance_probability": round(prob, 2),
            "recommendation": recommendation,
            "priority": "high" if prob > 0.7 else "medium",
        }
