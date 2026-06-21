"""
V4.2B Uncertainty Engine
Identifies knowledge gaps, blocked execution paths, and latent boundaries in the mission.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.core.models import Observation, Task, UncertaintyRecord
from ai_osop.memory.graph_memory import GraphMemory

logger = logging.getLogger(__name__)


class UncertaintyEngine:
    """
    Analyzes the attack graph and task results to identify where the AI is stuck.
    """

    def __init__(self, graph_memory: GraphMemory):
        self.graph_memory = graph_memory

    async def analyze_mission_gaps(self, engagement_id: str) -> List[UncertaintyRecord]:
        """
        Scan the engagement for knowledge gaps.

        Indicators of uncertainty:
        1. High-value endpoints with 0 successful transitions.
        2. Repeated 403/401 errors on the same path.
        3. "Unknown" nodes in the attack graph.
        4. Tasks that timed out or failed with 'ambiguous' reasons.
        """
        records = []

        # 1. Identify Blocked Paths (Repeated Auth Failures)
        blocked_paths = await self._identify_blocked_paths(engagement_id)
        for path, count in blocked_paths.items():
            if count >= 3:  # Threshold for uncertainty
                records.append(
                    UncertaintyRecord(
                        target_id=path,
                        knowns=["Path discovered", f"Attempted {count} times"],
                        unknowns=["Authentication scheme", "Session requirements"],
                        blocked_paths=[path],
                        engagement_id=engagement_id,
                    )
                )

        # 2. Identify Knowledge Boundaries (Unknown tech stacks)
        unknown_stacks = await self._identify_unknown_tech(engagement_id)
        for stack in unknown_stacks:
            records.append(
                UncertaintyRecord(
                    target_id=stack["target"],
                    knowns=["Port open", "Banner captured"],
                    unknowns=[f"Version of {stack['name']}", "Exploitability"],
                    blocked_paths=[],
                    engagement_id=engagement_id,
                )
            )

        return records

    async def _identify_blocked_paths(self, engagement_id: str) -> Dict[str, int]:
        """Query graph for paths with high failure rates."""
        # Simulated query result
        # In production, this runs a Cypher query for nodes with high error-to-success ratio
        return {"/admin/billing": 5, "/api/v1/internal/debug": 3}

    async def _identify_unknown_tech(self, engagement_id: str) -> List[Dict[str, str]]:
        """Query graph for nodes with 'unknown' tech properties."""
        return [
            {"target": "10.0.1.50:8080", "name": "Custom-Binary-Protocol"},
            {"target": "billing.target.com", "name": "MFA-Gateway"},
        ]

    def record_task_uncertainty(self, task: Task, error: str) -> Optional[UncertaintyRecord]:
        """Generate a record if a task fails due to lack of knowledge."""
        ambiguous_keywords = [
            "unknown",
            "ambiguous",
            "not found",
            "access denied",
            "blocked",
            "timeout",
        ]

        if any(kw in error.lower() for kw in ambiguous_keywords):
            return UncertaintyRecord(
                target_id=str(task.payload.get("url", task.type)),
                knowns=[f"Task {task.id} started", f"Action: {task.type}"],
                unknowns=[f"Reason for failure: {error}"],
                blocked_paths=[str(task.payload.get("url", ""))] if "url" in task.payload else [],
                engagement_id=task.engagement_id,
            )
        return None
