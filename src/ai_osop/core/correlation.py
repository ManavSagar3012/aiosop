"""
V4.1 Event Correlation Engine
Correlates observations across agents and building higher-level evidence chains.
"""

from typing import List

from ai_osop.core.models import Observation
from ai_osop.memory.session_memory import SessionMemory


class CorrelationEngine:
    """
    Reactive engine that correlates disparate observations.
    """

    def __init__(self, session_memory: SessionMemory):
        self.session_memory = session_memory

    async def correlate(self, observation: Observation) -> List[str]:
        """
        Analyze a new observation and find related existing ones.
        Returns a list of correlated observation IDs.
        """
        correlated_ids = []

        # 1. Direct Target Correlation (same endpoint/asset)
        # In a real implementation, we would query the database for observations
        # with the same target_id within a certain time window.
        # For now, we simulate this or perform simple heuristic matching.

        correlated_observations = await self.session_memory.get_observations_by_target(
            observation.target_id, window_seconds=3600
        )
        correlated_ids = [o.id for o in correlated_observations if o.id != observation.id]

        # 2. Heuristic: Shared Data Keys
        # If two observations share specific metadata (e.g., same IP, same token hash)

        return correlated_ids

    async def process_observation(self, observation: Observation) -> Observation:
        """
        Main entry point for processing and correlating an observation.
        """
        # Find correlations
        correlated_ids = await self.correlate(observation)
        observation.correlated_observation_ids.extend(correlated_ids)

        # Persist to warm storage
        await self.session_memory.add_observation(observation)

        if len(observation.correlated_observation_ids) >= 3:
            await self.session_memory.trigger_escalation(
                observation.engagement_id, "vulnerability_hypothesis"
            )

        return observation
