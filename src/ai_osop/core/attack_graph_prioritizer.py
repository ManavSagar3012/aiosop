from typing import Any, Dict

import structlog

from ai_osop.core.models import DiffAuthFinding
from ai_osop.memory.graph_memory import GraphMemory

logger = structlog.get_logger("ai_osop.attack_graph_prioritizer")


class AttackGraphChainPrioritizer:
    """
    Sprint 7: Prioritizes findings based on reachable attack graph paths.
    """

    def __init__(self, graph_memory: GraphMemory):
        self.graph_memory = graph_memory

    async def get_path_impact_score(self, finding_id: str) -> float:
        """
        Query the Neo4j graph for paths from this finding to critical assets.
        Returns a score from 0.0 to 1.0.
        """
        # Find paths from finding -> vulnerability -> critical assets
        cypher = """
        MATCH (d:DiffAuthFinding {id: $finding_id})-[:HAS_DIFF_AUTH_FINDING]-(v:Vulnerability)
        MATCH path = (v)-[:LEADS_TO*1..5]->(target:Asset)
        WHERE target.criticality = 'high'
        RETURN count(path) as path_count, max(length(path)) as max_depth
        """
        records = await self.graph_memory.run_read_query(cypher, {"finding_id": finding_id})
        if not records:
            return 0.1  # Baseline low impact
        record = records[0]
        logger.debug("path_impact_record", record=record)
        path_count = record.get("path_count", 0)
        if path_count == 0:
            return 0.1
        max_depth = record.get("max_depth", 1)
        return min(1.0, (path_count * 0.1) + (1.0 / (max_depth + 1)))

    async def prioritize_finding(self, finding: DiffAuthFinding) -> Dict[str, Any]:
        """Compute the prioritized risk score."""
        path_impact = await self.get_path_impact_score(finding.id)

        # Combine confidence, business impact, and path impact
        final_priority = "medium"
        if path_impact > 0.7 or finding.confidence > 0.9:
            final_priority = "critical"
        elif path_impact > 0.4:
            final_priority = "high"

        return {
            "finding_id": finding.id,
            "path_impact": round(path_impact, 2),
            "priority": final_priority,
        }
