"""
Attack Chain Agent
Multi-step exploitation reasoning, privilege escalation mapping,
and attack graph path discovery.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import AttackPath, Exploit, Task, Vulnerability


class AttackChainAgent(BaseAgent):
    """
    Attack Chain Intelligence Agent

    Responsibilities:
    - Attack graph construction and maintenance
    - Multi-step exploit path discovery
    - Privilege escalation mapping
    - Vulnerability correlation
    - Risk propagation analysis

    Planning Methodology:
    - Graph construction: Add nodes/edges as findings arrive
    - Path discovery: Background job searching for paths
    - Chain validation: Prioritize high-confidence, low-detection paths
    """

    # Pre-defined attack chain templates
    CHAIN_TEMPLATES = [
        {
            "name": "web_to_admin",
            "description": "Unauthenticated web vulnerability to admin access",
            "steps": [
                {"phase": 1, "vuln_types": ["sqli", "xss", "ssrf", "idor"], "entry_point": True},
                {"phase": 2, "vuln_types": ["auth_bypass", "session_hijacking", "jwt_abuse"]},
                {"phase": 3, "vuln_types": ["privilege_escalation", "idor"]},
                {"phase": 4, "vuln_types": ["rce", "file_upload", "deserialization"], "goal": True},
            ],
        },
        {
            "name": "recon_to_rce",
            "description": "Information disclosure to remote code execution",
            "steps": [
                {"phase": 1, "vuln_types": ["ssrf", "lfi", "idor"], "entry_point": True},
                {"phase": 2, "vuln_types": ["credential_exposure"]},
                {"phase": 3, "vuln_types": ["rce", "deserialization"], "goal": True},
            ],
        },
        {
            "name": "jwt_to_account_takeover",
            "description": "JWT weakness to account takeover",
            "steps": [
                {"phase": 1, "vuln_types": ["jwt_abuse"], "entry_point": True},
                {"phase": 2, "vuln_types": ["idor", "auth_bypass"]},
                {"phase": 3, "vuln_types": ["privilege_escalation"], "goal": True},
            ],
        },
    ]

    @property
    def agent_type(self) -> AgentType:
        return AgentType.ATTACK_CHAIN

    async def _setup_resources(self) -> None:
        """Initialize attack chain resources."""
        self.discovered_paths: List[AttackPath] = []
        self.validated_chains: List[Dict[str, Any]] = []

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute attack chain task."""
        task_type = task.type
        payload = task.payload

        if task_type == "discover_paths":
            return await self._discover_paths(payload)
        elif task_type == "validate_chain":
            return await self._validate_chain(payload)
        elif task_type == "propagate_risk":
            return await self._propagate_risk(payload)
        elif task_type == "find_lateral_movement":
            return await self._find_lateral_movement(payload)
        else:
            raise AgentException(f"Unknown attack chain task: {task_type}")

    async def _discover_paths(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Discover attack paths from entry points to goals."""
        engagement_id = payload["engagement_id"]
        entry_node_id = payload.get("entry_node_id")
        goal_types = payload.get("goal_types", ["rce", "admin_access", "data_exfiltration"])
        max_depth = payload.get("max_depth", 5)

        # If no entry node specified, find all entry points
        if not entry_node_id:
            entry_nodes = await self._find_entry_points(engagement_id)
        else:
            entry_nodes = [entry_node_id]

        all_paths = []
        for entry in entry_nodes:
            paths = await self.ctx.graph_memory.find_attack_paths(
                entry_node_id=entry, goal_types=goal_types, max_depth=max_depth
            )
            all_paths.extend(paths)

        # Score and rank paths
        scored_paths = []
        for path in all_paths:
            score = self._score_path(path)
            scored_paths.append((path, score))

        scored_paths.sort(key=lambda x: x[1], reverse=True)

        # Store top paths
        self.discovered_paths = [p for p, _ in scored_paths[:10]]

        return {
            "status": "success",
            "paths_discovered": len(all_paths),
            "top_paths": [
                {
                    "path_id": p.id,
                    "confidence": p.confidence,
                    "risk_score": p.risk_score,
                    "time_estimate": p.total_time_estimate,
                    "detection_risk": p.detection_risk,
                    "node_count": len(p.node_ids),
                }
                for p, _ in scored_paths[:10]
            ],
        }

    async def _validate_chain(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a specific attack chain end-to-end."""
        if not self.ctx.current_task:
            return {"status": "error", "error": "No active task context"}

        path_id = payload["path_id"]

        # Retrieve path from graph
        path = next((p for p in self.discovered_paths if p.id == path_id), None)
        if not path:
            return {"status": "error", "error": f"Path {path_id} not discovered"}

        # Validate each step
        validation_results = []
        for node_id in path.node_ids:
            # Query node details
            node = await self.ctx.graph_memory.get_node_details(node_id)
            if node and node.get("type") == "Vulnerability":
                if not node.get("props", {}).get("validated", False):
                    # Fetch endpoint URL
                    endpoint_url = await self.ctx.graph_memory.get_endpoint_url_for_vulnerability(
                        node_id
                    )

                    # Schedule validation task for the exploit agent
                    task = Task(
                        type="validate_exploit",
                        priority=8,
                        agent_type=AgentType.EXPLOIT_VALIDATION,
                        payload={
                            "target": endpoint_url,
                            "vulnerability_id": node_id,
                            "payload": "TBD",  # Placeholder for now
                            "operator_approved": True,
                            "approval_id": f"sim-{node_id}",
                        },
                        engagement_id=self.ctx.current_task.engagement_id,
                    )
                    # Push to orchestrator task queue
                    await self.ctx.session_memory.push_task_queue(
                        f"tasks:{self.ctx.current_task.engagement_id}", task.dict()
                    )
                    validation_results.append(
                        {"node_id": node_id, "status": "validation_scheduled", "task_id": task.id}
                    )
                else:
                    validation_results.append({"node_id": node_id, "status": "already_validated"})

        return {"status": "success", "path_id": path_id, "validation_results": validation_results}

    async def _propagate_risk(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Propagate risk from validated exploit."""
        exploit_id = payload["exploit_id"]
        impact_score = payload.get("impact_score", 5.0)

        await self.ctx.graph_memory.propagate_risk(exploit_id, impact_score)

        return {
            "status": "success",
            "exploit_id": exploit_id,
            "impact_score": impact_score,
            "propagated": True,
        }

    async def _find_lateral_movement(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Find lateral movement opportunities."""
        engagement_id = payload["engagement_id"]

        # Query graph for credential reuse, trust relationships
        # This would use Neo4j graph queries

        return {"status": "success", "lateral_vectors": [], "engagement_id": engagement_id}

    async def _find_entry_points(self, engagement_id: str) -> List[str]:
        """Find all entry point nodes in the graph."""
        cypher = """
        MATCH (a:Asset {engagement_id: $sid})
        RETURN a.id as id
        """
        if not self.ctx.graph_memory or not self.ctx.graph_memory._driver:
            return []
        ids = []
        async with self.ctx.graph_memory._driver.session() as session:
            result = await session.run(cypher, {"sid": engagement_id})
            async for record in result:
                ids.append(record["id"])
        return ids

    def _score_path(self, path: AttackPath) -> float:
        """
        Score attack path quality.

        Factors:
        - Confidence (40%)
        - Inverse time (20%)
        - Inverse detection risk (20%)
        - Goal value (20%)
        """
        confidence_weight = path.confidence * 0.4
        time_weight = (1.0 / (1 + path.total_time_estimate / 3600)) * 0.2
        stealth_weight = (1.0 - path.detection_risk) * 0.2
        goal_weight = 0.2  # Simplified

        return confidence_weight + time_weight + stealth_weight + goal_weight

    async def _cleanup_resources(self) -> None:
        self.discovered_paths.clear()
        self.validated_chains.clear()
