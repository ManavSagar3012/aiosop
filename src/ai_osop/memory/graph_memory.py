"""
Graph Memory Layer (Neo4j)
Attack graph construction, pathfinding, and risk propagation.
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.graph import Node, Path, Relationship

from ai_osop.core.config import settings
from ai_osop.core.exceptions import GraphQueryError, MemoryException
from ai_osop.core.models import Asset, AttackPath, Endpoint, Exploit, Payload, Vulnerability


class GraphMemory:
    """
    Neo4j-backed attack graph with offensive security schema.

    Schema:
    - (:Asset)-[:HAS_ENDPOINT]->(:Endpoint)
    - (:Endpoint)-[:HAS_VULNERABILITY]->(:Vulnerability)
    - (:Vulnerability)-[:EXPLOITED_BY]->(:Exploit)
    - (:Exploit)-[:USES_PAYLOAD]->(:Payload)
    - (:Vulnerability)-[:LEADS_TO]->(:Vulnerability)
    - (:Asset)-[:DEPENDS_ON]->(:Asset)
    - (:Identity)-[:CAN_ACCESS]->(:Endpoint)
    - (:Exploit)-[:ESCALATES_TO]->(:Identity)
    """

    def __init__(self):
        self._driver: Optional[AsyncDriver] = None
        self._initialized = False

    async def connect(self) -> None:
        """Initialize Neo4j connection."""
        self._driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
        )
        # Verify connectivity
        await self._driver.verify_connectivity()
        self._initialized = True

        # Create indexes and constraints
        await self._setup_schema()

    async def _setup_schema(self) -> None:
        """Create indexes and constraints for performance."""
        constraints = [
            "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT exploit_id IF NOT EXISTS FOR (x:Exploit) REQUIRE x.id IS UNIQUE",
            "CREATE CONSTRAINT payload_id IF NOT EXISTS FOR (p:Payload) REQUIRE p.id IS UNIQUE",
        ]

        indexes = [
            "CREATE INDEX asset_type_value IF NOT EXISTS FOR (a:Asset) ON (a.type, a.value)",
            "CREATE INDEX endpoint_url IF NOT EXISTS FOR (e:Endpoint) ON (e.url)",
            "CREATE INDEX vuln_type_confidence IF NOT EXISTS FOR (v:Vulnerability) ON (v.vuln_type, v.confidence)",
            "CREATE INDEX exploit_timestamp IF NOT EXISTS FOR (x:Exploit) ON (x.timestamp)",
        ]

        async with self._driver.session() as session:
            for cypher in constraints + indexes:
                try:
                    await session.run(cypher)
                except Exception:
                    pass  # Constraint/index may already exist

    async def add_asset(self, asset: Asset) -> str:
        """Add or update an Asset node."""
        cypher = """
        MERGE (a:Asset {id: $id})
        SET a.type = $type,
            a.value = $value,
            a.source = $source,
            a.confidence = $confidence,
            a.metadata = $metadata,
            a.first_seen = CASE WHEN a.first_seen IS NULL THEN $first_seen ELSE a.first_seen END,
            a.last_seen = $last_seen,
            a.engagement_id = $engagement_id
        RETURN a.id
        """

        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": asset.id,
                    "type": asset.type,
                    "value": asset.value,
                    "source": asset.source,
                    "confidence": asset.confidence,
                    "metadata": json.dumps(asset.metadata),
                    "first_seen": asset.first_seen.isoformat(),
                    "last_seen": asset.last_seen.isoformat(),
                    "engagement_id": asset.engagement_id,
                },
            )
            record = await result.single()
            return record["a.id"]

    async def add_endpoint(self, endpoint: Endpoint) -> str:
        """Add an Endpoint and link to its Asset."""
        cypher = """
        MERGE (e:Endpoint {id: $id})
        SET e.url = $url,
            e.method = $method,
            e.status_code = $status_code,
            e.title = $title,
            e.technologies = $technologies,
            e.parameters = $parameters,
            e.auth_required = $auth_required,
            e.source = $source,
            e.confidence = $confidence,
            e.engagement_id = $engagement_id,
            e.screenshot_path = $screenshot_path
        WITH e
        MATCH (a:Asset {id: $asset_id})
        MERGE (a)-[:HAS_ENDPOINT]->(e)
        RETURN e.id
        """

        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": endpoint.id,
                    "url": endpoint.url,
                    "method": endpoint.method,
                    "status_code": endpoint.status_code,
                    "title": endpoint.title,
                    "technologies": endpoint.technologies,
                    "parameters": endpoint.parameters,
                    "auth_required": endpoint.auth_required,
                    "source": endpoint.source,
                    "confidence": endpoint.confidence,
                    "engagement_id": endpoint.engagement_id,
                    "screenshot_path": endpoint.screenshot_path,
                    "asset_id": endpoint.asset_id,
                },
            )
            record = await result.single()
            return record["e.id"]

    async def add_vulnerability(self, vuln: Vulnerability) -> str:
        """Add a Vulnerability and link to its Endpoint."""
        cypher = """
        MERGE (v:Vulnerability {id: $id})
        SET v.cwe = $cwe,
            v.vuln_type = $vuln_type,
            v.severity = $severity,
            v.cvss_score = $cvss_score,
            v.title = $title,
            v.description = $description,
            v.evidence = $evidence,
            v.tool_source = $tool_source,
            v.confidence = $confidence,
            v.entry_point = $entry_point,
            v.requires_auth = $requires_auth,
            v.validated = $validated,
            v.exploitability = $exploitability,
            v.impact = $impact,
            v.endpoint_id = $endpoint_id,
            v.engagement_id = $engagement_id,
            v.created_at = $created_at
        WITH v
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_VULNERABILITY]->(v)
        )
        RETURN v.id
        """

        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": vuln.id,
                    "cwe": vuln.cwe,
                    "vuln_type": vuln.vuln_type.value,
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "title": vuln.title,
                    "description": vuln.description,
                    "evidence": json.dumps(vuln.evidence, default=str),
                    "tool_source": vuln.tool_source,
                    "confidence": vuln.confidence,
                    "entry_point": vuln.entry_point,
                    "requires_auth": vuln.requires_auth,
                    "validated": vuln.validated,
                    "exploitability": vuln.exploitability,
                    "impact": vuln.impact,
                    "engagement_id": vuln.engagement_id,
                    "created_at": vuln.created_at.isoformat(),
                    "endpoint_id": vuln.endpoint_id,
                },
            )
            record = await result.single()
            return record["v.id"]

    async def add_exploit(self, exploit: Exploit) -> str:
        """Add an Exploit and link to Vulnerability and Payload."""
        cypher = """
        MERGE (x:Exploit {id: $id})
        SET x.type = $type,
            x.validated = $validated,
            x.operator_approved = $operator_approved,
            x.approval_id = $approval_id,
            x.evidence_path = $evidence_path,
            x.timestamp = $timestamp,
            x.time_to_exploit = $time_to_exploit,
            x.impact_confirmed = $impact_confirmed,
            x.engagement_id = $engagement_id
        WITH x
        MATCH (v:Vulnerability {id: $vuln_id})
        MATCH (p:Payload {id: $payload_id})
        MERGE (v)-[:EXPLOITED_BY]->(x)
        MERGE (x)-[:USES_PAYLOAD]->(p)
        RETURN x.id
        """

        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": exploit.id,
                    "type": exploit.type,
                    "validated": exploit.validated,
                    "operator_approved": exploit.operator_approved,
                    "approval_id": exploit.approval_id,
                    "evidence_path": exploit.evidence_path,
                    "timestamp": exploit.timestamp.isoformat(),
                    "time_to_exploit": exploit.time_to_exploit,
                    "impact_confirmed": exploit.impact_confirmed,
                    "engagement_id": exploit.engagement_id,
                    "vuln_id": exploit.vuln_id,
                    "payload_id": exploit.payload_id,
                },
            )
            record = await result.single()
            return record["x.id"]

    async def add_attack_path(self, path: AttackPath) -> str:
        """Add an attack path with its nodes and edges."""
        # Create LEADS_TO relationships between consecutive nodes
        cypher = """
        UNWIND $edges as edge
        MATCH (from {id: edge.from_id})
        MATCH (to {id: edge.to_id})
        MERGE (from)-[r:LEADS_TO]->(to)
        SET r.type = edge.type,
            r.probability = edge.probability,
            r.time_estimate = edge.time_estimate,
            r.detection_risk = edge.detection_risk
        """

        edges = []
        for i in range(len(path.node_ids) - 1):
            edges.append(
                {
                    "from_id": path.node_ids[i],
                    "to_id": path.node_ids[i + 1],
                    "type": "exploit_chain",
                    "probability": path.confidence,
                    "time_estimate": path.total_time_estimate // max(len(path.node_ids) - 1, 1),
                    "detection_risk": path.detection_risk,
                }
            )

        async with self._driver.session() as session:
            await session.run(cypher, {"edges": edges})

        return path.id

    async def find_attack_paths(
        self,
        entry_node_id: str,
        goal_types: List[str],
        max_depth: int = 5,
        min_confidence: float = 0.5,
    ) -> List[AttackPath]:
        """
        Find attack paths from entry node to high-value targets.
        Uses weighted shortest path with confidence thresholds.
        """
        cypher = """
        MATCH (start)
        WHERE start.id = $entry_id
        MATCH (goal:Vulnerability)
        WHERE goal.impact IN $goal_types AND coalesce(goal.confidence, 1.0) >= $min_conf
        CALL apoc.algo.dijkstra(start, goal, 'HAS_ENDPOINT>|HAS_VULNERABILITY>|LEADS_TO>', 'probability') 
        YIELD path, weight
        WITH path, weight, start, goal
        WHERE length(path) <= $max_depth
        RETURN 
            [node in nodes(path) | node.id] as node_ids,
            [rel in relationships(path) | {type: type(rel), weight: coalesce(rel.probability, 1.0)}] as edges,
            coalesce(weight, 1.0) as confidence,
            reduce(time = 0, r in relationships(path) | time + coalesce(r.time_estimate, 60)) as total_time,
            reduce(risk = 0.0, r in relationships(path) | risk + coalesce(r.detection_risk, 0.1)) as total_risk,
            start.id as entry_id,
            goal.id as goal_id
        ORDER BY confidence DESC
        LIMIT 10
        """

        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "entry_id": entry_node_id,
                    "goal_types": goal_types,
                    "min_conf": min_confidence,
                    "max_depth": max_depth,
                },
            )

            paths = []
            async for record in result:
                # Ensure no NaN
                conf = record["confidence"] if not isinstance(record["confidence"], float) or not (record["confidence"] != record["confidence"]) else 0.5
                
                path = AttackPath(
                    node_ids=record["node_ids"],
                    edge_ids=[f"{e['type']}-{i}" for i, e in enumerate(record["edges"])],
                    confidence=min(max(conf, 0.0), 1.0),
                    risk_score=min(max(conf * 10, 0.0), 10.0),
                    total_time_estimate=record["total_time"],
                    detection_risk=0.5, # Default for now
                    entry_node_id=record["entry_id"],
                    goal_node_id=record["goal_id"],
                    engagement_id="",
                )
                paths.append(path)

            return paths

    async def get_attack_surface(self, node_id: str) -> List[Dict[str, Any]]:
        """Get all reachable nodes from a given position."""
        cypher = """
        MATCH (start)
        WHERE start.id = $node_id
        CALL apoc.path.subgraphNodes(start, {relationshipFilter: 'LEADS_TO>|HAS_VULNERABILITY>|EXPLOITED_BY>', maxLevel: 3})
        YIELD node
        RETURN node.id as id, labels(node)[0] as type, node.confidence as confidence
        """

        async with self._driver.session() as session:
            result = await session.run(cypher, {"node_id": node_id})
            nodes = []
            async for record in result:
                nodes.append(
                    {"id": record["id"], "type": record["type"], "confidence": record["confidence"]}
                )
            return nodes

    async def propagate_risk(self, exploit_id: str, impact_score: float) -> None:
        """
        Propagate risk from a validated exploit through the graph.
        Updates downstream node risk scores.
        """
        cypher = """
        MATCH (x:Exploit {id: $exploit_id})-[:USES_PAYLOAD]->(p:Payload)
        MATCH (v:Vulnerability)-[:EXPLOITED_BY]->(x)
        SET v.risk_score = $impact_score
        WITH v
        MATCH path = (v)-[:LEADS_TO*1..5]->(downstream)
        WITH downstream, path, $impact_score as base_risk
        SET downstream.risk_score = CASE 
            WHEN downstream.risk_score IS NULL THEN base_risk * reduce(conf = 1.0, r in relationships(path) | conf * r.probability)
            ELSE downstream.risk_score + base_risk * reduce(conf = 1.0, r in relationships(path) | conf * r.probability)
        END
        """

        async with self._driver.session() as session:
            await session.run(cypher, {"exploit_id": exploit_id, "impact_score": impact_score})

    async def get_node_details(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve details for a node by ID."""
        cypher = """
        MATCH (n {id: $node_id})
        RETURN labels(n)[0] as type, properties(n) as props
        """
        async with self._driver.session() as session:
            result = await session.run(cypher, {"node_id": node_id})
            record = await result.single()
            if record:
                return {"type": record["type"], **record["props"]}
            return None

    async def get_endpoint_url_for_vulnerability(self, vuln_id: str) -> Optional[str]:
        """Retrieve the URL of the endpoint associated with a vulnerability."""
        cypher = """
        MATCH (v:Vulnerability {id: $vuln_id})-[:HAS_VULNERABILITY]-(e:Endpoint)
        RETURN e.url as url
        """
        async with self._driver.session() as session:
            result = await session.run(cypher, {"vuln_id": vuln_id})
            record = await result.single()
            if record:
                return record["url"]
            return None

    async def get_graph_stats(self, engagement_id: str) -> Dict[str, Any]:
        """Get engagement graph statistics."""
        cypher = """
        MATCH (n)
        WHERE n.engagement_id = $engagement_id
        RETURN 
            count(DISTINCT n) as total_nodes,
            count(DISTINCT CASE WHEN n:Asset THEN n END) as assets,
            count(DISTINCT CASE WHEN n:Endpoint THEN n END) as endpoints,
            count(DISTINCT CASE WHEN n:Vulnerability THEN n END) as vulnerabilities,
            count(DISTINCT CASE WHEN n:Exploit THEN n END) as exploits
        """

        async with self._driver.session() as session:
            result = await session.run(cypher, {"engagement_id": engagement_id})
            record = await result.single()
            return dict(record) if record else {}

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()
