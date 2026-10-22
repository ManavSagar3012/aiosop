"""
Graph Memory Layer (Neo4j)
Attack graph construction, pathfinding, and risk propagation.
"""

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.graph import Node, Path, Relationship
from neo4j.exceptions import ServiceUnavailable

from ai_osop.core.config import settings
from ai_osop.core.exceptions import GraphQueryError, MemoryException
from ai_osop.core.models import (
    Asset,
    AttackPath,
    BusinessInvariant,
    DiffAuthFinding,
    Endpoint,
    Exploit,
    Payload,
    Vulnerability,
    Workflow,
    WorkflowStep,
    WorkflowTransition,
)
from ai_osop.core.tracing import trace_span
from ai_osop.reliability.retry import retry_with_backoff


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
        """Initialize Neo4j connection with exponential backoff retry.

        Sprint 7: Survives Neo4j restarts during startup without crashing the platform.
        """

        async def _connect() -> None:
            self._driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
            )
            await self._driver.verify_connectivity()
            self._initialized = True

        await retry_with_backoff(
            _connect,
            max_retries=5,
            base_delay=1.0,
            max_delay=30.0,
            exceptions=(ServiceUnavailable, Exception),
            retry_name="neo4j.connect",
        )

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
            "CREATE CONSTRAINT diff_auth_id IF NOT EXISTS FOR (d:DiffAuthFinding) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (ev:Evidence) REQUIRE ev.id IS UNIQUE",
            "CREATE CONSTRAINT workflow_id IF NOT EXISTS FOR (w:Workflow) REQUIRE w.id IS UNIQUE",
            "CREATE CONSTRAINT step_id IF NOT EXISTS FOR (s:Step) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT task_id IF NOT EXISTS FOR (t:Task) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT tool_action_id IF NOT EXISTS FOR (a:ToolAction) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT engagement_id IF NOT EXISTS FOR (e:Engagement) REQUIRE e.engagement_id IS UNIQUE",
            "CREATE CONSTRAINT auto_discovery_claim_eid IF NOT EXISTS FOR (c:AutoDiscoveryClaim) REQUIRE c.engagement_id IS UNIQUE",
        ]

        indexes = [
            "CREATE INDEX endpoint_type_idx IF NOT EXISTS FOR (e:Endpoint) ON (e.type)",
            "CREATE INDEX endpoint_eid_idx IF NOT EXISTS FOR (e:Endpoint) ON (e.engagement_id)",
            "CREATE INDEX endpoint_url_idx IF NOT EXISTS FOR (e:Endpoint) ON (e.url)",
            "CREATE INDEX task_eid_idx IF NOT EXISTS FOR (t:Task) ON (t.engagement_id)",
            "CREATE INDEX task_status_idx IF NOT EXISTS FOR (t:Task) ON (t.status)",
            "CREATE INDEX vuln_eid_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.engagement_id)",
            "CREATE INDEX vuln_class_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.vuln_class)",
            "CREATE INDEX replay_eid_idx IF NOT EXISTS FOR (r:ReplayResult) ON (r.engagement_id)",
            "CREATE INDEX authtest_eid_idx IF NOT EXISTS FOR (a:AuthorizationTest) ON (a.engagement_id)",
            "CREATE INDEX diffauth_eid_idx IF NOT EXISTS FOR (d:DiffAuthFinding) ON (d.engagement_id)",
            "CREATE INDEX evidence_eid_idx IF NOT EXISTS FOR (e:Evidence) ON (e.engagement_id)",
            "CREATE INDEX workflow_eid_idx IF NOT EXISTS FOR (w:Workflow) ON (w.engagement_id)",
            "CREATE INDEX asset_type_value IF NOT EXISTS FOR (a:Asset) ON (a.type, a.value)",
            "CREATE INDEX vuln_type_confidence IF NOT EXISTS FOR (v:Vulnerability) ON (v.vuln_type, v.confidence)",
            "CREATE INDEX exploit_timestamp IF NOT EXISTS FOR (x:Exploit) ON (x.timestamp)",
            "CREATE INDEX diff_auth_category IF NOT EXISTS FOR (d:DiffAuthFinding) ON (d.category, d.engagement_id)",
        ]

        async with self._driver.session() as session:
            for cypher in constraints + indexes:
                try:
                    await session.run(cypher)
                except Exception as e:
                    msg = str(e).lower()
                    # Only swallow the benign "already exists / equivalent rule" case.
                    # Surface anything else (e.g. a uniqueness constraint that cannot
                    # be created because duplicate nodes already exist in the DB).
                    if "equivalent" in msg or "already exists" in msg:
                        continue
                    logger.warning("DDL statement failed: %s | error: %s", cypher, e)

    async def add_asset(self, asset: Asset) -> str:
        """Add or update an Asset node with tracing."""
        with trace_span(
            "neo4j.add_asset",
            attributes={
                "ai_osop.asset_id": asset.id,
                "ai_osop.engagement_id": asset.engagement_id,
                "ai_osop.asset_type": asset.type,
            },
        ):
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
        """Add or update an Endpoint node. Handles both web and api endpoint types."""
        cypher = """
        // Endpoint IDs are globally unique. A duplicate foreign ID must
        // raise a uniqueness conflict rather than changing ownership.
        MERGE (e:Endpoint {id: $id, engagement_id: $engagement_id})
        SET e.url = $url,
            e.method = $method,
            e.type = $type,
            e.status_code = $status_code,
            e.title = $title,
            e.technologies = $technologies,
            e.parameters = $parameters,
            e.auth_required = $auth_required,
            e.source = $source,
            e.confidence = $confidence,
            e.engagement_id = $engagement_id,
            e.screenshot_path = $screenshot_path,
            e.host = $host,
            e.path = $path,
            e.query_keys = $query_keys,
            e.has_body = $has_body,
            e.content_type = $content_type,
            e.body_schema_keys = $body_schema_keys,
            e.auth_class = $auth_class,
            e.request_headers_sample = $request_headers_sample,
            e.status_codes_seen = $status_codes_seen,
            e.response_size_avg = $response_size_avg,
            e.response_content_type = $response_content_type,
            e.user_label = $user_label,
            e.workflow_id = $workflow_id,
            e.first_seen = CASE WHEN e.first_seen IS NULL THEN $first_seen ELSE e.first_seen END,
            e.last_seen = $last_seen,
            e.observations = $observations
        WITH e
        OPTIONAL MATCH (a:Asset {id: $asset_id})
        FOREACH (x IN CASE WHEN a IS NOT NULL THEN [a] ELSE [] END |
            MERGE (a)-[:HAS_ENDPOINT]->(e)
        )
        WITH e
        OPTIONAL MATCH (w:Workflow {id: $workflow_id})
        FOREACH (x IN CASE WHEN w IS NOT NULL THEN [w] ELSE [] END |
            MERGE (w)-[:CALLED]->(e)
        )
        RETURN e.id AS id
        """

        async with self._driver.session() as session:
            with trace_span(
                "graph_memory.add_endpoint",
                attributes={
                    "endpoint_id": endpoint.id,
                    "endpoint_type": endpoint.type,
                    "engagement_id": endpoint.engagement_id,
                },
            ):
                result = await session.run(
                    cypher,
                    {
                        "id": endpoint.id,
                        "url": endpoint.url,
                        "method": endpoint.method,
                        "type": endpoint.type,
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
                        "host": endpoint.host,
                        "path": endpoint.path,
                        "query_keys": endpoint.query_keys,
                        "has_body": endpoint.has_body,
                        "content_type": endpoint.content_type,
                        "body_schema_keys": endpoint.body_schema_keys,
                        "auth_class": endpoint.auth_class,
                        "request_headers_sample": json.dumps(endpoint.request_headers_sample),
                        "status_codes_seen": endpoint.status_codes_seen,
                        "response_size_avg": endpoint.response_size_avg,
                        "response_content_type": endpoint.response_content_type,
                        "user_label": endpoint.user_label,
                        "workflow_id": endpoint.workflow_id,
                        "first_seen": endpoint.first_seen.isoformat(),
                        "last_seen": endpoint.last_seen.isoformat(),
                        "observations": endpoint.observations,
                    },
                )
                record = await result.single()
                return record["id"] if record else endpoint.id

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
            with trace_span(
                "graph_memory.add_vulnerability",
                attributes={
                    "vuln_id": vuln.id,
                    "vuln_type": vuln.vuln_type.value,
                    "engagement_id": vuln.engagement_id,
                },
            ):
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

    async def validate_vulnerability(self, vuln_id: str) -> None:
        """Mark a vulnerability as validated in the graph."""
        cypher = """
        MATCH (v:Vulnerability {id: $vid})
        SET v.validated = true,
            v.last_validated = $ts,
            v.confidence = 1.0
        RETURN v.id
        """
        async with self._driver.session() as session:
            await session.run(cypher, {"vid": vuln_id, "ts": datetime.utcnow().isoformat()})

    async def override_vulnerability_status(
        self,
        vuln_id: str,
        status: str,
        reason: str,
        operator_id: str,
    ) -> None:
        """Record a human operator override decision on a vulnerability."""
        cypher = """
        MATCH (v:Vulnerability {id: $vid})
        SET v.finding_status = $status,
            v.validated = ($status = 'verified'),
            v.override_reason = $reason,
            v.override_by = $operator_id,
            v.override_at = $ts
        RETURN v.id
        """
        async with self._driver.session() as session:
            await session.run(
                cypher,
                {
                    "vid": vuln_id,
                    "status": status,
                    "reason": reason,
                    "operator_id": operator_id,
                    "ts": datetime.utcnow().isoformat(),
                },
            )

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
        OPTIONAL MATCH (v:Vulnerability {id: $vuln_id})
        FOREACH (y IN CASE WHEN v IS NOT NULL THEN [v] ELSE [] END |
            MERGE (v)-[:EXPLOITED_BY]->(x)
        )
        WITH x
        OPTIONAL MATCH (p:Payload {id: $payload_id})
        FOREACH (y IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
            MERGE (x)-[:USES_PAYLOAD]->(p)
        )
        RETURN x.id AS id
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
            return record["id"] if record else exploit.id

    async def add_attack_path(self, path: AttackPath) -> str:
        """Add an attack path with its nodes and edges."""
        # Create LEADS_TO relationships between consecutive nodes
        cypher = """
        UNWIND $edges as edge
        OPTIONAL MATCH (from {id: edge.from_id})
        OPTIONAL MATCH (to {id: edge.to_id})
        FOREACH (pair IN CASE WHEN from IS NOT NULL AND to IS NOT NULL THEN [1] ELSE [] END |
            MERGE (from)-[r:LEADS_TO]->(to)
            SET r.type = edge.type,
                r.probability = edge.probability,
                r.time_estimate = edge.time_estimate,
                r.detection_risk = edge.detection_risk
        )
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
                conf = (
                    record["confidence"]
                    if not isinstance(record["confidence"], float)
                    or not (record["confidence"] != record["confidence"])
                    else 0.5
                )

                path = AttackPath(
                    node_ids=record["node_ids"],
                    edge_ids=[f"{e['type']}-{i}" for i, e in enumerate(record["edges"])],
                    confidence=min(max(conf, 0.0), 1.0),
                    risk_score=min(max(conf * 10, 0.0), 10.0),
                    total_time_estimate=record["total_time"],
                    detection_risk=0.5,  # Default for now
                    entry_node_id=record["entry_id"],
                    goal_node_id=record["goal_id"],
                    engagement_id="",
                )
                paths.append(path)

            return paths

    async def find_tenant_attack_paths(
        self,
        *,
        engagement_id: str,
        entry_node_id: str,
        goal_types: List[str],
        max_depth: int = 5,
    ) -> List[AttackPath]:
        """Bounded, read-only paths with *every* node and relationship tenant-scoped.

        No APOC shortest-path call: a post-hoc tenant check on APOC traversal
        could traverse another tenant's graph before applying the filter.
        """
        ident = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
        if (
            not isinstance(engagement_id, str)
            or not re.fullmatch(r"eng-[A-Za-z0-9._-]{1,60}", engagement_id)
            or not isinstance(entry_node_id, str)
            or not ident.fullmatch(entry_node_id)
            or type(max_depth) is not int
            or not 1 <= max_depth <= 8
            or not isinstance(goal_types, list)
            or not 1 <= len(goal_types) <= 12
            or any(not isinstance(goal, str) or not ident.fullmatch(goal) for goal in goal_types)
        ):
            raise GraphQueryError("Invalid bounded tenant graph path request")
        # Every edge's two endpoints AND its relationship must be labeled with
        # the same signed tenant. No public or owner-unknown bridge is allowed.
        query = """
        MATCH p=(start {id:$entry_id, engagement_id:$sid})
          -[:HAS_ENDPOINT|HAS_VULNERABILITY|LEADS_TO*1..8]->(goal:Vulnerability)
        WHERE length(p) <= $max_depth
          AND goal.engagement_id = $sid
          AND goal.impact IN $goal_types
          AND all(n IN nodes(p) WHERE n.engagement_id = $sid)
          AND all(r IN relationships(p) WHERE r.engagement_id = $sid)
        RETURN [n IN nodes(p) | n.id] AS node_ids,
               [r IN relationships(p) | type(r)] AS edge_types,
               start.id AS entry_id, goal.id AS goal_id,
               reduce(duration=0, r IN relationships(p) |
                 duration + coalesce(r.time_estimate, 60)) AS total_time
        ORDER BY goal.id LIMIT 11
        """
        if self._driver is None:
            raise GraphQueryError("Tenant graph database unavailable")
        async with self._driver.session() as session:
            result = await session.run(
                query,
                {
                    "sid": engagement_id,
                    "entry_id": entry_node_id,
                    "goal_types": goal_types,
                    "max_depth": max_depth,
                },
            )
            records = [row async for row in result]
        if len(records) > 10:
            raise GraphQueryError("Tenant path result exceeds bounded limit")
        paths = []
        for row in records:
            nodes, edges = row["node_ids"], row["edge_types"]
            if (
                not isinstance(nodes, list)
                or len(nodes) < 2
                or len(nodes) > max_depth + 1
                or len(edges) != len(nodes) - 1
                or nodes[0] != entry_node_id
                or nodes[-1] != row["goal_id"]
                or any(not isinstance(node, str) or not ident.fullmatch(node) for node in nodes)
                or any(
                    edge not in {"HAS_ENDPOINT", "HAS_VULNERABILITY", "LEADS_TO"} for edge in edges
                )
            ):
                raise GraphQueryError("Malformed tenant path provenance")
            paths.append(
                AttackPath(
                    node_ids=nodes,
                    edge_ids=[f"{edge}-{i}" for i, edge in enumerate(edges)],
                    confidence=0.0,
                    risk_score=0.0,
                    total_time_estimate=row["total_time"],
                    detection_risk=0.0,
                    validated=False,
                    entry_node_id=entry_node_id,
                    goal_node_id=nodes[-1],
                    engagement_id=engagement_id,
                )
            )
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

    async def add_workflow(self, workflow: Workflow) -> str:
        """Persist a Workflow node."""
        cypher = """
        // ID is globally unique. A foreign tenant's existing Workflow ID
        // must collide with its uniqueness constraint, not transfer owner.
        MERGE (w:Workflow {id: $id, engagement_id: $engagement_id})
        SET w.name = $name,
            w.role = $role,
            w.engagement_id = $engagement_id,
            w.created_at = coalesce(w.created_at, $created_at)
        RETURN w.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": workflow.id,
                    "name": workflow.name,
                    "role": workflow.role,
                    "engagement_id": workflow.engagement_id,
                    "created_at": workflow.created_at.isoformat(),
                },
            )
            record = await result.single()
            return record["id"]

    async def add_workflow_step(self, step: WorkflowStep) -> str:
        """Persist a WorkflowStep node and link to its parent Workflow."""
        cypher = """
        // A dangling Step without a same-tenant Workflow/Endpoint must not
        // be reported as a successfully admitted workflow observation.
        MATCH (w:Workflow {id: $workflow_id, engagement_id: $engagement_id})
        MATCH (e:Endpoint {id: $endpoint_id, engagement_id: $engagement_id})
        // Prevent an existing same-tenant step ID from being reassigned to
        // another workflow/endpoint by a late or conflicting graph writer.
        MERGE (s:Step {id: $id, engagement_id: $engagement_id,
                       workflow_id: $workflow_id, endpoint_id: $endpoint_id})
        SET s.workflow_id = $workflow_id,
            s.endpoint_id = $endpoint_id,
            s.order = $order,
            s.action_type = $action_type,
            s.engagement_id = $engagement_id,
            s.created_at = coalesce(s.created_at, $created_at)
        MERGE (w)-[:HAS_STEP]->(s)
        MERGE (s)-[:TARGETS_ENDPOINT]->(e)
        RETURN s.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": step.id,
                    "workflow_id": step.workflow_id,
                    "endpoint_id": step.endpoint_id,
                    "order": step.order,
                    "action_type": step.action_type,
                    "engagement_id": step.engagement_id,
                    "created_at": step.created_at.isoformat(),
                },
            )
            record = await result.single()
            if record is None:
                raise ValueError("Workflow step source is absent or outside engagement")
            return record["id"]

    async def add_workflow_transition(self, transition: WorkflowTransition) -> str:
        """Persist a transition edge between two WorkflowSteps."""
        cypher = """
        MATCH (a:Step {id: $from_step_id, engagement_id: $engagement_id}),
              (b:Step {id: $to_step_id, engagement_id: $engagement_id})
        MERGE (a)-[r:TRANSITION {id: $id}]->(b)
        SET r.trigger = $trigger,
            r.engagement_id = $engagement_id
        RETURN $id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": transition.id,
                    "from_step_id": transition.from_step_id,
                    "to_step_id": transition.to_step_id,
                    "trigger": transition.trigger,
                    "engagement_id": transition.engagement_id,
                },
            )
            record = await result.single()
            if record is None:
                raise ValueError("Workflow transition has no same-tenant source and destination")
            return record["id"]

    async def add_diff_auth_finding(self, finding: DiffAuthFinding) -> str:
        """Persist a DiffAuthFinding and link it to the affected Resource/Endpoint."""
        cypher = """
        MERGE (d:DiffAuthFinding {id: $id})
        SET d.category = $category,
            d.resource_id = $resource_id,
            d.test_identity_id = $test_identity_id,
            d.expected_result = $expected_result,
            d.observed_result = $observed_result,
            d.evidence_diff = $evidence_diff,
            d.confidence = $confidence,
            d.engagement_id = $engagement_id,
            d.created_at = $created_at,
            d.outcome = $outcome,
            d.outcome_notes = $outcome_notes,
            d.outcome_at = $outcome_at
        WITH d
        OPTIONAL MATCH (e:Endpoint {id: $resource_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_DIFF_AUTH_FINDING]->(d)
        )
        WITH d
        OPTIONAL MATCH (r:Resource {id: $resource_id})
        FOREACH (x IN CASE WHEN r IS NOT NULL THEN [r] ELSE [] END |
            MERGE (r)-[:HAS_DIFF_AUTH_FINDING]->(d)
        )
        RETURN d.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": finding.id,
                    "category": finding.category,
                    "resource_id": finding.resource_id,
                    "test_identity_id": finding.test_identity_id,
                    "expected_result": finding.expected_result,
                    "observed_result": finding.observed_result,
                    "evidence_diff": json.dumps(finding.evidence_diff, default=str),
                    "confidence": finding.confidence,
                    "engagement_id": finding.engagement_id,
                    "created_at": finding.created_at.isoformat(),
                    "outcome": finding.outcome,
                    "outcome_notes": finding.outcome_notes,
                    "outcome_at": finding.outcome_at.isoformat() if finding.outcome_at else None,
                },
            )
            record = await result.single()
            return record["id"]

    # ---- Phase 2: Differential Authorization persistence ----

    async def add_replay_result(self, rr: Dict[str, Any]) -> str:
        """Persist a ReplayResult and link it to its Endpoint:
        (:Endpoint)-[:HAS_REPLAY]->(:ReplayResult)."""
        cypher = """
        MERGE (rr:ReplayResult {id: $id})
        SET rr.endpoint_id = $endpoint_id, rr.identity = $identity,
            rr.status_code = $status_code, rr.response_size = $response_size,
            rr.json_keys = $json_keys, rr.sensitive_fields = $sensitive_fields,
            rr.ownership_hits = $ownership_hits, rr.content_type = $content_type,
            rr.error = $error, rr.engagement_id = $engagement_id,
            rr.created_at = $created_at
        WITH rr
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_REPLAY]->(rr))
        RETURN rr.id AS id
        """
        async with self._driver.session() as session:
            res = await session.run(
                cypher,
                {
                    "id": rr["id"],
                    "endpoint_id": rr["endpoint_id"],
                    "identity": rr["identity"],
                    "status_code": rr.get("status_code", 0),
                    "response_size": rr.get("response_size", 0),
                    "json_keys": rr.get("json_keys", []),
                    "sensitive_fields": rr.get("sensitive_fields", []),
                    "ownership_hits": rr.get("ownership_hits", []),
                    "content_type": rr.get("content_type", ""),
                    "error": rr.get("error", ""),
                    "engagement_id": rr["engagement_id"],
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            rec = await res.single()
            return rec["id"]

    async def add_authorization_test(self, at: Dict[str, Any]) -> str:
        """Persist an AuthorizationTest and link it to its Endpoint:
        (:Endpoint)-[:HAS_AUTH_TEST]->(:AuthorizationTest)."""
        cypher = """
        MERGE (t:AuthorizationTest {id: $id})
        SET t.endpoint_id = $endpoint_id, t.user_a = $user_a, t.user_b = $user_b,
            t.signals = $signals, t.verdict = $verdict, t.category = $category,
            t.confidence = $confidence, t.engagement_id = $engagement_id,
            t.created_at = $created_at
        WITH t
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_AUTH_TEST]->(t))
        RETURN t.id AS id
        """
        async with self._driver.session() as session:
            res = await session.run(
                cypher,
                {
                    "id": at["id"],
                    "endpoint_id": at["endpoint_id"],
                    "user_a": at.get("user_a", ""),
                    "user_b": at.get("user_b", ""),
                    "signals": json.dumps(at.get("signals", {}), default=str),
                    "verdict": at.get("verdict", ""),
                    "category": at.get("category", ""),
                    "confidence": at.get("confidence", 0.0),
                    "engagement_id": at["engagement_id"],
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            rec = await res.single()
            return rec["id"]

    async def add_diff_auth_finding_for_endpoint(
        self, finding: DiffAuthFinding, endpoint_id: str, test_id: str = ""
    ) -> str:
        """Persist a DiffAuthFinding linked to its Endpoint and AuthorizationTest:
        (:Endpoint)-[:HAS_DIFF_AUTH_FINDING]->(:DiffAuthFinding)<-[:PRODUCED]-(:AuthorizationTest).
        """
        cypher = """
        MERGE (d:DiffAuthFinding {id: $id})
        SET d.category = $category, d.resource_id = $resource_id,
            d.test_identity_id = $test_identity_id, d.expected_result = $expected_result,
            d.observed_result = $observed_result, d.evidence_diff = $evidence_diff,
            d.confidence = $confidence, d.engagement_id = $engagement_id, d.created_at = $created_at
        WITH d
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_DIFF_AUTH_FINDING]->(d))
        WITH d
        OPTIONAL MATCH (t:AuthorizationTest {id: $test_id})
        FOREACH (x IN CASE WHEN t IS NOT NULL THEN [t] ELSE [] END |
            MERGE (t)-[:PRODUCED]->(d))
        RETURN d.id AS id
        """
        async with self._driver.session() as session:
            res = await session.run(
                cypher,
                {
                    "id": finding.id,
                    "category": finding.category,
                    "resource_id": finding.resource_id,
                    "test_identity_id": finding.test_identity_id,
                    "expected_result": finding.expected_result,
                    "observed_result": finding.observed_result,
                    "evidence_diff": json.dumps(finding.evidence_diff, default=str),
                    "confidence": finding.confidence,
                    "engagement_id": finding.engagement_id,
                    "endpoint_id": endpoint_id,
                    "test_id": test_id,
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            rec = await res.single()
            return rec["id"]

    # ---- Reliability sprint: durable task lifecycle + dedupe + recovery ----

    async def upsert_task(self, task: Any, result_summary: Optional[Dict[str, Any]] = None) -> bool:
        """Persist a Task's lifecycle state to Neo4j. Ground truth for the stuck-task
        reaper, restart recovery, and graph-backed dedupe (replaces in-memory only state)."""
        # AIOSOP-AUDIT-2026-06-16: persist payload + priority so restart recovery can
        # faithfully RE-DISPATCH interrupted tasks (previously payload was dropped, so
        # interrupted tasks could only be reset, never re-run). recovery_attempts is
        # preserved if already set (incremented by reset_interrupted_tasks).
        cypher = """
        MERGE (t:Task {id: $id})
        SET t.type=$type, t.status=$status, t.engagement_id=$engagement_id,
            t.agent_type=$agent_type, t.retry_count=$retry_count, t.max_retries=$max_retries,
            t.timeout_seconds=$timeout_seconds, t.created_at=$created_at, t.started_at=$started_at,
            t.completed_at=$completed_at, t.updated_at=$updated_at, t.result_summary=$result_summary,
            t.payload=$payload, t.priority=$priority,
            t.recovery_attempts=coalesce(t.recovery_attempts, 0)
        RETURN t.id AS id
        """
        params = {
            "id": task.id,
            "type": task.type,
            "status": task.status,
            "engagement_id": task.engagement_id,
            "agent_type": getattr(task.agent_type, "value", str(task.agent_type)),
            "retry_count": getattr(task, "retry_count", 0),
            "max_retries": getattr(task, "max_retries", 0),
            "timeout_seconds": getattr(task, "timeout_seconds", 300),
            "created_at": (
                task.created_at.isoformat() if getattr(task, "created_at", None) else None
            ),
            "started_at": (
                task.started_at.isoformat() if getattr(task, "started_at", None) else None
            ),
            "completed_at": (
                task.completed_at.isoformat() if getattr(task, "completed_at", None) else None
            ),
            "updated_at": datetime.utcnow().isoformat(),
            "result_summary": json.dumps(result_summary or {}, default=str),
            "payload": json.dumps(getattr(task, "payload", {}) or {}, default=str),
            "priority": getattr(task, "priority", 5),
        }
        # Bounded retry so a brief Neo4j blip doesn't silently drop a lifecycle
        # transition (would make Neo4j diverge from in-memory -> zombie tasks).
        backoffs = [0.2, 0.4]
        for attempt in range(len(backoffs) + 1):
            try:
                async with self._driver.session() as s:
                    with trace_span(
                        "graph_memory.upsert_task",
                        attributes={
                            "task_id": task.id,
                            "task_type": task.type,
                            "task_status": task.status,
                            "engagement_id": task.engagement_id,
                        },
                    ):
                        await s.run(cypher, params)
                return True
            except Exception as e:
                if attempt < len(backoffs):
                    await asyncio.sleep(backoffs[attempt])
                    continue
                # All callers ignore the return value, so re-raising would change
                # behavior (and could crash lifecycle transitions); return False
                # after logging at ERROR so the dropped write stays observable.
                logger.error("upsert_task failed for task %s after retries: %s", task.id, e)
                return False

    async def task_has_spawned(self, task_id: str, engagement_id: str) -> bool:
        """Check a SPAWNED child without admitting another tenant's graph edge."""
        if (
            not isinstance(task_id, str)
            or not isinstance(engagement_id, str)
            or not task_id.startswith("task-")
            or not engagement_id.startswith("eng-")
        ):
            return False
        try:
            async with self._driver.session() as s:
                res = await s.run(
                    "MATCH (t:Task {id:$id, engagement_id:$eid})-[:SPAWNED]->"
                    "(c:Task {engagement_id:$eid}) RETURN count(*) AS c",
                    {"id": task_id, "eid": engagement_id},
                )
                rec = await res.single()
                return bool(rec and rec["c"] > 0)
        except Exception as e:
            logger.debug("task_has_spawned_failed", error=str(e))
            return False

    async def claim_auto_discovery(self, engagement_id: str) -> bool:
        """Atomically claim auto-discovery dispatch for an engagement. Returns True only
        for the first caller — Neo4j MERGE locks the key, so concurrent hooks (and a
        restarted process) cannot both win. Returns False if Neo4j is unreachable (safe:
        no dispatch while the graph is down)."""
        cypher = """
        MERGE (c:AutoDiscoveryClaim {engagement_id: $eid})
        ON CREATE SET c.claimed_at = $ts, c._new = true
        ON MATCH SET c._new = false
        RETURN c._new AS is_new
        """
        try:
            async with self._driver.session() as s:
                res = await s.run(
                    cypher, {"eid": engagement_id, "ts": datetime.utcnow().isoformat()}
                )
                rec = await res.single()
                return bool(rec and rec["is_new"])
        except Exception as e:
            logger.debug("claim_auto_discovery_failed", error=str(e))
            return False

    async def reset_interrupted_tasks(self) -> List[Dict[str, Any]]:
        """Mark tasks left 'running' by a dead process as 'interrupted', increment their
        recovery_attempts, and return the full props needed to RE-DISPATCH them
        (AIOSOP-AUDIT-2026-06-16). Previously only id/type/engagement_id were returned,
        so recover_state could not actually re-run the interrupted work."""
        cypher = """
        MATCH (t:Task {status:'running'})
        SET t.status='interrupted', t.updated_at=$ts,
            t.recovery_attempts=coalesce(t.recovery_attempts, 0)+1
        RETURN t.id AS id, t.type AS type, t.engagement_id AS engagement_id,
               t.agent_type AS agent_type, t.payload AS payload, t.priority AS priority,
               t.max_retries AS max_retries, t.timeout_seconds AS timeout_seconds,
               t.recovery_attempts AS recovery_attempts
        """
        out: List[Dict[str, Any]] = []
        try:
            async with self._driver.session() as s:
                res = await s.run(cypher, {"ts": datetime.utcnow().isoformat()})
                async for rec in res:
                    out.append(dict(rec))
        except Exception as e:
            logger.debug("reset_interrupted_tasks_failed", error=str(e))
        return out

    async def mark_task_status(self, task_id: str, status: str) -> None:
        """Set a Task node's status (used by recovery to fail tasks over the
        re-dispatch cap). AIOSOP-AUDIT-2026-06-16."""
        try:
            async with self._driver.session() as s:
                await s.run(
                    "MATCH (t:Task {id:$id}) SET t.status=$status, t.updated_at=$ts",
                    {"id": task_id, "status": status, "ts": datetime.utcnow().isoformat()},
                )
        except Exception as e:
            logger.debug("mark_task_status_failed", error=str(e))

    async def find_incomplete_chains(
        self, *, include_spawned: bool = False, limit: int = 500
    ) -> List[Dict[str, Any]]:
        """Bounded graph hints for chain recovery, never execution authority.

        For signed PostgreSQL recovery include historical graph-only SPAWNED
        edges: the old writer created the edge before admitting its child to
        TaskORM, and a crash left a false deduplication marker. The caller
        must verify the authoritative completed parent and deterministic child.
        Legacy graph-only recovery retains its earlier missing-edge filter.
        """
        limit = max(1, min(int(limit), 500))
        cypher = """
        MATCH (t:Task {status:'completed'})
        WHERE t.type IN ['map_workflow','capture_authenticated_surface','extract_har_api_inventory']
          AND ($include_spawned OR NOT (t)-[:SPAWNED]->(:Task))
        RETURN t.id AS id, t.type AS type, t.engagement_id AS engagement_id,
               t.result_summary AS result_summary
        ORDER BY t.created_at DESC, t.id
        LIMIT $limit
        """
        out: List[Dict[str, Any]] = []
        try:
            async with self._driver.session() as s:
                res = await s.run(
                    cypher,
                    {"include_spawned": bool(include_spawned), "limit": limit},
                )
                async for rec in res:
                    out.append(dict(rec))
        except Exception as e:
            logger.debug("find_incomplete_chains_failed", error=str(e))
        return out

    async def attach_evidence_to_step(
        self,
        step_id: str,
        evidence_type: str,
        path: str,
        engagement_id: str,
        workflow_id: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create an Evidence node and link it to a WorkflowStep and parent Workflow.
        Returns the evidence node id. Idempotent on (step_id, path)."""
        evidence_id = f"ev-{hashlib.sha1(f'{step_id}|{path}'.encode()).hexdigest()[:16]}"
        cypher = """
        // Never write unattached evidence and then falsely return its ID.
        MATCH (w:Workflow {id: $workflow_id, engagement_id: $engagement_id})
            -[:HAS_STEP]->(s:Step {id: $step_id, engagement_id: $engagement_id,
                                   workflow_id: $workflow_id})
        MERGE (ev:Evidence {id: $id, engagement_id: $engagement_id})
        SET ev.type = $type,
            ev.path = $path,
            ev.engagement_id = $engagement_id,
            ev.workflow_id = $workflow_id,
            ev.extra = $extra,
            ev.created_at = coalesce(ev.created_at, $created_at)
        MERGE (s)-[:HAS_EVIDENCE]->(ev)
        MERGE (w)-[:HAS_EVIDENCE]->(ev)
        RETURN ev.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": evidence_id,
                    "type": evidence_type,
                    "path": path,
                    "engagement_id": engagement_id,
                    "workflow_id": workflow_id,
                    "step_id": step_id,
                    "extra": json.dumps(extra or {}, default=str),
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            record = await result.single()
            if record is None:
                raise ValueError("Workflow evidence has no same-tenant source step")
            return record["id"]

    async def add_business_invariant(
        self, invariant: BusinessInvariant, engagement_id: str, is_violated: bool = False
    ) -> str:
        """Persist a BusinessInvariant so it can be surfaced on the Research
        Intelligence dashboard. Idempotent on invariant id."""
        cypher = """
        MERGE (i:BusinessInvariant {id: $id})
        SET i.description = $description,
            i.target_resource_type = $target_resource_type,
            i.required_state = $required_state,
            i.violation_strategy = $violation_strategy,
            i.actor_constraints = $actor_constraints,
            i.is_violated = $is_violated,
            i.engagement_id = $engagement_id,
            i.created_at = coalesce(i.created_at, $created_at)
        RETURN i.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": invariant.id,
                    "description": invariant.description,
                    "target_resource_type": invariant.target_resource_type,
                    "required_state": invariant.required_state,
                    "violation_strategy": invariant.violation_strategy,
                    "actor_constraints": invariant.actor_constraints,
                    "is_violated": is_violated,
                    "engagement_id": engagement_id or invariant.engagement_id,
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            record = await result.single()
            return record["id"]

    async def mark_invariant_violated(self, invariant_id: str) -> None:
        """Flag a previously-persisted invariant as violated."""
        cypher = "MATCH (i:BusinessInvariant {id: $id}) SET i.is_violated = true RETURN i.id"
        async with self._driver.session() as session:
            await session.run(cypher, {"id": invariant_id})

    async def get_invariants(self, engagement_id: str) -> List[Dict[str, Any]]:
        """Return persisted invariants for an engagement, shaped for the UI."""
        cypher = (
            "MATCH (i:BusinessInvariant) WHERE i.engagement_id = $sid "
            "RETURN i ORDER BY i.created_at DESC"
        )
        out: List[Dict[str, Any]] = []
        async with self._driver.session() as session:
            result = await session.run(cypher, {"sid": engagement_id})
            async for record in result:
                i = dict(record["i"])
                out.append(
                    {
                        "id": i.get("id"),
                        "description": i.get("description"),
                        "target_resource_type": i.get("target_resource_type"),
                        "violation_strategy": i.get("violation_strategy"),
                        "is_violated": bool(i.get("is_violated", False)),
                    }
                )
        return out

    async def project_signed_tool_action(self, proof: Dict[str, Any]) -> bool:
        """Persist an inert successful-tool receipt index; PostgreSQL is truth.

        Called only after independently verifying the signed MCP event and
        completed Flow Task. A pre-existing node belonging to a different
        source cannot be overwritten. Retrying the same projection is safe.
        """
        from ai_osop.memory.graph_research_context import _TOOL_KINDS

        digest_fields = (
            "authorization_sha256",
            "source_task_sha256",
            "receipt_sha256",
            "provider_receipt_sha256",
            "provider_signer_key_sha256",
        )
        identity_fields = ("id", "engagement_id", "flow_id", "source_task_id", "source_event_id")
        if (
            not isinstance(proof, dict)
            or any(
                not isinstance(proof.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", proof[key])
                for key in digest_fields
            )
            or any(
                not isinstance(proof.get(key), str)
                or len(proof[key]) > 80
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", proof[key])
                for key in identity_fields
            )
            or not proof["id"].startswith("action-")
            or not proof["engagement_id"].startswith("eng-")
            or not proof["flow_id"].startswith("flow-")
            or not proof["source_task_id"].startswith("task-")
            or not proof["source_event_id"].startswith("evt-")
            or not isinstance(proof.get("provider_server_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", proof["provider_server_id"])
            or not isinstance(proof.get("provider_signing_kid"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,96}", proof["provider_signing_kid"])
            or proof.get("tool_kind") not in _TOOL_KINDS
            or proof.get("outcome") != "succeeded"
            or type(proof.get("authorization_version")) is not int
            or proof["authorization_version"] < 1
            or type(proof.get("flow_revision")) is not int
            or proof["flow_revision"] < 0
        ):
            raise ValueError("Malformed signed graph projection")
        if self._driver is None:
            raise RuntimeError("Signed graph projection store unavailable")
        cypher = """
        MERGE (a:ToolAction {id:$id})
        ON CREATE SET
          a.engagement_id=$engagement_id, a.flow_id=$flow_id,
          a.flow_revision=$flow_revision,
          a.authorization_version=$authorization_version,
          a.authorization_sha256=$authorization_sha256,
          a.source_task_id=$source_task_id,
          a.source_task_sha256=$source_task_sha256,
          a.source_event_id=$source_event_id,
          a.tool_kind=$tool_kind, a.receipt_sha256=$receipt_sha256,
          a.provider_receipt_sha256=$provider_receipt_sha256,
          a.provider_server_id=$provider_server_id,
          a.provider_signing_kid=$provider_signing_kid,
          a.provider_signer_key_sha256=$provider_signer_key_sha256,
          a.outcome=$outcome
        WITH a
        WHERE a.engagement_id=$engagement_id AND a.flow_id=$flow_id
          AND a.flow_revision=$flow_revision
          AND a.authorization_version=$authorization_version
          AND a.authorization_sha256=$authorization_sha256
          AND a.source_task_id=$source_task_id
          AND a.source_task_sha256=$source_task_sha256
          AND a.source_event_id=$source_event_id
          AND a.tool_kind=$tool_kind
          AND a.receipt_sha256=$receipt_sha256
          AND a.provider_receipt_sha256=$provider_receipt_sha256
          AND a.provider_server_id=$provider_server_id
          AND a.provider_signing_kid=$provider_signing_kid
          AND a.provider_signer_key_sha256=$provider_signer_key_sha256
          AND a.outcome='succeeded'
        RETURN a.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(cypher, proof)
            row = await result.single()
            return bool(row and row["id"] == proof["id"])

    async def read_signed_research_candidates(
        self,
        engagement_id: str,
        flow_id: str,
        authorization_version: int,
        authorization_sha256: str,
        *,
        limit: int = 12,
        topics: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Read only tightly bound graph *candidates*, never attest them.

        Neo4j graph properties are NOT authority: callers must independently
        verify signed ROE, active Flow/current Task, each originating durable
        Task and cryptographic receipt fingerprints. Graph Vulnerability nodes
        are ineligible until a source-authenticating evidence writer exists.

        Parameterized queries constrain both node labels, tenant, Flow and
        version before projection. Deliberately excludes titles, descriptions,
        target URLs, commands, raw tool outputs and agent prose.
        """
        if (
            not isinstance(engagement_id, str)
            or not engagement_id.startswith("eng-")
            or not isinstance(flow_id, str)
            or not flow_id.startswith("flow-")
            or type(authorization_version) is not int
            or authorization_version < 1
            or not isinstance(authorization_sha256, str)
            or len(authorization_sha256) != 64
            or type(limit) is not int
            or not 1 <= limit <= 16
            or not isinstance(topics, (list, type(None)))
            or (
                topics is not None
                and (
                    len(topics) > 24
                    or any(
                        not isinstance(t, str)
                        or not t.isascii()
                        or not t.islower()
                        or not t.isalpha()
                        or not 2 <= len(t) <= 24
                        for t in topics
                    )
                )
            )
        ):
            raise ValueError("Invalid signed graph research boundary")
        if self._driver is None:
            raise RuntimeError("Graph research store unavailable")
        query = """
        MATCH (a:ToolAction {
            engagement_id:$eid, flow_id:$fid,
            authorization_version:$version,
            authorization_sha256:$digest
        })
        WHERE a.outcome = 'succeeded' AND a.source_task_id IS NOT NULL
        RETURN 'action' AS kind, a.id AS id,
               a.engagement_id AS engagement_id, a.flow_id AS flow_id,
               a.flow_revision AS flow_revision,
               a.authorization_version AS authorization_version,
               a.authorization_sha256 AS authorization_sha256,
               a.source_task_id AS source_task_id,
               a.source_task_sha256 AS source_task_sha256,
               a.tool_kind AS classification,
               a.receipt_sha256 AS receipt_sha256,
               a.outcome AS outcome, a.source_event_id AS source_event_id,
               a.provider_receipt_sha256 AS provider_receipt_sha256,
               a.provider_server_id AS provider_server_id,
               a.provider_signing_kid AS provider_signing_kid,
               a.provider_signer_key_sha256 AS provider_signer_key_sha256
        ORDER BY CASE WHEN classification IN $topics THEN 0 ELSE 1 END,
                 kind, id LIMIT $limit
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    query,
                    {
                        "eid": engagement_id,
                        "fid": flow_id,
                        "version": authorization_version,
                        "digest": authorization_sha256,
                        "limit": limit,
                        "topics": topics or [],
                    },
                )
                return [dict(record) async for record in result]
        except Exception as exc:
            # Caller MUST stop inference rather than promoting incomplete or
            # cross-tenant graph responses into authoritative prompt context.
            raise RuntimeError("Signed graph research retrieval unavailable") from exc

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()
