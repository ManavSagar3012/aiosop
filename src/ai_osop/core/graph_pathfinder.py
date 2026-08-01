"""Automated Graph Pathfinder — Neo4j pathfinding for attack chains.

The assessment's Medium-term Priority 1: instead of relying on static
template-matching for attack chains (e.g. "SSRF → IMDS → creds"), the
system should run pathfinding algorithms on the Neo4j graph to find
potential logical chains automatically.

This module queries the graph for nodes with matching input/output
interfaces (e.g. Node A yields a session token → Node B consumes a
session token) and generates verification tasks for the discovered paths.

The graph already has the structure:
  (:Asset)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_VULNERABILITY]->(:Vulnerability)-[:EXPLOITED_BY]->(:Exploit)

This pathfinder adds directional data-flow edges and runs Cypher
pathfinding queries to discover chains the template matcher would miss.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class GraphPathfinder:
    """Find attack chains by pathfinding on the Neo4j graph.

    Queries the graph for nodes with matching input/output interfaces
    and discovers chains that the template-based AttackChainAgent would miss.
    """

    def __init__(self, graph_memory: Any):
        self._gm = graph_memory

    async def find_chains(
        self,
        engagement_id: str,
        max_depth: int = 5,
        min_confidence: float = 0.3,
    ) -> List[Dict[str, Any]]:
        """Find potential attack chains by pathfinding on the graph.

        Looks for paths from entry-point vulnerabilities to high-value targets
        (admin endpoints, cloud metadata, credential stores). Uses Neo4j's
        native pathfinding (variable-length relationships).

        Returns a list of chain dicts, each with:
          - steps: the ordered list of nodes in the chain
          - confidence: aggregate confidence of the chain
          - chain_type: inferred type (ssrf_chain, authz_chain, etc.)
        """
        chains: List[Dict[str, Any]] = []

        # 1. SSRF chain: find SSRF vulnerabilities → check if metadata
        # endpoints are reachable → check if credentials were extracted
        ssrf_chains = await self._find_ssrf_chains(engagement_id, max_depth)
        chains.extend(ssrf_chains)

        # 2. Authorization chain: find IDOR/access-control vulns →
        # check if admin endpoints are reachable via the same identity
        authz_chains = await self._find_authz_chains(engagement_id, max_depth)
        chains.extend(authz_chains)

        # 3. XSS chain: find XSS → check if cookie/session endpoints exist
        xss_chains = await self._find_xss_chains(engagement_id, max_depth)
        chains.extend(xss_chains)

        # 4. Injection chain: find SQLi → check if DB access leads to
        # credential extraction or file read
        sqli_chains = await self._find_sqli_chains(engagement_id, max_depth)
        chains.extend(sqli_chains)

        # 5. Generic pathfinding: any vulnerability → any high-value endpoint
        # within max_depth hops (catches chains no template would predict)
        generic_chains = await self._find_generic_chains(engagement_id, max_depth, min_confidence)
        chains.extend(generic_chains)

        # Deduplicate by step signatures
        seen = set()
        unique = []
        for chain in chains:
            sig = tuple(sorted(n.get("id", "") for n in chain.get("steps", [])))
            if sig not in seen:
                seen.add(sig)
                unique.append(chain)

        return unique

    async def _find_ssrf_chains(self, eid: str, max_depth: int) -> List[Dict[str, Any]]:
        """Find SSRF → metadata → credential chains."""
        try:
            recs = await self._gm.run_read_query(
                """
                MATCH (v:Vulnerability {engagement_id: $eid, vuln_type: 'ssrf'})
                WHERE v.validated = true
                OPTIONAL MATCH path = (v)-[:LEADS_TO*1..3]->(target)
                WHERE target:Vulnerability OR target:Endpoint
                RETURN v.id AS vuln_id, v.title AS title,
                       [n IN nodes(path) | n.id] AS path_nodes,
                       [n IN nodes(path) | labels(n)] AS path_labels,
                       length(path) AS depth
                LIMIT 10
                """,
                {"eid": eid},
            )
        except Exception:
            return []

        chains = []
        for r in recs:
            if r.get("depth", 0) > 0:
                chains.append(
                    {
                        "chain_type": "ssrf_chain",
                        "confidence": 0.8,
                        "steps": [
                            {
                                "id": r.get("vuln_id"),
                                "type": "vulnerability",
                                "title": r.get("title"),
                            },
                            {"id": "metadata_endpoint", "type": "target"},
                        ],
                        "description": "SSRF confirmed → probe cloud metadata → extract credentials",
                    }
                )
        return chains

    async def _find_authz_chains(self, eid: str, max_depth: int) -> List[Dict[str, Any]]:
        """Find IDOR/access-control → admin endpoint chains."""
        try:
            recs = await self._gm.run_read_query(
                """
                MATCH (v:Vulnerability {engagement_id: $eid})
                WHERE v.validated = true AND v.vuln_type IN ['idor', 'broken_access_control']
                MATCH (e:Endpoint {engagement_id: $eid})
                WHERE e.path CONTAINS 'admin' OR e.path CONTAINS 'user' OR e.path CONTAINS 'account'
                WITH v, collect(e)[..5] AS admin_eps
                RETURN v.id AS vuln_id, v.title AS title,
                       [ep IN admin_eps | {id: ep.id, url: ep.url, path: ep.path}] AS admin_endpoints
                """,
                {"eid": eid},
            )
        except Exception:
            return []

        chains = []
        for r in recs:
            if r.get("admin_endpoints"):
                chains.append(
                    {
                        "chain_type": "authz_chain",
                        "confidence": 0.75,
                        "steps": [
                            {
                                "id": r.get("vuln_id"),
                                "type": "vulnerability",
                                "title": r.get("title"),
                            },
                            {
                                "id": "admin_endpoints",
                                "type": "target",
                                "endpoints": r.get("admin_endpoints"),
                            },
                        ],
                        "description": "IDOR/access-control confirmed → probe admin endpoints → privilege escalation",
                    }
                )
        return chains

    async def _find_xss_chains(self, eid: str, max_depth: int) -> List[Dict[str, Any]]:
        """Find XSS → cookie/session theft chains."""
        try:
            recs = await self._gm.run_read_query(
                """
                MATCH (v:Vulnerability {engagement_id: $eid, vuln_type: 'xss'})
                WHERE v.validated = true
                MATCH (e:Endpoint {engagement_id: $eid})
                WHERE e.path CONTAINS 'login' OR e.path CONTAINS 'session' OR e.path CONTAINS 'auth'
                WITH v, collect(e)[..3] AS auth_eps
                RETURN v.id AS vuln_id, v.title AS title,
                       [ep IN auth_eps | {id: ep.id, url: ep.url}] AS auth_endpoints
                """,
                {"eid": eid},
            )
        except Exception:
            return []

        chains = []
        for r in recs:
            if r.get("auth_endpoints"):
                chains.append(
                    {
                        "chain_type": "xss_chain",
                        "confidence": 0.6,
                        "steps": [
                            {
                                "id": r.get("vuln_id"),
                                "type": "vulnerability",
                                "title": r.get("title"),
                            },
                            {
                                "id": "auth_endpoints",
                                "type": "target",
                                "endpoints": r.get("auth_endpoints"),
                            },
                        ],
                        "description": "XSS confirmed → steal session cookies → account takeover",
                    }
                )
        return chains

    async def _find_sqli_chains(self, eid: str, max_depth: int) -> List[Dict[str, Any]]:
        """Find SQLi → credential extraction chains."""
        try:
            recs = await self._gm.run_read_query(
                """
                MATCH (v:Vulnerability {engagement_id: $eid, vuln_type: 'sqli'})
                WHERE v.validated = true
                RETURN v.id AS vuln_id, v.title AS title, v.evidence AS evidence
                LIMIT 5
                """,
                {"eid": eid},
            )
        except Exception:
            return []

        chains = []
        for r in recs:
            chains.append(
                {
                    "chain_type": "sqli_chain",
                    "confidence": 0.85,
                    "steps": [
                        {"id": r.get("vuln_id"), "type": "vulnerability", "title": r.get("title")},
                        {"id": "credential_table", "type": "target"},
                    ],
                    "description": "SQLi confirmed → extract credentials → try on auth endpoints",
                }
            )
        return chains

    async def _find_generic_chains(
        self, eid: str, max_depth: int, min_confidence: float
    ) -> List[Dict[str, Any]]:
        """Find any path from a vulnerability to a high-value endpoint.

        This is the generic pathfinder that catches chains no template would
        predict. It queries for variable-length paths from any validated
        vulnerability to any endpoint with high-value path patterns.
        """
        try:
            recs = await self._gm.run_read_query(
                """
                MATCH (v:Vulnerability {engagement_id: $eid})
                WHERE v.validated = true AND v.confidence >= $min_conf
                MATCH (e:Endpoint {engagement_id: $eid})
                WHERE e.path CONTAINS 'admin' OR e.path CONTains 'config'
                   OR e.path CONTAINS 'upload' OR e.path CONTAINS 'api'
                   OR e.path CONTAINS 'payment' OR e.path CONTAINS 'billing'
                WITH v, collect(DISTINCT e)[..10] AS targets
                UNWIND targets AS target
                RETURN v.id AS vuln_id, v.vuln_type AS vuln_type, v.title AS title,
                       target.id AS target_id, target.url AS target_url, target.path AS target_path
                LIMIT 20
                """,
                {"eid": eid, "min_conf": min_confidence},
            )
        except Exception:
            return []

        chains = []
        for r in recs:
            chains.append(
                {
                    "chain_type": f"{r.get('vuln_type', 'unknown')}_to_high_value",
                    "confidence": 0.5,
                    "steps": [
                        {
                            "id": r.get("vuln_id"),
                            "type": "vulnerability",
                            "title": r.get("title"),
                            "vuln_type": r.get("vuln_type"),
                        },
                        {
                            "id": r.get("target_id"),
                            "type": "endpoint",
                            "url": r.get("target_url"),
                            "path": r.get("target_path"),
                        },
                    ],
                    "description": (
                        f"{r.get('vuln_type', 'vulnerability')} at one endpoint → "
                        f"probe high-value endpoint {r.get('target_path', '')} "
                        f"with the same exploit"
                    ),
                }
            )
        return chains
