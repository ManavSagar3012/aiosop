"""AI-OSOP Intelligence Router

Attack graph, attack paths, vulnerability education, and WAF profiles.
"""

import math
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ai_osop.api.deps import assert_engagement_access, state, verify_token
from ai_osop.memory.authorization_store import guard_sql

router = APIRouter(tags=["intelligence"])
_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_NODE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_MAX_GRAPH = 500
# This is a display-only projection, NOT a report/evidence endpoint. Neo4j
# property dictionaries include arbitrary tool responses, private HTTP bodies,
# credentials, other identities and source claims. None are public graph data.
_PUBLIC_NODE_LABELS = frozenset(
    {
        "Asset",
        "Endpoint",
        "Vulnerability",
        "Exploit",
        "Payload",
        "Workflow",
        "Step",
        "Transition",
        "Intent",
        "SemanticElement",
        "CloudResource",
        "State",
        "OutcomeRecord",
        "CriticalOperation",
    }
)
_PUBLIC_EDGE_TYPES = frozenset(
    {
        "CALLED",
        "CAN_ACCESS",
        "DEPENDS_ON",
        "ESCALATES_TO",
        "EXPLOITED_BY",
        "HAS_AUTH_TEST",
        "HAS_DIFF_AUTH_FINDING",
        "HAS_ENDPOINT",
        "HAS_EVIDENCE",
        "HAS_REPLAY",
        "HAS_STEP",
        "HAS_VULNERABILITY",
        "LEADS_TO",
        "PRODUCED",
        "SPAWNED",
        "TARGETS_ENDPOINT",
        "USES_PAYLOAD",
    }
)
_PUBLIC_DISPLAY = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,_()#+-]{0,95}\Z")
_PRIVATE_DISPLAY = re.compile(
    r"(?:^|[^a-z0-9])(?:bearer|password|secret|private|credential|"
    r"token|cookie|evidence|proof|request.body|response.body|"
    r"session.id|api.key|access.key|private.key|authorization.header)"
    r"(?:$|[^a-z0-9])",
    re.I,
)
_PUBLIC_SEVERITY = frozenset({"critical", "high", "medium", "low", "info", "informational"})
_PUBLIC_STATUS = frozenset(
    {
        "discovered",
        "open",
        "closed",
        "active",
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
        "unknown",
        "confirmed",
    }
)


def _display_graph_text(value: Any) -> Optional[str]:
    """Accept only small plain labels, never URL/query/body/JSON/credential text."""
    if type(value) is not str or _PUBLIC_DISPLAY.fullmatch(value) is None:
        return None
    if _PRIVATE_DISPLAY.search(value):
        return None
    return value


def _public_graph_node(node: Any, session_id: str) -> Optional[Dict[str, Any]]:
    """Copy bounded scalar display fields without materializing dict(node)."""
    node_id = node.get("id")
    if (
        node.get("engagement_id") != session_id
        or type(node_id) is not str
        or _NODE.fullmatch(node_id) is None
    ):
        return None
    # Graph labels can also be dynamically supplied. Unknown labels never
    # appear as raw strings in the public JSON response.
    public_labels = sorted(
        {label for label in node.labels if type(label) is str and label in _PUBLIC_NODE_LABELS}
    )[:4]
    if not public_labels:
        return None
    props: Dict[str, Any] = {"id": node_id, "type": public_labels[0]}
    for key in ("name", "title", "value"):
        label = _display_graph_text(node.get(key))
        if label is not None:
            props[key] = label
    # KnowledgeGraphs.tsx displays name -> value -> id. Preserve a safe title
    # for nodes with no name without ever falling back to raw URLs or evidence.
    if "name" not in props and "title" in props:
        props["name"] = props["title"]
    severity = node.get("severity")
    if type(severity) is str and severity.lower() in _PUBLIC_SEVERITY:
        props["severity"] = severity.lower()
    status = node.get("status")
    if type(status) is str and status.lower() in _PUBLIC_STATUS:
        props["status"] = status.lower()
    confidence = node.get("confidence")
    if type(confidence) in (float, int) and math.isfinite(confidence) and 0 <= confidence <= 1:
        props["confidence"] = round(confidence, 3)
    return {"id": node_id, "labels": public_labels, "properties": props}


async def _current_graph_authority(
    session_id: str, operator: Dict[str, Any]
) -> tuple[str, str, int]:
    """Bind every graph read to the current durable tenant and signed ROE."""
    if _ENG.fullmatch(session_id) is None:
        raise HTTPException(status_code=422, detail="Invalid signed engagement")
    await assert_engagement_access(operator, session_id)
    memory = getattr(state.get("orchestrator"), "session_memory", None)
    if not callable(getattr(memory, "_async_session", None)):
        raise HTTPException(status_code=503, detail="Signed graph authority unavailable")
    try:
        async with memory._async_session() as db:
            async with db.begin():
                signed = await guard_sql(db, session_id)
                identity = (signed.authorization_id, signed.policy_sha256, signed.version)
        if (
            not isinstance(identity[0], str)
            or not isinstance(identity[1], str)
            or type(identity[2]) is not int
        ):
            raise ValueError("Incomplete signed scope")
        return identity
    except Exception as exc:
        raise HTTPException(
            status_code=403, detail="Current signed graph authorization required"
        ) from exc


async def _recheck_graph_authority(
    session_id: str, operator: Dict[str, Any], expected: tuple[str, str, int]
) -> None:
    if await _current_graph_authority(session_id, operator) != expected:
        raise HTTPException(
            status_code=409, detail="Signed graph authorization changed during read"
        )


@router.get("/engagements/{session_id}/graph")
async def get_full_graph(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get full attack graph nodes and edges."""
    authority = await _current_graph_authority(session_id, operator)
    node_query = """
    MATCH (n)
    WHERE n.engagement_id = $session_id
    RETURN n ORDER BY n.id LIMIT $limit
    """
    rel_query = """
    MATCH (n)-[r]->(m)
    WHERE n.engagement_id = $session_id AND m.engagement_id = $session_id
    RETURN n.id as from_id, m.id as to_id, r LIMIT $limit
    """

    nodes = {}
    edges = []

    async with state["orchestrator"].graph_memory._driver.session() as session:
        node_result = await session.run(
            node_query, {"session_id": session_id, "limit": _MAX_GRAPH + 1}
        )
        async for record in node_result:
            if len(nodes) >= _MAX_GRAPH:
                raise HTTPException(status_code=413, detail="Graph exceeds bounded readback")
            n = record["n"]
            if n and n.get("engagement_id") == session_id:
                public_node = _public_graph_node(n, session_id)
                if public_node is not None and public_node["id"] not in nodes:
                    nodes[public_node["id"]] = public_node

        rel_result = await session.run(
            rel_query, {"session_id": session_id, "limit": _MAX_GRAPH + 1}
        )
        async for record in rel_result:
            if len(edges) >= _MAX_GRAPH:
                raise HTTPException(status_code=413, detail="Graph edges exceed bounded readback")
            r = record["r"]
            from_id = record["from_id"]
            to_id = record["to_id"]
            if (
                type(from_id) is not str
                or type(to_id) is not str
                or from_id not in nodes
                or to_id not in nodes
                or r is None
            ):
                # The Cypher query already scopes both endpoints. Reconcile
                # against the actual returned public nodes as a second fence.
                continue
            edges.append(
                {
                    # Element IDs and dynamic relationship types/properties
                    # are never public identity/provenance. A bounded local
                    # edge index suffices for ReactFlow rendering.
                    "id": f"edge-{len(edges) + 1}",
                    "type": (
                        r.type
                        if type(r.type) is str and r.type in _PUBLIC_EDGE_TYPES
                        else "RELATED"
                    ),
                    "from": from_id,
                    "to": to_id,
                    "properties": {},
                }
            )

    await _recheck_graph_authority(session_id, operator, authority)
    return {"nodes": list(nodes.values()), "edges": edges}


@router.get("/engagements/{session_id}/attack-paths")
async def get_attack_paths(
    session_id: str,
    entry_node_id: Optional[str] = Query(None),
    goal_types: Optional[List[str]] = Query(None),
    max_depth: int = Query(5),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Discover attack paths from entry to goals."""
    authority = await _current_graph_authority(session_id, operator)
    if entry_node_id is not None and _NODE.fullmatch(entry_node_id) is None:
        raise HTTPException(status_code=422, detail="Invalid scoped graph entry")
    if type(max_depth) is not int or not 1 <= max_depth <= 8:
        raise HTTPException(status_code=422, detail="Bounded path depth required")
    if goal_types is None:
        goal_types = ["rce", "admin_access", "data_exfiltration"]

    if not entry_node_id:
        cypher = "MATCH (a:Asset {engagement_id: $sid}) RETURN a.id as id LIMIT 1"
        async with state["orchestrator"].graph_memory._driver.session() as session:
            res = await session.run(cypher, {"sid": session_id})
            record = await res.single()
            if record:
                entry_node_id = record["id"]

    if not entry_node_id:
        await _recheck_graph_authority(session_id, operator, authority)
        return []

    # The traversal helper does not accept tenant scope. Resolve the entry
    # against the engagement first, then refuse any foreign nodes in results.
    async with state["orchestrator"].graph_memory._driver.session() as session:
        entry = await session.run(
            "MATCH (a {id:$id, engagement_id:$sid}) RETURN a.id AS id LIMIT 1",
            {"id": entry_node_id, "sid": session_id},
        )
        if await entry.single() is None:
            raise HTTPException(status_code=404, detail="Entry node not in signed engagement")

    tenant_traversal = getattr(state["orchestrator"].graph_memory, "find_tenant_attack_paths", None)
    if not callable(tenant_traversal):
        raise HTTPException(status_code=503, detail="Tenant-scoped graph traversal unavailable")
    try:
        paths = await tenant_traversal(
            engagement_id=session_id,
            entry_node_id=entry_node_id,
            goal_types=goal_types,
            max_depth=max_depth,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Tenant graph traversal unavailable") from exc
    if any(
        p.engagement_id != session_id or p.entry_node_id != entry_node_id or p.validated
        for p in paths
    ):
        raise HTTPException(status_code=503, detail="Untrusted tenant graph traversal")
    if len(paths) > 100:
        raise HTTPException(status_code=413, detail="Attack paths exceed bounded readback")
    await _recheck_graph_authority(session_id, operator, authority)
    # A traversal with no tenant selector cannot certify membership of all
    # interior nodes. Treat these graph suggestions as unverified leads.
    return [
        {**p.model_dump(), "validation_state": "UNKNOWN", "finding_verified": False} for p in paths
    ]


@router.get("/intelligence/vulnerability-edu/{vuln_class}")
async def get_vuln_education(vuln_class: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Educational content for vulnerability classes and exploitation techniques."""
    education_db = {
        "sqli": {
            "title": "SQL Injection (SQLi)",
            "description": "SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.",
            "impact": "Can lead to unauthorized access to sensitive data, including passwords, credit card details, and personal user information.",
            "how_to_exploit": [
                "1. Identify an input parameter (URL query, POST body) that is used in a database query.",
                "2. Inject a single quote (') to test if it breaks the query structure.",
                "3. Use a tautology payload like ' OR 1=1 -- to bypass authentication.",
                "4. Use UNION SELECT statements to extract data from other tables.",
                "5. Use blind SQLi techniques (sleep, timing) if no data is reflected.",
            ],
            "prevention": "Use parameterized queries (prepared statements) and input validation.",
        },
        "xss": {
            "title": "Cross-Site Scripting (XSS)",
            "description": "XSS allows an attacker to execute arbitrary scripts in the victim's browser.",
            "impact": "Can lead to session hijacking, defacement, or redirection to malicious sites.",
            "how_to_exploit": [
                "1. Locate input fields that are reflected in the HTML response.",
                "2. Inject <script>alert(1)</script> to test for execution.",
                "3. Use document.cookie to steal session tokens.",
                "4. Bypass filters using encoding or different tags like <img src=x onerror=alert(1)>.",
            ],
            "prevention": "Context-aware output encoding and Content Security Policy (CSP).",
        },
        "ssrf": {
            "title": "Server-Side Request Forgery (SSRF)",
            "description": "SSRF allows an attacker to induce the server-side application to make requests to an arbitrary domain of the attacker's choosing.",
            "impact": "Can result in unauthorized access to internal services, cloud metadata (like AWS IAM keys), and port scanning of the internal network.",
            "how_to_exploit": [
                "1. Find parameters that take URLs or IP addresses as input.",
                "2. Provide an internal IP address (e.g., 127.0.0.1 or 169.254.169.254) as the input.",
                "3. Attempt to access sensitive internal endpoints or cloud metadata APIs.",
                "4. Use different protocols like file:// or gopher:// if http:// is restricted.",
            ],
            "prevention": "Sanitize user-provided URLs and use a strict allowlist of allowed domains/IPs.",
        },
        "idor": {
            "title": "Insecure Direct Object Reference (IDOR)",
            "description": "IDOR occurs when an application provides direct access to objects based on user-supplied input without performing authorization checks.",
            "impact": "Allows attackers to view or modify data belonging to other users (e.g., profiles, invoices, private messages).",
            "how_to_exploit": [
                "1. Identify a request that uses an ID to reference an object (e.g., /api/user/123).",
                "2. Change the ID to another value (e.g., /api/user/124) and check if you can access that user's data.",
                "3. Test across different roles to see if a low-privilege user can access admin-level objects.",
                "4. Look for IDs in parameters, headers, or JSON bodies.",
            ],
            "prevention": "Implement robust per-object authorization checks for every request.",
        },
        "ssti": {
            "title": "Server-Side Template Injection (SSTI)",
            "description": "SSTI occurs when user input is concatenated directly into a template, allowing an attacker to inject malicious template directives.",
            "impact": "Can lead to full Remote Code Execution (RCE) on the server, allowing an attacker to take over the application and the underlying host.",
            "how_to_exploit": [
                "1. Identify input points that are rendered using a template engine (e.g., Jinja2, Mako).",
                "2. Inject mathematical expressions like {{7*7}} to see if the server evaluates them to 49.",
                "3. Use specialized payloads to access the underlying Python environment (e.g., {{config.__class__.__init__.__globals__}}).",
                "4. Execute system commands using available class methods.",
            ],
            "prevention": "Never concatenate user input into templates; pass them as variables to the template rendering function.",
        },
    }
    content = education_db.get(vuln_class.lower())
    if not content:
        raise HTTPException(status_code=404, detail="Educational content not found for this class")
    return content


@router.get("/engagements/{session_id}/waf-profiles")
async def get_waf_profiles(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Return only observed WAF profiles for this engagement."""
    await assert_engagement_access(operator, session_id)
    # No signed, tenant-scoped WAF observation store is wired to this route.
    # An empty list would imply that a real observation found no WAF.
    raise HTTPException(status_code=503, detail="WAF telemetry unavailable")
