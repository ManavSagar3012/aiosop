"""AI-OSOP Intelligence Router

Attack graph, attack paths, vulnerability education, and WAF profiles.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ai_osop.api.deps import assert_engagement_access, engagement_id_forms, state, verify_token
from ai_osop.core.hypothesis_engine import HypothesisEngine

router = APIRouter(tags=["intelligence"])


@router.get("/engagements/{session_id}/graph")
async def get_full_graph(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get full attack graph nodes and edges."""
    session = await assert_engagement_access(operator, session_id)
    forms = engagement_id_forms(session, session_id)
    nodes = {}
    edges = []

    # AIOSOP-GRAPHVIZ-001 (2026-07-03): the graph_memory methods return FLATTENED
    # records — nodes as {id, labels, properties}, edges as {source, target, type}
    # (this is the established contract; reporting_agent.py consumes the same shape).
    # This router previously read record.get("n") / record.get("r") — keys that never
    # exist in those records — so it silently produced an EMPTY graph for EVERY
    # engagement while the DB held live nodes (runtime-proven: 124 nodes returned by
    # the query, 0 rendered). Parse the real shape so the dashboard graph reflects
    # live execution.
    node_records = await state["orchestrator"].graph_memory.get_all_nodes_for_engagement(*forms)
    for record in node_records:
        nid = record.get("id")
        if nid is None or nid in nodes:
            continue
        nodes[nid] = {
            "id": nid,
            "labels": list(record.get("labels") or []),
            "properties": record.get("properties") or {},
        }

    edge_records = await state["orchestrator"].graph_memory.get_all_edges_for_engagement(*forms)
    for record in edge_records:
        src = record.get("source")
        tgt = record.get("target")
        if src is None or tgt is None:
            continue
        edges.append(
            {
                "id": f"{src}->{tgt}:{record.get('type')}",
                "type": record.get("type"),
                "from": src,
                "to": tgt,
                "properties": {},
            }
        )

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
    await assert_engagement_access(operator, session_id)
    if goal_types is None:
        goal_types = ["rce", "admin_access", "data_exfiltration"]

    if not entry_node_id:
        asset_records = await state["orchestrator"].graph_memory.run_read_query(
            "MATCH (a:Asset {engagement_id: $sid}) RETURN a.id as id LIMIT 1",
            {"sid": session_id},
        )
        if asset_records:
            entry_node_id = asset_records[0].get("id")

    if not entry_node_id:
        return []

    paths = await state["orchestrator"].graph_memory.find_attack_paths(
        entry_node_id=entry_node_id, goal_types=goal_types, max_depth=max_depth
    )
    return [p.model_dump() for p in paths]


@router.get("/engagements/{session_id}/hypotheses")
async def get_hypotheses(
    session_id: str,
    refresh: bool = Query(False),
    limit: int = Query(8, ge=1, le=50),
    focus: str = Query(""),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Generate or return graph-native hypotheses for an engagement."""
    session = await assert_engagement_access(operator, session_id)
    forms = engagement_id_forms(session, session_id)
    orch = state["orchestrator"]
    engine = HypothesisEngine(
        orch.graph_memory,
        state.get("skill_engine"),
        session_memory=getattr(orch, "session_memory", None),
    )

    if refresh:
        hypotheses = await engine.generate_and_persist(session_id, focus=focus, limit=limit)
    else:
        stored = await orch.graph_memory.get_hypotheses_by_engagement(*forms)
        hypotheses = [dict(item) for item in stored[:limit]]
        if not hypotheses:
            hypotheses = [
                h.model_dump()
                for h in await engine.generate_hypotheses(session_id, focus=focus, limit=limit)
            ]

    return {"session_id": session_id, "count": len(hypotheses), "hypotheses": hypotheses}


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
    """Get WAF profiles actually detected for the engagement (from the graph).

    FIX (audit 2026-08-01): this endpoint previously returned a HARDCODED,
    fabricated profile for "ginandjuice.shop" regardless of input — the operator
    console was showing canned WAF intel for a target that may not even be in
    scope, presented as a real detection. Now it queries the graph for Asset /
    Endpoint nodes that actually carry a detected WAF, and reports NOTHING (an
    empty profile count) when no WAF was observed — never invented data.
    """
    session = await assert_engagement_access(operator, session_id)
    forms = engagement_id_forms(session, session_id)
    gm = state["orchestrator"].graph_memory
    try:
        assets = await gm.run_read_query(
            "MATCH (a:Asset) WHERE a.engagement_id IN $ids AND a.waf IS NOT NULL "
            "RETURN a.value AS target, a.waf AS waf_type LIMIT 200",
            {"ids": forms},
        )
    except Exception as e:  # noqa: BLE001 - report empty rather than 500 the console
        logger.warning("waf_profiles_query_failed", session_id=session_id, error=str(e))
        assets = []
    profiles = [
        {
            "target": a.get("target"),
            "waf_type": a.get("waf_type"),
            "confidence": None,  # not yet measured per-detection; unknown, not fabricated
            "source": "runtime-detection",
        }
        for a in (assets or [])
    ]
    return {"session_id": session_id, "count": len(profiles), "profiles": profiles}
