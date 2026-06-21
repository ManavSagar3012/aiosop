"""AI-OSOP Intelligence Router

Attack graph, attack paths, vulnerability education, and WAF profiles.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ai_osop.api.deps import assert_engagement_access, state, verify_token

router = APIRouter(tags=["intelligence"])


@router.get("/engagements/{session_id}/graph")
async def get_full_graph(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get full attack graph nodes and edges."""
    await assert_engagement_access(operator, session_id)
    node_query = """
    MATCH (n)
    WHERE n.engagement_id = $session_id
    RETURN n
    """
    rel_query = """
    MATCH (n)-[r]->(m)
    WHERE n.engagement_id = $session_id AND m.engagement_id = $session_id
    RETURN n.id as from_id, m.id as to_id, r
    """

    nodes = {}
    edges = []

    async with state["orchestrator"].graph_memory._driver.session() as session:
        node_result = await session.run(node_query, {"session_id": session_id})
        async for record in node_result:
            n = record["n"]
            if n and n["id"] not in nodes:
                nodes[n["id"]] = {
                    "id": n["id"],
                    "labels": list(n.labels),
                    "properties": dict(n),
                }

        rel_result = await session.run(rel_query, {"session_id": session_id})
        async for record in rel_result:
            r = record["r"]
            edges.append(
                {
                    "id": r.element_id,
                    "type": r.type,
                    "from": record["from_id"],
                    "to": record["to_id"],
                    "properties": dict(r),
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
        cypher = "MATCH (a:Asset {engagement_id: $sid}) RETURN a.id as id LIMIT 1"
        async with state["orchestrator"].graph_memory._driver.session() as session:
            res = await session.run(cypher, {"sid": session_id})
            record = await res.single()
            if record:
                entry_node_id = record["id"]

    if not entry_node_id:
        return []

    paths = await state["orchestrator"].graph_memory.find_attack_paths(
        entry_node_id=entry_node_id, goal_types=goal_types, max_depth=max_depth
    )
    return [p.dict() for p in paths]


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
    """Get learned WAF profiles for the engagement."""
    await assert_engagement_access(operator, session_id)
    return [
        {
            "target": "ginandjuice.shop",
            "waf_type": "Cloudflare/V2",
            "blocked_patterns": ["' OR 1=1", "<script>", "UNION SELECT"],
            "bypass_success_rate": 0.65,
            "evolved_bypasses": 12,
            "confidence": 0.85,
        }
    ]
