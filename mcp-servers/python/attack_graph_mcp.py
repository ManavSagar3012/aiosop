"""
Attack Graph MCP Server (Production Implementation)
Provides secure, parameterized, and authenticated graph operations over Neo4j.
"""

import sys
import os
import uuid
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel

from ai_osop.core.config import settings
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.models import Vulnerability, AttackPath

app = FastAPI(title="Attack Graph MCP Server")
graph_memory: Optional[GraphMemory] = None


async def verify_mcp_token(authorization: Optional[str] = Header(None)):
    """Enforce strict bearer token verification."""
    expected = settings.api_token or os.getenv("OSOP_API_TOKEN")
    if not expected:
        if settings.environment in ("production", "prod"):
            raise HTTPException(status_code=401, detail="Authentication is not configured")
        return

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing Authorization header")

    token = authorization.split(" ", 1)[1]
    import hmac
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.on_event("startup")
async def startup():
    global graph_memory
    graph_memory = GraphMemory()
    await graph_memory.connect()


@app.on_event("shutdown")
async def shutdown():
    global graph_memory
    if graph_memory:
        await graph_memory.close()


@app.get("/health")
async def health():
    if not graph_memory or graph_memory._driver is None:
        raise HTTPException(status_code=503, detail="Neo4j connection not ready")
    return {"status": "ready", "server": "attack-graph-mcp", "is_stub": False}


class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None


@app.post("/mcp/initialize")
async def mcp_initialize(authenticated: None = Depends(verify_mcp_token)):
    return {
        "server_id": "attack-graph-mcp",
        "version": "1.0",
        "status": "ready",
        "capabilities": ["tools"],
        "tools": [
            {
                "name": "get_asset_neighbors",
                "description": "Retrieve adjacent nodes and relationship types for a specific node.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {"name": "node_id", "type": "string", "required": True},
                ],
                "returns": {"status": "string", "result": "array"},
            },
            {
                "name": "get_attack_paths",
                "description": "Find path from entry node to goal node types.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {"name": "entry_node_id", "type": "string", "required": True},
                    {"name": "goal_types", "type": "array", "items": {"type": "string"}, "required": True},
                    {"name": "max_depth", "type": "integer", "required": False},
                ],
                "returns": {"status": "string", "result": "array"},
            },
            {
                "name": "upsert_verified_finding",
                "description": "Add or update a verified vulnerability finding in the attack graph.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {"name": "finding", "type": "object", "required": True},
                ],
                "returns": {"status": "string", "result": "string"},
            },
            {
                "name": "get_graph_summary",
                "description": "Retrieve high-level node and edge statistics for an engagement.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                ],
                "returns": {"status": "string", "result": "object"},
            }
        ]
    }


@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest, authenticated: None = Depends(verify_mcp_token)):
    request_id = req.request_id or str(uuid.uuid4())
    params = req.parameters or {}

    if not graph_memory:
        return {
            "request_id": request_id,
            "status": "error",
            "error": "GraphMemory connection not initialized",
        }

    engagement_id = params.get("engagement_id")
    if not engagement_id:
        return {
            "request_id": request_id,
            "status": "error",
            "error": "engagement_id parameter is required",
        }

    if req.tool_name == "get_asset_neighbors":
        node_id = params.get("node_id")
        if not node_id:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "node_id parameter is required",
            }
        try:
            cypher = """
            MATCH (n {id: $node_id, engagement_id: $engagement_id})-[r]-(m {engagement_id: $engagement_id})
            RETURN n.id AS source, type(r) AS relationship, m.id AS target, labels(m) AS target_labels
            LIMIT 100
            """
            async with graph_memory._driver.session() as session:
                res = await session.run(cypher, {"node_id": node_id, "engagement_id": engagement_id})
                records = await res.data()
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"neighbors": records},
            }
        except Exception as e:  # noqa: BLE001
            return {
                "request_id": request_id,
                "status": "error",
                "error": f"Failed to retrieve neighbors: {e}",
            }

    elif req.tool_name == "get_attack_paths":
        entry_node_id = params.get("entry_node_id")
        goal_types = params.get("goal_types")
        max_depth = params.get("max_depth", 5)

        if not entry_node_id or not goal_types:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "entry_node_id and goal_types parameters are required",
            }
        try:
            paths = await graph_memory.find_attack_paths(
                entry_node_id=entry_node_id,
                goal_types=list(goal_types),
                max_depth=int(max_depth),
                engagement_id=engagement_id,
            )
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"paths": [p.model_dump() for p in paths]},
            }
        except Exception as e:  # noqa: BLE001
            return {
                "request_id": request_id,
                "status": "error",
                "error": f"Failed to find attack paths: {e}",
            }

    elif req.tool_name == "upsert_verified_finding":
        finding_data = params.get("finding")
        if not finding_data:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "finding parameter is required",
            }
        try:
            finding_data["engagement_id"] = engagement_id
            vuln = Vulnerability(**finding_data)
            vuln_id = await graph_memory.add_vulnerability(vuln)
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"vulnerability_id": vuln_id},
            }
        except Exception as e:  # noqa: BLE001
            return {
                "request_id": request_id,
                "status": "error",
                "error": f"Failed to upsert finding: {e}",
            }

    elif req.tool_name == "get_graph_summary":
        try:
            stats = await graph_memory.get_graph_stats(engagement_id)
            return {
                "request_id": request_id,
                "status": "success",
                "result": stats,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "request_id": request_id,
                "status": "error",
                "error": f"Failed to retrieve graph summary: {e}",
            }

    return {
        "request_id": request_id,
        "status": "error",
        "error": f"Unknown tool: {req.tool_name}",
    }


if __name__ == "__main__":
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8093)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
