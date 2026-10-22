"""
Attack Graph MCP Server
Reserved attack-graph MCP facade. No tenant-scoped Neo4j query client is wired.
"""

import uuid
import re
from typing import Any, Dict, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

app = FastAPI(title="Attack Graph MCP Server")


@app.get("/health")
async def health():
    return JSONResponse(
        status_code=503,
        content={"status": "unavailable", "server": "attack-graph-mcp"},
    )


class MCPExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None
    timeout_override: Optional[int] = None


@app.post("/mcp/initialize")
async def mcp_initialize():
    return {
        "server_id": "attack-graph-mcp",
        "version": "1.0",
        "capabilities": ["unimplemented"],
        "status": "unavailable",
        "tools": [
            {
                "name": "query_graph",
                "description": "UNAVAILABLE: arbitrary Cypher is not connected to signed tenant-scoped graph authority.",
                "parameters": [
                    {
                        "name": "query",
                        "type": "string",
                        "description": "Untrusted Cypher (disabled)",
                        "required": True,
                    },
                    {
                        "name": "params",
                        "type": "object",
                        "description": "Untrusted Cypher parameters (disabled)",
                        "required": False,
                    },
                ],
                "returns": {
                    "type": "object",
                    "description": "Unavailable until independent scope checking exists",
                },
                "side_effect_class": "INVASIVE_EXPLOIT",
                "requires_approval": True,
                "scope_check": True,
            },
            {
                "name": "get_neighbors",
                "description": "UNAVAILABLE: no tenant-scoped Neo4j reader is connected.",
                "parameters": [
                    {
                        "name": "node_id",
                        "type": "string",
                        "description": "Scoped node reference",
                        "required": True,
                    }
                ],
                "returns": {
                    "type": "object",
                    "description": "Unavailable without authoritative graph reader",
                },
                "side_effect_class": "READ_ONLY",
                "requires_approval": True,
                "scope_check": True,
            },
        ],
    }


@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest):
    request_id = (
        req.request_id
        if isinstance(req.request_id, str)
        and re.fullmatch(r"req-[A-Za-z0-9_-]{1,120}", req.request_id)
        else f"req-{uuid.uuid4().hex}"
    )
    return {
        "request_id": request_id,
        "status": "error",
        "error": "server_unavailable",
    }


if __name__ == "__main__":
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8093)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
