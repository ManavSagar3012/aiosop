"""
Session Memory MCP Server
Reserved session-memory MCP facade. No authoritative storage is connected.
"""

import uuid
import re
from typing import Any, Dict, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

app = FastAPI(title="Session Memory MCP Server")


@app.get("/health")
async def health():
    return JSONResponse(
        status_code=503,
        content={"status": "unavailable", "server": "session-memory-mcp"},
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
        "server_id": "session-memory-mcp",
        "version": "1.0",
        "capabilities": ["unimplemented"],
        "status": "unavailable",
        "tools": [
            {
                "name": "get_session_state",
                "description": "UNAVAILABLE: no authoritative session storage is connected.",
                "parameters": [
                    {
                        "name": "session_id",
                        "type": "string",
                        "description": "Signed session reference",
                        "required": True,
                    }
                ],
                "returns": {
                    "type": "object",
                    "description": "Unavailable without signed session storage",
                },
                "side_effect_class": "READ_ONLY",
                "requires_approval": True,
                "scope_check": True,
            },
            {
                "name": "store_checkpoint",
                "description": "UNAVAILABLE: no durable checkpoint writer is connected.",
                "parameters": [
                    {
                        "name": "session_id",
                        "type": "string",
                        "description": "Signed session reference",
                        "required": True,
                    },
                    {
                        "name": "metadata",
                        "type": "object",
                        "description": "Inert metadata only",
                        "required": False,
                    },
                ],
                "returns": {
                    "type": "object",
                    "description": "Unavailable without a durable checkpoint writer",
                },
                "side_effect_class": "RECON_ACTIVE",
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
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
