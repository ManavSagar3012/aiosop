"""
Reporting MCP Server
Reserved reporting MCP facade. No reporting engine is wired into this server.
Do not mistake a synthetic URL for a generated report.
"""

import uuid
import re
from typing import Any, Dict, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

app = FastAPI(title="Reporting MCP Server")


@app.get("/health")
async def health():
    return JSONResponse(
        status_code=503,
        content={"status": "unavailable", "server": "reporting-mcp"},
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
        "server_id": "reporting-mcp",
        "version": "1.0",
        "capabilities": ["unimplemented"],
        "status": "unavailable",
        "tools": [
            {
                "name": "compile_findings",
                "description": "UNAVAILABLE: no signed reporting engine is connected to this facade.",
                "parameters": [
                    {
                        "name": "engagement_id",
                        "type": "string",
                        "description": "Signed engagement reference",
                        "required": True,
                    },
                    {
                        "name": "format",
                        "type": "string",
                        "description": "Requested report encoding",
                        "enum": ["markdown", "html", "json"],
                        "required": False,
                    },
                ],
                "returns": {
                    "type": "object",
                    "description": "Unavailable until backed by signed reporting evidence",
                },
                "side_effect_class": "READ_ONLY",
                "requires_approval": True,
                "scope_check": True,
            }
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
    parser.add_argument("--port", type=int, default=8092)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
