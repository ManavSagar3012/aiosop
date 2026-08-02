"""
Session Memory MCP Server (Production Implementation)
Provides secure, scope-aware, and authenticated access to session state and checkpoints.
"""

import sys
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel

from ai_osop.core.config import settings
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.core.models import AuditEvent

app = FastAPI(title="Session Memory MCP Server")
memory: Optional[SessionMemory] = None


async def verify_mcp_token(authorization: Optional[str] = Header(None)):
    """Enforce strict bearer token verification."""
    expected = settings.api_token or os.getenv("OSOP_API_TOKEN")
    if not expected:
        # If no auth token is configured, fail closed in production
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
    global memory
    memory = SessionMemory()
    await memory.connect()


@app.on_event("shutdown")
async def shutdown():
    global memory
    if memory:
        await memory.close()


@app.get("/health")
async def health():
    if not memory or memory._redis is None:
        raise HTTPException(status_code=503, detail="Database connection not ready")
    return {"status": "ready", "server": "session-memory-mcp", "is_stub": False}


class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None


@app.post("/mcp/initialize")
async def mcp_initialize(authenticated: None = Depends(verify_mcp_token)):
    return {
        "server_id": "session-memory-mcp",
        "version": "1.0",
        "status": "ready",
        "capabilities": ["tools"],
        "tools": [
            {
                "name": "get_session_state",
                "description": "Retrieve current engagement phase and scope.",
                "parameters": [{"name": "session_id", "type": "string", "required": True}],
                "returns": {"status": "string", "result": "object"},
            },
            {
                "name": "store_checkpoint",
                "description": "Create a restorable checkpoint of the mission state.",
                "parameters": [
                    {"name": "session_id", "type": "string", "required": True},
                    {"name": "metadata", "type": "object", "required": False},
                ],
                "returns": {"status": "string", "result": "object"},
            }
        ]
    }


@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest, authenticated: None = Depends(verify_mcp_token)):
    request_id = req.request_id or str(uuid.uuid4())
    params = req.parameters or {}

    if not memory:
        return {
            "request_id": request_id,
            "status": "error",
            "error": "SessionMemory database connection not initialized",
        }

    if req.tool_name == "get_session_state":
        session_id = params.get("session_id")
        if not session_id:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "session_id parameter is required",
            }
        try:
            state = await memory.get_session_state(session_id)
            if not state:
                return {
                    "request_id": request_id,
                    "status": "success",
                    "result": {"found": False, "state": None},
                }
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"found": True, "state": state.model_dump()},
            }
        except Exception as e:  # noqa: BLE001
            return {
                "request_id": request_id,
                "status": "error",
                "error": f"Failed to retrieve session state: {e}",
            }

    elif req.tool_name == "store_checkpoint":
        session_id = params.get("session_id")
        metadata = params.get("metadata") or {}
        if not session_id:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "session_id parameter is required",
            }
        try:
            checkpoint_id = await memory.create_checkpoint(session_id, metadata)
            
            # Emit audit event
            event = AuditEvent(
                event_type="session_checkpoint_created",
                severity="info",
                actor_type="system",
                actor_id="mcp-session-memory",
                action={"method": "store_checkpoint", "session_id": session_id},
                result={"status": "success", "checkpoint_id": checkpoint_id},
                context=metadata,
                engagement_id=session_id,
            )
            await memory.write_audit_event(event)

            return {
                "request_id": request_id,
                "status": "success",
                "result": {
                    "checkpoint_id": checkpoint_id,
                    "session_id": session_id,
                    "status": "created",
                },
            }
        except Exception as e:  # noqa: BLE001
            return {
                "request_id": request_id,
                "status": "error",
                "error": f"Failed to store checkpoint: {e}",
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
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
