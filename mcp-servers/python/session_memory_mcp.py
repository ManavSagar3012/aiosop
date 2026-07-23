"""
Session Memory MCP Server (Production Implementation)
Provides secure, authenticated, multi-tier session state operations over Redis + PostgreSQL.
"""

import sys
import os
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel

from ai_osop.core.config import settings
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.core.models import AuditEvent

app = FastAPI(title="Session Memory MCP Server")

session_memory: Optional[SessionMemory] = None


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
    global session_memory
    session_memory = SessionMemory()
    await session_memory.connect()


@app.on_event("shutdown")
async def shutdown():
    global session_memory
    if session_memory:
        await session_memory.close()


@app.get("/health")
async def health():
    if not session_memory:
        raise HTTPException(status_code=503, detail="SessionMemory not initialized")
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
                "description": "Retrieve session state by session_id or engagement_id.",
                "parameters": [
                    {"name": "session_id", "type": "string", "required": True},
                    {
                        "name": "use_engagement_id",
                        "type": "boolean",
                        "required": False,
                        "description": "If true, session_id is treated as engagement_id",
                    },
                ],
                "returns": {"status": "string", "result": "object"},
            },
            {
                "name": "store_checkpoint",
                "description": "Create a durable session checkpoint in Redis + PostgreSQL.",
                "parameters": [
                    {"name": "session_id", "type": "string", "required": True},
                    {"name": "metadata", "type": "object", "required": False},
                ],
                "returns": {"status": "string", "result": "object"},
            },
            {
                "name": "write_audit_event",
                "description": "Write a cryptographically signed audit event to PostgreSQL.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {"name": "event_type", "type": "string", "required": True},
                    {"name": "severity", "type": "string", "required": True},
                    {"name": "actor_type", "type": "string", "required": True},
                    {"name": "actor_id", "type": "string", "required": True},
                    {"name": "action", "type": "object", "required": False},
                    {"name": "result", "type": "object", "required": False},
                    {"name": "context", "type": "object", "required": False},
                ],
                "returns": {"status": "string", "result": "string"},
            },
            {
                "name": "query_audit_log",
                "description": "Query audit events with optional filters.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {"name": "event_types", "type": "array", "required": False},
                    {"name": "start_time", "type": "string", "required": False},
                    {"name": "end_time", "type": "string", "required": False},
                    {"name": "limit", "type": "integer", "required": False},
                ],
                "returns": {"status": "string", "result": "array"},
            },
            {
                "name": "list_pending_approvals",
                "description": "List all pending approval requests.",
                "parameters": [],
                "returns": {"status": "string", "result": "array"},
            },
            {
                "name": "list_all_sessions",
                "description": "List all active session keys from Redis.",
                "parameters": [],
                "returns": {"status": "string", "result": "array"},
            },
            {
                "name": "get_dlq_entry",
                "description": "Retrieve a DLQ entry by ID with Redis cache fallback.",
                "parameters": [
                    {"name": "entry_id", "type": "string", "required": True},
                ],
                "returns": {"status": "string", "result": "object"},
            },
            {
                "name": "list_dlq_entries",
                "description": "List DLQ entries with optional engagement and status filters.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": False},
                    {"name": "status", "type": "string", "required": False},
                ],
                "returns": {"status": "string", "result": "array"},
            },
            {
                "name": "store_agent_state",
                "description": "Store agent working memory in Redis.",
                "parameters": [
                    {"name": "agent_id", "type": "string", "required": True},
                    {"name": "state", "type": "object", "required": True},
                    {"name": "ttl", "type": "integer", "required": False},
                ],
                "returns": {"status": "string", "result": "string"},
            },
            {
                "name": "get_agent_state",
                "description": "Retrieve agent working memory from Redis.",
                "parameters": [
                    {"name": "agent_id", "type": "string", "required": True},
                ],
                "returns": {"status": "string", "result": "object"},
            },
            {
                "name": "get_all_busy_agents",
                "description": "Return all currently claimed agent IDs from Redis.",
                "parameters": [],
                "returns": {"status": "string", "result": "array"},
            },
        ],
    }


@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest, authenticated: None = Depends(verify_mcp_token)):
    request_id = req.request_id or str(uuid.uuid4())
    params = req.parameters or {}

    if not session_memory:
        return {
            "request_id": request_id,
            "status": "error",
            "error": "SessionMemory connection not initialized",
        }

    tool = req.tool_name

    try:
        if tool == "get_session_state":
            session_id = params.get("session_id")
            if not session_id:
                return {
                    "request_id": request_id,
                    "status": "error",
                    "error": "session_id parameter is required",
                }
            use_engagement = params.get("use_engagement_id", False)
            if use_engagement:
                state = await session_memory.get_session_state_by_engagement_id(session_id)
            else:
                state = await session_memory.get_session_state(session_id)
            if state:
                return {
                    "request_id": request_id,
                    "status": "success",
                    "result": state.model_dump(mode="json"),
                }
            return {"request_id": request_id, "status": "success", "result": None}

        elif tool == "store_checkpoint":
            session_id = params.get("session_id")
            if not session_id:
                return {
                    "request_id": request_id,
                    "status": "error",
                    "error": "session_id parameter is required",
                }
            metadata = params.get("metadata", {})
            checkpoint_id = await session_memory.create_checkpoint(session_id, metadata)
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"checkpoint_id": checkpoint_id},
            }

        elif tool == "write_audit_event":
            engagement_id = params.get("engagement_id")
            event_type = params.get("event_type")
            severity = params.get("severity")
            actor_type = params.get("actor_type")
            actor_id = params.get("actor_id")
            if not all([engagement_id, event_type, severity, actor_type, actor_id]):
                return {
                    "request_id": request_id,
                    "status": "error",
                    "error": "engagement_id, event_type, severity, actor_type, actor_id are required",
                }
            event = AuditEvent(
                event_id=f"evt-{uuid.uuid4().hex[:12]}",
                timestamp=datetime.utcnow(),
                event_type=event_type,
                severity=severity,
                actor_type=actor_type,
                actor_id=actor_id,
                action=params.get("action", {}),
                result=params.get("result", {}),
                context=params.get("context", {}),
                engagement_id=engagement_id,
            )
            await session_memory.write_audit_event(event)
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"event_id": event.event_id},
            }

        elif tool == "query_audit_log":
            engagement_id = params.get("engagement_id")
            if not engagement_id:
                return {
                    "request_id": request_id,
                    "status": "error",
                    "error": "engagement_id parameter is required",
                }
            event_types = params.get("event_types")
            start_time = params.get("start_time")
            end_time = params.get("end_time")
            limit = params.get("limit", 1000)

            start_dt = datetime.fromisoformat(start_time) if start_time else None
            end_dt = datetime.fromisoformat(end_time) if end_time else None

            events = await session_memory.query_audit_log(
                engagement_id=engagement_id,
                event_types=event_types,
                start_time=start_dt,
                end_time=end_dt,
                limit=int(limit),
            )
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"events": [e.model_dump(mode="json") for e in events]},
            }

        elif tool == "list_pending_approvals":
            approvals = await session_memory.list_pending_approvals()
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"approvals": [a.model_dump(mode="json") for a in approvals]},
            }

        elif tool == "list_all_sessions":
            keys = await session_memory.list_all_sessions()
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"sessions": list(keys)},
            }

        elif tool == "get_dlq_entry":
            entry_id = params.get("entry_id")
            if not entry_id:
                return {
                    "request_id": request_id,
                    "status": "error",
                    "error": "entry_id parameter is required",
                }
            entry = await session_memory.get_dlq_entry(entry_id)
            if entry:
                return {
                    "request_id": request_id,
                    "status": "success",
                    "result": entry.model_dump(mode="json"),
                }
            return {"request_id": request_id, "status": "success", "result": None}

        elif tool == "list_dlq_entries":
            engagement_id = params.get("engagement_id")
            status = params.get("status")
            entries = await session_memory.list_dlq_entries(
                engagement_id=engagement_id, status=status
            )
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"entries": [e.model_dump(mode="json") for e in entries]},
            }

        elif tool == "store_agent_state":
            agent_id = params.get("agent_id")
            state = params.get("state")
            if not agent_id or state is None:
                return {
                    "request_id": request_id,
                    "status": "error",
                    "error": "agent_id and state parameters are required",
                }
            ttl = params.get("ttl", 3600)
            await session_memory.store_agent_state(agent_id, state, ttl=int(ttl))
            return {"request_id": request_id, "status": "success", "result": {"agent_id": agent_id}}

        elif tool == "get_agent_state":
            agent_id = params.get("agent_id")
            if not agent_id:
                return {
                    "request_id": request_id,
                    "status": "error",
                    "error": "agent_id parameter is required",
                }
            state = await session_memory.get_agent_state(agent_id)
            return {"request_id": request_id, "status": "success", "result": state}

        elif tool == "get_all_busy_agents":
            agents = await session_memory.get_all_busy_agents()
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"agents": list(agents)},
            }

        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Unknown tool: {tool}",
        }

    except Exception as e:  # noqa: BLE001
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
        }


if __name__ == "__main__":
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
