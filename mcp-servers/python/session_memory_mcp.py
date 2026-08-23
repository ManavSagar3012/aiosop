"""
Session Memory MCP Server - REAL IMPLEMENTATION
Provides tool-based access to session memory with Redis/PostgreSQL persistence.
Supports session state management, audit logging, and checkpoint creation.
"""

import os
import sys
import uuid
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# Add src to path for importing ai_osop modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

app = FastAPI(title="Session Memory MCP Server")

# Redis connection
redis_client = None
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))

if REDIS_AVAILABLE:
    try:
        redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
        redis_client.ping()
        print(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
    except Exception as e:
        print(f"Redis connection failed: {e}. Using in-memory storage.")
        redis_client = None

# In-memory fallback storage
_memory_store: Dict[str, Dict[str, Any]] = {}
_audit_log: List[Dict[str, Any]] = []
_checkpoints: Dict[str, Dict[str, Any]] = {}

def _get_redis_key(session_id: str, key_type: str = "session") -> str:
    """Generate Redis key for session data."""
    return f"ai_osop:{key_type}:{session_id}"

def _store_in_backend(session_id: str, data: Dict[str, Any], key_type: str = "session") -> bool:
    """Store data in Redis or fallback to memory."""
    if redis_client:
        try:
            redis_key = _get_redis_key(session_id, key_type)
            redis_client.setex(redis_key, 86400, json.dumps(data))  # 24h TTL
            return True
        except Exception as e:
            print(f"Redis store failed: {e}")
    
    # Fallback to memory
    if key_type == "session":
        _memory_store[session_id] = data
    elif key_type == "checkpoint":
        _checkpoints[session_id] = data
    return True

def _retrieve_from_backend(session_id: str, key_type: str = "session") -> Optional[Dict[str, Any]]:
    """Retrieve data from Redis or fallback to memory."""
    if redis_client:
        try:
            redis_key = _get_redis_key(session_id, key_type)
            data = redis_client.get(redis_key)
            if data:
                return json.loads(data)
        except Exception as e:
            print(f"Redis retrieve failed: {e}")
    
    # Fallback to memory
    if key_type == "session":
        return _memory_store.get(session_id)
    elif key_type == "checkpoint":
        return _checkpoints.get(session_id)
    return None

def _write_audit_event(event: Dict[str, Any]) -> None:
    """Write audit event to Redis list or memory."""
    if redis_client:
        try:
            redis_client.lpush("ai_osop:audit_log", json.dumps(event))
            redis_client.ltrim("ai_osop:audit_log", 0, 9999)  # Keep last 10k events
            return
        except Exception as e:
            print(f"Redis audit write failed: {e}")
    
    # Fallback to memory
    _audit_log.append(event)
    if len(_audit_log) > 10000:
        _audit_log.pop(0)

def _query_audit_events(engagement_id: str, event_types: Optional[List[str]] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Query audit events from Redis or memory."""
    results = []
    
    if redis_client:
        try:
            events = redis_client.lrange("ai_osop:audit_log", 0, -1)
            for event_json in events:
                event = json.loads(event_json)
                if event.get("engagement_id") == engagement_id:
                    if event_types is None or event.get("event_type") in event_types:
                        results.append(event)
                        if len(results) >= limit:
                            break
            return results
        except Exception as e:
            print(f"Redis audit query failed: {e}")
    
    # Fallback to memory
    for event in reversed(_audit_log):
        if event.get("engagement_id") == engagement_id:
            if event_types is None or event.get("event_type") in event_types:
                results.append(event)
                if len(results) >= limit:
                    break
    return results

@app.get("/health")
async def health():
    redis_status = "disconnected"
    if redis_client:
        try:
            redis_client.ping()
            redis_status = "connected"
        except:
            redis_status = "error"
    
    return {
        "status": "ready",
        "server": "session-memory-mcp",
        "redis_available": REDIS_AVAILABLE,
        "redis_status": redis_status,
        "storage_backend": "redis" if redis_client else "memory"
    }

class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None

@app.post("/mcp/initialize")
async def mcp_initialize():
    return {
        "server_id": "session-memory-mcp",
        "version": "2.0",
        "capabilities": ["session_storage", "audit_logging", "checkpointing"],
        "tools": [
            {
                "name": "get_session_state",
                "description": "Retrieve current engagement phase and scope from persistent storage.",
                "parameters": [{"name": "session_id", "type": "string", "required": True}]
            },
            {
                "name": "store_session_state",
                "description": "Persist session state to Redis/memory with TTL.",
                "parameters": [
                    {"name": "session_id", "type": "string", "required": True},
                    {"name": "state", "type": "object", "required": True},
                    {"name": "ttl_seconds", "type": "integer", "required": False}
                ]
            },
            {
                "name": "store_checkpoint",
                "description": "Create a restorable checkpoint of the mission state.",
                "parameters": [
                    {"name": "session_id", "type": "string", "required": True},
                    {"name": "checkpoint_data", "type": "object", "required": True},
                    {"name": "label", "type": "string", "required": False}
                ]
            },
            {
                "name": "restore_checkpoint",
                "description": "Restore session state from a checkpoint.",
                "parameters": [
                    {"name": "session_id", "type": "string", "required": True},
                    {"name": "checkpoint_id", "type": "string", "required": True}
                ]
            },
            {
                "name": "write_audit_event",
                "description": "Log an audit event for compliance and replay.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {"name": "event_type", "type": "string", "required": True},
                    {"name": "data", "type": "object", "required": True}
                ]
            },
            {
                "name": "query_audit_log",
                "description": "Query audit events by engagement ID and event type.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {"name": "event_types", "type": "array", "required": False},
                    {"name": "limit", "type": "integer", "required": False}
                ]
            }
        ]
    }

@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest):
    request_id = req.request_id or str(uuid.uuid4())
    params = req.parameters or {}
    
    if req.tool_name == "get_session_state":
        session_id = params.get("session_id", "")
        if not session_id:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "session_id is required"
            }
        
        state = _retrieve_from_backend(session_id, "session")
        if state:
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"session_id": session_id, "state": state, "retrieved_at": datetime.utcnow().isoformat() + "Z"}
            }
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Session not found: {session_id}"
        }
    
    elif req.tool_name == "store_session_state":
        session_id = params.get("session_id", "")
        state = params.get("state", {})
        ttl = params.get("ttl_seconds", 86400)
        
        if not session_id:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "session_id is required"
            }
        
        state["updated_at"] = datetime.utcnow().isoformat() + "Z"
        success = _store_in_backend(session_id, state, "session")
        
        return {
            "request_id": request_id,
            "status": "success" if success else "error",
            "result": {"session_id": session_id, "stored": success}
        }
    
    elif req.tool_name == "store_checkpoint":
        session_id = params.get("session_id", "")
        checkpoint_data = params.get("checkpoint_data", {})
        label = params.get("label", f"checkpoint_{int(time.time())}")
        
        if not session_id:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "session_id is required"
            }
        
        checkpoint_id = str(uuid.uuid4())
        checkpoint = {
            "checkpoint_id": checkpoint_id,
            "session_id": session_id,
            "label": label,
            "data": checkpoint_data,
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
        
        # Store checkpoint
        checkpoint_key = f"{session_id}:{checkpoint_id}"
        _store_in_backend(checkpoint_key, checkpoint, "checkpoint")
        
        # Also index by session
        session_checkpoints = _retrieve_from_backend(session_id, "checkpoint_index") or []
        session_checkpoints.append(checkpoint_id)
        _store_in_backend(session_id, {"checkpoint_ids": session_checkpoints}, "checkpoint_index")
        
        return {
            "request_id": request_id,
            "status": "success",
            "result": {"checkpoint_id": checkpoint_id, "session_id": session_id, "label": label}
        }
    
    elif req.tool_name == "restore_checkpoint":
        session_id = params.get("session_id", "")
        checkpoint_id = params.get("checkpoint_id", "")
        
        if not session_id or not checkpoint_id:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "session_id and checkpoint_id are required"
            }
        
        checkpoint_key = f"{session_id}:{checkpoint_id}"
        checkpoint = _retrieve_from_backend(checkpoint_key, "checkpoint")
        
        if checkpoint:
            # Restore the session state
            _store_in_backend(session_id, checkpoint.get("data", {}), "session")
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"restored": True, "checkpoint_id": checkpoint_id}
            }
        
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Checkpoint not found: {checkpoint_id}"
        }
    
    elif req.tool_name == "write_audit_event":
        engagement_id = params.get("engagement_id", "")
        event_type = params.get("event_type", "")
        event_data = params.get("data", {})
        
        if not engagement_id or not event_type:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "engagement_id and event_type are required"
            }
        
        event = {
            "event_id": str(uuid.uuid4()),
            "engagement_id": engagement_id,
            "event_type": event_type,
            "data": event_data,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        _write_audit_event(event)
        
        return {
            "request_id": request_id,
            "status": "success",
            "result": {"event_id": event["event_id"], "written": True}
        }
    
    elif req.tool_name == "query_audit_log":
        engagement_id = params.get("engagement_id", "")
        event_types = params.get("event_types")
        limit = params.get("limit", 100)
        
        if not engagement_id:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "engagement_id is required"
            }
        
        events = _query_audit_events(engagement_id, event_types, limit)
        
        return {
            "request_id": request_id,
            "status": "success",
            "result": {"events": events, "count": len(events), "engagement_id": engagement_id}
        }
    
    return {
        "request_id": request_id,
        "status": "error",
        "error": f"Unknown tool: {req.tool_name}"
    }

if __name__ == "__main__":
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    print(f"Starting Session Memory MCP server (Redis: {REDIS_AVAILABLE}, Backend: {'redis' if redis_client else 'memory'})...")
    uvicorn.run(app, host="0.0.0.0", port=args.port)
