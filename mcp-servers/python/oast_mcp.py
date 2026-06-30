# mcp-servers/python/oast_mcp.py
import argparse
import os
import threading
import time
import uuid
from typing import Any, Dict, List

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response
from pydantic import BaseModel

app = FastAPI(title="OAST Interaction MCP Server")

# In-memory, lock-guarded correlation state.
_LOCK = threading.Lock()
_TOKENS: Dict[str, Dict[str, Any]] = {}            # token -> {label, created_at}
_INTERACTIONS: Dict[str, List[Dict[str, Any]]] = {}  # token -> [interaction]
_TTL = 3600.0

# Reachability (the configurable-hybrid knob); overridden in __main__ from env/args.
PUBLIC_HOST = os.environ.get("OAST_PUBLIC_HOST", "127.0.0.1")
PORT = int(os.environ.get("OAST_PORT", "8099"))
SCHEME = os.environ.get("OAST_SCHEME", "http")

# 1x1 transparent GIF so <img>/fetch beacons get a valid response.
_GIF = bytes.fromhex(
    "47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b"
)


def _prune_locked() -> None:
    now = time.time()
    for tok in list(_TOKENS):
        if now - _TOKENS[tok]["created_at"] > _TTL:
            _TOKENS.pop(tok, None)
            _INTERACTIONS.pop(tok, None)


@app.get("/health")
async def health():
    return {"status": "ready", "server": "oast-mcp"}


@app.post("/mcp/initialize")
async def initialize():
    return {
        "server_id": "oast-mcp",
        "capabilities": ["tool"],
        "status": "ready",
        "tools": [
            {"name": "oast_register",
             "description": "Mint an OAST correlation token and callback URL.",
             "parameters": {"type": "object", "properties": {
                 "label": {"type": "string"}}, "required": []}},
            {"name": "oast_poll",
             "description": "Return captured out-of-band interactions for a token.",
             "parameters": {"type": "object", "properties": {
                 "token": {"type": "string"}}, "required": ["token"]}},
        ],
    }


class ExecuteRequest(BaseModel):
    tool_name: str
    parameters: dict
    request_id: str


@app.post("/mcp/execute")
async def execute(req: ExecuteRequest):
    p = req.parameters
    if req.tool_name == "oast_register":
        with _LOCK:
            _prune_locked()
            token = uuid.uuid4().hex[:20]
            _TOKENS[token] = {"label": p.get("label", ""), "created_at": time.time()}
            _INTERACTIONS[token] = []
        url = f"{SCHEME}://{PUBLIC_HOST}:{PORT}/{token}"
        return {"request_id": req.request_id, "status": "success",
                "result": {"token": token, "callback_url": url}}
    if req.tool_name == "oast_poll":
        token = p.get("token", "")
        with _LOCK:
            hits = list(_INTERACTIONS.get(token, []))
        return {"request_id": req.request_id, "status": "success",
                "result": {"token": token, "hit_count": len(hits), "interactions": hits}}
    return {"request_id": req.request_id, "status": "error",
            "error": f"unknown tool: {req.tool_name}"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--public-host", default=PUBLIC_HOST)
    parser.add_argument("--scheme", default=SCHEME)
    args = parser.parse_args()
    PORT = args.port
    PUBLIC_HOST = args.public_host
    SCHEME = args.scheme
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
