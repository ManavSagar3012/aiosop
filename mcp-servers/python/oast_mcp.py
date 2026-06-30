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
             "parameters": [
                 {"name": "label", "type": "string", "description": "Optional probe label", "required": False},
             ],
             "returns": {"token": "string", "callback_url": "string"}},
            {"name": "oast_poll",
             "description": "Return captured out-of-band interactions for a token.",
             "parameters": [
                 {"name": "token", "type": "string", "description": "Correlation token", "required": True},
             ],
             "returns": {"token": "string", "hit_count": "integer", "interactions": "array"}},
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


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def capture(full_path: str, request: Request):
    """Catch-all: record any inbound request as an interaction keyed by the token
    in the first path segment. A captured callback is the ground-truth signal that
    a blind vulnerability fired."""
    token = full_path.split("/", 1)[0] if full_path else ""
    if token:
        try:
            raw = await request.body()
            body_snippet = raw[:512].decode("utf-8", "replace")
        except Exception:
            body_snippet = ""
        with _LOCK:
            if token in _TOKENS:
                _INTERACTIONS.setdefault(token, []).append({
                    "ts": time.time(),
                    "method": request.method,
                    "path": "/" + full_path,
                    "source_ip": request.client.host if request.client else "",
                    "headers": {k: v for k, v in request.headers.items()
                                if k.lower() in ("user-agent", "host", "referer", "x-forwarded-for")},
                    "body_snippet": body_snippet,
                })
    return Response(content=_GIF, media_type="image/gif")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=PORT)
    # public-host is what targets call back to (the URL we hand out); bind is the
    # local interface uvicorn listens on. An OAST server must receive inbound from
    # the *target's* network view: a containerized/remote target cannot reach
    # 127.0.0.1, so default the bind to 0.0.0.0 and let public-host name the route
    # the target should use (e.g. host.docker.internal, or a public domain).
    parser.add_argument("--public-host", default=PUBLIC_HOST)
    parser.add_argument("--scheme", default=SCHEME)
    parser.add_argument("--bind", default=os.environ.get("OAST_BIND", "0.0.0.0"))
    args = parser.parse_args()
    PORT = args.port
    PUBLIC_HOST = args.public_host
    SCHEME = args.scheme
    uvicorn.run(app, host=args.bind, port=args.port, log_level="warning")
