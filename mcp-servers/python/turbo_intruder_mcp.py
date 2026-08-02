import sys
import os
import json
import asyncio
import argparse
import socket
import ssl
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

# Add src to path so we can import ai_osop modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from fastapi import FastAPI, Header, Depends, HTTPException
from pydantic import BaseModel
import uvicorn

from ai_osop.core.config import settings
from ai_osop.safety.scope import ScopeEnforcer
from ai_osop.core.models import ScopeDefinition

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

app = FastAPI(title="Turbo Intruder MCP Server")


# ---------------------------------------------------------------------------
# REAL single-packet / last-byte-synchronization race attack (HTTP/1.1).
#
# Prior implementation fired aiohttp requests over a pooled connector and called
# it a "single-packet attack" — it was not. Connection setup, TLS, and event-loop
# scheduling spread the requests across tens of milliseconds, far wider than the
# server-side race window, so it could not reliably trigger TOCTOU. This is the
# real technique (James Kettle): open N raw sockets, send every byte of each
# request EXCEPT the final one, wait until all N are primed, then release the
# withheld last byte on every socket at once (threading.Barrier). The server
# completes parsing all N requests within microseconds -> maximal race overlap.
# ---------------------------------------------------------------------------
def _build_raw_request(method: str, host: str, path: str, headers: Dict[str, str], body: str) -> bytes:
    method = method.upper()
    body_bytes = body.encode() if isinstance(body, str) else (body or b"")
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    for k, v in (headers or {}).items():
        if k.lower() in ("host", "content-length", "connection"):
            continue
        lines.append(f"{k}: {v}")
    if method in ("POST", "PUT", "PATCH") or body_bytes:
        if "content-type" not in hdrs:
            lines.append("Content-Type: application/json")
        lines.append(f"Content-Length: {len(body_bytes)}")
    lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode()
    return head + body_bytes


def _one_socket_attack(
    host: str, port: int, use_tls: bool, request_bytes: bytes,
    barrier: threading.Barrier, results: List[Dict[str, Any]], idx: int,
    connect_timeout: float,
):
    """Connect, send all-but-last byte, sync on the barrier, release last byte,
    read the response. Records status/timing/body into results[idx]."""
    rec: Dict[str, Any] = {"index": idx}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        # Prime: send everything except the final byte.
        sock.sendall(request_bytes[:-1])
        last = request_bytes[-1:]
        # All threads gather here; the last to arrive releases everyone together.
        barrier.wait(timeout=20)
        t0 = time.perf_counter()
        sock.sendall(last)            # the synchronized release
        rec["release_ts"] = t0
        sock.settimeout(15)
        chunks = []
        while True:
            try:
                b = sock.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        raw = b"".join(chunks)
        rec["recv_ts"] = time.perf_counter()
        status = 0
        if raw.startswith(b"HTTP/"):
            try:
                status = int(raw.split(b" ", 2)[1])
            except Exception:
                status = 0
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        rec.update({
            "status": status,
            "resp_bytes": len(raw),
            "body_sha1_12": __import__("hashlib").sha1(body).hexdigest()[:12],
        })
    except Exception as e:
        rec.update({"status": "error", "error": str(e)})
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    results[idx] = rec


def _run_single_packet_attack(
    target_url: str, method: str, headers: Dict[str, str], body: str, n: int,
) -> Dict[str, Any]:
    parts = urlsplit(target_url)
    use_tls = parts.scheme == "https"
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if use_tls else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    request_bytes = _build_raw_request(method, host, path, headers, body)

    results: List[Optional[Dict[str, Any]]] = [None] * n
    barrier = threading.Barrier(n)
    threads = []
    for i in range(n):
        t = threading.Thread(
            target=_one_socket_attack,
            args=(host, port, use_tls, request_bytes, barrier, results, i, 10.0),
            daemon=True,
        )
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=40)

    done = [r for r in results if r]
    releases = [r["release_ts"] for r in done if "release_ts" in r]
    window_ms = round((max(releases) - min(releases)) * 1000, 3) if len(releases) > 1 else 0.0

    dist: Dict[str, int] = {}
    bodies = set()
    for r in done:
        dist[str(r.get("status"))] = dist.get(str(r.get("status")), 0) + 1
        if "body_sha1_12" in r:
            bodies.add(r["body_sha1_12"])

    return {
        "attack": "single_packet_last_byte_sync",
        "real": True,
        "concurrency": n,
        "completed": len(done),
        "release_window_ms": window_ms,   # how tight the synchronized release was
        "status_distribution": dist,
        "distinct_response_bodies": len(bodies),
        "results": done,
    }


async def execute_spa(target_url: str, method: str, headers: dict, body: str, concurrent_requests: int) -> Dict[str, Any]:
    """Run the real raw-socket single-packet attack off the event loop."""
    n = max(1, int(concurrent_requests or 10))
    return await asyncio.to_thread(
        _run_single_packet_attack, target_url, method, headers or {}, body or "", n
    )


@app.get("/health")
async def health(authenticated: None = Depends(verify_mcp_token)):
    return {"status": "ready", "server": "turbo-intruder-mcp"}


class MCPInitializeRequest(BaseModel):
    server_id: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None


@app.post("/mcp/initialize")
async def initialize(req: MCPInitializeRequest, authenticated: None = Depends(verify_mcp_token)):
    if req.scope:
        try:
            scope_def = ScopeDefinition(**req.scope)
            app.state.scope_enforcer = ScopeEnforcer(scope_def)
            app.state.session_id = req.session_id
        except Exception as e:  # noqa: BLE001
            import logging
            logging.getLogger("turbo-intruder-mcp").warning(f"Failed to initialize scope: {e}")

    return {
        "server_id": "turbo-intruder-mcp",
        "capabilities": ["tool"],
        "tools": [
            {
                "name": "execute_single_packet_attack",
                "description": "Real raw-socket single-packet (last-byte-sync) HTTP/1.1 race attack for TOCTOU / double-spend testing.",
                "parameters": [
                    {"name": "target_url", "type": "string", "description": "Target URL", "required": True},
                    {"name": "method", "type": "string", "description": "HTTP method", "required": False},
                    {"name": "headers", "type": "object", "description": "Request headers", "required": False},
                    {"name": "body", "type": "string", "description": "Request body", "required": False},
                    {"name": "concurrent_requests", "type": "number", "description": "Number of synchronized requests", "required": False}
                ],
                "returns": {"status": "string", "result": "object"}
            }
        ],
        "status": "ready"
    }


class ExecuteRequest(BaseModel):
    tool_name: str
    parameters: dict
    request_id: str


@app.post("/mcp/execute")
async def execute(req: ExecuteRequest, authenticated: None = Depends(verify_mcp_token)):
    if req.tool_name == "execute_single_packet_attack":
        params = req.parameters
        target_url = params.get("target_url")
        if not target_url:
            return {"request_id": req.request_id, "status": "error", "error": "target_url is required"}

        # Strict URL parsing
        try:
            parts = urlsplit(target_url)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                raise ValueError("Invalid target scheme (must be http/https) or missing host")
        except Exception as e:  # noqa: BLE001
            return {"request_id": req.request_id, "status": "error", "error": f"Invalid URL: {e}"}

        # Enforce scope check
        if getattr(app.state, "scope_enforcer", None) and getattr(app.state, "session_id", "") != "api-bootstrap":
            try:
                app.state.scope_enforcer.validate_target(target_url)
            except Exception as e:  # noqa: BLE001
                return {"request_id": req.request_id, "status": "error", "error": f"Out of scope target: {e}"}

        try:
            result = await execute_spa(
                target_url,
                params.get("method", "GET"),
                params.get("headers", {}),
                params.get("body", ""),
                params.get("concurrent_requests", 10),
            )
            return {"request_id": req.request_id, "status": "success", "result": result}
        except Exception as e:  # noqa: BLE001
            return {"request_id": req.request_id, "status": "error", "error": str(e)}
    return {"request_id": req.request_id, "status": "error", "error": f"unknown tool: {req.tool_name}"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8098)
    args = parser.parse_args()

    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
