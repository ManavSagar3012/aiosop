"""
Source Map MCP Server (Production Implementation)
Provides secure, scope-aware, and authenticated webpack/js sourcemap analysis.
"""

import sys
import os
import uuid
import re
import json
import httpx
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from urllib.parse import urlparse

from ai_osop.core.config import settings
from ai_osop.safety.scope import ScopeEnforcer
from ai_osop.core.models import ScopeDefinition

app = FastAPI(title="Source Map MCP Server")


async def verify_mcp_token(authorization: Optional[str] = Header(None)):
    """Enforce strict bearer token verification."""
    expected = settings.api_token or os.getenv("OSOP_API_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="MCP authentication is not configured")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing Authorization header")

    token = authorization.split(" ", 1)[1]
    import hmac
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


def mask_secret(val: str) -> str:
    """Mask credentials to prevent plaintext leakage in reports."""
    if len(val) <= 8:
        return "****"
    return f"{val[:4]}...{val[-4:]}"


@app.get("/health")
async def health():
    return {"status": "ready", "server": "source-map-mcp", "is_stub": False}


class MCPInitializeRequest(BaseModel):
    server_id: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None


class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None


@app.post("/mcp/initialize")
async def mcp_initialize(req: MCPInitializeRequest, authenticated: None = Depends(verify_mcp_token)):
    if not req.scope:
        raise HTTPException(status_code=422, detail="A valid engagement scope is required")
    try:
        scope_def = ScopeDefinition(**req.scope)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Invalid engagement scope: {e}") from e
    app.state.scope_enforcer = ScopeEnforcer(scope_def)
    app.state.session_id = req.session_id

    return {
        "server_id": "source-map-mcp",
        "version": "1.0",
        "capabilities": ["static_analysis"],
        "status": "ready",
        "tools": [
            {
                "name": "fetch_and_parse_sourcemap",
                "description": "Fetch a JS bundle or sourcemap URL and extract its contents and hardcoded secrets.",
                "parameters": [
                    {"name": "url", "type": "string", "description": "The URL to the JS file or sourcemap", "required": True}
                ],
                "returns": {"type": "object", "description": "Extraction results"}
            }
        ]
    }


async def analyze_sourcemap(url: str, scope_enforcer: ScopeEnforcer) -> Dict[str, Any]:
    # Secret regex patterns
    patterns = {
        "google_api": r"AIza[0-9A-Za-z-_]{35}",
        "generic_api_key": r"(?i)(api[_-]?key|secret|token|password)['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]",
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "jwt": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
    }

    results = {
        "sources": [],
        "secrets": [],
        "msg": ""
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Failed to fetch JS bundle: HTTP {resp.status_code}")
        
        content = resp.text
        
        # If it's a JS file, look for sourceMappingURL
        if url.endswith(".js"):
            match = re.search(r"//# sourceMappingURL=(.+)", content)
            if match:
                map_url = match.group(1).strip()
                if not map_url.startswith("http"):
                    base_url = url.rsplit("/", 1)[0]
                    map_url = f"{base_url}/{map_url}"

                parsed_map_url = urlparse(map_url)
                if parsed_map_url.scheme not in ("http", "https") or not parsed_map_url.hostname:
                    raise HTTPException(status_code=400, detail="Invalid sourcemap URL")
                scope_enforcer.validate_target(map_url)
                
                resp = await client.get(map_url)
                if resp.status_code != 200:
                    raise HTTPException(status_code=400, detail=f"Failed to fetch sourcemap: HTTP {resp.status_code}")
                content = resp.text
        
        try:
            data = json.loads(content)
            sources = data.get("sourcesContent", [])
            filenames = data.get("sources", [])
            
            for idx, src in enumerate(sources):
                if not src:
                    continue
                filename = filenames[idx] if idx < len(filenames) else f"source_{idx}.js"
                results["sources"].append(filename)
                
                for name, pattern in patterns.items():
                    for secret_match in re.finditer(pattern, src):
                        if isinstance(secret_match.groups(), tuple) and len(secret_match.groups()) > 0:
                            val = secret_match.group(len(secret_match.groups()))
                        else:
                            val = secret_match.group(0)
                        
                        results["secrets"].append({
                            "type": name,
                            "value": mask_secret(val),
                            "file": filename
                        })
            
            results["msg"] = "Successfully parsed sourcemap."
        except json.JSONDecodeError:
            # If not a JSON sourcemap, just scan the raw content
            for name, pattern in patterns.items():
                for secret_match in re.finditer(pattern, content):
                    if isinstance(secret_match.groups(), tuple) and len(secret_match.groups()) > 0:
                        val = secret_match.group(len(secret_match.groups()))
                    else:
                        val = secret_match.group(0)
                        
                    results["secrets"].append({
                        "type": name,
                        "value": mask_secret(val),
                        "file": url
                    })
            results["msg"] = "Parsed raw bundle directly (no valid sourcemap)."

    return results


@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest, authenticated: None = Depends(verify_mcp_token)):
    request_id = req.request_id or str(uuid.uuid4())
    params = req.parameters or {}
    
    if req.tool_name != "fetch_and_parse_sourcemap":
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Unknown tool: {req.tool_name}"
        }

    url = params.get("url")
    if not isinstance(url, str) or not url:
        return {
            "request_id": request_id,
            "status": "error",
            "error": "URL is required"
        }
    
    # Enforce strict URL validation (prevent SSRF/file scheme access)
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Invalid URL scheme: {parsed_url.scheme}. Only HTTP/HTTPS are allowed."
        }

    # Enforce scope
    scope_enforcer = getattr(app.state, "scope_enforcer", None)
    if scope_enforcer is None:
        return {
            "request_id": request_id,
            "status": "error",
            "error": "MCP scope has not been initialized",
        }
    try:
        scope_enforcer.validate_target(url)
    except Exception as e:  # noqa: BLE001
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Out of scope target: {e}",
        }
            
    try:
        result = await analyze_sourcemap(url, scope_enforcer)
        return {
            "request_id": request_id,
            "status": "success",
            "result": result
        }
    except Exception as e:  # noqa: BLE001
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Failed to analyze sourcemap: {e}"
        }


if __name__ == "__main__":
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8096)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
