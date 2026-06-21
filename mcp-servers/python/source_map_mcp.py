"""
Source Map MCP Server
Fetches and parses webpack sourcemaps, and extracts hardcoded API keys.
"""

import uuid
import re
import json
import httpx
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Source Map MCP Server")

@app.get("/health")
async def health():
    return {"status": "ready", "server": "source-map-mcp"}

class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None

@app.post("/mcp/initialize")
async def mcp_initialize():
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

async def analyze_sourcemap(url: str) -> Dict[str, Any]:
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

    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(url)
            content = resp.text
            
            # If it's a JS file, look for sourceMappingURL
            if url.endswith(".js"):
                match = re.search(r"//# sourceMappingURL=(.+)", content)
                if match:
                    map_url = match.group(1).strip()
                    if not map_url.startswith("http"):
                        base_url = url.rsplit("/", 1)[0]
                        map_url = f"{base_url}/{map_url}"
                    
                    resp = await client.get(map_url)
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
                                "value": val,
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
                            "value": val,
                            "file": url
                        })
                results["msg"] = "Parsed raw bundle directly (no valid sourcemap)."
                
    except Exception as e:
        results["msg"] = f"Error fetching or parsing: {str(e)}"

    return results

@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest):
    request_id = req.request_id or str(uuid.uuid4())
    
    if req.tool_name == "fetch_and_parse_sourcemap":
        url = req.parameters.get("url") if req.parameters else None
        if not url:
            return {
                "request_id": request_id,
                "status": "error",
                "error": "URL is required"
            }
        
        result = await analyze_sourcemap(url)
        
        return {
            "request_id": request_id,
            "status": "success",
            "result": result
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
    parser.add_argument("--port", type=int, default=8096)
    args = parser.parse_args()
    uvicorn.run(app, host="0.0.0.0", port=args.port)
