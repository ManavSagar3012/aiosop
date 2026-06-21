"""
Threat Intel MCP Server
Fetches and caches data from NVD, CISA KEV, ExploitDB, MITRE, and Shodan.
Exposed via MCP for autonomous enrichment by agents.
"""

import asyncio
import csv
import io
import json
import logging
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Initialize FastAPI
app = FastAPI(title="Threat Intel MCP Server")
logger = logging.getLogger(__name__)

# --- Re-use Logic from Adapter ---
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

class ThreatIntelManager:
    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(hours=24)
        self.client = httpx.AsyncClient(timeout=10.0)
        self.nvd_lock = asyncio.Semaphore(1)

    async def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        cve_id = cve_id.strip().upper()
        if not _CVE_PATTERN.match(cve_id):
            return {"error": "Invalid CVE format"}

        async with self.nvd_lock:
            try:
                resp = await self.client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("vulnerabilities"):
                        v = data["vulnerabilities"][0]["cve"]
                        return {
                            "id": v.get("id"),
                            "description": v.get("descriptions", [{}])[0].get("value", ""),
                            "cvss": self._extract_cvss(v.get("metrics", {}))
                        }
                return {"error": f"NVD returned {resp.status_code}"}
            except Exception as e:
                return {"error": str(e)}

    def _extract_cvss(self, metrics: Dict[str, Any]) -> float:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric = metrics.get(key, [])
            if metric:
                return float(metric[0].get("cvssData", {}).get("baseScore", 0.0))
        return 0.0

    async def search_exploitdb(self, cve_id: str) -> List[Dict]:
        try:
            resp = await self.client.get(_EXPLOITDB_CSV_URL)
            if resp.status_code != 200:
                return []
            
            exploits = []
            reader = csv.DictReader(io.StringIO(resp.text))
            for row in reader:
                haystack = " ".join(str(value or "") for value in row.values()).upper()
                if cve_id.upper() in haystack:
                    exploits.append({
                        "id": row.get("id"),
                        "title": row.get("description"),
                        "url": f"https://www.exploit-db.com/exploits/{row.get('id')}"
                    })
            return exploits
        except Exception:
            return []

manager = ThreatIntelManager()

@app.get("/health")
async def health():
    return {"status": "ready", "server": "threat-intel-mcp"}

# --- MCP Models ---
class MCPInitializeRequest(BaseModel):
    server_id: Optional[str] = None

class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None

# --- MCP Endpoints ---
@app.post("/mcp/initialize")
async def mcp_initialize(req: MCPInitializeRequest):
    return {
        "server_id": "threat-intel-mcp",
        "version": "1.0",
        "tools": [
            {
                "name": "cve_lookup",
                "description": "Fetch CVE details and CVSS from NVD.",
                "parameters": [{"name": "cve_id", "type": "string", "required": True}]
            },
            {
                "name": "search_exploits",
                "description": "Search ExploitDB for public PoCs.",
                "parameters": [{"name": "cve_id", "type": "string", "required": True}]
            }
        ]
    }

@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest):
    request_id = req.request_id or str(uuid.uuid4())
    params = req.parameters or {}
    
    if req.tool_name == "cve_lookup":
        result = await manager.get_cve_details(params.get("cve_id", ""))
        return {"request_id": request_id, "status": "success", "result": result}
    
    elif req.tool_name == "search_exploits":
        result = await manager.search_exploitdb(params.get("cve_id", ""))
        return {"request_id": request_id, "status": "success", "result": {"exploits": result}}

    return {"request_id": request_id, "status": "error", "error": f"Unknown tool: {req.tool_name}"}

if __name__ == "__main__":
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8086)
    args = parser.parse_args()
    uvicorn.run(app, host="0.0.0.0", port=args.port)
