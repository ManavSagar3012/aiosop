"""AI-OSOP MCP Stub Server
Lightweight MCP server for development/testing that returns proper tool definitions
and handles tool execution with mock results.

Usage:
    python mcp_stub.py --port 8081 --server-id burp-mcp
    python mcp_stub.py --port 8084 --server-id nuclei-mcp
"""

import argparse
import json
import time
import uuid
from typing import Any, Dict, List

import uvicorn
from fastapi import FastAPI

app = FastAPI()

# ── Tool definitions per MCP server ─────────────────────────────────────────

# Schemas match MCPToolDefinition/MCPToolParameter in src/ai_osop/mcp/protocol.py


def _tool(name: str, desc: str, params: List[Dict[str, Any]],
          returns: str = "object", timeout: int = 30) -> Dict[str, Any]:
    return {
        "name": name,
        "description": desc,
        "parameters": [
            {"name": p["name"], "type": p.get("type", "string"),
             "description": p.get("desc", ""), "required": p.get("required", True)}
            for p in params
        ],
        "returns": {"type": returns},
        "timeout_seconds": timeout,
        "requires_approval": False,
        "scope_check": True,
    }


TOOL_DEFS: Dict[str, List[Dict[str, Any]]] = {
    "burp-mcp": [
        _tool("scan_target", "Start a Burp Suite scan on a target URL",
              [{"name": "url", "desc": "Target URL to scan"},
               {"name": "config", "type": "object", "desc": "Scan config",
                "required": False}]),
        _tool("get_scan_issues", "Retrieve scan issues from Burp",
              [{"name": "url", "desc": "URL to get issues for", "required": False}],
              returns="array", timeout=60),
        _tool("get_sitemap", "Get Burp sitemap entries",
              [{"name": "url_prefix", "desc": "URL prefix filter",
                "required": False}], returns="array", timeout=30),
        _tool("get_proxy_history", "Get Burp proxy history",
              [], returns="array", timeout=30),
        _tool("intruder_attack", "Run an Intruder attack",
              [{"name": "request", "type": "object", "desc": "HTTP request"},
               {"name": "payload_positions", "type": "array", "desc": "Payload positions",
                "required": False},
               {"name": "payload_set", "type": "array", "desc": "Payload list",
                "required": False},
               {"name": "config", "type": "object", "desc": "Attack config",
                "required": False}],
              timeout=120),
    ],
    "nuclei-mcp": [
        _tool("scan", "Execute Nuclei templates against targets",
              [{"name": "targets", "type": "array", "desc": "Target URLs"},
               {"name": "templates", "type": "array", "desc": "Template paths",
                "required": False},
               {"name": "severity", "desc": "Severity filter", "required": False},
               {"name": "tags", "desc": "Template tags", "required": False},
               {"name": "rate_limit", "type": "integer", "desc": "Requests per second",
                "required": False}],
              timeout=900),
    ],
    "payload-mcp": [
        _tool("generate_payload", "Generate attack payloads",
              [{"name": "vuln_type", "desc": "Type of vulnerability"},
               {"name": "context", "type": "object", "desc": "Generation context"},
               {"name": "count", "type": "integer", "desc": "Number of payloads",
                "required": False}]),
    ],
    "shodan-mcp": [
        _tool("shodan_search", "Search Shodan for hosts",
              [{"name": "query", "desc": "Search query"}]),
        _tool("host_info", "Get Shodan host information",
              [{"name": "ip", "desc": "IP address"}]),
    ],
    "threat-intel-mcp": [
        _tool("query_threat", "Query threat intelligence feeds",
              [{"name": "indicator", "desc": "IOC to query"},
               {"name": "type", "desc": "Indicator type (ip/domain/hash)",
                "required": False}]),
    ],
    "security-bridge": [
        _tool("run_sqlmap", "Execute sqlmap injection test",
              [{"name": "url", "desc": "Target URL"},
               {"name": "data", "desc": "POST body", "required": False},
               {"name": "level", "type": "integer", "desc": "Test level (1-5)",
                "required": False},
               {"name": "risk", "type": "integer", "desc": "Test risk (1-3)",
                "required": False}],
              timeout=180),
    ],
    "browser-mcp": [
        _tool("navigate", "Navigate browser to URL",
              [{"name": "url", "desc": "Target URL"},
               {"name": "user_label", "desc": "Auth user label", "required": False},
               {"name": "engagement_id", "desc": "Engagement ID", "required": False}]),
        _tool("execute_action", "Execute browser action",
              [{"name": "action", "desc": "Action type (eval/click/type)"},
               {"name": "params", "type": "object", "desc": "Action parameters"}],
              timeout=60),
    ],
    "source-map-mcp": [
        _tool("analyze_source_map", "Analyze JavaScript source maps",
              [{"name": "url", "desc": "Source map URL"}]),
    ],
    "cloud-mcp": [
        _tool("cloud_scan", "Scan cloud infrastructure",
              [{"name": "provider", "desc": "Cloud provider (aws/azure/gcp)"},
               {"name": "target", "desc": "Target resource", "required": False}]),
    ],
    "turbo-intruder-mcp": [
        _tool("execute_single_packet_attack", "Execute single-packet race attack",
              [{"name": "target_url", "desc": "Target URL"},
               {"name": "method", "desc": "HTTP method", "required": False},
               {"name": "headers", "type": "object", "desc": "HTTP headers",
                "required": False},
               {"name": "body", "desc": "Request body", "required": False},
               {"name": "concurrent_requests", "type": "integer",
                "desc": "Number of concurrent requests", "required": False}],
              timeout=120),
    ],
}

# Default tools for unknown servers (empty list)
DEFAULT_TOOLS: List[Dict[str, Any]] = []


def _get_tools(server_id: str) -> List[Dict[str, Any]]:
    return TOOL_DEFS.get(server_id, DEFAULT_TOOLS)


# ── Mock execution responses ────────────────────────────────────────────────

def _mock_execute(server_id: str, tool_name: str,
                  params: Dict[str, Any]) -> Dict[str, Any]:
    """Return a plausible mock response for the given tool."""
    _ = params  # unused in mock, accepted for schema compatibility

    # Default mock — return a generic success
    if server_id == "nuclei-mcp" and tool_name == "scan":
        return {
            "status": "success",
            "result": {
                "findings": [],
                "scan_id": f"mock-nuclei-{uuid.uuid4().hex[:8]}",
                "targets_scanned": params.get("targets", []),
                "findings_count": 0,
            },
        }
    elif server_id == "burp-mcp":
        if tool_name == "scan_target":
            return {"status": "success", "result": {"scan_id": f"mock-{uuid.uuid4().hex[:8]}"}}
        elif tool_name in ("get_scan_issues", "get_sitemap", "get_proxy_history"):
            return {"status": "success", "result": {"items": [], "count": 0}}
        elif tool_name == "intruder_attack":
            return {"status": "success", "result": {"attack_id": f"mock-{uuid.uuid4().hex[:8]}"}}
    elif server_id == "security-bridge" and tool_name == "run_sqlmap":
        return {
            "status": "success",
            "result": {
                "injectable": False,
                "parameter": "",
                "dbms": "",
                "techniques": [],
                "payloads": [],
                "log": [],
            },
        }
    elif server_id == "browser-mcp":
        if tool_name == "navigate":
            return {"status": "success", "result": {"url": params.get("url", ""), "title": ""}}
        elif tool_name == "execute_action":
            return {"status": "success", "result": {"result": None}}
    elif server_id == "turbo-intruder-mcp" and tool_name == "execute_single_packet_attack":
        return {
            "status": "success",
            "result": {
                "status_distribution": {"200": 0, "429": 20},
                "success_count": 0,
                "release_window_ms": 50,
            },
        }
    elif server_id == "payload-mcp" and tool_name == "generate_payload":
        return {
            "status": "success",
            "result": {
                "payloads": [],
                "count": 0,
            },
        }

    # Generic success for any tool
    return {"status": "success", "result": {"message": f"Mock {tool_name} executed successfully"}}


# ── Endpoints ───────────────────────────────────────────────────────────────

_server_id_global: str = "unknown"


@app.get("/health")
async def health():
    return {"server_id": _server_id_global, "status": "ready"}


@app.post("/mcp/initialize")
async def initialize(request: dict):
    tools = _get_tools(_server_id_global)
    return {
        "server_id": _server_id_global,
        "version": "1.0.0",
        "status": "ready",
        "capabilities": ["tool"],
        "tools": tools,
    }


@app.post("/mcp/execute")
async def execute(request: dict):
    tool_name = request.get("tool_name", "unknown")
    parameters = request.get("parameters", {})
    request_id = request.get("request_id", f"req-{int(time.time())}")

    t0 = time.monotonic()
    result = _mock_execute(_server_id_global, tool_name, parameters)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    return {
        "request_id": request_id,
        "status": result.get("status", "success"),
        "result": result.get("result"),
        "error": result.get("error"),
        "execution_time_ms": elapsed_ms,
        "metadata": {},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--server-id", type=str, default="",
                        help="MCP server identity for tool definitions")
    args = parser.parse_args()
    _server_id_global = args.server_id or f"stub-{args.port}"
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
