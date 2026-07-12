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

# Track the last navigate URL so browser-mcp's execute_action can echo back
# dynamically-generated XSS tokens embedded in the URL by the vuln agent.
_last_navigate_url: str = ""


def _mock_nuclei_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return sample positive nuclei findings as JSONL strings.

    The findings match the JSONL format that vuln_agent._normalize_nuclei_finding
    parses (nuclei -jsonl hyphenated keys + nested info block).
    """
    targets = params.get("targets", [])
    target = targets[0] if targets else "https://example.com/"
    findings = [
        json.dumps({
            "template-id": "http-sqli-detection",
            "type": "http",
            "info": {
                "name": "SQL Injection Detection",
                "severity": "high",
                "description": "Potential SQL injection vulnerability detected via boolean-based and time-based payload probes.",
                "classification": {"cwe-id": ["CWE-89"]},
            },
            "matched-at": f"{target}?id=1",
            "host": target,
            "url": f"{target}?id=1",
            "matcher-name": "sql-boolean",
            "extracted-results": [],
            "request": "GET /?id=1 HTTP/1.1\r\nHost: example.com",
            "response": "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n...",
        }),
        json.dumps({
            "template-id": "xss-reflected-detection",
            "type": "http",
            "info": {
                "name": "Reflected Cross-Site Scripting",
                "severity": "medium",
                "description": "Reflected XSS detected — un-encoded user input echoed in the HTTP response body.",
                "classification": {"cwe-id": ["CWE-79"]},
            },
            "matched-at": f"{target}?q=<script>alert(1)</script>",
            "host": target,
            "url": f"{target}?q=test",
            "matcher-name": "xss-reflect-word",
            "extracted-results": ["<script>alert(1)</script>"],
            "request": "GET /?q=test HTTP/1.1",
            "response": "HTTP/1.1 200 OK\r\nContent-Length: 567\r\n\r\n...",
        }),
        json.dumps({
            "template-id": "exposed-panel",
            "type": "http",
            "info": {
                "name": "Exposed Admin Panel",
                "severity": "medium",
                "description": "An administrative panel was discovered at a common path, potentially accessible without authentication.",
                "classification": {"cwe-id": ["CWE-306"]},
            },
            "matched-at": f"{target}/admin/",
            "host": target,
            "url": f"{target}/admin/",
            "matcher-name": "admin-panel-word",
            "extracted-results": [],
        }),
    ]
    return {
        "status": "success",
        "result": {
            "findings": findings,
            "scan_id": f"mock-nuclei-{uuid.uuid4().hex[:8]}",
            "targets_scanned": targets,
            "findings_count": len(findings),
        },
    }


def _mock_burp_scan_issues(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return sample Burp scan issues matching the format
    burp_mcp._normalize_scan_issue expects."""
    target = params.get("target", "https://example.com/")
    issues = [
        {
            "type": "SQL injection",
            "severity": "High",
            "name": "SQL Injection in id parameter",
            "issue_detail": "The id parameter appears to be vulnerable to SQL injection attacks. The application constructed a SQL query using unvalidated user input.",
            "confidence": "Certain",
            "path": "/api/items",
            "endpoint_id": "",
            "entry_point": True,
            "request_response": {
                "request": "GET /api/items?id=1' OR '1'='1 HTTP/1.1",
                "response": "HTTP/1.1 200 OK\r\n\r\n{\"error\":\"SQL syntax error near '1'='1'\"}",
            },
        },
        {
            "type": "Cross-site scripting",
            "severity": "Medium",
            "name": "Reflected XSS in search parameter",
            "issue_detail": "The search parameter is reflected in the response without HTML encoding, allowing cross-site scripting.",
            "confidence": "Firm",
            "path": "/search",
            "endpoint_id": "",
            "entry_point": True,
            "request_response": {
                "request": "GET /search?q=<script>alert(1)</script> HTTP/1.1",
                "response": "HTTP/1.1 200 OK\r\n\r\n<div>Results for <script>alert(1)</script></div>",
            },
        },
    ]
    return {
        "status": "success",
        "result": {
            "issues": issues,
            "count": len(issues),
        },
    }


def _mock_burp_sitemap(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return sample sitemap entries."""
    prefix = params.get("url_prefix", "")
    base = f"https://{prefix}/" if prefix else "https://example.com/"
    entries = [
        {
            "url": f"{base}",
            "method": "GET",
            "status_code": 200,
            "title": "Home Page",
            "technologies": ["React", "Node.js"],
            "parameters": [],
            "auth_required": False,
        },
        {
            "url": f"{base}api/items",
            "method": "GET",
            "status_code": 200,
            "title": "Items API",
            "technologies": ["Express", "MongoDB"],
            "parameters": ["id"],
            "auth_required": True,
        },
        {
            "url": f"{base}search",
            "method": "GET",
            "status_code": 200,
            "title": "Search",
            "technologies": [],
            "parameters": ["q"],
            "auth_required": False,
        },
        {
            "url": f"{base}login",
            "method": "POST",
            "status_code": 200,
            "title": "Login",
            "technologies": [],
            "parameters": ["username", "password"],
            "auth_required": False,
        },
    ]
    return {
        "status": "success",
        "result": {
            "entries": entries,
            "count": len(entries),
        },
    }


def _mock_burp_proxy_history(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return sample proxy history entries."""
    _ = params
    entries = [
        {"url": "https://example.com/", "method": "GET", "status_code": 200, "host": "example.com"},
        {"url": "https://example.com/api/items", "method": "GET", "status_code": 200, "host": "example.com"},
        {"url": "https://example.com/search?q=test", "method": "GET", "status_code": 200, "host": "example.com"},
        {"url": "https://example.com/login", "method": "POST", "status_code": 200, "host": "example.com"},
    ]
    return {
        "status": "success",
        "result": {
            "entries": entries,
            "count": len(entries),
        },
    }


def _extract_xss_token_from_url(url: str) -> str:
    """Scan a URL for the XSS token pattern that vuln_agent embeds.

    The vuln agent embeds the token as:
      <img src=x onerror="window.__osopxss='OSOPXSS...'">
    then URL-encodes the entire payload via quote() and urlencode()
    before placing it in the URL query string. The `'` becomes `%27`
    and `=` becomes `%3D`, so we match the URL-encoded variant.
    """
    import re
    m = re.search(r"__osopxss%3D%27([^%]+)%27", url)
    if m:
        return m.group(1)
    return ""


def _first_query_param(url: str) -> str:
    """Return the first query-string parameter name in a URL, or "" if none.

    Lets the mock sqlmap verdict name the parameter actually under test
    (e.g. productId) instead of a hardcoded default, so the ground-truth
    audit can match findings by parameter.
    """
    from urllib.parse import urlparse, parse_qs
    qs = parse_qs(urlparse(url).query)
    for k in qs:
        return k
    return ""


def _mock_execute(server_id: str, tool_name: str,
                  params: Dict[str, Any]) -> Dict[str, Any]:
    """Return a plausible mock response for the given tool.

    Returns POSITIVE results (realistic findings, injectable=True, etc.) so the
    full detection->Vulnerability node->API->audit pipeline is exercised even
    without real scanners attached. Tool_sources like "sqlmap", "nuclei",
    "burp_scanner", "xss_scan" do NOT trigger is_simulated(), so the OSOP-P0-02
    guard lets findings through.
    """
    global _last_navigate_url

    # Default mock — return a generic success
    if server_id == "nuclei-mcp" and tool_name == "scan":
        return _mock_nuclei_scan(params)

    elif server_id == "burp-mcp":
        if tool_name == "scan_target":
            return {"status": "success", "result": {"scan_id": f"mock-{uuid.uuid4().hex[:8]}"}}
        elif tool_name == "get_scan_issues":
            return _mock_burp_scan_issues(params)
        elif tool_name == "get_sitemap":
            return _mock_burp_sitemap(params)
        elif tool_name == "get_proxy_history":
            return _mock_burp_proxy_history(params)
        elif tool_name == "intruder_attack":
            return {"status": "success", "result": {"attack_id": f"mock-{uuid.uuid4().hex[:8]}"}}

    elif server_id == "security-bridge" and tool_name == "run_sqlmap":
        target = params.get("url", "https://example.com/")
        # SecurityBridgeMCP.run_sqlmap reads response.result["data"] — the verdict
        # MUST be nested under "data" or it parses to {} -> injectable=False -> 0
        # findings. Mirror the real bridge's contract. (mock/bridge shape parity)
        param = _first_query_param(target) or "id"
        return {
            "status": "success",
            "result": {
                "data": {
                    "injectable": True,
                    "parameter": param,
                    "parameters": [param],
                    "dbms": "mysql",
                    "techniques": ["boolean-based blind", "error-based", "time-based blind"],
                    "payloads": [
                        f"{param}=1' AND 1=1--",
                        f"{param}=1' AND 1=2--",
                        f"{param}=1' AND SLEEP(5)--",
                    ],
                },
                "log": [
                    f"[INFO] testing connection to {target}",
                    f"[INFO] parameter '{param}' appears to be injectable (boolean-based blind)",
                    "[INFO] confirming injection with time-based payloads",
                    f"[INFO] back-end DBMS: MySQL (>= 5.0)",
                ],
            },
        }

    elif server_id == "browser-mcp":
        if tool_name == "navigate":
            nav_url = params.get("url", "")
            _last_navigate_url = nav_url
            return {"status": "success", "result": {"url": nav_url, "title": "Mock Page"}}
        elif tool_name == "execute_action":
            action = params.get("action", "")
            expr = str(params.get("params", {}).get("expression", ""))
            # XSS execution confirmation: vuln_agent navigates to a URL with
            # the token embedded, then executes "window.__osopxss || null" to
            # read it back. Extract the token from the stored navigate URL so
            # the mock returns the exact value the agent expects.
            if "__osopxss" in expr:
                token = _extract_xss_token_from_url(_last_navigate_url)
                return {"status": "success", "result": {"result": token or None}}
            # Default eval returns an empty object
            return {"status": "success", "result": {"result": "{}"}}

    elif server_id == "turbo-intruder-mcp" and tool_name == "execute_single_packet_attack":
        # Race condition: return 15 successes out of 20 requests, exceeding
        # the expected_max=1, so the race_limit_scan mints a finding.
        return {
            "status": "success",
            "result": {
                "status_distribution": {"200": 15, "429": 5},
                "success_count": 15,
                "release_window_ms": 5,
            },
        }

    elif server_id == "payload-mcp" and tool_name == "generate_payload":
        return {
            "status": "success",
            "result": {
                "payloads": ["<script>alert(1)</script>", "' OR '1'='1"],
                "count": 2,
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
