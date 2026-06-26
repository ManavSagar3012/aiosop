"""
Burp Suite MCP Adapter
Production-grade adapter for Burp Suite MCP with request/response normalization,
scanner issue correlation, and proxy history management.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.exceptions import MCPException
from ai_osop.core.models import Asset, Endpoint, ScopeDefinition, Vulnerability
from ai_osop.mcp.protocol import MCPExecuteRequest, MCPExecuteResponse, MCPRegistry


class BurpMCPAdapter:
    """
    High-level adapter for Burp Suite MCP server.

    Provides:
    - Proxy history retrieval with filtering
    - Scanner issue extraction and normalization
    - Repeater request execution
    - Intruder attack orchestration
    - Extension API invocation
    """

    SERVER_ID = "burp-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry
        self._proxy_history_buffer: List[Dict[str, Any]] = []
        self._max_history_size = 10000

    async def initialize(self, scope: ScopeDefinition, session_id: str) -> None:
        """Initialize Burp MCP with scope and auth."""
        credentials = {}
        await self.registry.initialize_server(
            self.SERVER_ID,
            scope=scope.model_dump(),
            credentials=credentials,
            session_id=session_id,
        )

    async def scan_target(
        self, url: str, config: Optional[Dict[str, Any]] = None
    ) -> MCPExecuteResponse:
        """Initiate Burp crawl + audit scan on target URL."""
        params = {
            "url": url,
            "config": config
            or {
                "scan_type": "crawl_and_audit",
                "audit_items": ["sqli", "xss", "csrf", "idor", "ssrf"],
                "scan_speed": "normal",
                "max_depth": 10,
            },
        }
        return await self.registry.execute_tool(
            self.SERVER_ID, "scan_target", params, timeout_override=3600
        )

    async def get_proxy_history(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve captured proxy traffic with optional filtering."""
        params = {"filters": filters or {}, "limit": 1000, "offset": 0}
        response = await self.registry.execute_tool(
            self.SERVER_ID, "get_proxy_history", params
        )

        if response.status == "success" and response.result:
            entries = response.result.get("entries", [])
            self._update_history_buffer(entries)
            return entries
        return []

    async def get_scan_issues(
        self, target: Optional[str] = None
    ) -> List[Vulnerability]:
        """Retrieve and normalize scanner findings."""
        params = {"target": target} if target else {}
        response = await self.registry.execute_tool(
            self.SERVER_ID, "get_scan_issues", params
        )

        if response.status != "success" or not response.result:
            return []

        raw_issues = response.result.get("issues", [])
        vulnerabilities = []

        for issue in raw_issues:
            vuln = self._normalize_scan_issue(issue)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def send_to_repeater(
        self, request: Dict[str, Any], tab_name: Optional[str] = None
    ) -> MCPExecuteResponse:
        """Send request to Repeater for manual manipulation."""
        params = {
            "request": request,
            "tab_name": tab_name or f"auto-{datetime.utcnow().timestamp()}",
        }
        return await self.registry.execute_tool(
            self.SERVER_ID, "send_to_repeater", params
        )

    async def intruder_attack(
        self,
        request: Dict[str, Any],
        payload_positions: List[Dict[str, Any]],
        payload_set: List[str],
        config: Optional[Dict[str, Any]] = None,
    ) -> MCPExecuteResponse:
        """Execute automated fuzzing attack via Intruder."""
        params = {
            "request": request,
            "payload_positions": payload_positions,
            "payload_set": payload_set,
            "config": config
            or {"attack_type": "sniper", "thread_count": 10, "delay_ms": 100},
        }
        return await self.registry.execute_tool(
            self.SERVER_ID, "intruder_attack", params, timeout_override=1800
        )

    async def extension_call(
        self, extension_name: str, method: str, params: Dict[str, Any]
    ) -> MCPExecuteResponse:
        """Invoke a Burp extension method. Requires approval."""
        request_params = {
            "extension_name": extension_name,
            "method": method,
            "params": params,
        }
        return await self.registry.execute_tool(
            self.SERVER_ID, "extension_call", request_params, timeout_override=300
        )

    async def get_sitemap(self, url_prefix: Optional[str] = None) -> List[Endpoint]:
        """Extract site map as normalized endpoints."""
        params = {"url_prefix": url_prefix} if url_prefix else {}
        response = await self.registry.execute_tool(
            self.SERVER_ID, "get_sitemap", params
        )

        if response.status != "success" or not response.result:
            return []

        endpoints = []
        for entry in response.result.get("entries", []):
            ep = Endpoint(
                url=entry.get("url"),
                method=entry.get("method", "GET"),
                status_code=entry.get("status_code"),
                title=entry.get("title"),
                technologies=entry.get("technologies", []),
                parameters=entry.get("parameters", []),
                auth_required=entry.get("auth_required", False),
                asset_id=entry.get("asset_id", ""),
                source="burp_sitemap",
                confidence=0.95,
                engagement_id=entry.get("engagement_id", ""),
            )
            endpoints.append(ep)

        return endpoints

    def _normalize_scan_issue(self, issue: Dict[str, Any]) -> Optional[Vulnerability]:
        """Convert Burp scan issue to standardized Vulnerability model."""
        burp_severity = issue.get("severity", "info")
        severity_map = {
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
            "Information": Severity.INFO,
        }

        # Map Burp issue types to CWE/VulnClass
        issue_type = issue.get("type", "")
        vuln_type = self._map_burp_issue_type(issue_type)
        cwe = self._map_burp_to_cwe(issue_type)

        return Vulnerability(
            cwe=cwe,
            vuln_type=vuln_type,
            severity=severity_map.get(burp_severity, Severity.INFO),
            title=issue.get("name", "Unknown Issue"),
            description=issue.get("issue_detail", ""),
            evidence=[
                {
                    "type": "burp_issue",
                    "confidence": issue.get("confidence"),
                    "path": issue.get("path"),
                    "request_response": issue.get("request_response"),
                }
            ],
            tool_source="burp_scanner",
            endpoint_id=issue.get("endpoint_id"),
            confidence=0.9 if issue.get("confidence") == "Certain" else 0.7,
            entry_point=issue.get("entry_point", False),
            requires_auth=issue.get("requires_auth", False),
            exploitability="high" if burp_severity == "High" else "medium",
            engagement_id=issue.get("engagement_id", ""),
        )

    def _map_burp_issue_type(self, issue_type: str) -> VulnClass:
        """Map Burp issue type string to VulnClass enum."""
        mapping = {
            "SQL injection": VulnClass.SQLI,
            "Cross-site scripting": VulnClass.XSS,
            "SSRF": VulnClass.SSRF,
            "XML external entity injection": VulnClass.XXE,
            "OS command injection": VulnClass.RCE,
            "File path traversal": VulnClass.LFI,
            "Insecure deserialization": VulnClass.DESERIALIZATION,
        }

        for key, value in mapping.items():
            if key.lower() in issue_type.lower():
                return value

        # Heuristic fallback
        if "sql" in issue_type.lower():
            return VulnClass.SQLI
        elif "xss" in issue_type.lower() or "scripting" in issue_type.lower():
            return VulnClass.XSS
        elif "ssrf" in issue_type.lower():
            return VulnClass.SSRF
        elif "jwt" in issue_type.lower():
            return VulnClass.JWT_ABUSE
        elif "idor" in issue_type.lower() or "direct" in issue_type.lower():
            return VulnClass.IDOR

        return VulnClass.UNKNOWN

    def _map_burp_to_cwe(self, issue_type: str) -> Optional[str]:
        """Map Burp issue to CWE identifier using substring matching."""
        cwe_map = {
            "SQL injection": "CWE-89",
            "Cross-site scripting": "CWE-79",
            "SSRF": "CWE-918",
            "XML external entity injection": "CWE-611",
            "OS command injection": "CWE-78",
            "File path traversal": "CWE-22",
            "Insecure deserialization": "CWE-502",
        }
        for key, value in cwe_map.items():
            if key.lower() in issue_type.lower():
                return value
        return None

    def _update_history_buffer(self, entries: List[Dict[str, Any]]) -> None:
        """Maintain circular buffer of proxy history."""
        self._proxy_history_buffer.extend(entries)
        if len(self._proxy_history_buffer) > self._max_history_size:
            self._proxy_history_buffer = self._proxy_history_buffer[
                -self._max_history_size :
            ]

    async def get_request_by_id(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve specific request from proxy history."""
        for entry in self._proxy_history_buffer:
            if entry.get("id") == request_id:
                return entry

        # Fallback to MCP query
        response = await self.registry.execute_tool(
            self.SERVER_ID, "get_request_by_id", {"request_id": request_id}
        )

        if response.status == "success" and response.result:
            return response.result
        return None
