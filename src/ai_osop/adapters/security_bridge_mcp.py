"""
Security Bridge MCP Adapter
Standardized interface for high-performance offensive tools (sqlmap, nmap, ffuf).
"""

import logging
from typing import Any, Dict, List, Optional

from ai_osop.core.exceptions import MCPException
from ai_osop.core.models import Asset, Endpoint
from ai_osop.mcp.protocol import MCPRegistry


class SecurityBridgeAdapter:
    """Adapter for the security-bridge MCP server."""

    SERVER_ID = "security-bridge"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        """Initialize the connection to the security-bridge server."""
        await self.registry.initialize_server(self.SERVER_ID, scope, {}, session_id)

    async def run_nmap(self, target: str, fast: bool = False) -> List[Asset]:
        """Run Nmap scan against target."""
        params = {"target": target, "fast": fast}
        response = await self.registry.execute_tool(self.SERVER_ID, "nmap", params)

        if response.status != "success":
            raise MCPException(f"Nmap execution failed: {response.error}")

        assets = []
        hosts = response.result.get("hosts", [])
        for host in hosts:
            assets.append(
                Asset(
                    type="host",
                    value=host["ip"],
                    source="nmap",
                    confidence=1.0,
                    metadata={"ports": host.get("ports", [])},
                    engagement_id="",  # Filled by agent
                )
            )
        return assets

    async def run_sqlmap(self, url: str, dump: bool = False) -> Dict[str, Any]:
        """Run SQLMap against target URL."""
        params = {"url": url, "dump": dump, "batch": True}
        response = await self.registry.execute_tool(self.SERVER_ID, "sqlmap", params)

        if response.status != "success":
            raise MCPException(f"SQLMap execution failed: {response.error}")

        return response.result.get("data", {})

    async def run_ffuf(self, url: str) -> List[Endpoint]:
        """Run FFUF directory/file fuzzing."""
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        params = {"url": url}
        response = await self.registry.execute_tool(self.SERVER_ID, "ffuf", params)

        if response.status != "success":
            raise MCPException(f"FFUF execution failed: {response.error}")

        endpoints = []
        results = response.result.get("results", [])
        for res in results:
            endpoints.append(
                Endpoint(
                    url=res["url"],
                    method="GET",
                    status_code=res["status"],
                    source="ffuf",
                    confidence=0.9,
                    engagement_id="",  # Filled by agent
                )
            )
        return endpoints

    async def run_katana(self, url: str, depth: int = 3) -> Dict[str, List[str]]:
        """Run Katana crawler."""
        params = {"url": url, "depth": depth, "js_crawl": True}
        response = await self.registry.execute_tool(self.SERVER_ID, "katana_crawl", params)

        if response.status != "success":
            raise MCPException(f"Katana crawl failed: {response.error}")

        return {
            "endpoints": response.result.get("endpoints", []),
            "js_files": response.result.get("js_files", []),
        }

    async def run_js_analyze(self, js_url: str) -> Dict[str, Any]:
        """Analyze JS file for routes and secrets."""
        params = {"js_url": js_url}
        response = await self.registry.execute_tool(self.SERVER_ID, "js_analyze", params)

        if response.status != "success":
            raise MCPException(f"JS analysis failed: {response.error}")

        return response.result
