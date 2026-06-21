"""Nuclei MCP Adapter — template-driven vulnerability scanner integration."""

from typing import Any, Dict, List, Optional

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry


class NucleiMCPAdapter:
    """Adapter for the nuclei-mcp server (Go binary on :8084)."""

    SERVER_ID = "nuclei-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(
            self.SERVER_ID, scope=scope, credentials={}, session_id=session_id
        )

    async def scan(
        self,
        targets: List[str],
        templates: Optional[List[str]] = None,
        rate_limit: int = 150,
        timeout_seconds: int = 900,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "targets": targets,
            "templates": templates or [],
            "rate_limit": rate_limit,
        }
        response = await self.registry.execute_tool(
            self.SERVER_ID, "scan", params, timeout_override=timeout_seconds
        )
        if response.status != "success":
            raise MCPException(f"nuclei scan failed: {response.error}")
        return response.result or {"findings": []}
