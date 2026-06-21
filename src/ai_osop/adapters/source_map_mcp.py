"""Source Map MCP Adapter — frontend javascript and sourcemap analyzer integration."""

from typing import Any, Dict, List, Optional

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry


class SourceMapMCPAdapter:
    """Adapter for the source-map-mcp server (Python binary on :8096)."""

    SERVER_ID = "source-map-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(
            self.SERVER_ID, scope=scope, credentials={}, session_id=session_id
        )

    async def fetch_and_parse_sourcemap(
        self,
        url: str,
        timeout_seconds: int = 60,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "url": url,
        }
        response = await self.registry.execute_tool(
            self.SERVER_ID, "fetch_and_parse_sourcemap", params, timeout_override=timeout_seconds
        )
        if response.status != "success":
            raise MCPException(f"source-map fetch failed: {response.error}")
        return response.result or {}
