"""Turbo Intruder MCP Adapter — precision timing engine integration."""

from typing import Any, Dict, Optional

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry


class TurboIntruderMCPAdapter:
    """Adapter for the turbo-intruder-mcp server (Python binary on :8098)."""

    SERVER_ID = "turbo-intruder-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(
            self.SERVER_ID, scope=scope, credentials={}, session_id=session_id
        )

    async def execute_single_packet_attack(
        self,
        target_url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        concurrent_requests: int = 10,
        timeout_seconds: int = 120,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "target_url": target_url,
            "method": method,
            "headers": headers or {},
            "body": body,
            "concurrent_requests": concurrent_requests,
        }
        response = await self.registry.execute_tool(
            self.SERVER_ID, "execute_single_packet_attack", params, timeout_override=timeout_seconds
        )
        if response.status != "success":
            raise MCPException(f"turbo-intruder-mcp attack failed: {response.error}")
        return response.result or {}
