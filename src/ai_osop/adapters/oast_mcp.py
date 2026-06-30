"""OAST Interaction MCP Adapter.

Wraps the oast-mcp server so agents can mint correlation tokens and poll for
captured out-of-band callbacks through the standard MCPRegistry.
"""
from typing import Any, Dict, List, Tuple

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry


class OASTAdapter:
    SERVER_ID = "oast-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(self.SERVER_ID, scope, {}, session_id)

    async def register(self, label: str = "") -> Tuple[str, str]:
        """Mint a token; returns (token, callback_url)."""
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_register", {"label": label})
        if resp.status != "success":
            raise MCPException(f"OAST register failed: {resp.error}")
        r = resp.result or {}
        return r.get("token", ""), r.get("callback_url", "")

    async def poll(self, token: str) -> List[Dict[str, Any]]:
        """Return captured interactions for a token (empty if none yet)."""
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_poll", {"token": token})
        if resp.status != "success":
            raise MCPException(f"OAST poll failed: {resp.error}")
        return (resp.result or {}).get("interactions", []) or []
