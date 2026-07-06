"""OAST Interaction MCP Adapter.

Wraps the oast-mcp server so agents can mint correlation tokens and poll for
captured out-of-band callbacks through the standard MCPRegistry.
"""
from typing import Any, Dict, List, Optional, Tuple

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry


class OASTAdapter:
    SERVER_ID = "oast-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(self.SERVER_ID, scope, {}, session_id)

    async def register(
        self, label: str = "", context: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, str]:
        """Mint a token; returns (token, callback_url).

        `context` carries probe provenance (engagement_id, vuln_class, injection
        point, payload, ...). The OAST server stores it against the token and
        echoes it back on poll/drain, so a captured callback can be attributed to
        the exact probe that caused it even after the injecting scan has returned.
        """
        params: Dict[str, Any] = {"label": label}
        if context:
            params["context"] = context
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_register", params)
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

    async def drain(
        self, since: int = 0, engagement_id: Optional[str] = None
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """Pull all interactions with seq > `since` across every token.

        Returns (cursor, interactions) where each interaction is annotated with
        its `token` and probe `context`. The cursor is the highest seq observed;
        pass it back as `since` next time to page only fresh callbacks. This is
        the slow-path reconciler's entry point — it catches blind callbacks that
        land after the injecting scan's inline poll window closed.
        """
        params: Dict[str, Any] = {"since": since}
        if engagement_id:
            params["engagement_id"] = engagement_id
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_drain", params)
        if resp.status != "success":
            raise MCPException(f"OAST drain failed: {resp.error}")
        r = resp.result or {}
        return int(r.get("cursor", since) or since), (r.get("interactions", []) or [])
