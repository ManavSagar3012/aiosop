"""
Browser MCP Adapter
Standardized interface for Playwright-based stateful browser automation.
"""

from typing import Any, Dict, Optional

from ai_osop.core.config import settings
from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry


class BrowserMCPAdapter:
    """Adapter for the browser-mcp server."""

    SERVER_ID = "browser-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        """Initialize the connection to the browser-mcp server."""
        await self.registry.initialize_server(self.SERVER_ID, scope, {}, session_id)

    async def execute_action(
        self,
        action: str,
        params: Optional[Dict[str, Any]] = None,
        user_label: str = "guest",
        engagement_id: str = "",
        storage_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generic action passthrough to browser-mcp."""
        body = {
            "url": (params or {}).get("url", ""),
            "action": action,
            "user_label": user_label,
            "engagement_id": engagement_id,
        }
        # Phase 1 Bug Bounty Upgrade: forward authenticated session import to the
        # browser-mcp server (separate process — it can't read our SessionStore).
        if storage_state:
            body["storage_state"] = storage_state
        if params:
            for k, v in params.items():
                if k not in body:
                    body[k] = v
        response = await self.registry.execute_tool(
            self.SERVER_ID, "execute", body, timeout_override=settings.browser_mcp_timeout
        )
        if response.status != "success":
            raise MCPException(f"Browser action '{action}' failed: {response.error}")
        return response.result or {}

    async def navigate(
        self,
        url: str,
        user_label: str = "guest",
        engagement_id: str = "",
        storage_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Navigate to a URL and capture state.

        When ``storage_state`` is provided (Playwright's {cookies, origins} shape),
        the browser context is seeded with those credentials so navigation runs as
        the imported user.
        """
        try:
            return await self.execute_action(
                "navigate",
                {"url": url},
                user_label=user_label,
                engagement_id=engagement_id,
                storage_state=storage_state,
            )
        except MCPException as e:
            # Defense-in-depth (2026-07-04): a localhost/private-range target that is
            # HTTP-only fails an https:// navigation with net::ERR_SSL_PROTOCOL_ERROR,
            # which otherwise kills the whole autonomous chain. Retry once over http.
            # Public targets are never downgraded (real bounty targets stay https).
            if ("SSL" in str(e) or "ERR_SSL" in str(e)) and self._is_local_http_target(url):
                return await self.execute_action(
                    "navigate",
                    {"url": "http://" + url[len("https://") :]},
                    user_label=user_label,
                    engagement_id=engagement_id,
                    storage_state=storage_state,
                )
            raise

    @staticmethod
    def _is_local_http_target(url: str) -> bool:
        if not url.startswith("https://"):
            return False
        host = url[len("https://") :].split("/")[0].split(":")[0].lower()
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        if host.startswith(("10.", "192.168.")):
            return True
        if host.startswith("172.") and host.count(".") >= 1:
            parts = host.split(".")
            return len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31
        return False

    async def capture_state(
        self, user_label: str = "guest", engagement_id: str = ""
    ) -> Dict[str, Any]:
        """Capture cookies and local storage."""
        result = await self.execute_action(
            "capture_session", None, user_label=user_label, engagement_id=engagement_id
        )
        return result.get("state", {})

    async def screenshot(
        self,
        user_label: str = "guest",
        engagement_id: str = "",
        workflow_id: str = "",
        step_id: str = "",
    ) -> Dict[str, Any]:
        """Take a PNG screenshot of the current page and return its path."""
        return await self.execute_action(
            "screenshot",
            {"workflow_id": workflow_id, "step_id": step_id},
            user_label=user_label,
            engagement_id=engagement_id,
        )

    async def dom_snapshot(
        self,
        user_label: str = "guest",
        engagement_id: str = "",
        workflow_id: str = "",
        step_id: str = "",
    ) -> Dict[str, Any]:
        """Persist the page HTML and return its path."""
        return await self.execute_action(
            "dom_snapshot",
            {"workflow_id": workflow_id, "step_id": step_id},
            user_label=user_label,
            engagement_id=engagement_id,
        )

    async def flush_har(
        self,
        user_label: str = "guest",
        engagement_id: str = "",
        workflow_id: str = "",
    ) -> Dict[str, Any]:
        """Close and persist the HAR file for this identity."""
        return await self.execute_action(
            "flush_har",
            {"workflow_id": workflow_id},
            user_label=user_label,
            engagement_id=engagement_id,
        )
