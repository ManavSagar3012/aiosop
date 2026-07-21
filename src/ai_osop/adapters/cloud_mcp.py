"""Cloud MCP Adapter — cloud enumeration and privilege escalation integration."""

from typing import Any, Dict, Optional

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry


class CloudMCPAdapter:
    """Adapter for the cloud-mcp server (Python binary on :8097)."""

    SERVER_ID = "cloud-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(
            self.SERVER_ID, scope=scope, credentials={}, session_id=session_id
        )

    async def analyze_iam_trust_policies(
        self,
        account_id: Optional[str] = None,
        timeout_seconds: int = 120,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "account_id": account_id,
        }
        response = await self.registry.execute_tool(
            self.SERVER_ID, "analyze_iam_trust_policies", params, timeout_override=timeout_seconds
        )
        if response.status != "success":
            raise MCPException(f"cloud-mcp analyze_iam failed: {response.error}")
        return response.result or {}

    async def discover_privilege_escalation(
        self,
        principal_arn: Optional[str] = None,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "principal_arn": principal_arn,
        }
        response = await self.registry.execute_tool(
            self.SERVER_ID,
            "discover_privilege_escalation",
            params,
            timeout_override=timeout_seconds,
        )
        if response.status != "success":
            raise MCPException(f"cloud-mcp discover_privesc failed: {response.error}")
        return response.result or {}

    async def probe_cloud_metadata(
        self,
        target_url: str,
        timeout_seconds: int = 60,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"target_url": target_url}
        response = await self.registry.execute_tool(
            self.SERVER_ID, "probe_cloud_metadata", params, timeout_override=timeout_seconds
        )
        if response.status != "success":
            raise MCPException(f"cloud-mcp probe_metadata failed: {response.error}")
        return response.result or {}

    async def probe_storage_exposure(
        self,
        target: str,
        timeout_seconds: int = 60,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"target": target}
        response = await self.registry.execute_tool(
            self.SERVER_ID, "probe_storage_exposure", params, timeout_override=timeout_seconds
        )
        if response.status != "success":
            raise MCPException(f"cloud-mcp probe_storage failed: {response.error}")
        return response.result or {}
