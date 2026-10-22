"""Cloud MCP Adapter — cloud enumeration and privilege escalation integration."""

from typing import Any, Dict, List, Optional

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

    async def scan_local_iac(self, timeout_seconds: int = 70) -> Dict[str, Any]:
        """Scan only the source's pinned tree, preserving static-only provenance."""
        response = await self.registry.execute_tool(
            self.SERVER_ID, "scan_local_iac", {}, timeout_override=timeout_seconds
        )
        result = response.result
        if (
            response.status != "success"
            or not isinstance(result, dict)
            or result.get("live_cloud_account_verified") is not False
            or result.get("target_effect_verified") is not False
            or result.get("source") != "CHECKOV_LOCAL_IAC_UNVERIFIED"
            or not isinstance(result.get("findings"), list)
            or type(result.get("findings_count")) is not int
            or result["findings_count"] != len(result["findings"])
        ):
            raise MCPException("cloud-mcp local IaC result unavailable or provenance invalid")
        return result

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
        if not isinstance(response.result, dict) or not response.result:
            raise MCPException("cloud-mcp analyze_iam returned no valid result")
        return response.result

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
        if not isinstance(response.result, dict) or not response.result:
            raise MCPException("cloud-mcp discover_privesc returned no valid result")
        return response.result
