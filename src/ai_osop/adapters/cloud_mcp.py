"""Cloud MCP Adapter — cloud enumeration and privilege escalation integration.

MAJ-1 (2026-07-22): the cloud-mcp server (:8097) is a STUB — it returns
hardcoded IAM data instead of probing real cloud APIs. Every method on this
adapter now raises ``NotImplementedError`` at call time so the stub CANNOT
silently produce fake findings. When a real cloud-mcp server lands, remove
the guard and let the ``registry.execute_tool`` call proceed.
"""

from typing import Any, Dict, Optional

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry

_STUB_WARNING = (
    "cloud-mcp is a STUB server (hardcoded IAM data). It cannot produce real "
    "cloud-security findings. Replace the cloud-mcp server with a real "
    "implementation that probes live STS/IAM/metadata APIs, then remove this "
    "guard. See BUG_BOUNTY_PLATFORM_AUDIT.md section 1.2 / MAJ-1."
)


class CloudMCPAdapter:
    """Adapter for the cloud-mcp server (Python binary on :8097).

    STUB — all tool calls raise ``NotImplementedError`` to prevent fake
    findings from reaching the corpus.
    """

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
        raise NotImplementedError(_STUB_WARNING)

    async def discover_privilege_escalation(
        self,
        principal_arn: Optional[str] = None,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        raise NotImplementedError(_STUB_WARNING)

    async def probe_cloud_metadata(
        self,
        target_url: str,
        timeout_seconds: int = 60,
    ) -> Dict[str, Any]:
        raise NotImplementedError(_STUB_WARNING)

    async def probe_storage_exposure(
        self,
        target: str,
        timeout_seconds: int = 60,
    ) -> Dict[str, Any]:
        raise NotImplementedError(_STUB_WARNING)
