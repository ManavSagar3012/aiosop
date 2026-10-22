"""SourceMap original-byte adapter: only a prepared signed 0027 Action may run.

This adapter never fetches an arbitrary page, issues permission, stages a host
file, or treats a successful native receipt as independently verified effects.
"""

import re
from typing import Any, Dict

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry, MCPInitializeResponse, SideEffectClass
from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor


class SourceMapMCPAdapter:
    """Adapter for the source-map-mcp server (Python binary on :8096)."""

    SERVER_ID = "source-map-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        try:
            manifest = await self.registry.initialize_server(
                self.SERVER_ID, scope=scope, credentials={}, session_id=session_id
            )
            server = self.registry._servers.get(self.SERVER_ID)
            if (
                not isinstance(manifest, MCPInitializeResponse)
                or manifest.status != "ready"
                or manifest.server_id != self.SERVER_ID
                or "original_sourcemap_signed_preflight_v1" not in manifest.capabilities
                or "mcp_bound_receipts_v1" not in manifest.capabilities
                or len(manifest.tools) != 1
                or manifest.tools[0].name != "inspect_local_original_sourcemap"
                or manifest.tools[0].side_effect_class is not SideEffectClass.READ_ONLY
                or manifest.tools[0].requires_approval is not True
                or manifest.tools[0].scope_check is not True
                or [
                    (param.name, param.type, param.required)
                    for param in manifest.tools[0].parameters
                ]
                != [("artifact_sha256", "string", True)]
                or server is None
                or server._initialized is not True
                or set(server._tools) != {"inspect_local_original_sourcemap"}
            ):
                raise MCPException("Independent original SourceMap declaration unavailable")
        except Exception:
            raise MCPException("Signed SourceMap initialization unavailable") from None

    async def fetch_and_parse_sourcemap(
        self,
        url: str,
        timeout_seconds: int = 60,
    ) -> Dict[str, Any]:
        # Public URL allowlisting is not an independently signed original
        # Task. Deny BEFORE registry/provider transport, even after the local
        # original-artifact tool becomes initialized.
        raise MCPException("Public SourceMap fetch lacks independently signed Task authority")

    async def dispatch_approved_original(
        self,
        executor: FlowMCPActionExecutor,
        binding: Dict[str, Any],
        operator: Dict[str, Any],
        action_id: str,
    ) -> Dict[str, Any]:
        """Invoke exact prepared original 0027 Action, never a standalone read.

        Its durable UNKNOWN is recorded before transport, and the native
        independently redeems the one-shot 0035 issuer receipt. Successful
        local source inspection remains provider testimony, not target proof.
        """
        if (
            not isinstance(executor, FlowMCPActionExecutor)
            or executor.registry is not self.registry
            or not isinstance(binding, dict)
            or not isinstance(operator, dict)
            or type(operator.get("sub")) is not str
            or type(action_id) is not str
            or re.fullmatch(r"action-[a-f0-9]{32}", action_id) is None
        ):
            raise MCPException("Current SourceMap original Action authority unavailable")
        try:
            await executor._authority(binding, operator)
            original = await executor.store.get(binding, operator["sub"], action_id)
            if (
                not isinstance(original, dict)
                or original.get("status") != "prepared"
                or original.get("server_id") != self.SERVER_ID
                or original.get("tool_name") != "inspect_local_original_sourcemap"
            ):
                raise MCPException("Prepared original SourceMap Action unavailable")
            result = await executor.dispatch(binding, operator, action_id)
        except Exception:
            # A lost acknowledgement may follow valid original-byte inspection.
            # Never retry this action or promote provider testimony to proof.
            raise MCPException("Original SourceMap Action outcome UNKNOWN") from None
        return {
            "status": "finished" if result.get("status") == "finished" else "unknown",
            "current_original_action_consumed": True,
            "independent_target_effect_verified": False,
        }
