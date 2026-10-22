"""Original SourceMap Action adapter contract, no target, real DB or network.

This proves adapter restrictions only; the 0035 PostgreSQL/issuer chain must
be separately qualified on a truly disposable database before certification.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.adapters.source_map_mcp import SourceMapMCPAdapter
from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import (
    MCPInitializeResponse,
    MCPRegistry,
    MCPToolDefinition,
    MCPToolParameter,
    SideEffectClass,
)
from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor


_ACTION = "action-" + "a" * 32
_BINDING = {
    "engagement_id": "eng-original",
    "flow_id": "flow-original",
    "revision": 1,
    "version": 2,
    "authorization_id": "auth-original",
    "authorization_sha256": "c" * 64,
}
_OPERATOR = {"sub": "owner-original", "role": "operator"}


def _manifest():
    tool = MCPToolDefinition(
        name="inspect_local_original_sourcemap",
        description="One signed original-byte inspected SourceMap artifact",
        parameters=[
            MCPToolParameter(
                name="artifact_sha256",
                type="string",
                description="Exact senior-reviewed original artifact digest",
                required=True,
            )
        ],
        returns={"type": "object", "description": "Inert metadata only"},
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        scope_check=True,
    )
    return MCPInitializeResponse(
        server_id="source-map-mcp",
        version="1.1.0",
        capabilities=["original_sourcemap_signed_preflight_v1", "mcp_bound_receipts_v1"],
        tools=[tool],
        status="ready",
    )


@pytest.mark.asyncio
async def test_only_one_bound_original_tool_initializes_and_public_url_never_dispatches():
    registry = MCPRegistry()
    manifest = _manifest()
    registry.initialize_server = AsyncMock(return_value=manifest)
    registry.execute_tool = AsyncMock()
    registry._servers["source-map-mcp"] = SimpleNamespace(
        _initialized=True,
        _tools={"inspect_local_original_sourcemap": manifest.tools[0]},
    )
    adapter = SourceMapMCPAdapter(registry)
    await adapter.initialize({"engagement_id": "eng-original"}, "eng-original")
    with pytest.raises(MCPException, match="Public SourceMap fetch"):
        await adapter.fetch_and_parse_sourcemap("https://untrusted.invalid/secret.map")
    registry.execute_tool.assert_not_called()
    broken = manifest.model_copy(deep=True)
    broken.tools[0].requires_approval = False
    registry.initialize_server = AsyncMock(return_value=broken)
    with pytest.raises(MCPException, match="initialization unavailable"):
        await adapter.initialize({}, "eng-original")
    registry.execute_tool.assert_not_called()


@pytest.mark.asyncio
async def test_only_prepared_current_action_enters_original_executor_once():
    registry = MCPRegistry()
    adapter = SourceMapMCPAdapter(registry)
    executor = object.__new__(FlowMCPActionExecutor)
    executor.registry = registry
    executor._authority = AsyncMock(return_value={})
    executor.store = SimpleNamespace(
        get=AsyncMock(
            return_value={
                "status": "prepared",
                "server_id": "source-map-mcp",
                "tool_name": "inspect_local_original_sourcemap",
            }
        )
    )
    executor.dispatch = AsyncMock(return_value={"status": "unknown"})
    result = await adapter.dispatch_approved_original(
        executor,
        _BINDING,
        _OPERATOR,
        _ACTION,
    )
    assert result == {
        "status": "unknown",
        "current_original_action_consumed": True,
        "independent_target_effect_verified": False,
    }
    executor.store.get.assert_awaited_once_with(
        _BINDING,
        "owner-original",
        _ACTION,
    )
    executor.dispatch.assert_awaited_once_with(
        _BINDING,
        _OPERATOR,
        _ACTION,
    )
    executor.dispatch.reset_mock()
    executor.store.get = AsyncMock(
        return_value={
            "status": "unknown",
            "server_id": "source-map-mcp",
            "tool_name": "inspect_local_original_sourcemap",
        }
    )
    with pytest.raises(MCPException, match="UNKNOWN|unavailable"):
        await adapter.dispatch_approved_original(executor, _BINDING, _OPERATOR, _ACTION)
    executor.dispatch.assert_not_awaited()
    with pytest.raises(MCPException):
        await adapter.dispatch_approved_original(
            executor, _BINDING, _OPERATOR, "action-" + "A" * 32
        )
    executor.dispatch.assert_not_awaited()


@pytest.mark.asyncio
async def test_ack_loss_does_not_retry_or_echo_external_errors():
    registry = MCPRegistry()
    adapter = SourceMapMCPAdapter(registry)
    executor = object.__new__(FlowMCPActionExecutor)
    executor.registry = registry
    executor._authority = AsyncMock(return_value={})
    executor.store = SimpleNamespace(
        get=AsyncMock(
            return_value={
                "status": "prepared",
                "server_id": "source-map-mcp",
                "tool_name": "inspect_local_original_sourcemap",
            }
        )
    )
    executor.dispatch = AsyncMock(side_effect=RuntimeError("PRIVATE_ORIGINAL_BYTES"))
    with pytest.raises(MCPException, match="outcome UNKNOWN") as denied:
        await adapter.dispatch_approved_original(executor, _BINDING, _OPERATOR, _ACTION)
    assert "PRIVATE_ORIGINAL_BYTES" not in str(denied.value)
    executor.dispatch.assert_awaited_once()
