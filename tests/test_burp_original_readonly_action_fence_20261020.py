"""Burp READ_ONLY Action must cross original 0027; no external Burp/targets.

The local adapter does not independently certify target effects or provide a
source-side Burp extension. Existing real 8081 provider remains unavailable.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.adapters.burp_mcp import BurpMCPAdapter
from ai_osop.core.config import settings
from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor

_ACTION = "action-" + "a" * 32
_BINDING = {
    "engagement_id": "eng-burp-reviewed",
    "flow_id": "flow-burp-reviewed",
    "revision": 1,
    "version": 2,
    "authorization_id": "auth-burp-original",
    "authorization_sha256": "c" * 64,
}
_OWNER = {"sub": "reviewed-owner", "role": "operator"}


def _executor(registry):
    executor = object.__new__(FlowMCPActionExecutor)
    executor.registry = registry
    executor._authority = AsyncMock(return_value={})
    executor.store = SimpleNamespace(
        get=AsyncMock(
            return_value={
                "status": "prepared",
                "server_id": "burp-mcp",
                "tool_name": "get_scan_issues",
            }
        ),
    )
    executor.dispatch = AsyncMock(return_value={"status": "unknown"})
    return executor


@pytest.mark.asyncio
async def test_production_legacy_read_only_burp_observation_never_bypasses_0027(
    monkeypatch,
):
    registry = MCPRegistry()
    registry.execute_tool = AsyncMock()
    adapter = BurpMCPAdapter(registry)
    monkeypatch.setattr(settings, "environment", "production")
    with pytest.raises(MCPException, match="Original reviewed Burp"):
        await adapter._observe("get_scan_issues", {"target": "https://local.test"})
    registry.execute_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_prepared_read_only_burp_consumes_once_and_reports_no_target_proof(monkeypatch):
    registry = MCPRegistry()
    adapter = BurpMCPAdapter(registry)
    adapter._connection = lambda: object()
    executor = _executor(registry)
    result = await adapter.dispatch_prepared_action(
        executor,
        _BINDING,
        _OWNER,
        _ACTION,
        "get_scan_issues",
    )
    assert result == {
        "status": "unknown",
        "execution_authority": "source_signed_flow_action",
        "independent_target_effect_verified": False,
    }
    executor.store.get.assert_awaited_once_with(
        _BINDING,
        "reviewed-owner",
        _ACTION,
    )
    executor.dispatch.assert_awaited_once_with(
        _BINDING,
        _OWNER,
        _ACTION,
    )
    executor.dispatch.reset_mock()
    executor.store.get = AsyncMock(
        return_value={
            "status": "unknown",
            "server_id": "burp-mcp",
            "tool_name": "get_scan_issues",
        }
    )
    with pytest.raises(MCPException, match="unavailable"):
        await adapter.dispatch_prepared_action(
            executor,
            _BINDING,
            _OWNER,
            _ACTION,
            "get_scan_issues",
        )
    executor.dispatch.assert_not_awaited()
    with pytest.raises(MCPException):
        await adapter.dispatch_prepared_action(
            executor,
            _BINDING,
            _OWNER,
            _ACTION,
            "unreviewed_extension",
        )
    executor.dispatch.assert_not_awaited()


@pytest.mark.asyncio
async def test_burp_lost_ack_stays_unknown_without_replay_or_error_disclosure():
    registry = MCPRegistry()
    adapter = BurpMCPAdapter(registry)
    adapter._connection = lambda: object()
    executor = _executor(registry)
    executor.dispatch = AsyncMock(side_effect=RuntimeError("SENSITIVE_BURP_CONTENT"))
    with pytest.raises(MCPException, match="outcome UNKNOWN") as denied:
        await adapter.dispatch_prepared_action(
            executor,
            _BINDING,
            _OWNER,
            _ACTION,
            "get_scan_issues",
        )
    assert "SENSITIVE_BURP_CONTENT" not in str(denied.value)
    executor.dispatch.assert_awaited_once()
