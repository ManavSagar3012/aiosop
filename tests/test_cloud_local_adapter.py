"""Local IaC adapter keeps static findings distinct from live cloud evidence."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.adapters.cloud_mcp import CloudMCPAdapter
from ai_osop.core.exceptions import MCPException


@pytest.mark.asyncio
async def test_local_adapter_dispatches_only_fixed_source_operation() -> None:
    result = {
        "findings": [],
        "findings_count": 0,
        "source": "CHECKOV_LOCAL_IAC_UNVERIFIED",
        "live_cloud_account_verified": False,
        "target_effect_verified": False,
    }
    registry = SimpleNamespace(
        execute_tool=AsyncMock(return_value=SimpleNamespace(status="success", result=result))
    )
    assert await CloudMCPAdapter(registry).scan_local_iac() == result
    registry.execute_tool.assert_awaited_once_with(
        "cloud-mcp", "scan_local_iac", {}, timeout_override=70
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["live_cloud_account_verified", "target_effect_verified"])
async def test_local_adapter_rejects_promoted_static_result(field: str) -> None:
    result = {
        "findings": [],
        "findings_count": 0,
        "source": "CHECKOV_LOCAL_IAC_UNVERIFIED",
        "live_cloud_account_verified": False,
        "target_effect_verified": False,
    }
    result[field] = True
    registry = SimpleNamespace(
        execute_tool=AsyncMock(return_value=SimpleNamespace(status="success", result=result))
    )
    with pytest.raises(MCPException):
        await CloudMCPAdapter(registry).scan_local_iac()
