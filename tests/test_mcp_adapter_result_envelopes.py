"""A successful transport status cannot manufacture an empty scan result."""

from types import SimpleNamespace

import pytest

from ai_osop.adapters.cloud_mcp import CloudMCPAdapter
from ai_osop.adapters.nuclei_mcp import NucleiMCPAdapter
from ai_osop.adapters.turbo_intruder_mcp import TurboIntruderMCPAdapter
from ai_osop.core.exceptions import MCPException


class _Registry:
    def __init__(self, result: object) -> None:
        self.result = result

    async def execute_tool(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(status="success", result=self.result, error=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("result", [None, {}, {"findings": None}, {"findings": {}}])
async def test_nuclei_never_turns_missing_result_into_no_findings(result: object) -> None:
    adapter = NucleiMCPAdapter(_Registry(result))
    with pytest.raises(MCPException, match="valid findings envelope"):
        await adapter.scan(["https://example.test"])
    assert await NucleiMCPAdapter(_Registry({"findings": []})).scan(
        ["https://example.test"]
    ) == {"findings": []}


@pytest.mark.asyncio
async def test_cloud_and_race_adapters_reject_empty_success() -> None:
    for result in (None, {}):
        cloud = CloudMCPAdapter(_Registry(result))
        with pytest.raises(MCPException, match="no valid result"):
            await cloud.analyze_iam_trust_policies("123456789012")
        with pytest.raises(MCPException, match="no valid result"):
            await cloud.discover_privilege_escalation("arn:aws:iam::123456789012:role/test")
        race = TurboIntruderMCPAdapter(_Registry(result))
        with pytest.raises(MCPException, match="no valid execution result"):
            await race.execute_single_packet_attack("https://example.test")
