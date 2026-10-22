"""Unavailable payload providers must not manufacture successful tool output."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.adapters.payload_mcp import PayloadMCPAdapter
from ai_osop.core.config import VulnClass
from ai_osop.core.exceptions import MCPException
from ai_osop.core.models import Payload


@pytest.mark.asyncio
async def test_payload_mcp_unavailable_does_not_generate_or_mutate() -> None:
    registry = SimpleNamespace(
        execute_tool=AsyncMock(
            return_value=SimpleNamespace(status="unknown", result=None, error="unavailable")
        )
    )
    adapter = PayloadMCPAdapter(registry)

    with pytest.raises(MCPException, match="generation unavailable"):
        await adapter.generate_payload(VulnClass.XSS, {"param": "q"})

    payload = Payload(
        vuln_type=VulnClass.XSS,
        content="input",
        content_hash="c96c6d5be8d08a12",
        context={},
        engagement_id="eng-test",
    )
    with pytest.raises(MCPException, match="mutation unavailable"):
        await adapter.mutate_payload(payload)
    with pytest.raises(MCPException, match="analysis unavailable"):
        await adapter.analyze_response(payload, {"status_code": 200})
    with pytest.raises(MCPException, match="history unavailable"):
        await adapter.get_payload_history(VulnClass.XSS, "target-hash")

    assert registry.execute_tool.await_count == 4


@pytest.mark.asyncio
async def test_payload_mcp_rejects_legacy_mock_shape_as_success() -> None:
    registry = SimpleNamespace(
        execute_tool=AsyncMock(
            return_value=SimpleNamespace(
                status="success",
                result={"payload": "<script>alert('mock-xss')</script>"},
            )
        )
    )
    adapter = PayloadMCPAdapter(registry)

    with pytest.raises(MCPException, match="no usable payload content"):
        await adapter.generate_payload(VulnClass.XSS, {"param": "q"})
