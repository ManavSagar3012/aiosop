"""A failed recon provider is not evidence of an empty target inventory."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.adapters.recon_mcp import ReconMCPAdapter
from ai_osop.core.exceptions import MCPException


@pytest.mark.asyncio
async def test_recon_mcp_unavailable_does_not_report_empty_inventory() -> None:
    registry = SimpleNamespace(
        execute_tool=AsyncMock(
            return_value=SimpleNamespace(status="unknown", result=None, error="unavailable")
        )
    )
    adapter = ReconMCPAdapter(registry)

    with pytest.raises(MCPException, match="enumeration unavailable"):
        await adapter.dns_enumeration("example.org", active=False)
    with pytest.raises(MCPException, match="port scan unavailable"):
        await adapter.port_scan(["example.org"])
    with pytest.raises(MCPException, match="service probe unavailable"):
        await adapter.service_probe(["https://example.org"])
    with pytest.raises(MCPException, match="historical URLs unavailable"):
        await adapter.historical_urls("example.org")
    with pytest.raises(MCPException, match="technology fingerprint unavailable"):
        await adapter.technology_fingerprint(["https://example.org"])


@pytest.mark.asyncio
async def test_http_probe_normalizes_declared_server_endpoint_shape() -> None:
    registry = SimpleNamespace(
        execute_tool=AsyncMock(
            return_value=SimpleNamespace(
                status="success",
                result={"endpoints": [{"url": "https://example.org/", "status_code": 200}]},
            )
        )
    )
    endpoints = await ReconMCPAdapter(registry).service_probe(["https://example.org/"])

    assert len(endpoints) == 1
    assert endpoints[0].url == "https://example.org/"
    assert endpoints[0].status_code == 200


def test_recon_normalizers_reject_missing_provider_collections() -> None:
    adapter = ReconMCPAdapter(SimpleNamespace())
    with pytest.raises(MCPException, match="Nmap result malformed"):
        adapter._normalize_nmap_output({"error": "unavailable"})
    with pytest.raises(MCPException, match="Shodan result malformed"):
        adapter._normalize_shodan_output({"error": "unavailable"}, "example.org")
    with pytest.raises(MCPException, match="Wayback result malformed"):
        adapter._normalize_wayback_output({"error": "unavailable"}, "example.org")
