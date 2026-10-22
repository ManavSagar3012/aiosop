"""Recon service probes use the adapter and persist endpoint observations."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.recon_agent import ReconAgent
from ai_osop.core.models import Endpoint


@pytest.mark.asyncio
async def test_service_probe_calls_existing_adapter_and_persists_endpoints() -> None:
    endpoint = Endpoint(url="https://example.org/", engagement_id="")
    graph = SimpleNamespace(add_endpoint=AsyncMock())
    context = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-owned"), graph_memory=graph
    )
    agent = ReconAgent(context)
    agent.recon_adapter = SimpleNamespace(service_probe=AsyncMock(return_value=[endpoint]))
    agent.endpoint_inventory = {}

    result = await agent._execute_service_probe({"targets": ["https://example.org/"]})

    assert result == {"status": "success", "probed_count": 1}
    agent.recon_adapter.service_probe.assert_awaited_once_with(["https://example.org/"])
    graph.add_endpoint.assert_awaited_once_with(endpoint)
    assert endpoint.engagement_id == "eng-owned"
    assert agent.endpoint_inventory[endpoint.id] is endpoint


@pytest.mark.asyncio
async def test_service_probe_persistence_failure_is_unknown() -> None:
    endpoint = Endpoint(url="https://example.org/", engagement_id="")
    graph = SimpleNamespace(add_endpoint=AsyncMock(side_effect=RuntimeError("db down")))
    context = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-owned"), graph_memory=graph
    )
    agent = ReconAgent(context)
    agent.recon_adapter = SimpleNamespace(service_probe=AsyncMock(return_value=[endpoint]))
    agent.endpoint_inventory = {}

    result = await agent._execute_service_probe({"targets": ["https://example.org/"]})

    assert result["status"] == "unknown"
    assert result["provider_status"] == "persistence_unavailable"
