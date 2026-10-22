"""Provider outages cannot become observed assets or successful recon scans.

These are deterministic adapter/graph faults. No network or target is touched.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.recon_agent import ReconAgent
from ai_osop.core.models import Asset


def _agent():
    graph = SimpleNamespace(add_asset=AsyncMock())
    task = SimpleNamespace(engagement_id="eng-owned", id="task-owned")
    agent = ReconAgent(SimpleNamespace(current_task=task, graph_memory=graph))
    agent.recon_adapter = SimpleNamespace(
        dns_enumeration=AsyncMock(),
        port_scan=AsyncMock(),
        service_discovery=AsyncMock(),
    )
    agent.asset_inventory = {}
    agent._get_relevant_skills = AsyncMock(return_value=[])
    agent.think = AsyncMock(return_value="Synthetic safe research.")
    return agent, graph


@pytest.mark.asyncio
async def test_dns_provider_error_stays_unknown_without_fabricated_scope_asset():
    agent, graph = _agent()
    agent.recon_adapter.dns_enumeration.side_effect = TimeoutError("private provider detail")
    result = await agent._execute_dns_enum({"domain": "example.org"})
    assert result["status"] == result["validation_state"].lower()
    assert result["assets"] == [] and result["assets_discovered"] == 0
    assert "private provider detail" not in str(result)
    graph.add_asset.assert_not_awaited()
    assert agent.asset_inventory == {}


@pytest.mark.asyncio
async def test_full_recon_dns_outage_blocks_reasoning_seeding_and_port_dispatch():
    agent, graph = _agent()
    agent.recon_adapter.dns_enumeration.side_effect = OSError("loss after DNS receipt")
    result = await agent._execute_full_recon({"domain": "example.org"})
    assert result["status"] == "unknown"
    assert result["validation_state"] == "UNKNOWN"
    assert result["subdomains_found"] == 0
    graph.add_asset.assert_not_awaited()
    agent.think.assert_not_awaited()
    agent.recon_adapter.port_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_full_recon_scope_input_is_not_dns_observation():
    agent, graph = _agent()
    agent.recon_adapter.dns_enumeration.return_value = []
    result = await agent._execute_full_recon({"domain": "example.org"})
    assert result["status"] == "success"
    graph.add_asset.assert_awaited_once()
    scope_input = graph.add_asset.await_args.args[0]
    assert scope_input.value == "example.org"
    assert scope_input.source == "recon_scope_seed_unverified"
    assert scope_input.confidence == 0.0
    agent.recon_adapter.port_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_bad_dns_provider_shape_cannot_be_persisted_or_discovered():
    agent, graph = _agent()
    agent.recon_adapter.dns_enumeration.return_value = ["unverified-foreign.example"]
    result = await agent._execute_dns_enum({"domain": "example.org"})
    assert result["status"] == "unknown"
    assert result["assets_discovered"] == 0
    graph.add_asset.assert_not_awaited()


@pytest.mark.asyncio
async def test_port_and_service_provider_outages_do_not_return_success():
    agent, graph = _agent()
    agent.recon_adapter.port_scan.side_effect = TimeoutError("port scan uncertain")
    agent.recon_adapter.service_discovery.side_effect = TimeoutError("service probe uncertain")
    ports = await agent._execute_port_scan({"targets": ["example.org"]})
    probes = await agent._execute_service_probe({"targets": ["example.org"]})
    assert ports["status"] == "unknown" and ports["assets_discovered"] == 0
    assert probes["status"] == "unknown" and probes["probed_count"] == 0
    graph.add_asset.assert_not_awaited()


@pytest.mark.asyncio
async def test_full_recon_never_reports_success_when_authorized_port_scan_failed():
    agent, graph = _agent()
    agent.recon_adapter.dns_enumeration.return_value = [
        Asset(
            type="subdomain",
            value="api.example.org",
            source="dns",
            confidence=0.9,
            engagement_id="eng-owned",
        ),
    ]
    agent.recon_adapter.port_scan.side_effect = ConnectionError("ambiguous scan")
    result = await agent._execute_full_recon({"domain": "example.org"})
    assert result["status"] == "unknown"
    assert result["validation_state"] == "UNKNOWN"
    assert result["subdomains_found"] == 1
    assert agent.think.await_count == 1
