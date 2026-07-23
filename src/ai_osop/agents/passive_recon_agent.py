"""
Passive Reconnaissance Agent
Discovers subdomains and staging endpoints silently using third-party APIs.
"""

from typing import Any, Dict

import structlog

from ai_osop.adapters.passive_recon_mcp import PassiveReconMCPAdapter
from ai_osop.agents.base import BaseAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task

logger = structlog.get_logger("ai_osop.agents.passive_recon_agent")


class PassiveReconAgent(BaseAgent):
    """
    Agent responsible for silent/passive reconnaissance using OSINT and CT log sources.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.RECON

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "passive_recon"

    async def _setup_resources(self) -> None:
        """Initialize passive recon adapters."""
        self.passive_adapter = PassiveReconMCPAdapter(self.ctx.mcp_registry)

    async def _cleanup_resources(self) -> None:
        """Cleanup resources."""
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute passive recon task."""
        payload = task.payload
        domain = payload.get("domain") or payload.get("target") or payload.get("url")
        if not domain:
            raise AgentException("passive_recon: domain, target, or url is required in payload")

        # Strip scheme/path from domain if it's a URL
        if "://" in domain:
            domain = domain.split("://")[1].split("/")[0]

        # Initialize passive adapter
        await self.passive_adapter.initialize({}, task.engagement_id)

        logger.info("passive_recon_started", domain=domain, task_id=task.id)

        # 1. Discover subdomains passively
        subdomains = await self.passive_adapter.passive_subdomain_discovery(domain)
        for asset in subdomains:
            try:
                asset.engagement_id = task.engagement_id
                await self.ctx.graph_memory.add_asset(asset)
            except Exception as e:  # noqa: BLE001
                logger.error("passive_subdomain_persist_failed", value=asset.value, error=str(e))

        # 2. Query Shodan passively for hosts
        hosts = await self.passive_adapter.shodan_lookup(domain)
        for asset in hosts:
            try:
                asset.engagement_id = task.engagement_id
                await self.ctx.graph_memory.add_asset(asset)
            except Exception as e:  # noqa: BLE001
                logger.error("passive_host_persist_failed", value=asset.value, error=str(e))

        return {
            "status": "success",
            "domain": domain,
            "subdomains_discovered": len(subdomains),
            "hosts_discovered": len(hosts),
        }
