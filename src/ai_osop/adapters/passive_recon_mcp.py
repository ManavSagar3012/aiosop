"""
Passive Reconnaissance MCP Server Adapter
Discovers subdomains and staging endpoints silently using third-party passive APIs.
"""

from typing import Any, Dict, List

import structlog

from ai_osop.core.models import Asset
from ai_osop.mcp.protocol import MCPRegistry

logger = structlog.get_logger("ai_osop.adapters.passive_recon_mcp")


class PassiveReconMCPAdapter:
    """Orchestrates passive reconnaissance via MCP without actively scanning targets."""

    SERVER_ID = "recon-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        """Initialize recon MCP with scope."""
        await self.registry.initialize_server(
            self.SERVER_ID, scope=scope, credentials={}, session_id=session_id
        )

    async def passive_subdomain_discovery(self, domain: str) -> List[Asset]:
        """Query passive DNS/subdomain APIs (Subfinder, Amass passive)."""
        subdomains = []

        # 1. Query subfinder (passive subdomains)
        try:
            resp = await self.registry.execute_tool(
                self.SERVER_ID, "subfinder_enum", {"domain": domain}
            )
            if resp.status == "success" and resp.result:
                subs = resp.result.get("subdomains", [])
                for sub in subs:
                    sub_val = (
                        sub.get("domain") or sub.get("value") if isinstance(sub, dict) else str(sub)
                    )
                    subdomains.append({"domain": sub_val, "source": "subfinder", "confidence": 0.8})
        except Exception as e:  # noqa: BLE001
            logger.warning("passive_subfinder_failed", domain=domain, error=str(e))

        # 2. Query amass passive
        try:
            resp = await self.registry.execute_tool(
                self.SERVER_ID, "amass_passive", {"domain": domain}
            )
            if resp.status == "success" and resp.result:
                subs = resp.result.get("subdomains", [])
                for sub in subs:
                    sub_val = (
                        sub.get("domain") or sub.get("value") if isinstance(sub, dict) else str(sub)
                    )
                    subdomains.append(
                        {"domain": sub_val, "source": "amass_passive", "confidence": 0.85}
                    )
        except Exception as e:  # noqa: BLE001
            logger.warning("passive_amass_failed", domain=domain, error=str(e))

        # 3. Deduplicate subdomains
        seen = {}
        for entry in subdomains:
            host = entry["domain"].lower().strip()
            if not host or not host.endswith(domain.lower()):
                continue
            if host not in seen:
                seen[host] = {
                    "domain": host,
                    "confidence": entry["confidence"],
                    "sources": [entry["source"]],
                }
            else:
                seen[host]["sources"].append(entry["source"])
                # Probabilistic merge
                seen[host]["confidence"] = 1.0 - (1.0 - seen[host]["confidence"]) * (
                    1.0 - entry["confidence"]
                )

        assets = []
        for host, data in seen.items():
            assets.append(
                Asset(
                    type="subdomain",
                    value=host,
                    source="passive_recon",
                    confidence=data["confidence"],
                    metadata={"sources": list(set(data["sources"])), "passive": True},
                    engagement_id="",
                )
            )

        return assets

    async def shodan_lookup(self, domain: str) -> List[Asset]:
        """Discovers internet-facing assets passively using Shodan API."""
        try:
            resp = await self.registry.execute_tool(
                self.SERVER_ID, "shodan_lookup", {"domain": domain}
            )
            if resp.status == "success" and resp.result:
                # Normalize Shodan hosts to Asset models
                assets = []
                hosts_data = (
                    resp.result.get("hosts") or resp.result if isinstance(resp.result, dict) else []
                )
                if isinstance(hosts_data, list):
                    for host in hosts_data:
                        if isinstance(host, dict):
                            assets.append(
                                Asset(
                                    type="host",
                                    value=host.get("ip") or host.get("ip_address", ""),
                                    source="shodan_passive",
                                    confidence=0.9,
                                    metadata={
                                        "ports": host.get("ports", []),
                                        "hostnames": host.get("hostnames", []),
                                        "passive": True,
                                    },
                                    engagement_id="",
                                )
                            )
                return assets
        except Exception as e:  # noqa: BLE001
            logger.warning("shodan_passive_lookup_failed", domain=domain, error=str(e))
        return []
