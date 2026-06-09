"""
Reconnaissance MCP Server
Unified interface for all reconnaissance tools with result normalization,
deduplication, and confidence scoring.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.core.config import settings
from ai_osop.core.models import Asset, Endpoint
from ai_osop.mcp.protocol import MCPExecuteResponse, MCPRegistry


class ReconMCPAdapter:
    """
    Unified reconnaissance orchestration via MCP.

    Integrates:
    - Nmap (port scanning, service detection)
    - Amass (subdomain enumeration)
    - Subfinder (passive subdomain discovery)
    - httpx (HTTP probing, tech detection)
    - Shodan (internet-facing asset discovery)
    - Wayback Machine (historical URL discovery)
    """

    SERVER_ID = "recon-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry
        self._cache: Dict[str, Any] = {}
        self._cache_ttl_seconds = 3600

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        """Initialize recon MCP with scope."""
        await self.registry.initialize_server(
            self.SERVER_ID, scope=scope, credentials={}, session_id=session_id
        )

    async def dns_enumeration(
        self, domain: str, wordlist: Optional[str] = None, depth: int = 2, active: bool = True
    ) -> List[Asset]:
        """
        Comprehensive DNS enumeration using Amass + Subfinder.
        Returns deduplicated subdomain assets.
        """
        cache_key = f"dns:{domain}:{depth}:{active}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Passive enumeration first
        passive_tasks = [self._subfinder_enum(domain), self._amass_passive(domain)]

        passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)

        all_subdomains = []
        for result in passive_results:
            if isinstance(result, list):
                all_subdomains.extend(result)

        # Active enumeration if enabled
        if active:
            active_result = await self._amass_active(domain, depth)
            if isinstance(active_result, list):
                all_subdomains.extend(active_result)

        # Deduplicate and normalize
        assets = self._deduplicate_subdomains(all_subdomains, domain)

        self._cache[cache_key] = assets
        return assets

    async def port_scan(
        self, targets: List[str], ports: str = "top-1000", speed: str = "normal"
    ) -> List[Asset]:
        """
        Nmap-based port scanning with service detection.
        Returns host assets with port/service information.
        """
        params = {
            "targets": targets,
            "ports": ports,
            "speed": speed,
            "options": "-sS -sV -O --script vuln",
        }

        response = await self.registry.execute_tool(
            self.SERVER_ID, "nmap_scan", params, timeout_override=3600
        )

        if response.status != "success" or not response.result:
            return []

        return self._normalize_nmap_output(response.result)

    async def service_probe(
        self, urls: List[str], screenshot: bool = False, tech_detect: bool = True
    ) -> List[Endpoint]:
        """
        httpx-based HTTP probing with technology detection.
        Returns normalized endpoint inventory.
        """
        params = {
            "urls": urls,
            "screenshot": screenshot,
            "tech_detect": tech_detect,
            "status_code": True,
            "title": True,
            "content_length": True,
        }

        response = await self.registry.execute_tool(
            self.SERVER_ID, "httpx_probe", params, timeout_override=600
        )

        if response.status != "success" or not response.result:
            return []

        return self._normalize_httpx_output(response.result)

    async def osint_lookup(self, domain: str) -> List[Asset]:
        """
        Shodan-based OSINT enrichment.
        Returns internet-facing asset findings.
        """
        params = {"domain": domain}

        response = await self.registry.execute_tool(
            self.SERVER_ID, "shodan_lookup", params, timeout_override=120
        )

        if response.status != "success" or not response.result:
            return []

        return self._normalize_shodan_output(response.result, domain)

    async def historical_urls(self, domain: str) -> List[Endpoint]:
        """
        Wayback Machine historical URL discovery.
        Returns historical endpoint inventory.
        """
        params = {"domain": domain}

        response = await self.registry.execute_tool(
            self.SERVER_ID, "wayback_urls", params, timeout_override=300
        )

        if response.status != "success" or not response.result:
            return []

        return self._normalize_wayback_output(response.result, domain)

    async def technology_fingerprint(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        Technology stack fingerprinting across endpoints.
        Returns mapping of URL -> technologies.
        """
        params = {"urls": urls}

        response = await self.registry.execute_tool(
            self.SERVER_ID, "tech_fingerprint", params, timeout_override=300
        )

        if response.status == "success" and response.result:
            return response.result.get("fingerprints", {})
        return {}

    # ============== PRIVATE HELPERS ==============

    async def _subfinder_enum(self, domain: str) -> List[Dict[str, Any]]:
        response = await self.registry.execute_tool(
            self.SERVER_ID, "subfinder_enum", {"domain": domain}
        )
        if response.status == "success" and response.result:
            return response.result.get("subdomains", [])
        return []

    async def _amass_passive(self, domain: str) -> List[Dict[str, Any]]:
        response = await self.registry.execute_tool(
            self.SERVER_ID, "amass_passive", {"domain": domain}
        )
        if response.status == "success" and response.result:
            return response.result.get("subdomains", [])
        return []

    async def _amass_active(self, domain: str, depth: int) -> List[Dict[str, Any]]:
        response = await self.registry.execute_tool(
            self.SERVER_ID, "amass_active", {"domain": domain, "depth": depth}
        )
        if response.status == "success" and response.result:
            return response.result.get("subdomains", [])
        return []

    def _deduplicate_subdomains(
        self, raw_subdomains: List[Dict[str, Any]], parent_domain: str
    ) -> List[Asset]:
        """Deduplicate subdomains using probabilistic OR for confidence."""
        seen = {}

        for sub in raw_subdomains:
            domain = sub.get("domain", "").lower().strip()
            if not domain or not domain.endswith(parent_domain.lower()):
                continue

            if domain in seen:
                # Merge confidence: P(A or B) = 1 - (1-P(A))(1-P(B))
                old_conf = seen[domain]["confidence"]
                new_conf = sub.get("confidence", 0.5)
                seen[domain]["confidence"] = 1 - (1 - old_conf) * (1 - new_conf)
                seen[domain]["sources"] = list(
                    set(seen[domain].get("sources", []) + [sub.get("source", "unknown")])
                )
            else:
                seen[domain] = {
                    "domain": domain,
                    "confidence": sub.get("confidence", 0.5),
                    "sources": [sub.get("source", "unknown")],
                    "ip_addresses": sub.get("ip_addresses", []),
                }

        assets = []
        for domain, data in seen.items():
            # Confidence scoring based on source type
            source_confidence = 0.95 if "direct" in data["sources"] else 0.70
            final_confidence = max(data["confidence"], source_confidence)

            asset = Asset(
                type="subdomain",
                value=domain,
                source="amass+subfinder",
                confidence=min(final_confidence, 1.0),
                metadata={
                    "sources": data["sources"],
                    "ip_addresses": data["ip_addresses"],
                    "parent_domain": parent_domain,
                },
                engagement_id="",  # Set by caller
            )
            assets.append(asset)

        return assets

    def _normalize_nmap_output(self, result: Dict[str, Any]) -> List[Asset]:
        """Convert Nmap XML/JSON output to Asset models."""
        assets = []
        for host in result.get("hosts", []):
            asset = Asset(
                type="host",
                value=host.get("ip"),
                source="nmap",
                confidence=0.90,
                metadata={
                    "ports": host.get("ports", []),
                    "os": host.get("os"),
                    "hostnames": host.get("hostnames", []),
                },
                engagement_id="",
            )
            assets.append(asset)
        return assets

    def _normalize_httpx_output(self, result: Dict[str, Any]) -> List[Endpoint]:
        """Convert httpx JSON output to Endpoint models."""
        endpoints = []
        for entry in result.get("results", []):
            ep = Endpoint(
                url=entry.get("url"),
                method=entry.get("method", "GET"),
                status_code=entry.get("status_code"),
                title=entry.get("title"),
                technologies=entry.get("technologies", []),
                parameters=entry.get("parameters", []),
                auth_required=entry.get("auth_required", False),
                asset_id=entry.get("asset_id", ""),
                source="httpx",
                confidence=1.0,
                engagement_id="",
                screenshot_path=entry.get("screenshot_path"),
            )
            endpoints.append(ep)
        return endpoints

    def _normalize_shodan_output(self, result: Dict[str, Any], domain: str) -> List[Asset]:
        """Convert Shodan output to Asset models."""
        assets = []
        for match in result.get("matches", []):
            asset = Asset(
                type="host",
                value=match.get("ip_str"),
                source="shodan",
                confidence=0.70,
                metadata={
                    "ports": match.get("ports", []),
                    "vulns": match.get("vulns", []),
                    "tags": match.get("tags", []),
                    "org": match.get("org"),
                    "domain": domain,
                },
                engagement_id="",
            )
            assets.append(asset)
        return assets

    def _normalize_wayback_output(self, result: Dict[str, Any], domain: str) -> List[Endpoint]:
        """Convert Wayback output to Endpoint models."""
        endpoints = []
        for entry in result.get("urls", []):
            ep = Endpoint(
                url=entry.get("url"),
                method=entry.get("method", "GET"),
                status_code=entry.get("status_code"),
                source="wayback",
                confidence=0.80,
                engagement_id="",
                metadata={
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen"),
                    "domain": domain,
                },
            )
            endpoints.append(ep)
        return endpoints
