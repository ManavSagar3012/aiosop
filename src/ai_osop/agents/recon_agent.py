"""
Reconnaissance Agent
Specialized agent for DNS enumeration, port scanning, service discovery,
and asset inventory maintenance.
"""

from datetime import datetime
from typing import Any, Dict, List

from ai_osop.adapters.recon_mcp import ReconMCPAdapter
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Asset, Endpoint, Task
from ai_osop.core.trusted_search import discover_trusted_search


class ReconAgent(BaseAgent):
    """
    Agent responsible for infrastructure discovery and mapping.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.RECON

    async def _setup_resources(self) -> None:
        """Initialize recon tools and inventory."""
        self.recon_adapter = ReconMCPAdapter(self.ctx.mcp_registry)
        self.asset_inventory: Dict[str, Asset] = {}
        self.endpoint_inventory: Dict[str, Endpoint] = {}

    async def think(self, context: str, skill_names: List[str]) -> str:
        """Reason about the current context using specialized skills."""
        skills_content = "\n\n".join([self._load_skill(s) for s in skill_names])

        messages = [
            {
                "role": "system",
                "content": f"You are an AI Reconnaissance Agent. Use the following specialized skills to perform your analysis:\n\n{skills_content}",
            },
            {"role": "user", "content": context},
        ]

        return await self._complete_supervised_messages(messages)

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute reconnaissance task."""
        task_type = task.type
        payload = task.payload

        # Initialize adapter if scope is provided in payload (Issue 12)
        if "scope" in payload and not (
            task_type == "osint_lookup" and payload.get("trusted_search") is True
        ):
            await self.recon_adapter.initialize(payload["scope"], task.engagement_id)

        if task_type == "dns_enumeration":
            return await self._execute_dns_enum(payload)
        elif task_type == "port_scan":
            return await self._execute_port_scan(payload)
        elif task_type == "service_probe":
            return await self._execute_service_probe(payload)
        elif task_type == "osint_lookup":
            return await self._execute_osint(payload)
        elif task_type == "technology_fingerprint":
            return await self._execute_tech_fingerprint(payload)
        elif task_type == "full_recon":
            return await self._execute_full_recon(payload)
        else:
            raise AgentException(f"Unknown recon task type: {task_type}")

    async def _execute_dns_enum(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute DNS enumeration for domain."""
        domain = payload.get("domain")
        if not domain and "url" in payload:
            domain = payload["url"].replace("https://", "").replace("http://", "").split("/")[0]
        if not domain and payload.get("targets"):
            domain = payload["targets"][0]

        if not domain:
            return {"status": "failed", "error": "domain parameter is required"}

        depth = payload.get("depth", 2)
        active = payload.get("active", True)

        try:
            assets = await self.recon_adapter.dns_enumeration(
                domain=domain, depth=depth, active=active
            )
        except Exception:
            # A failed DNS provider is not evidence that even the submitted
            # domain resolved. The old fallback invented a 100%-confidence
            # discovered asset and could enqueue downstream active scans.
            return {
                "status": "unknown",
                "validation_state": "UNKNOWN",
                "domain": domain,
                "assets_discovered": 0,
                "assets": [],
                "provider_status": "unavailable",
            }
        if not isinstance(assets, list) or any(not isinstance(asset, Asset) for asset in assets):
            return {
                "status": "unknown",
                "validation_state": "UNKNOWN",
                "domain": domain,
                "assets_discovered": 0,
                "assets": [],
                "provider_status": "malformed",
            }

        # Set engagement ID and store in graph memory
        persisted = []
        for asset in assets:
            try:
                asset.engagement_id = self.ctx.current_task.engagement_id
                await self.ctx.graph_memory.add_asset(asset)
                self.asset_inventory[asset.id] = asset
                persisted.append(asset)
            except Exception:
                # Graph failure makes this collection uncertain: a partial
                # write cannot be advertised as a completed recon task.
                return {
                    "status": "unknown",
                    "validation_state": "UNKNOWN",
                    "domain": domain,
                    "assets_discovered": 0,
                    "assets": [],
                    "provider_status": "graph_unavailable",
                }

        return {
            "status": "success",
            "assets_discovered": len(persisted),
            "assets": [a.model_dump() for a in persisted],
            "domain": domain,
        }

    async def _execute_port_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute port scanning."""
        targets = payload["targets"]
        ports = payload.get("ports", "top-1000")

        try:
            assets = await self.recon_adapter.port_scan(targets=targets, ports=ports)
        except Exception:
            return {
                "status": "unknown",
                "validation_state": "UNKNOWN",
                "targets": targets,
                "assets_discovered": 0,
                "provider_status": "unavailable",
            }

        # Set engagement ID and store in graph memory
        for asset in assets:
            try:
                asset.engagement_id = self.ctx.current_task.engagement_id
                await self.ctx.graph_memory.add_asset(asset)
                self.asset_inventory[asset.id] = asset
            except Exception as e:
                print(f"ERROR: Failed to add asset {asset.value} to graph: {e}")

        return {"status": "success", "targets": targets, "assets_discovered": len(assets)}

    async def _execute_service_probe(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute service probing/fingerprinting."""
        targets = payload["targets"]

        try:
            endpoints = await self.recon_adapter.service_probe(targets)
        except Exception:
            return {
                "status": "unknown",
                "validation_state": "UNKNOWN",
                "probed_count": 0,
                "provider_status": "unavailable",
            }

        for endpoint in endpoints:
            try:
                endpoint.engagement_id = self.ctx.current_task.engagement_id
                await self.ctx.graph_memory.add_endpoint(endpoint)
                self.endpoint_inventory[endpoint.id] = endpoint
            except Exception:
                return {
                    "status": "unknown",
                    "validation_state": "UNKNOWN",
                    "probed_count": 0,
                    "provider_status": "persistence_unavailable",
                }

        return {"status": "success", "probed_count": len(endpoints)}

    async def _execute_osint(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Discover unverified public-source leads with explicit signed opt-in."""
        domain = payload.get("domain")
        if payload.get("trusted_search") is not True:
            # Preserve legacy opt-out behavior without implying a finding.
            return {"status": "success", "domain": domain, "findings": []}
        task = self.ctx.current_task
        return await discover_trusted_search(context=self.ctx, task=task, domain=domain)

    async def _execute_tech_fingerprint(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Fingerprint technologies on endpoints."""
        endpoints = payload["endpoints"]
        try:
            fingerprints = await self.recon_adapter.technology_fingerprint(endpoints)
        except Exception:
            return {
                "status": "unknown",
                "validation_state": "UNKNOWN",
                "processed_count": 0,
                "provider_status": "unavailable",
            }
        return {
            "status": "success",
            "processed_count": len(fingerprints),
            "fingerprints": fingerprints,
        }

    async def _execute_full_recon(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive reconnaissance chain."""
        domain = payload.get("domain")
        if not domain and "url" in payload:
            domain = payload["url"].replace("https://", "").replace("http://", "").split("/")[0]

        if not domain:
            return {"status": "failed", "error": "domain parameter is required for full recon"}

        # 1. DNS Enum
        dns_results = await self._execute_dns_enum({"domain": domain})
        if dns_results.get("status", "success") != "success":
            # Do not seed the graph, reason from fictitious observations or
            # trigger an active scan when DNS admission was inconclusive.
            return {
                "status": "unknown",
                "validation_state": "UNKNOWN",
                "target": domain,
                "subdomains_found": 0,
                "reason": "signed_dns_observation_unavailable",
            }

        # Guarantee the root domain itself is always persisted as an Asset, even
        # when DNS enumeration resolves nothing. Downstream VULNERABILITY_DISCOVERY
        # schedules one scan task per Asset; with zero assets it would schedule
        # zero scans and the engagement would hang in that phase forever. The seed
        # domain is always a valid scan target. add_asset MERGEs on id, so this is
        # idempotent with any subdomain asset that happens to equal the root.
        # (AIOSOP-AUTO-2026-06-16)
        try:
            root_asset = Asset(
                id=f"asset-{domain}",
                type="domain",
                value=domain,
                # This is a known operator-supplied scope seed, NOT an
                # independently observed DNS result.
                source="recon_scope_seed_unverified",
                confidence=0.0,
                engagement_id=self.ctx.current_task.engagement_id,
            )
            await self.ctx.graph_memory.add_asset(root_asset)
            self.asset_inventory[root_asset.id] = root_asset
        except Exception as e:
            print(f"ERROR: failed to seed root asset for {domain}: {e}")

        # 2. Port Scan found subdomains
        subdomains = [a["value"] for a in dns_results["assets"]]

        # Perform reasoning using recon skills
        analysis_context = (
            f"Initial infrastructure discovery for {domain}:\n"
            + f"Found {len(subdomains)} subdomains: {', '.join(subdomains[:10])}"
        )
        skills = await self._get_relevant_skills(self.ctx.current_task)
        reasoning = await self.think(analysis_context, skills)
        print(f"AGENT REASONING: {reasoning}")

        if subdomains:
            scan_status = await self._execute_port_scan({"targets": subdomains})
            if not isinstance(scan_status, dict) or scan_status.get("status") != "success":
                return {
                    "status": "unknown",
                    "validation_state": "UNKNOWN",
                    "target": domain,
                    "subdomains_found": len(subdomains),
                    "reason": "signed_port_observation_unavailable",
                }

        result = {
            "status": "success",
            "target": domain,
            "subdomains_found": len(subdomains),
            "reasoning": reasoning,
        }
        # Search snippets are only returned as unverified operator leads.
        # Never add links to the graph, inventory or subsequent port-scan set.
        if payload.get("trusted_search") is True:
            result["search_discovery"] = await discover_trusted_search(
                context=self.ctx, task=self.ctx.current_task, domain=domain
            )
        return result

    async def _cleanup_resources(self) -> None:
        """Cleanup recon resources."""
        self.asset_inventory.clear()
        self.endpoint_inventory.clear()
