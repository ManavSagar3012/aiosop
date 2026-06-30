"""
Reconnaissance Agent
Specialized agent for DNS enumeration, port scanning, service discovery,
and asset inventory maintenance.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.adapters.recon_mcp import ReconMCPAdapter
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Asset, Endpoint, Task, make_asset_id
import re
from ai_osop.agents.retrieval_agent import RetrievalAgent
import hashlib
import aiohttp
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs
import structlog
logger = structlog.get_logger(__name__)

class SimpleHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and "href" in attrs_dict:
            self.links.append(attrs_dict["href"])
        elif tag == "script" and "src" in attrs_dict:
            self.scripts.append(attrs_dict["src"])
        elif tag == "form" and "action" in attrs_dict:
            self.current_form = {
                "action": attrs_dict["action"],
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": []
            }
            self.forms.append(self.current_form)
        elif tag == "input" and self.current_form and "name" in attrs_dict:
            self.current_form["inputs"].append(attrs_dict["name"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None


class ReconAgent(BaseAgent):
    """
    Agent responsible for infrastructure discovery and mapping.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.RECON
    def supports_task_type(self, task_type: str) -> bool:
        return task_type in ["full_recon", "dns_enumeration", "port_scan", "service_probe", "osint_lookup", "technology_fingerprint"]

    async def _setup_resources(self) -> None:
        """Initialize recon tools and inventory."""
        self.recon_adapter = ReconMCPAdapter(self.ctx.mcp_registry)
        self.asset_inventory: Dict[str, Asset] = {}
        self.endpoint_inventory: Dict[str, Endpoint] = {}

    async def think(self, context: str, skill_names: List[str]) -> str:
        """Reason about the current context using specialized skills."""
        skills_content = "\n\n".join([self._load_skill(s) for s in skill_names])

        # Retrieve methodology
        retrieval_agent = RetrievalAgent(self.ctx)
        await retrieval_agent._setup_resources()
        methodologies = retrieval_agent.search("Other")
        
        # Filter for recon-related methodology
        recon_methodologies = [m for m in methodologies if any(tool in m.get("command_pattern", "") for tool in ["subfinder", "httpx", "nuclei", "katana"])]
        
        # Add retrieved methodology to context
        retrieved_patterns = "\n".join([m.get("command_pattern", "") for m in recon_methodologies])
        retrieved_prerequisites = "\n".join([str(p) for m in recon_methodologies for p in m.get("prerequisites", [])])
        
        enriched_context = f"{context}\n\nRetrieved Recon Methodology:\n{retrieved_patterns}\n\nRetrieved Recon Prerequisites:\n{retrieved_prerequisites}"

        messages = [
            {
                "role": "system",
                "content": f"You are an AI Reconnaissance Agent. Use the following specialized skills to perform your analysis:\n\n{skills_content}",
            },
            {"role": "user", "content": enriched_context},
        ]

        return await self.ctx.llm_client.complete(messages)

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute reconnaissance task."""
        task_type = task.type
        payload = task.payload

        # Initialize adapter if scope is provided in payload (Issue 12)
        if "scope" in payload:
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
        elif task_type == "expand_subdomains":
            return await self._execute_expand_subdomains(payload)
        else:
            raise AgentException(f"Unknown recon task type: {task_type}")

    async def _execute_expand_subdomains(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Expand discovered subdomains into likely candidates (altdns-style) and,
        when resolve=True, keep the ones that resolve — broadening attack surface to
        feed subdomain_takeover_scan / recon. Permutation is deterministic; resolution
        is best-effort and bounded.

        Payload: domain, known_subs (list), resolve (bool, default True),
                 max_resolve (default 500), engagement_id.
        """
        import asyncio
        import socket

        from ai_osop.core.subdomain_permutations import generate_permutations

        domain = payload.get("domain")
        if not domain and payload.get("url"):
            domain = payload["url"].replace("https://", "").replace("http://", "").split("/")[0]
        if not domain:
            return {"status": "failed", "error": "domain parameter is required"}
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )

        known = payload.get("known_subs") or list(self.asset_inventory and
                                                  [a.value for a in self.asset_inventory.values()
                                                   if getattr(a, "type", "") in ("subdomain", "domain")])
        candidates = generate_permutations(domain, known, payload.get("words"))

        resolve = bool(payload.get("resolve", True))
        max_resolve = int(payload.get("max_resolve", 500))
        live: List[str] = []
        if resolve:
            async def _res(host: str) -> bool:
                try:
                    await asyncio.to_thread(socket.gethostbyname, host)
                    return True
                except Exception:
                    return False
            checked = candidates[:max_resolve]
            results = await asyncio.gather(*[_res(h) for h in checked])
            live = [h for h, ok in zip(checked, results) if ok]
            for host in live:
                try:
                    asset = Asset(
                        id=f"asset-{engagement_id}-{host}", type="subdomain", value=host,
                        source="permutation", confidence=0.9, engagement_id=engagement_id,
                    )
                    await self.ctx.graph_memory.add_asset(asset)
                    self.asset_inventory[asset.id] = asset
                except Exception as e:
                    logger.error(f"Failed to persist permutation asset {host}: {e}")

        return {
            "status": "success",
            "domain": domain,
            "candidates_generated": len(candidates),
            "resolved_live": len(live),
            "live_subdomains": live,
            "candidates": candidates if not resolve else candidates[:50],
        }

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
        except Exception as e:
            logger.warning(r"DNS enum failed for {domain}: {e}")
            # Fallback: create base domain asset
            assets = [
                Asset(
                    id=f"asset-{self.ctx.current_task.engagement_id}-{domain}",
                    type="domain",
                    value=domain,
                    source="recon_fallback",
                    confidence=1.0,
                    engagement_id=self.ctx.current_task.engagement_id,
                )
            ]

        # Set engagement ID and store in graph memory
        for asset in assets:
            try:
                asset.engagement_id = self.ctx.current_task.engagement_id
                await self.ctx.graph_memory.add_asset(asset)
                self.asset_inventory[asset.id] = asset
            except Exception as e:
                logger.error(r"Failed to add asset {asset.value} to graph: {e}")

        return {
            "status": "success",
            "assets_discovered": len(assets),
            "assets": [a.model_dump() for a in assets],
            "domain": domain,
        }

    async def _execute_port_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute port scanning."""
        targets = payload["targets"]
        ports = payload.get("ports", "top-1000")

        try:
            assets = await self.recon_adapter.port_scan(targets=targets, ports=ports)
        except Exception as e:
            logger.warning(r"Port scan failed: {e}")
            assets = []

        # Set engagement ID and store in graph memory
        for asset in assets:
            try:
                asset.engagement_id = self.ctx.current_task.engagement_id
                await self.ctx.graph_memory.add_asset(asset)
                self.asset_inventory[asset.id] = asset
            except Exception as e:
                logger.error(r"Failed to add asset {asset.value} to graph: {e}")

        return {"status": "success", "targets": targets, "assets_discovered": len(assets)}

    async def _execute_service_probe(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute service probing/fingerprinting."""
        targets = payload["targets"]

        try:
            endpoints = await self.recon_adapter.service_probe(targets)
        except Exception as e:
            # Parity with _execute_dns_enum: make a probe-tool outage VISIBLE rather
            # than silently yielding zero endpoints (the bug that hid the recon-mcp
            # "not initialized" failure for so long). AIOSOP-RECON-PERSIST-2026-06-24.
            import logging
            logging.getLogger("ai_osop.recon").error(
                "service_probe_failed", error=str(e), target_count=len(targets), exc_info=True
            )
            logger.warning(r"Service probe failed ({len(targets)} targets): {e}")
            endpoints = []

        for endpoint in endpoints:
            try:
                endpoint.engagement_id = self.ctx.current_task.engagement_id
                await self.ctx.graph_memory.add_endpoint(endpoint)
                self.endpoint_inventory[endpoint.id] = endpoint
            except Exception as e:
                logger.error(r"Failed to add endpoint {endpoint.url} to graph: {e}")

        return {"status": "success", "endpoints_discovered": len(endpoints)}

    async def _execute_osint(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute OSINT lookups."""
        domain = payload["domain"]
        return {"status": "success", "domain": domain, "findings": []}

    async def _execute_tech_fingerprint(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Fingerprint technologies on endpoints."""
        endpoints = payload["endpoints"]
        return {"status": "success", "processed_count": len(endpoints)}

    async def _execute_full_recon(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive reconnaissance chain."""
        domain = payload.get("domain")
        if not domain and "url" in payload:
            domain = payload["url"].replace("https://", "").replace("http://", "").split("/")[0]

        if not domain:
            return {"status": "failed", "error": "domain parameter is required for full recon"}

        # 1. DNS Enum
        dns_results = await self._execute_dns_enum({"domain": domain})

        # Guarantee the root domain itself is always persisted as an Asset, even
        # when DNS enumeration resolves nothing. Downstream VULNERABILITY_DISCOVERY
        # schedules one scan task per Asset; with zero assets it would schedule
        # zero scans and the engagement would hang in that phase forever. The seed
        # domain is always a valid scan target. add_asset MERGEs on id, so this is
        # idempotent with any subdomain asset that happens to equal the root.
        # (AIOSOP-AUTO-2026-06-16)
        try:
            root_asset = Asset(
                id=f"asset-{self.ctx.current_task.engagement_id}-{domain}",
                type="domain",
                value=domain,
                source="recon_seed",
                confidence=1.0,
                engagement_id=self.ctx.current_task.engagement_id,
            )
            await self.ctx.graph_memory.add_asset(root_asset)
            self.asset_inventory[root_asset.id] = root_asset
        except Exception as e:
            logger.debug(r"full_recon_failure: {str(e)}")
            import logging
            logging.getLogger("ai_osop.recon").error("full_recon_failure", error=str(e), exc_info=True)
            return {"status": "failed", "error": str(e)}

        # 2. Port Scan found subdomains
        subdomains = [a["value"] for a in dns_results["assets"]]

        # Perform reasoning using recon skills
        analysis_context = (
            f"Initial infrastructure discovery for {domain}:\n"
            + f"Found {len(subdomains)} subdomains: {', '.join(subdomains[:10])}"
        )
        skills = await self._get_relevant_skills(self.ctx.current_task)
        reasoning = await self.think(analysis_context, skills)
        logger.info(f"AGENT REASONING: {reasoning}")

        if subdomains:
            await self._execute_port_scan({"targets": subdomains})

        # 3. Service Probing (HTTPX) on discovered subdomains/ports (Sprint 12)
        urls_to_probe = []
        for sub in subdomains:
            urls_to_probe.extend([f"http://{sub}", f"https://{sub}"])
        urls_to_probe.extend([f"http://{domain}", f"https://{domain}"])
        
        endpoints_count = 0
        if urls_to_probe:
            try:
                logger.debug(r"Probing {len(urls_to_probe)} URLs for web services...")
                probe_res = await self._execute_service_probe({"targets": urls_to_probe})
                endpoints_count = probe_res.get("endpoints_discovered", 0)
            except Exception as e:
                logger.warning(r"Full recon service probe failed: {e}")

        # 3.5. Active Web Crawling & Endpoint Explosion (Sprint 12)
        active_endpoints = []
        try:
            logger.debug(r"Initiating active web crawl / endpoint explosion on {domain}...")
            active_endpoints = await self._active_crawl_target(domain)
            for ep in active_endpoints:
                try:
                    await self.ctx.graph_memory.add_endpoint(ep)
                    self.endpoint_inventory[ep.id] = ep
                except Exception as ex:
                    logger.error(r"Failed to add active crawled endpoint {ep.url} to graph: {ex}")
        except Exception as e:
            logger.warning(r"Active crawl failed: {e}")

        # 4. Historical URLs (Wayback) (Sprint 12)
        historical_count = 0
        try:
            logger.debug(r"Fetching historical URLs from Wayback for {domain}...")
            hist_endpoints = await self.recon_adapter.historical_urls(domain)
            for ep in hist_endpoints:
                try:
                    ep.engagement_id = self.ctx.current_task.engagement_id
                    await self.ctx.graph_memory.add_endpoint(ep)
                    self.endpoint_inventory[ep.id] = ep
                    historical_count += 1
                except Exception as ex:
                    logger.error(r"Failed to add historical endpoint {ep.url} to graph: {ex}")
        except Exception as e:
            logger.warning(r"Historical URLs lookup failed: {e}")
            
        # 5. OSINT Shodan Lookup (Sprint 12)
        shodan_assets_count = 0
        try:
            logger.debug(r"Running Shodan OSINT lookup for {domain}...")
            shodan_assets = await self.recon_adapter.osint_lookup(domain)
            for asset in shodan_assets:
                try:
                    asset.engagement_id = self.ctx.current_task.engagement_id
                    await self.ctx.graph_memory.add_asset(asset)
                    self.asset_inventory[asset.id] = asset
                    shodan_assets_count += 1
                except Exception as ex:
                    logger.error(r"Failed to add Shodan asset {asset.value} to graph: {ex}")
        except Exception as e:
            logger.warning(r"Shodan OSINT lookup failed: {e}")

        return {
            "status": "success",
            "target": domain,
            "subdomains_found": len(subdomains),
            "endpoints_found": endpoints_count + historical_count + len(active_endpoints),
            "reasoning": reasoning,
        }

    async def _active_crawl_target(self, domain: str, session_store: Optional[Any] = None) -> List[Endpoint]:
        """
        Active Web Crawler & Endpoint Explosion Engine (Sprint 13).
        Actively crawls the target application under multiple authenticated identities
        to map role-specific routes and calculate the Privilege Expansion Ratio (PER).
        """
        # 1. Load captured user sessions for the engagement (Swarm Identity Matrix)
        store = session_store or SessionStore(self.ctx.session_memory)
        sessions = await store.list_sessions(self.ctx.current_task.engagement_id)
        
        # Load previously discovered endpoints to adapt crawling
        known_endpoints = await self.ctx.graph_memory.get_endpoints(self.ctx.current_task.engagement_id)
        known_paths = {ep.url for ep in known_endpoints}

        # Seed crawl with known endpoints if available
        initial_urls = [f"https://{domain}/", f"http://{domain}/"]
        if known_paths:
            # Prioritize discovery of sub-paths from previously known endpoints
            initial_urls = list(known_paths) + initial_urls
            
        discovered_endpoints = []
        
        # Limit total identity-identities to maintain budget
        identities = [{"label": "anonymous", "session": None}]
        for s in sessions:
            identities.append({"label": s.user_label, "session": s})
            
        logger.debug(r"Active crawler initialized with {len(identities)} identities: {[i['label'] for i in identities]}. Known paths: {len(known_paths)}")
        
        # Regex patterns for API routes and parameters in JS
        param_pattern = re.compile(r"[?&]([a-zA-Z0-9_\-]+)=")
        
        for identity in identities:
            user_label = identity["label"]
            user_session = identity["session"]
            
            logger.debug(r"Starting active crawl phase for identity: {user_label}")
            
            visited_urls = set()
            urls_to_crawl = list(set(initial_urls))
            
            max_pages = 20 # Limit per identity to stay within budget
            pages_crawled = 0
            
            js_files = set()
            api_routes = set()
            parameters_found = set()
            
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-OSOP-Crawler/1.2"}
            cookies = {}
            
            # Inject session tokens/cookies if present
            if user_session:
                if user_session.bearer_token:
                    headers["Authorization"] = f"Bearer {user_session.bearer_token}"
                if user_session.extra_headers:
                    headers.update(user_session.extra_headers)
                if user_session.cookies:
                    for c in user_session.cookies:
                        cookies[c["name"]] = c["value"]
                        
            async with aiohttp.ClientSession(headers=headers, cookies=cookies) as session:
                while urls_to_crawl and pages_crawled < max_pages:
                    url = urls_to_crawl.pop(0)
                    if url in visited_urls:
                        continue
                    visited_urls.add(url)
                    pages_crawled += 1
                    
                    try:
                        async with session.get(url, timeout=5, allow_redirects=True) as response:
                            status = response.status
                            content_type = response.headers.get("Content-Type", "")
                            
                            parsed_url = urlparse(str(response.url))
                            if parsed_url.netloc.endswith(domain):
                                # Check if already discovered
                                is_new = str(response.url) not in self.endpoint_inventory
                                
                                # Set auth parameters based on identity context
                                auth_req = user_label != "anonymous" if is_new else self.endpoint_inventory[str(response.url)].auth_required
                                final_label = user_label if is_new else self.endpoint_inventory[str(response.url)].user_label
                                
                                query_params = list(parse_qs(parsed_url.query).keys())
                                ep = Endpoint(
                                    id=f"endpoint-{hashlib.md5(str(response.url).encode()).hexdigest()[:12]}",
                                    type="web",
                                    url=str(response.url),
                                    method="GET",
                                    confidence=0.9,
                                    engagement_id=self.ctx.current_task.engagement_id,
                                    source="active_crawl",
                                    status_codes_seen=[status],
                                    query_keys=query_params,
                                    auth_required=auth_req,
                                    user_label=final_label
                                )
                                discovered_endpoints.append(ep)
                                self.endpoint_inventory[str(response.url)] = ep
                                
                                if "text/html" in content_type:
                                    html_text = await response.text()
                                    parser = SimpleHTMLParser()
                                    parser.feed(html_text)
                                    
                                    # 1. Extract Links
                                    for href in parser.links:
                                        link = urljoin(str(response.url), href)
                                        parsed_link = urlparse(link)
                                        if parsed_link.netloc.endswith(domain) and link not in visited_urls:
                                            urls_to_crawl.append(link)
                                            
                                    # 2. Extract Forms & Parameters
                                    for form in parser.forms:
                                        form_url = urljoin(str(response.url), form["action"])
                                        form_method = form["method"]
                                        form_params = form["inputs"]
                                        for p in form_params:
                                            parameters_found.add(p)
                                            
                                        is_form_new = form_url not in self.endpoint_inventory
                                        form_auth_req = user_label != "anonymous" if is_form_new else self.endpoint_inventory[form_url].auth_required
                                        form_final_label = user_label if is_form_new else self.endpoint_inventory[form_url].user_label
                                        
                                        form_ep = Endpoint(
                                            id=f"endpoint-{hashlib.md5(form_url.encode()).hexdigest()[:12]}",
                                            type="web",
                                            url=form_url,
                                            method=form_method,
                                            confidence=0.95,
                                            engagement_id=self.ctx.current_task.engagement_id,
                                            source="active_crawl_form",
                                            body_schema_keys=form_params if form_method == "POST" else [],
                                            query_keys=form_params if form_method == "GET" else [],
                                            auth_required=form_auth_req,
                                            user_label=form_final_label
                                        )
                                        discovered_endpoints.append(form_ep)
                                        self.endpoint_inventory[form_url] = form_ep
                                        
                                    # 3. Extract Script sources (JS bundles) (Sprint 12)
                                    for src in parser.scripts:
                                        script_url = urljoin(str(response.url), src)
                                        parsed_script = urlparse(script_url)
                                        script_host = parsed_script.netloc
                                        
                                        # Get root domain dynamically
                                        domain_parts = domain.split(".")
                                        root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
                                        
                                        # Allow same subdomain, same root domain, relative paths, or Webflow assets (for Webflow targets)
                                        is_valid = (
                                            script_host == "" or 
                                            script_host.endswith(domain) or 
                                            script_host.endswith(root_domain) or
                                            "website-files.com" in script_host or
                                            "webflow" in script_host
                                        )
                                        
                                        # Ignore common global trackers to avoid noise
                                        ignore_trackers = ["google-analytics", "googletagmanager", "facebook.net", "doubleclick"]
                                        if is_valid and not any(t in script_url for t in ignore_trackers):
                                            js_files.add(script_url)
                                            
                                            is_js_new = script_url not in self.endpoint_inventory
                                            js_auth_req = user_label != "anonymous" if is_js_new else self.endpoint_inventory[script_url].auth_required
                                            js_final_label = user_label if is_js_new else self.endpoint_inventory[script_url].user_label
                                            
                                            # Persist the JS file itself as an Endpoint in the graph
                                            js_ep = Endpoint(
                                                id=f"endpoint-{hashlib.md5(script_url.encode()).hexdigest()[:12]}",
                                                type="web",
                                                url=script_url,
                                                method="GET",
                                                confidence=0.9,
                                                engagement_id=self.ctx.current_task.engagement_id,
                                                source="active_crawl_script",
                                                auth_required=js_auth_req,
                                                user_label=js_final_label
                                            )
                                            discovered_endpoints.append(js_ep)
                                            self.endpoint_inventory[script_url] = js_ep
                                            
                    except Exception as e:
                        logger.debug(r"Active crawl failed for {url} under {user_label}: {e}")
                        
                # 4. Parse JavaScript Bundles for hidden API routes and parameters
                logger.debug(r"Discovered {len(js_files)} JS bundles for {user_label}. Starting deep route extraction...")
                for js_url in list(js_files)[:10]:
                    try:
                        async with session.get(js_url, timeout=5) as js_response:
                            if js_response.status == 200:
                                js_text = await js_response.text()
                                
                                routes = js_route_pattern.findall(js_text)
                                params = param_pattern.findall(js_text)
                                
                                for route in routes:
                                    api_routes.add(route)
                                    full_api_url = urljoin(f"https://{domain}/", route)
                                    
                                    is_api_new = full_api_url not in self.endpoint_inventory
                                    api_auth_req = user_label != "anonymous" if is_api_new else self.endpoint_inventory[full_api_url].auth_required
                                    api_final_label = user_label if is_api_new else self.endpoint_inventory[full_api_url].user_label
                                    
                                    api_ep = Endpoint(
                                        id=f"endpoint-{hashlib.md5(full_api_url.encode()).hexdigest()[:12]}",
                                        type="api",
                                        url=full_api_url,
                                        method="GET",
                                        confidence=0.85,
                                        engagement_id=self.ctx.current_task.engagement_id,
                                        source="js_route_extraction",
                                        path=route,
                                        auth_required=api_auth_req,
                                        user_label=api_final_label
                                    )
                                    discovered_endpoints.append(api_ep)
                                    self.endpoint_inventory[full_api_url] = api_ep
                                    
                                for param in params:
                                    parameters_found.add(param)
                                    
                    except Exception as e:
                        logger.debug(r"JS route extraction failed for {js_url} under {user_label}: {e}")
                        
            logger.debug(r"Active crawl complete for {user_label}. Found {len(discovered_endpoints)} total endpoints, {len(api_routes)} API routes, and {len(parameters_found)} parameters.")
            
        return discovered_endpoints
    async def _cleanup_resources(self) -> None:
        """Cleanup recon resources."""
        self.asset_inventory.clear()
        self.endpoint_inventory.clear()
