"""
Reconnaissance Agent
Specialized agent for DNS enumeration, port scanning, service discovery,
and asset inventory maintenance.
"""

import asyncio
import hashlib
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import structlog

from ai_osop.adapters.recon_mcp import ReconMCPAdapter
from ai_osop.adapters.security_bridge_mcp import SecurityBridgeAdapter
from ai_osop.agents.base import BaseAgent
from ai_osop.agents.retrieval_agent import RetrievalAgent
from ai_osop.auth.session_store import SessionStore
from ai_osop.core.enums import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Asset, Endpoint, ScopeDefinition, Task
from ai_osop.core.openapi_ingest import is_spec, parse_spec, spec_candidate_urls
from ai_osop.core.url_intelligence import (
    classify_url,
    endpoint_template,
    extract_form_fields,
    extract_params,
    mine_urls,
)
from ai_osop.safety.scope import ScopeEnforcer

logger = structlog.get_logger(__name__)


def normalize_endpoint_url(url: Any) -> "str | None":
    """Return a clean single http(s) URL, or None if it's malformed extractor noise.

    Recon's href/src join (urljoin on a relative path + a stray absolute URL) can
    emit junk like ``https://host/core/    https:/cdn.jsdelivr.net/chart.js`` —
    whitespace and a second scheme fused into the PATH. Query strings are exempt
    (``?url=https://…`` and ``?redirect=…`` are legitimate params worth testing).
    """
    if not url or not isinstance(url, str):
        return None
    u = url.strip()
    try:
        parsed = urlparse(u)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    # Malformed extraction shows up in the netloc/path, never the query.
    if any(ch.isspace() for ch in parsed.netloc) or any(ch.isspace() for ch in parsed.path):
        return None
    if "http" in parsed.path.lower():  # a second URL fused into the path
        return None
    return u


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
                "inputs": [],
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
        return task_type in [
            "full_recon",
            "dns_enumeration",
            "port_scan",
            "service_probe",
            "osint_lookup",
            "technology_fingerprint",
            "content_discovery",
            "openapi_ingest",
            "expand_subdomains",
            "cert_transparency",
            "wayback_discovery",
            "waf_detection",
        ]

    async def _setup_resources(self) -> None:
        """Initialize recon tools and inventory."""
        self.recon_adapter = ReconMCPAdapter(self.ctx.mcp_registry)
        self.security_bridge = SecurityBridgeAdapter(self.ctx.mcp_registry)
        self.asset_inventory: Dict[str, Asset] = {}
        self.endpoint_inventory: Dict[str, Endpoint] = {}
        self._rejected_scope_urls: set = set()  # Dedup scope-rejection log spam

    async def think(self, context: str, skill_names: List[str]) -> str:
        """Reason about the current context using specialized skills.

        AIOSOP-LLM-TIMEOUT-001 (2026-07-03): this reasoning output is advisory only
        (it is logged as ``AGENT REASONING`` and never drives downstream recon steps),
        so it must degrade gracefully rather than abort full_recon. The base
        ``think()`` already returns "" on any failure; this override previously did
        not, letting a stalled LLM call propagate and kill the whole recon task
        (starving port-scan/crawl/Wayback/Shodan). The LLM client now bounds the call
        with a timeout; here we additionally swallow failures to "" so recon proceeds.
        """
        try:
            skills_content = "\n\n".join([self._load_skill(s) for s in skill_names])

            # Retrieve methodology
            retrieval_agent = RetrievalAgent(self.ctx)
            await retrieval_agent._setup_resources()
            methodologies = retrieval_agent.search("Other")

            # Filter for recon-related methodology
            recon_methodologies = [
                m
                for m in methodologies
                if any(
                    tool in m.get("command_pattern", "")
                    for tool in ["subfinder", "httpx", "nuclei", "katana"]
                )
            ]

            # Add retrieved methodology to context
            retrieved_patterns = "\n".join(
                [m.get("command_pattern", "") for m in recon_methodologies]
            )
            retrieved_prerequisites = "\n".join(
                [str(p) for m in recon_methodologies for p in m.get("prerequisites", [])]
            )

            enriched_context = f"{context}\n\nRetrieved Recon Methodology:\n{retrieved_patterns}\n\nRetrieved Recon Prerequisites:\n{retrieved_prerequisites}"

            messages = [
                {
                    "role": "system",
                    "content": f"You are an AI Reconnaissance Agent. Use the following specialized skills to perform your analysis:\n\n{skills_content}",
                },
                {"role": "user", "content": enriched_context},
            ]

            # AIOSOP-LLM-WARM-001: cap advisory reasoning tokens so a warm model
            # answers fast (and a reasoning model's <think> trace can't blow the bound).
            from ai_osop.core.config import settings as _settings

            return await self.ctx.llm_client.complete(
                messages, max_tokens=_settings.llm_reasoning_max_tokens
            )
        except Exception as e:
            logger.warning("recon_think_degraded", error=str(e))
            return ""

    @staticmethod
    def _build_scope_enforcer(payload: Dict[str, Any]):
        """ScopeEnforcer from the task payload's scope, or None if unavailable."""
        raw = payload.get("scope") if isinstance(payload, dict) else None
        if not raw:
            return None
        try:
            scope = raw if isinstance(raw, ScopeDefinition) else ScopeDefinition(**raw)
            return ScopeEnforcer(scope)
        except Exception as e:  # noqa: BLE001 - scope gating is best-effort
            logger.warning("recon_scope_enforcer_init_failed", error=str(e))
            return None

    async def _persist_endpoint(self, ep: Endpoint) -> bool:
        """Normalize + scope-gate an endpoint, then persist. Returns True if stored.

        Single chokepoint for every recon endpoint write: drops malformed URLs and
        off-scope hosts so downstream (graph, planning, scans, reports) stays clean.
        """
        norm = normalize_endpoint_url(getattr(ep, "url", None))
        if norm is None:
            logger.debug("recon_endpoint_rejected_malformed", url=getattr(ep, "url", None))
            return False
        ep.url = norm
        enforcer = getattr(self, "_ep_scope_enforcer", None)
        if enforcer is not None:
            host = urlparse(norm).hostname
            if not enforcer.host_in_scope(host):
                # Log only on first rejection per URL to avoid spam (was 102 repeats)
                _rejected = getattr(self, "_rejected_scope_urls", None)
                if _rejected is not None:
                    if norm not in _rejected:
                        _rejected.add(norm)
                        logger.info("recon_endpoint_out_of_scope", url=norm)
                else:
                    logger.info("recon_endpoint_out_of_scope", url=norm)
                return False
        await self.ctx.graph_memory.add_endpoint(ep)
        return True

    async def _persist_endpoints_batch(self, endpoints: "List[Endpoint]") -> int:
        """Scope-gate + normalize a list of endpoints, then batch-persist the valid ones.

        Returns the count of endpoints that passed scope/normalization and were persisted.
        Uses a single UNWIND Neo4j transaction instead of N round-trips.
        """
        valid: List[Endpoint] = []
        for ep in endpoints:
            norm = normalize_endpoint_url(getattr(ep, "url", None))
            if norm is None:
                logger.debug("recon_endpoint_rejected_malformed", url=getattr(ep, "url", None))
                continue
            ep.url = norm
            enforcer = getattr(self, "_ep_scope_enforcer", None)
            if enforcer is not None:
                host = urlparse(norm).hostname
                if not enforcer.host_in_scope(host):
                    _rejected = getattr(self, "_rejected_scope_urls", None)
                    if _rejected is not None:
                        if norm not in _rejected:
                            _rejected.add(norm)
                            logger.info("recon_endpoint_out_of_scope", url=norm)
                    else:
                        logger.info("recon_endpoint_out_of_scope", url=norm)
                    continue
            valid.append(ep)
        if valid:
            await self.ctx.graph_memory.add_endpoints_batch(valid)
        return len(valid)

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute reconnaissance task."""
        task_type = task.type
        payload = task.payload

        # Per-task scope gate for endpoint persistence (fixes scope bleed: recon was
        # storing off-scope hosts like www.syfe.com / third-party CDNs as endpoints).
        self._ep_scope_enforcer = self._build_scope_enforcer(payload)

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
        elif task_type == "content_discovery":
            return await self._execute_content_discovery(payload)
        elif task_type == "openapi_ingest":
            return await self._execute_openapi_ingest(payload)
        elif task_type == "cert_transparency":
            return await self._execute_cert_transparency(payload)
        elif task_type == "wayback_discovery":
            return await self._execute_wayback_discovery(payload)
        elif task_type == "waf_detection":
            return await self._execute_waf_detection(payload)
        else:
            raise AgentException(f"Unknown recon task type: {task_type}")

    def _mk_endpoint(self, url: str, engagement_id: str, source: str, **extra: Any) -> Endpoint:
        """Build an enriched Endpoint from a raw URL (params, tags, template).

        ``parameters`` defaults to the URL's query keys but callers (e.g. OpenAPI
        ingest) may override it with spec-derived parameter names.
        """
        from urllib.parse import urlsplit as _us

        _p = _us(url)
        params = extra.pop("parameters", None)
        if params is None:
            params = extract_params(url)
        return Endpoint(
            url=url,
            source=source,
            confidence=extra.pop("confidence", 0.85),
            engagement_id=engagement_id,
            parameters=params,
            query_keys=params,
            host=_p.netloc,
            path=extra.pop("path", _p.path),
            metadata={
                "tags": classify_url(url),
                "template": endpoint_template(url),
                **extra.pop("metadata", {}),
            },
            **extra,
        )

    async def _execute_content_discovery(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Deep content/parameter discovery via katana (P1.2) + targeted permutator.

        JS-aware crawl of the target, then every discovered URL is mined for hidden
        parameters and high-risk surface and written to the graph as enriched
        endpoints. Reuses the P1.1 url_intelligence module for the mining.

        Short-term Priority 2 (2026-07-23): after the katana crawl, queries the
        graph for detected technologies on the target Asset and uses the
        TargetedPermutator to generate framework-specific wordlist paths. These
        are probed via the governed client — a human researcher would fuzz
        /actuator/env if Spring is detected, /admin/login if Django, etc.
        """
        target = payload.get("url") or payload.get("target")
        if not target:
            raise AgentException("content_discovery requires 'url' or 'target' in payload")
        depth = int(payload.get("depth", 3))
        engagement_id = self.ctx.current_task.engagement_id if self.ctx.current_task else ""
        try:
            result = await self.security_bridge.run_katana(
                target, depth=depth, timeout_override=120
            )
        except Exception as e:
            logger.warning("content_discovery_katana_failed", error=str(e))
            return {"status": "error", "error": f"katana crawl failed: {e}"}
        urls = [
            u
            for u in (list(result.get("endpoints", [])) + list(result.get("js_files", [])))
            if isinstance(u, str) and u
        ]

        # Targeted Permutator: generate framework-specific paths and probe them.
        # A human researcher doesn't use a generic wordlist — they generate
        # custom paths based on the detected technology stack.
        try:
            from ai_osop.core.targeted_permutator import TargetedPermutator

            # Query the graph for technologies detected on the target asset
            tech_records = await self.ctx.graph_memory.run_read_query(
                "MATCH (a:Asset {engagement_id: $eid}) "
                "WHERE a.value CONTAINS $domain OR a.technologies IS NOT NULL "
                "RETURN a.technologies AS techs, a.value AS value LIMIT 5",
                {"eid": engagement_id, "domain": target.split("//")[-1].split("/")[0]},
            )
            all_techs: list = []
            for rec in tech_records:
                techs = rec.get("techs")
                if isinstance(techs, list):
                    all_techs.extend(techs)
                elif isinstance(techs, str):
                    all_techs.append(techs)

            if all_techs:
                framework_paths = TargetedPermutator.get_permutations(all_techs)
                base_url = target.rstrip("/")
                # Probe framework-specific paths via the governed client
                async with self.get_governed_client(tool="content_fuzz", timeout=10.0) as client:
                    for path in framework_paths[:80]:  # cap at 80 to stay bounded
                        probe_url = f"{base_url}{path}"
                        try:
                            resp = await client.get(probe_url)
                            if resp.status_code not in (404,):
                                # Path exists (200, 401, 403, 500, etc.) — persist it
                                ep = self._mk_endpoint(
                                    probe_url, engagement_id, source="targeted_permutator",
                                )
                                await self._persist_endpoint(ep)
                                self.endpoint_inventory[ep.id] = ep
                        except Exception:
                            continue
                logger.info(
                    "content_discovery_targeted_permutator",
                    technologies=all_techs,
                    paths_probed=len(framework_paths[:80]),
                )
        except Exception as e:
            logger.warning("content_discovery_targeted_permutator_failed", error=str(e))

        # 1. Fetch form fields from up to 50 crawled URLs
        form_params_by_url = {}
        try:
            form_params_by_url = await self._fetch_and_extract_form_fields(urls)
        except Exception as e:
            logger.warning("fetch_form_fields_failed", error=str(e))

        added = 0
        for url in urls:
            try:
                # Merge query params with form fields
                query_params = extract_params(url)
                form_fields = form_params_by_url.get(url, [])
                combined_params = sorted(list(set(query_params + form_fields)))

                ep = self._mk_endpoint(
                    url, engagement_id, source="katana", parameters=combined_params
                )
                await self._persist_endpoint(ep)
                self.endpoint_inventory[ep.id] = ep
                added += 1
            except Exception as ex:
                logger.error("content_discovery_add_endpoint_failed", url=url, error=str(ex))
        intel = mine_urls(urls).as_dict()
        if intel["interesting_params"]:
            logger.info(
                "content_discovery_param_intel",
                high_risk_params=intel["interesting_params"],
                unique_endpoints=intel["unique_endpoint_count"],
            )
        return {
            "status": "success",
            "target": target,
            "endpoints_found": added,
            "js_files": len(result.get("js_files", [])),
            "parameter_intelligence": intel,
        }

    async def _fetch_and_extract_form_fields(self, urls: List[str]) -> Dict[str, List[str]]:
        form_params_by_url = {}
        web_urls = [u for u in urls if not u.lower().endswith(".js")][:50]
        if not web_urls:
            return {}

        async with self.get_governed_client(tool="recon") as session:
            tasks = []
            for url in web_urls:
                tasks.append(self._fetch_single_url_forms(session, url))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for url, fields in zip(web_urls, results):
                if isinstance(fields, list) and fields:
                    form_params_by_url[url] = fields
        return form_params_by_url

    async def _fetch_single_url_forms(self, session: Any, url: str) -> List[str]:
        try:
            resp = await session.get(url, timeout=5.0)
            if resp.status_code == 200:
                html = resp.text
                return extract_form_fields(html)
        except Exception:
            pass
        return []

    async def _execute_openapi_ingest(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Discover + ingest an exposed OpenAPI/Swagger spec (P1.3).

        Probes conventional spec locations (scope-gated), parses the first valid
        spec into endpoints (with query/path params and request-body fields), and
        writes them to the graph as API attack surface.
        """
        target = payload.get("url") or payload.get("target")
        if not target:
            raise AgentException("openapi_ingest requires 'url' or 'target' in payload")
        engagement_id = self.ctx.current_task.engagement_id if self.ctx.current_task else ""
        candidates = payload.get("spec_urls") or spec_candidate_urls(target)
        scope = ScopeEnforcer(self.ctx.scope) if getattr(self.ctx, "scope", None) else None
        spec = None
        found_url = ""
        async with self.get_governed_client(tool="recon") as session:
            for cand in candidates:
                if scope is not None:
                    try:
                        if not scope.validate_target(cand):
                            continue
                    except Exception:
                        continue  # out of scope / invalid -> skip
                try:
                    resp = await session.get(cand, timeout=10.0)
                    if resp.status_code != 200:
                        continue
                    doc = resp.json()
                except Exception:
                    continue
                if is_spec(doc):
                    spec, found_url = doc, cand
                    break
        if spec is None:
            return {
                "status": "success",
                "target": target,
                "spec_found": False,
                "endpoints_found": 0,
            }
        descriptors = parse_spec(spec, base_url=payload.get("base_url") or target)
        added = 0
        for d in descriptors:
            try:
                ep = self._mk_endpoint(
                    d["url"],
                    engagement_id,
                    source="openapi",
                    confidence=0.9,
                    method=d["method"],
                    type="api",
                    path=d["path"],
                    parameters=d.get("parameters", []),
                    body_schema_keys=d.get("body_keys", []),
                    metadata={"operation_id": d.get("operation_id", ""), "spec_url": found_url},
                )
                await self._persist_endpoint(ep)
                self.endpoint_inventory[ep.id] = ep
                added += 1
            except Exception as ex:
                logger.error("openapi_add_endpoint_failed", url=d["url"], error=str(ex))
        logger.info("openapi_ingested", spec_url=found_url, endpoints=added)
        return {
            "status": "success",
            "target": target,
            "spec_found": True,
            "spec_url": found_url,
            "endpoints_found": added,
        }

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

        known = payload.get("known_subs") or list(
            self.asset_inventory
            and [
                a.value
                for a in self.asset_inventory.values()
                if getattr(a, "type", "") in ("subdomain", "domain")
            ]
        )
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
                        id=f"asset-{engagement_id}-{host}",
                        type="subdomain",
                        value=host,
                        source="permutation",
                        confidence=0.9,
                        engagement_id=engagement_id,
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
            logger.warning(f"DNS enum failed for {domain}: {e}")
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
                logger.error(f"Failed to add asset {asset.value} to graph: {e}")

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
            logger.warning(f"Port scan failed: {e}")
            assets = []

        # Set engagement ID and store in graph memory
        for asset in assets:
            try:
                asset.engagement_id = self.ctx.current_task.engagement_id
                await self.ctx.graph_memory.add_asset(asset)
                self.asset_inventory[asset.id] = asset
            except Exception as e:
                logger.error(f"Failed to add asset {asset.value} to graph: {e}")

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
            logger.error(
                "service_probe_failed", error=str(e), target_count=len(targets), exc_info=True
            )
            logger.warning(f"Service probe failed ({len(targets)} targets): {e}")
            endpoints = []

        for endpoint in endpoints:
            endpoint.engagement_id = self.ctx.current_task.engagement_id
        try:
            await self._persist_endpoints_batch(endpoints)
            for endpoint in endpoints:
                self.endpoint_inventory[endpoint.id] = endpoint
        except Exception as e:
            logger.error(f"Failed to batch-persist endpoints to graph: {e}")

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
            logger.debug(f"full_recon_failure: {str(e)}")
            logger.error("full_recon_failure", error=str(e), exc_info=True)
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
                logger.debug(f"Probing {len(urls_to_probe)} URLs for web services...")
                probe_res = await self._execute_service_probe({"targets": urls_to_probe})
                endpoints_count = probe_res.get("endpoints_discovered", 0)
            except Exception as e:
                logger.warning(f"Full recon service probe failed: {e}")

        # 3.5. Active Web Crawling & Endpoint Explosion (Sprint 12)
        active_endpoints = []
        try:
            logger.debug(f"Initiating active web crawl / endpoint explosion on {domain}...")
            active_endpoints = await self._active_crawl_target(domain)
            for ep in active_endpoints:
                try:
                    await self._persist_endpoint(ep)
                    self.endpoint_inventory[ep.id] = ep
                except Exception as ex:
                    logger.error(f"Failed to add active crawled endpoint {ep.url} to graph: {ex}")
        except Exception as e:
            logger.warning(f"Active crawl failed: {e}")

        # 4. Historical URLs (Wayback) (Sprint 12)
        historical_count = 0
        try:
            logger.debug(f"Fetching historical URLs from Wayback for {domain}...")
            hist_endpoints = await self.recon_adapter.historical_urls(domain)
            for ep in hist_endpoints:
                try:
                    ep.engagement_id = self.ctx.current_task.engagement_id
                    await self._persist_endpoint(ep)
                    self.endpoint_inventory[ep.id] = ep
                    historical_count += 1
                except Exception as ex:
                    logger.error(f"Failed to add historical endpoint {ep.url} to graph: {ex}")
        except Exception as e:
            logger.warning(f"Historical URLs lookup failed: {e}")

        # 5. OSINT Shodan Lookup (Sprint 12)
        shodan_assets_count = 0
        try:
            logger.debug(f"Running Shodan OSINT lookup for {domain}...")
            shodan_assets = await self.recon_adapter.osint_lookup(domain)
            for asset in shodan_assets:
                try:
                    asset.engagement_id = self.ctx.current_task.engagement_id
                    await self.ctx.graph_memory.add_asset(asset)
                    self.asset_inventory[asset.id] = asset
                    shodan_assets_count += 1
                except Exception as ex:
                    logger.error(f"Failed to add Shodan asset {asset.value} to graph: {ex}")
        except Exception as e:
            logger.warning(f"Shodan OSINT lookup failed: {e}")

        # 5a. Certificate Transparency (crt.sh) — passive subdomain discovery
        try:
            ct_result = await self._execute_cert_transparency({
                "domain": domain,
                "engagement_id": self.ctx.current_task.engagement_id,
            })
            logger.info(f"CT logs found {ct_result.get('subdomains_found', 0)} subdomains")
        except Exception as e:
            logger.warning(f"CT log lookup failed: {e}")

        # 5b. Wayback Machine — historical URL discovery
        try:
            wb_result = await self._execute_wayback_discovery({
                "domain": domain,
                "engagement_id": self.ctx.current_task.engagement_id,
            })
            logger.info(f"Wayback found {wb_result.get('urls_found', 0)} historical URLs")
        except Exception as e:
            logger.warning(f"Wayback discovery failed: {e}")

        # 5c. WAF Detection — identify WAF for context-aware payload generation
        try:
            waf_result = await self._execute_waf_detection({
                "domain": domain,
                "engagement_id": self.ctx.current_task.engagement_id,
            })
            if waf_result.get("waf_detected"):
                logger.info(f"WAF detected: {waf_result['waf_detected']} (signals: {waf_result['waf_signals']})")
        except Exception as e:
            logger.warning(f"WAF detection failed: {e}")

        # P1 recon multiplier: consolidate every discovered URL (crawl + historical +
        # probes) into parameter/endpoint intelligence. This turns a raw URL dump into
        # a prioritised list of hidden parameters and high-risk surface (open-redirect,
        # SSRF, LFI, IDOR candidates) that the vuln/exploit agents can target directly.
        all_urls = [ep.url for ep in self.endpoint_inventory.values() if getattr(ep, "url", None)]
        param_intel = mine_urls(all_urls).as_dict()
        if param_intel["interesting_params"]:
            logger.info(
                "recon_param_intel",
                engagement_id=self.ctx.current_task.engagement_id,
                unique_endpoints=param_intel["unique_endpoint_count"],
                high_risk_params=param_intel["interesting_params"],
                interesting_files=len(param_intel["interesting_files"]),
            )

        return {
            "status": "success",
            "target": domain,
            "subdomains_found": len(subdomains),
            "endpoints_found": endpoints_count + historical_count + len(active_endpoints),
            "parameter_intelligence": param_intel,
            "reasoning": reasoning,
        }

    async def _active_crawl_target(
        self, domain: str, session_store: Optional[Any] = None
    ) -> List[Endpoint]:
        """
        Active Web Crawler & Endpoint Explosion Engine (Sprint 13).
        Actively crawls the target application under multiple authenticated identities
        to map role-specific routes and calculate the Privilege Expansion Ratio (PER).
        """
        # 1. Load captured user sessions for the engagement (Swarm Identity Matrix)
        store = session_store or SessionStore(self.ctx.session_memory, self.ctx.graph_memory)
        sessions = await store.list_sessions(self.ctx.current_task.engagement_id)

        # Load previously discovered endpoints to adapt crawling
        known_endpoints = []
        try:
            records = await self.ctx.graph_memory.run_read_query(
                "MATCH (e:Endpoint {engagement_id: $engagement_id}) RETURN e",
                {"engagement_id": self.ctx.current_task.engagement_id},
            )
            for record in records:
                e_data = record["e"]
                techs = e_data.get("technologies") or []
                if isinstance(techs, str):
                    techs = [techs]
                known_endpoints.append(
                    Endpoint(
                        id=e_data.get("id"),
                        type=e_data.get("type", "web"),
                        url=e_data.get("url"),
                        method=e_data.get("method", "GET"),
                        confidence=e_data.get("confidence", 1.0),
                        engagement_id=e_data.get("engagement_id"),
                        source=e_data.get("source", "recon"),
                        query_keys=e_data.get("query_keys") or [],
                        body_schema_keys=e_data.get("body_schema_keys") or [],
                        auth_required=e_data.get("auth_required", False),
                        user_label=e_data.get("user_label", "anonymous"),
                        technologies=techs,
                    )
                )
        except Exception as e:
            logger.warning(f"Failed to query known endpoints from graph: {e}")
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

        logger.debug(
            f"Active crawler initialized with {len(identities)} identities: {[i['label'] for i in identities]}. Known paths: {len(known_paths)}"
        )

        # Regex patterns for API routes and parameters in JS
        param_pattern = re.compile(r"[?&]([a-zA-Z0-9_\-]+)=")
        # Routes embedded in JS bundles (root-relative paths, optional query).
        # Previously referenced below but never defined -> NameError silently
        # killed all JS-bundle route extraction (AIOSOP-RECON-JSROUTE-FIX).
        js_route_pattern = re.compile(r"""["'`](/(?:[A-Za-z0-9_.\-]+/?)+(?:\?[^"'`\s<>]*)?)["'`]""")
        # Routes embedded in INLINE <script> blocks / raw HTML that are NOT
        # <a href> anchors — e.g. SPA route tables and filter menus. This is how
        # ginandjuice.shop exposes its (SQLi-injectable) ?category= links, which
        # a pure href crawler never sees. Matches quoted absolute URLs or quoted
        # root-relative paths that carry a query string.
        inline_route_pattern = re.compile(
            r"""["'`]((?:https?://[^"'`\s<>]+)|(?:/[A-Za-z0-9_./\-]+\?[^"'`\s<>]+))["'`]"""
        )

        for identity in identities:
            user_label = identity["label"]
            user_session = identity["session"]

            logger.debug(f"Starting active crawl phase for identity: {user_label}")

            visited_urls = set()
            urls_to_crawl = sorted(list(set(initial_urls)))

            # MIN-7 (2026-07-21): crawl budget configurable from task payload.
            # Previously hardcoded to 20; callers (phase_monitor, API) can now
            # pass max_pages in the task payload to adjust for large in-scope apps.
            # Read defensively from the bound task context — ``payload`` is not a
            # local here (fixing a NameError that crashed the active crawler), and
            # some contexts (tests, direct calls) have no current_task at all.
            _task = getattr(self.ctx, "current_task", None)
            _payload = getattr(_task, "payload", None)
            max_pages = int(_payload.get("max_pages", 20)) if isinstance(_payload, dict) else 20
            pages_crawled = 0

            js_files = set()
            api_routes = set()
            parameters_found = set()

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-OSOP-Crawler/1.2"
            }
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

            async with self.get_governed_client(
                tool="recon", headers=headers, cookies=cookies
            ) as session:
                while urls_to_crawl and pages_crawled < max_pages:
                    url = urls_to_crawl.pop(0)
                    if url in visited_urls:
                        continue
                    visited_urls.add(url)
                    pages_crawled += 1

                    try:
                        response = await session.get(url, timeout=5.0)
                        status = response.status_code
                        content_type = response.headers.get("Content-Type", "")
                        parsed_url = urlparse(str(response.url))
                        # MAJ-2 (2026-07-21): use host_in_scope instead of
                        # netloc.endswith(domain). endswith allows lookalike
                        # hosts (e.g. evilsyfe.com.endswith('syfe.com') == True)
                        # and leaks auth cookies/bearer to attacker-glued hosts.
                        enforcer = getattr(self, "_ep_scope_enforcer", None)
                        h = (parsed_url.hostname or "").lower().strip()
                        _fallback_in_scope = h == domain or h.endswith(f".{domain}")
                        _in_scope = (
                            enforcer.host_in_scope(h)
                            if enforcer is not None
                            else _fallback_in_scope
                        )
                        if _in_scope:
                            is_new = str(response.url) not in self.endpoint_inventory
                            # Set auth parameters based on identity context
                            auth_req = (
                                user_label != "anonymous"
                                if is_new
                                else self.endpoint_inventory[str(response.url)].auth_required
                            )
                            final_label = (
                                user_label
                                if is_new
                                else self.endpoint_inventory[str(response.url)].user_label
                            )
                            query_params = list(parse_qs(parsed_url.query).keys())
                            if is_new:
                                from ai_osop.core.url_intelligence import active_parameter_mine

                                try:
                                    mined_params = await active_parameter_mine(
                                        str(response.url), session
                                    )
                                    if mined_params:
                                        query_params = list(set(query_params + mined_params))
                                        for p in mined_params:
                                            parameters_found.add(p)
                                except Exception:
                                    pass
                            ep = Endpoint(
                                id=f"endpoint-{hashlib.md5(str(response.url).encode()).hexdigest()[:12]}",
                                type="web",
                                url=str(response.url),
                                method="GET",
                                confidence=0.9,
                                engagement_id=self.ctx.current_task.engagement_id,
                                source="active_crawl",
                                status_code=status,
                                status_codes_seen=[status],
                                query_keys=query_params,
                                auth_required=auth_req,
                                user_label=final_label,
                            )
                            discovered_endpoints.append(ep)
                            self.endpoint_inventory[str(response.url)] = ep
                            if "text/html" in content_type:
                                html_text = response.text
                                parser = SimpleHTMLParser()
                                parser.feed(html_text)

                                # 1. Extract Links
                                for href in parser.links:
                                    link = urljoin(str(response.url), href)
                                    parsed_link = urlparse(link)
                                    # MAJ-2: use host_in_scope to prevent lookalike domain bleed
                                    link_enforcer = getattr(self, "_ep_scope_enforcer", None)
                                    lh = (parsed_link.hostname or "").lower().strip()
                                    _link_fallback = lh == domain or lh.endswith(f".{domain}")
                                    _link_in_scope = (
                                        link_enforcer.host_in_scope(lh)
                                        if link_enforcer is not None
                                        else _link_fallback
                                    )
                                    if _link_in_scope and link not in visited_urls:
                                        urls_to_crawl.append(link)

                                # 1b. Extract routes embedded in inline JS / raw HTML
                                for raw_route in inline_route_pattern.findall(html_text):
                                    link = urljoin(str(response.url), raw_route)
                                    parsed_link = urlparse(link)
                                    inline_enforcer = getattr(self, "_ep_scope_enforcer", None)
                                    ilh = (parsed_link.hostname or "").lower().strip()
                                    _inline_fallback = ilh == domain or ilh.endswith(f".{domain}")
                                    _inline_in_scope = (
                                        inline_enforcer.host_in_scope(ilh)
                                        if inline_enforcer is not None
                                        else _inline_fallback
                                    )
                                    if (
                                        _inline_in_scope
                                        and link not in visited_urls
                                        and link not in urls_to_crawl
                                    ):
                                        urls_to_crawl.append(link)
                                    # 2. Extract Forms & Parameters
                                    for form in parser.forms:
                                        form_url = urljoin(str(response.url), form["action"])
                                        form_method = form["method"]
                                        form_params = form["inputs"]
                                        for p in form_params:
                                            parameters_found.add(p)

                                        is_form_new = form_url not in self.endpoint_inventory
                                        form_auth_req = (
                                            user_label != "anonymous"
                                            if is_form_new
                                            else self.endpoint_inventory[form_url].auth_required
                                        )
                                        form_final_label = (
                                            user_label
                                            if is_form_new
                                            else self.endpoint_inventory[form_url].user_label
                                        )

                                        form_ep = Endpoint(
                                            id=f"endpoint-{hashlib.md5(form_url.encode()).hexdigest()[:12]}",
                                            type="web",
                                            url=form_url,
                                            method=form_method,
                                            confidence=0.95,
                                            engagement_id=self.ctx.current_task.engagement_id,
                                            source="active_crawl_form",
                                            body_schema_keys=(
                                                form_params if form_method == "POST" else []
                                            ),
                                            query_keys=form_params if form_method == "GET" else [],
                                            auth_required=form_auth_req,
                                            user_label=form_final_label,
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
                                        root_domain = (
                                            ".".join(domain_parts[-2:])
                                            if len(domain_parts) >= 2
                                            else domain
                                        )

                                        sh = script_host.lower().strip()
                                        _fallback_valid = (
                                            sh == ""
                                            or sh == domain
                                            or sh.endswith(f".{domain}")
                                            or sh == root_domain
                                            or sh.endswith(f".{root_domain}")
                                            or "website-files.com" in sh
                                            or "webflow" in sh
                                        )

                                        is_valid = (
                                            link_enforcer.host_in_scope(sh)
                                            if link_enforcer is not None
                                            else _fallback_valid
                                        )
                                        # Ignore common global trackers to avoid noise
                                        ignore_trackers = [
                                            "google-analytics",
                                            "googletagmanager",
                                            "facebook.net",
                                            "doubleclick",
                                        ]
                                        if is_valid and not any(
                                            t in script_url for t in ignore_trackers
                                        ):
                                            js_files.add(script_url)

                                            is_js_new = script_url not in self.endpoint_inventory
                                            js_auth_req = (
                                                user_label != "anonymous"
                                                if is_js_new
                                                else self.endpoint_inventory[
                                                    script_url
                                                ].auth_required
                                            )
                                            js_final_label = (
                                                user_label
                                                if is_js_new
                                                else self.endpoint_inventory[script_url].user_label
                                            )

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
                                                user_label=js_final_label,
                                            )
                                            discovered_endpoints.append(js_ep)
                                            self.endpoint_inventory[script_url] = js_ep

                    except Exception as e:
                        logger.debug(f"Active crawl failed for {url} under {user_label}: {e}")

                # 4. Parse JavaScript Bundles for hidden API routes and parameters
                logger.debug(
                    f"Discovered {len(js_files)} JS bundles for {user_label}. Starting deep route extraction..."
                )
                for js_url in sorted(list(js_files))[:10]:
                    try:
                        js_response = await session.get(js_url, timeout=5.0)
                        if js_response.status_code == 200:
                            js_text = js_response.text
                            routes = js_route_pattern.findall(js_text)
                            params = param_pattern.findall(js_text)

                            for route in routes:
                                api_routes.add(route)
                                full_api_url = urljoin(f"https://{domain}/", route)

                                is_api_new = full_api_url not in self.endpoint_inventory
                                api_auth_req = (
                                    user_label != "anonymous"
                                    if is_api_new
                                    else self.endpoint_inventory[full_api_url].auth_required
                                )
                                api_final_label = (
                                    user_label
                                    if is_api_new
                                    else self.endpoint_inventory[full_api_url].user_label
                                )

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
                                    user_label=api_final_label,
                                    query_keys=list(set(params)),
                                    parameters=list(set(params)),
                                )
                                discovered_endpoints.append(api_ep)
                                self.endpoint_inventory[full_api_url] = api_ep

                            for param in params:
                                parameters_found.add(param)
                    except Exception as e:
                        logger.debug(
                            f"JS route extraction failed for {js_url} under {user_label}: {e}"
                        )

            logger.debug(
                f"Active crawl complete for {user_label}. Found {len(discovered_endpoints)} total endpoints, {len(api_routes)} API routes, and {len(parameters_found)} parameters."
            )

        return discovered_endpoints

    async def _execute_cert_transparency(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Query crt.sh certificate transparency logs for subdomains.

        crt.sh is a free CT log search that reveals subdomains the target
        may not publicize — a core recon technique for elite researchers.
        Uses the governed client so the egress is scope-checked + rate-limited.
        """
        domain = payload.get("domain") or payload.get("url", "").replace("https://", "").replace("http://", "").split("/")[0]
        if not domain:
            return {"status": "failed", "error": "domain parameter is required"}

        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else ""
        )
        found_subdomains: list = []

        try:
            async with self.get_governed_client(tool="cert_ct", timeout=15.0) as client:
                resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if resp.status_code == 200:
                    import json as _json
                    try:
                        data = _json.loads(resp.text)
                        for entry in data:
                            for name in entry.get("name_value", "").split("\n"):
                                name = name.strip().lower()
                                if name and name.endswith(f".{domain}") and name not in found_subdomains:
                                    found_subdomains.append(name)
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"cert_transparency failed for {domain}: {e}")

        # Persist discovered subdomains as assets
        for sub in found_subdomains[:50]:  # cap to avoid flooding
            try:
                asset = Asset(
                    id=f"asset-{engagement_id}-{sub}",
                    type="domain",
                    value=sub,
                    source="cert_transparency",
                    confidence=0.95,
                    engagement_id=engagement_id,
                )
                await self.ctx.graph_memory.add_asset(asset)
            except Exception:
                pass

        return {
            "status": "success",
            "tool": "cert_transparency",
            "domain": domain,
            "subdomains_found": len(found_subdomains),
            "subdomains": found_subdomains[:20],
        }

    async def _execute_wayback_discovery(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Query the Wayback Machine for historical URLs of the target.

        The Wayback Machine reveals endpoints that may no longer be linked
        from the current site — old API paths, deprecated admin panels,
        removed features that are still live. This is a core recon technique.
        """
        domain = payload.get("domain") or payload.get("url", "").replace("https://", "").replace("http://", "").split("/")[0]
        if not domain:
            return {"status": "failed", "error": "domain parameter is required"}

        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else ""
        )
        found_urls: list = []

        try:
            async with self.get_governed_client(tool="wayback", timeout=20.0) as client:
                resp = await client.get(
                    f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
                )
                if resp.status_code == 200:
                    import json as _json
                    try:
                        data = _json.loads(resp.text)
                        if len(data) > 1:  # first row is headers
                            for row in data[1:]:
                                if row and row[0] and row[0] not in found_urls:
                                    found_urls.append(row[0])
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"wayback_discovery failed for {domain}: {e}")

        # Persist discovered URLs as endpoints
        seeded = 0
        for url in found_urls[:100]:
            try:
                ep = self._mk_endpoint(url, engagement_id, source="wayback")
                await self._persist_endpoint(ep)
                seeded += 1
            except Exception:
                pass

        return {
            "status": "success",
            "tool": "wayback_discovery",
            "domain": domain,
            "urls_found": len(found_urls),
            "endpoints_seeded": seeded,
        }

    async def _execute_waf_detection(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Detect WAF protection on the target.

        Identifies the WAF (Cloudflare, AWS WAF, Akamai, etc.) by checking
        response headers, cookies, and challenge patterns. WAF detection
        is critical for context-aware payload generation — knowing the WAF
        lets the payload engine choose WAF-bypass variants.
        """
        target_url = payload.get("url") or payload.get("target")
        if not target_url:
            domain = payload.get("domain", "")
            if domain:
                target_url = f"http://{domain}"
            else:
                return {"status": "failed", "error": "url or domain parameter is required"}

        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else ""
        )

        waf_detected = None
        waf_signals: list = []

        try:
            async with self.get_governed_client(tool="waf_detect", timeout=10.0) as client:
                resp = await client.get(target_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = resp.headers.get("set-cookie", "").lower()

                # Cloudflare
                if "cf-ray" in headers or "cloudflare" in cookies:
                    waf_detected = "cloudflare"
                    waf_signals.append("cf-ray header present")
                # AWS WAF
                elif "x-amzn-waf" in headers or "awselb" in cookies:
                    waf_detected = "aws_waf"
                    waf_signals.append("x-amzn-waf header present")
                # Akamai
                elif "akamaighost" in headers or "akamai" in cookies:
                    waf_detected = "akamai"
                    waf_signals.append("akamai headers present")
                # F5 BIG-IP
                elif "bigipserver" in cookies:
                    waf_detected = "f5_bigip"
                    waf_signals.append("BIGipServer cookie present")
                # Sucuri
                elif "x-sucuri-id" in headers:
                    waf_detected = "sucuri"
                    waf_signals.append("x-sucuri-id header present")
                # Imperva
                elif "incap_ses" in cookies or "visid_incap" in cookies:
                    waf_detected = "imperva"
                    waf_signals.append("incap_ses/visid_incap cookies present")

                # Check for challenge pages
                body_lower = resp.text[:2000].lower()
                if not waf_detected:
                    if "just a moment" in body_lower or "cf-browser-verification" in body_lower:
                        waf_detected = "cloudflare"
                        waf_signals.append("challenge page detected")
                    elif "access denied" in body_lower and "akamai" in body_lower:
                        waf_detected = "akamai"
                        waf_signals.append("access denied page")
        except Exception as e:
            logger.warning(f"waf_detection failed for {target_url}: {e}")
            return {"status": "failed", "error": str(e)}

        result = {
            "status": "success",
            "tool": "waf_detection",
            "target": target_url,
            "waf_detected": waf_detected,
            "waf_signals": waf_signals,
        }

        # Store the WAF finding as an asset attribute so the payload engine
        # and the reasoning loop can use it for context-aware generation.
        if waf_detected:
            try:
                await self.ctx.graph_memory.run_write_query(
                    "MERGE (a:Asset {value: $domain}) SET a.waf = $waf, a.waf_signals = $signals",
                    {
                        "domain": target_url.split("//")[-1].split("/")[0],
                        "waf": waf_detected,
                        "signals": waf_signals,
                    },
                )
            except Exception:
                pass

        return result

    async def _cleanup_resources(self) -> None:
        """Cleanup recon resources."""
        self.asset_inventory.clear()
        self.endpoint_inventory.clear()
