"""
Security Bridge MCP Adapter
Standardized interface for high-performance offensive tools (sqlmap, nmap, ffuf).
"""

import logging
from typing import Any, Dict, List, Optional

from ai_osop.core.exceptions import MCPException
from ai_osop.core.models import Asset, Endpoint
from ai_osop.mcp.protocol import MCPRegistry


class SecurityBridgeAdapter:
    """Adapter for the security-bridge MCP server."""

    SERVER_ID = "security-bridge"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        """Initialize the connection to the security-bridge server."""
        await self.registry.initialize_server(self.SERVER_ID, scope, {}, session_id)

    async def run_nmap(
        self, target: str, fast: bool = False, timeout_override: Optional[int] = None
    ) -> List[Asset]:
        """Run Nmap scan against target."""
        params = {"target": target, "fast": fast}
        response = await self.registry.execute_tool(
            self.SERVER_ID, "nmap", params, timeout_override=timeout_override
        )

        if response.status != "success":
            raise MCPException(f"Nmap execution failed: {response.error}")
        assets = []
        hosts = response.result.get("hosts", [])
        for host in hosts:
            assets.append(
                Asset(
                    type="host",
                    value=host["ip"],
                    source="nmap",
                    confidence=1.0,
                    metadata={"ports": host.get("ports", [])},
                    engagement_id="",  # Filled by agent
                )
            )
        return assets

    async def run_sqlmap(
        self,
        url: str,
        *,
        data: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        dump: bool = False,
        timeout_override: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run SQLMap against a target URL and return a parsed injection verdict.

        Args:
            url:   target URL (GET params injectable directly, e.g. ...?q=test).
            data:  optional POST body (must be whitespace-free per the bridge's
                   argument-injection sanitizer, e.g. "email=a&password=b").
            level: sqlmap detection depth 1-5 (higher tests more params/headers).
            risk:  sqlmap risk of payloads 1-3.
            dump:  attempt to dump table contents once an injection is confirmed.

        Returns the bridge's structured ``data`` dict:
            {injectable: bool, parameter: str, parameters: [str], dbms: str,
             techniques: [str], payloads: [str]}
        """
        params: Dict[str, Any] = {
            "url": url,
            "batch": True,
            "level": int(level),
            "risk": int(risk),
        }
        if data:
            params["data"] = data
        if dump:
            params["dump"] = True

        response = await self.registry.execute_tool(
            self.SERVER_ID, "sqlmap", params, timeout_override=timeout_override
        )

        if response.status != "success":
            raise MCPException(f"SQLMap execution failed: {response.error}")

        return response.result.get("data", {}) or {}

    async def run_ffuf(self, url: str, timeout_override: Optional[int] = None) -> List[Endpoint]:
        """Run FFUF directory/file fuzzing."""
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        params = {"url": url}
        response = await self.registry.execute_tool(
            self.SERVER_ID, "ffuf", params, timeout_override=timeout_override
        )

        if response.status != "success":
            raise MCPException(f"FFUF execution failed: {response.error}")

        endpoints = []
        results = response.result.get("results", [])
        for res in results:
            endpoints.append(
                Endpoint(
                    url=res["url"],
                    method="GET",
                    status_code=res["status"],
                    source="ffuf",
                    confidence=0.9,
                    engagement_id="",  # Filled by agent
                )
            )
        return endpoints

    async def run_katana(
        self, url: str, depth: int = 3, timeout_override: Optional[int] = None
    ) -> Dict[str, List[str]]:
        """Run Katana crawler and return discovered {endpoints, js_files}.

        The security-bridge server runs ``katana -j`` (JSONL) and returns katana's
        raw output under ``raw`` — its whole-output ``json.Unmarshal`` fails on
        multi-line JSONL, so the structured ``data``/``endpoints`` keys are usually
        empty. We therefore parse ``raw`` defensively; this is why content
        discovery previously returned nothing even when katana found URLs.
        """
        params = {"url": url, "depth": depth, "js_crawl": True}
        response = await self.registry.execute_tool(
            self.SERVER_ID, "katana_crawl", params, timeout_override=timeout_override
        )

        if response.status != "success":
            raise MCPException(f"Katana crawl failed: {response.error}")
        res = response.result or {}
        endpoints = list(res.get("endpoints") or [])
        js_files = list(res.get("js_files") or [])
        if not endpoints and not js_files:
            endpoints, js_files = self._parse_katana_output(res)
        return {"endpoints": endpoints, "js_files": js_files}

    @staticmethod
    def _parse_katana_output(res: Dict[str, Any]) -> "tuple[List[str], List[str]]":
        """Extract URLs from katana output, splitting .js files out.

        Handles a structured ``data`` list, JSONL lines under ``raw`` (each
        ``{"request": {"endpoint": URL}}`` or ``{"endpoint": URL}``), and plain
        one-URL-per-line output.
        """
        import json as _json

        def _url_of(obj: Any) -> Optional[str]:
            if isinstance(obj, str) and obj.startswith("http"):
                return obj
            if isinstance(obj, dict):
                req = obj.get("request")
                if isinstance(req, dict) and isinstance(req.get("endpoint"), str):
                    return req["endpoint"]
                for k in ("endpoint", "url", "URL"):
                    if isinstance(obj.get(k), str):
                        return obj[k]
            return None

        urls: List[str] = []
        data = res.get("data")
        if isinstance(data, list):
            urls.extend(u for u in (_url_of(x) for x in data) if u)
        if not urls:
            raw = res.get("raw") or ""
            if isinstance(raw, str):
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("{"):
                        try:
                            u = _url_of(_json.loads(line))
                        except (ValueError, _json.JSONDecodeError):
                            u = None
                        if u:
                            urls.append(u)
                    elif line.startswith("http"):
                        urls.append(line)

        seen: set = set()
        endpoints: List[str] = []
        js_files: List[str] = []
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            (js_files if u.split("?")[0].lower().endswith(".js") else endpoints).append(u)
        return endpoints, js_files

    async def run_js_analyze(self, js_url: str) -> Dict[str, Any]:
        """Analyze JS file for routes and secrets."""
        params = {"js_url": js_url}
        response = await self.registry.execute_tool(self.SERVER_ID, "js_analyze", params)

        if response.status != "success":
            raise MCPException(f"JS analysis failed: {response.error}")

        return response.result
