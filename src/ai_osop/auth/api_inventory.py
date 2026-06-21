"""
api_inventory — HAR → Endpoint Neo4j extraction.

Reads a Playwright-captured HAR file and persists every API call as an Endpoint
node with type="api" in Neo4j.

Schema (unified):

    (:Workflow)-[:CALLED]->(:Endpoint {type: "api"})
    (:Endpoint)-[:HAS_REPLAY]->(:ReplayResult)
    (:UserSession)-[:OWNS]->(:Workflow)
    (:UserSession)-[:CAPTURED]->(:Endpoint)

Endpoint node properties (type="api"):
    id (str)                  — fingerprint(method + path + auth_class)
    type (str)                — "api"
    method (str)
    url (str)                 — full url including host
    host (str)
    path (str)                — path only (no query)
    query_keys (list[str])    — keys observed (values NOT stored — too noisy)
    has_body (bool)
    content_type (str)
    body_schema (json string) — flattened key list if JSON body
    auth_class (str)          — 'anonymous' | 'bearer' | 'cookie' | 'mixed'
    request_headers_sample (json string)  — non-sensitive headers only
    status_codes_seen (list[int])
    response_size_avg (int)
    response_content_type (str)
    user_label (str)          — which UserSession captured this
    engagement_id (str)
    first_seen / last_seen (datetime str)

Filtering:
    - Skips static asset requests by default (.js .css .png .woff .ico .svg .map .json:big)
    - Skips analytics pixels (bat.bing.com, ads-twitter.com, tiktok, outbrain,
      bat.bing, google-analytics, doubleclick, facebook.net).
    - Counts every same-method+same-path-template as ONE endpoint, merging
      observations across the HAR.

CLI:
    python -m ai_osop.auth.api_inventory <har_path> --engagement-id X --user-label user_a
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import parse_qsl, urlparse

from ai_osop.core.models import Endpoint
from ai_osop.memory.graph_memory import GraphMemory

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------- filters

STATIC_EXTS = {
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".ico",
    ".map",
    ".mp4",
    ".webm",
    ".pdf",
}

ANALYTICS_HOSTS = {
    # marketing pixels — never bug-bounty material
    "bat.bing.com",
    "static.ads-twitter.com",
    "analytics.tiktok.com",
    "amplify.outbrain.com",
    "googletagmanager.com",
    "google-analytics.com",
    "doubleclick.net",
    "connect.facebook.net",
    "ads.linkedin.com",
    "snap.licdn.com",
    "px.ads.linkedin.com",
    "stats.g.doubleclick.net",
    "www.google.com",  # recaptcha
    "recaptcha.net",
    "hotjar.com",
    "fullstory.com",
    "logrocket.io",
}


def _is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTS)


def _is_analytics(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return any(host.endswith(a) for a in ANALYTICS_HOSTS)


# ------------------------------------------------------- HAR entry → APIEndpoint


@dataclass
class APIEndpoint:
    """In-memory aggregate; one per (method, host, path) tuple."""

    id: str
    method: str
    url: str  # representative (first observed)
    host: str
    path: str
    query_keys: Set[str] = field(default_factory=set)
    has_body: bool = False
    content_type: str = ""
    body_schema_keys: Set[str] = field(default_factory=set)
    auth_class: str = "anonymous"
    request_headers_sample: Dict[str, str] = field(default_factory=dict)
    status_codes_seen: Set[int] = field(default_factory=set)
    response_sizes: List[int] = field(default_factory=list)
    response_content_type: str = ""
    user_label: str = ""
    engagement_id: str = ""
    workflow_id: str = ""
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    observations: int = 0

    @property
    def response_size_avg(self) -> int:
        return (
            int(sum(self.response_sizes) / len(self.response_sizes)) if self.response_sizes else 0
        )

    def to_endpoint(self) -> Endpoint:
        """Convert to the unified Endpoint model for Neo4j persistence."""
        return Endpoint(
            id=self.id,
            url=self.url,
            method=self.method,
            type="api",
            host=self.host,
            path=self.path,
            query_keys=sorted(self.query_keys),
            has_body=self.has_body,
            content_type=self.content_type,
            body_schema_keys=sorted(self.body_schema_keys),
            auth_class=self.auth_class,
            request_headers_sample=self.request_headers_sample,
            status_codes_seen=sorted(self.status_codes_seen),
            response_size_avg=self.response_size_avg,
            response_content_type=self.response_content_type,
            user_label=self.user_label,
            engagement_id=self.engagement_id,
            workflow_id=self.workflow_id,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            observations=self.observations,
        )


def _fingerprint(method: str, host: str, path: str, auth_class: str) -> str:
    raw = f"{method.upper()}|{host}|{path}|{auth_class}"
    return "api-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _auth_class_for(headers: Dict[str, str], cookies_present: bool) -> str:
    has_bearer = any(
        h.lower() == "authorization" and v.lower().startswith("bearer ") for h, v in headers.items()
    )
    if has_bearer and cookies_present:
        return "mixed"
    if has_bearer:
        return "bearer"
    if cookies_present:
        return "cookie"
    return "anonymous"


# minimal allowlist of "safe to record" request headers (avoid leaking auth tokens)
SAFE_HEADER_NAMES = {
    "accept",
    "accept-language",
    "content-type",
    "user-agent",
    "referer",
    "origin",
    "x-requested-with",
    "x-csrf-token",
    "x-xsrf-token",
    "sec-ch-ua",
    "sec-ch-ua-platform",
    "sec-fetch-mode",
    "sec-fetch-site",
}


def _safe_headers(headers: List[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in headers or []:
        name = (h.get("name") or "").lower()
        value = h.get("value") or ""
        if name in SAFE_HEADER_NAMES:
            out[name] = value[:200]
    return out


def _extract_body_keys(post_data: Optional[Dict[str, Any]]) -> Set[str]:
    """Return a set of top-level keys from a JSON-or-form body, or empty set."""
    if not post_data:
        return set()
    text = post_data.get("text") or ""
    mime = (post_data.get("mimeType") or "").lower()
    if "json" in mime:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return set(parsed.keys())
        except Exception:
            return set()
    if "urlencoded" in mime or post_data.get("params"):
        params = post_data.get("params") or []
        if params:
            return {p.get("name", "") for p in params if p.get("name")}
        # fallback: parse text
        try:
            return {k for k, _ in parse_qsl(text, keep_blank_values=True)}
        except Exception:
            return set()
    return set()


# ------------------------------------------------------------- core extractor


class HARExtractor:
    """Parse a HAR file into APIEndpoint aggregates."""

    def __init__(
        self,
        *,
        engagement_id: str,
        user_label: str = "guest",
        workflow_id: str = "",
        scope_hosts: Optional[Iterable[str]] = None,
        include_static: bool = False,
        include_analytics: bool = False,
    ):
        self.engagement_id = engagement_id
        self.user_label = user_label
        self.workflow_id = workflow_id
        self.scope_hosts = {h.lower() for h in scope_hosts} if scope_hosts else None
        self.include_static = include_static
        self.include_analytics = include_analytics
        self.endpoints: Dict[str, APIEndpoint] = {}
        self.skipped = {"static": 0, "analytics": 0, "out_of_scope": 0, "malformed": 0}

    # -- entry point -----------------------------------------------------------

    def parse_file(self, har_path: str) -> List[APIEndpoint]:
        path = Path(har_path)
        if not path.exists():
            raise FileNotFoundError(har_path)
        with path.open("r", encoding="utf-8", errors="replace") as f:
            har = json.load(f)
        return self.parse_har(har)

    def parse_har(self, har: Dict[str, Any]) -> List[APIEndpoint]:
        entries = (har.get("log") or {}).get("entries") or []
        for entry in entries:
            try:
                self._absorb(entry)
            except Exception as e:
                logger.debug("har.entry_skip err=%s", e)
                self.skipped["malformed"] += 1
        return list(self.endpoints.values())

    # -- per-entry processing --------------------------------------------------

    def _absorb(self, entry: Dict[str, Any]) -> None:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = request.get("url") or ""
        method = (request.get("method") or "GET").upper()
        if not url:
            self.skipped["malformed"] += 1
            return

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        if not self.include_analytics and _is_analytics(url):
            self.skipped["analytics"] += 1
            return
        if not self.include_static and _is_static_asset(url):
            self.skipped["static"] += 1
            return
        if self.scope_hosts and not any(
            host == h or host.endswith("." + h) for h in self.scope_hosts
        ):
            self.skipped["out_of_scope"] += 1
            return

        headers_list = request.get("headers") or []
        headers_map = {(h.get("name") or "").lower(): h.get("value") or "" for h in headers_list}
        cookies_present = bool(request.get("cookies")) or "cookie" in headers_map
        auth_class = _auth_class_for(headers_map, cookies_present)

        # query keys (don't store values)
        query_keys = {q.get("name") for q in (request.get("queryString") or []) if q.get("name")}

        # body
        post_data = request.get("postData")
        body_keys = _extract_body_keys(post_data)
        content_type = (
            (post_data or {}).get("mimeType", "")
            if post_data
            else headers_map.get("content-type", "")
        )

        fid = _fingerprint(method, host, path, auth_class)
        existing = self.endpoints.get(fid)
        if existing is None:
            ep = APIEndpoint(
                id=fid,
                method=method,
                url=url,
                host=host,
                path=path,
                query_keys=query_keys,
                has_body=bool(body_keys) or bool(post_data),
                content_type=content_type,
                body_schema_keys=body_keys,
                auth_class=auth_class,
                request_headers_sample=_safe_headers(headers_list),
                user_label=self.user_label,
                engagement_id=self.engagement_id,
                workflow_id=self.workflow_id,
            )
            self.endpoints[fid] = ep
            existing = ep
        else:
            existing.query_keys |= query_keys
            existing.body_schema_keys |= body_keys
            existing.has_body = existing.has_body or bool(body_keys) or bool(post_data)
            existing.last_seen = datetime.now(timezone.utc)

        # response side
        status = response.get("status")
        if isinstance(status, int):
            existing.status_codes_seen.add(status)
        try:
            size = int(response.get("content", {}).get("size") or 0)
            if size >= 0:
                existing.response_sizes.append(size)
        except Exception:
            pass
        resp_ct = ""
        for h in response.get("headers", []) or []:
            if (h.get("name") or "").lower() == "content-type":
                resp_ct = h.get("value", "")
                break
        if resp_ct and not existing.response_content_type:
            existing.response_content_type = resp_ct

        existing.observations += 1
        existing.last_seen = datetime.now(timezone.utc)


# ------------------------------------------------------------- Neo4j persistence


async def persist_endpoints(graph_memory: GraphMemory, endpoints: List[APIEndpoint]) -> int:
    """Write Endpoint nodes (type=api) via the unified graph_memory.add_endpoint()."""
    if not endpoints:
        return 0
    written = 0
    for ep in endpoints:
        await graph_memory.add_endpoint(ep.to_endpoint())
        written += 1
    return written


# -------------------------------------------------------------------- CLI


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="api_inventory")
    p.add_argument("har_path")
    p.add_argument("--engagement-id", required=True)
    p.add_argument("--user-label", default="guest")
    p.add_argument("--workflow-id", default="")
    p.add_argument("--scope-hosts", nargs="*")
    p.add_argument("--include-static", action="store_true")
    p.add_argument("--include-analytics", action="store_true")
    p.add_argument("--no-persist", action="store_true", help="parse only, don't write to Neo4j")
    return p


async def _cli_main(args: argparse.Namespace) -> None:
    extractor = HARExtractor(
        engagement_id=args.engagement_id,
        user_label=args.user_label,
        workflow_id=args.workflow_id,
        scope_hosts=args.scope_hosts,
        include_static=args.include_static,
        include_analytics=args.include_analytics,
    )
    endpoints = extractor.parse_file(args.har_path)
    print(f"parsed: {len(endpoints)} unique endpoints")
    print(f"skipped: {extractor.skipped}")
    for ep in endpoints[:50]:
        print(
            f"  {ep.method:6s} {ep.host:40s} {ep.path:60s} auth={ep.auth_class:9s} "
            f"obs={ep.observations} codes={sorted(ep.status_codes_seen)} qkeys={sorted(ep.query_keys)[:5]}"
        )
    if not args.no_persist:
        gm = GraphMemory()
        await gm.connect()
        try:
            written = await persist_endpoints(gm, endpoints)
            print(f"persisted: {written} APIEndpoint nodes")
        finally:
            await gm.close()


def main() -> None:
    args = _build_arg_parser().parse_args()
    asyncio.run(_cli_main(args))


if __name__ == "__main__":  # pragma: no cover
    main()
