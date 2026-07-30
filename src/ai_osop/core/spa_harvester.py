"""Harvests endpoints for modern/JS-heavy apps.

Pure-text extraction of candidate endpoints from inline HTML/JS and external JS
bundles. The fetch / persistence helper (``harvest_spa_endpoints``) accepts an
httpx-like client and graph memory object, adds scope gating, and writes
``Endpoint`` models for downstream scanners.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse

from ai_osop.core.models import Endpoint
from ai_osop.core.url_intelligence import classify_url, endpoint_template, extract_params

_ABS_URL_RE = re.compile(r"""["'`](https?://[^"'`<>\s)]+)["'`]""")
_REL_PATH_RE = re.compile(r"""["'`](/(?:[A-Za-z0-9_.\-~]+/?)+(?:\?[^"'`<>\s]+)?)["'`]""")
_FETCH_ROUTE_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete))\(\s*[`'"]([^`'"<>\s]+)[`'"]""")
_TEMPLATE_API_RE = re.compile(r"""(/(?:rest|api|graphql)/[A-Za-z0-9_\-./]+(?:\?[A-Za-z0-9_&=-]+)?)""")
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"""<script(?![^>]+src)[^>]*>(.*?)</script>""", re.IGNORECASE | re.DOTALL)
_STATIC_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".map")


@dataclass(frozen=True)
class Candidate:
    url: str
    source: str
    parameters: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def merge_key(self) -> str:
        """Group by path, preserving the parameter signature as a discriminator.

        Two candidates are merged only if they represent the same endpoint shape:
        `/rest/products/search?q=` must not be collapsed into `/rest/products/search`
        because the usable attack surface lives in the parameter. Same-path hits
        with different parameter sets (e.g., ?q vs ?next) stay separate findings.
        """
        if "://" in self.url:
            parsed = urlparse(self.url)
            params = "&".join(sorted(dict(parse_qsl(parsed.query, keep_blank_values=True)).keys()))
            return f"{parsed.path}?{params}" if params else parsed.path
        path = self.url.split("#", 1)[0]
        params = ""
        if "?" in path:
            path, query = path.split("?", 1)
            params = "&".join(sorted(dict(parse_qsl(query, keep_blank_values=True)).keys()))
        return f"{path}?{params}" if params else path


@dataclass(frozen=True)
class MergedCandidate:
    url: str
    source: str
    sources: Tuple[str, ...]
    parameters: Tuple[str, ...] = field(default_factory=tuple)

    def to_candidate(self) -> Candidate:
        return Candidate(self.url, "{%s}" % "+".join(sorted(set(self.sources))) if self.sources else self.source, self.parameters)


_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"""<script(?![^>]+src)[^>]*>(.*?)</script>""", re.IGNORECASE | re.DOTALL)
_FORM_ACTION_RE = re.compile(r"""<form[^>]+action\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_STATIC_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".map")


@dataclass(frozen=True)
class SpaHarvestConfig:
    max_bundle_fetches: int = 5
    js_route_limit: int = 200


@dataclass
class HarvestResult:
    js_files_seen: int = 0
    candidates_found: int = 0
    endpoints_persisted: int = 0


def _to_tuples(params: Iterable[str]) -> Tuple[str, ...]:
    return tuple(sorted(set(params)))


def _normalize(raw: str, base_url: str) -> Optional[str]:
    target = raw.strip().strip("\"'`<>(){} ")
    if not target or target.startswith(("data:", "javascript:", "mailto:", "tel:")):
        return None
    if target.startswith("//"):
        target = "https:" + target
    if not urlparse(target).scheme and not target.startswith("/"):
        return None
    if target.startswith("/"):
        target = urljoin(base_url, target)
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return target


def _candidate_from_url(url: str, base_url: str, source: str, base_host_override: str = "") -> Optional[Candidate]:
    normalized = _normalize(url, base_url)
    if not normalized:
        return None
    parsed = urlparse(normalized)
    base_host = (base_host_override or urlparse(base_url).netloc).lower()
    # Only same-host (or relative) URLs survive. Cross-host items from JS and
    # HTML are dropped: embedded trackers/CDNs must not be included.
    if parsed.netloc.lower() != base_host:
        return None
    path_lower = parsed.path.lower()
    if any(path_lower.endswith(ext) for ext in _STATIC_EXTENSIONS):
        return None
    params = extract_params(normalized)
    if not params:
        params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    if source == "js_template_api" and not params:
        marker = re.match(r"^/(?:rest|api)/[^/]+/([A-Za-z0-9_-]+)$", parsed.path)
        if marker and marker.group(1) in ("search", "autocomplete", "suggest"):
            params = ["q"]
    return Candidate(url=normalized, source=source, parameters=_to_tuples(params))


def _dedupe(candidates: Iterable[Candidate]) -> List[Candidate]:
    unique: Dict[str, Candidate] = {}
    for candidate in candidates:
        if not candidate.url:
            continue
        existing = unique.get(candidate.url)
        if existing is None or (candidate.parameters and not existing.parameters):
            unique[candidate.url] = candidate
    return list(unique.values())


def endpoint_candidates_from_js_text(js_text: str, base_url: str = "") -> List[Candidate]:
    """Extract endpoint candidates from JS bundle or inline script text.

    ``base_url`` should be the app's base URL (e.g. the page that loaded the
    bundle) so cross-origin relative-looking paths and API hosts resolve against
    it; absolute URLs that do not match its host are dropped by
    ``_candidate_from_url``.
    """
    if not js_text:
        return []
    base = base_url or "http://example.invalid/"
    out: List[Candidate] = []
    for match in _ABS_URL_RE.finditer(js_text):
        cand = _candidate_from_url(match.group(1), base, "js_bundle_url")
        if cand:
            out.append(cand)
    for match in _REL_PATH_RE.finditer(js_text):
        cand = _candidate_from_url(match.group(1), base, "js_bundle")
        if cand:
            out.append(cand)
    for match in _FETCH_ROUTE_RE.finditer(js_text):
        cand = _candidate_from_url(match.group(1), base, "js_fetch")
        if cand:
            out.append(cand)
    for match in _TEMPLATE_API_RE.finditer(js_text):
        cand = _candidate_from_url(match.group(1), base, "js_template_api")
        if cand:
            out.append(cand)
    return _dedupe(out)


def endpoint_candidates_from_html(html_text: str, base_url: str) -> List[Candidate]:
    """Harvest candidates from inline <script> bodies and <script src/> tags."""
    if not html_text or not base_url:
        return []
    out: List[Candidate] = []
    for match in _INLINE_SCRIPT_RE.finditer(html_text):
        out.extend(endpoint_candidates_from_js_text(match.group(1), base_url=base_url))
    out = [Candidate(c.url, "html_inline" if c.source != "js_bundle_url" else c.source, c.parameters) for c in out]
    for match in _SCRIPT_SRC_RE.finditer(html_text):
        cand = _candidate_from_url(match.group(1), base_url, "script_src")
        if cand:
            out.append(cand)
    return _dedupe(out)


def merge_candidates(*groups: Iterable[Candidate]) -> List[MergedCandidate]:
    """Group by normalized endpoint shape (template), merging params and source evidence.

    Prevents `/user/42?q=x` and `/user/77?q=y` from drowning the pool with
    duplicates while keeping `/rest/products/search?q=...` distinct from
    `/rest/products/search?productId=...` since each maps to a different
    parameter contract.
    """
    merged: Dict[str, MergedCandidate] = {}
    for group in groups:
        for candidate in group:
            if not candidate.url:
                continue
            template = endpoint_template(candidate.url)
            params_key = "&".join(sorted(candidate.parameters))
            key = f"{template}::{params_key}"
            existing = merged.get(key)
            if existing is None:
                merged[key] = MergedCandidate(
                    url=candidate.url,
                    source=candidate.source,
                    sources=(candidate.source,),
                    parameters=candidate.parameters,
                )
                continue
            merged[key] = MergedCandidate(
                url=existing.url,
                source="{merged}",
                sources=tuple(sorted(set(existing.sources).union({candidate.source}))),
                parameters=tuple(sorted(set(existing.parameters).union(candidate.parameters))),
            )
    return list(merged.values())


async def harvest_spa_endpoints(
    target_url: str,
    *,
    client: Any,
    graph: Any,
    engagement_id: str,
    cfg: Optional[SpaHarvestConfig] = None,
) -> HarvestResult:
    """Fetch target HTML and referenced JS to harvest and persist real endpoints."""
    cfg = cfg or SpaHarvestConfig()
    result = HarvestResult()

    def _is_js_url(u: str) -> bool:
        lu = (u or "").lower()
        return lu.endswith(".js") or ".js?" in lu or ".js#" in lu

    try:
        landing = await client.get(target_url)
    except Exception:  # noqa: BLE001
        return result

    landing_candidates = endpoint_candidates_from_html(getattr(landing, "text", "") or "", base_url=target_url)
    bundle_urls = [c.url for c in landing_candidates if _is_js_url(c.url)]
    direct_candidates = [c for c in landing_candidates if not _is_js_url(c.url)]
    result.candidates_found += len(direct_candidates)

    all_groups: List[List[Candidate]] = [direct_candidates]

    for bundle in bundle_urls[: cfg.max_bundle_fetches]:
        try:
            resp = await client.get(bundle)
        except Exception:  # noqa: BLE001
            continue
        text = getattr(resp, "text", "") or ""
        if not text:
            continue
        result.js_files_seen += 1
        js_candidates = endpoint_candidates_from_js_text(text, base_url=target_url)
        js_candidates = [c for c in js_candidates if not _is_js_url(c.url)]
        js_extra_count = len(js_candidates)
        js_extra_count += 0
        all_groups.append(js_candidates)

    merged = merge_candidates(*all_groups)
    result.candidates_found = len(merged)
    for candidate in merged[: cfg.js_route_limit]:
        params = list(candidate.parameters)
        ep = Endpoint(
            url=candidate.url,
            source="spa_harvest",
            engagement_id=engagement_id,
            parameters=params,
            query_keys=params,
            confidence=0.9,
            metadata={
                "harvest_source": candidate.sources,
                "tags": classify_url(candidate.url),
                "template": endpoint_template(candidate.url),
            },
        )
        maybe = graph.add_endpoint(ep)
        if hasattr(maybe, "__await__"):
            await maybe
        result.endpoints_persisted += 1
    return result
