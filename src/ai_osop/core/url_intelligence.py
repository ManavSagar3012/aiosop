"""URL intelligence (P1 recon multiplier).

Raw historical/crawled URLs (Wayback CDX, active crawl, JS mining, logs) are a
firehose of low-signal strings. Their *value* to a bug-bounty hunter is the
attack surface hidden inside them: parameters, deduplicated endpoint templates,
and files/paths that shouldn't be public. This module turns that firehose into
structured, targetable intelligence.

Pure functions — no network, no I/O — so they are trivially testable and safe to
call anywhere in the recon pipeline.

Key ideas
---------
* ``extract_params`` pulls query-string keys — hidden-parameter discovery.
* ``endpoint_template`` collapses id-like path segments (``/user/123`` ->
  ``/user/{id}``) so 10k historical URLs dedupe to a handful of real endpoints.
* ``INTERESTING_PARAMS`` maps a parameter name to the bug class it most often
  enables, so the vuln agents can prioritise ``?redirect=`` (open-redirect/SSRF)
  or ``?file=`` (LFI) instead of fuzzing everything blindly.
* ``mine_urls`` aggregates a URL set into a compact report.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set, Tuple
from urllib.parse import parse_qsl, urlsplit
from html.parser import HTMLParser

# Parameter name -> the bug class it most commonly enables. Used to prioritise
# which discovered parameters the vuln/exploit agents should probe first.
INTERESTING_PARAMS: Dict[str, str] = {
    "redirect": "open_redirect", "redirect_uri": "open_redirect", "redir": "open_redirect",
    "return": "open_redirect", "returnurl": "open_redirect", "return_url": "open_redirect",
    "next": "open_redirect", "dest": "open_redirect", "destination": "open_redirect",
    "continue": "open_redirect", "url": "ssrf", "uri": "ssrf", "u": "ssrf",
    "link": "ssrf", "domain": "ssrf", "callback": "ssrf", "webhook": "ssrf",
    "file": "lfi", "filename": "lfi", "path": "path_traversal", "dir": "path_traversal",
    "folder": "path_traversal", "download": "lfi", "template": "ssti", "lang": "lfi",
    "include": "lfi", "page": "lfi", "cmd": "rce", "exec": "rce", "command": "rce",
    "id": "idor", "user": "idor", "user_id": "idor", "uid": "idor", "account": "idor",
    "order": "idor", "doc": "idor", "debug": "debug_exposure", "test": "debug_exposure",
    "admin": "authz", "role": "authz", "token": "secret_leak", "api_key": "secret_leak",
    "apikey": "secret_leak", "access_token": "secret_leak", "key": "secret_leak",
    "q": "injection", "s": "injection", "search": "injection", "query": "injection",
    "sort": "sqli", "filter": "sqli", "jsonp": "jsonp",
}

# File extensions that frequently indicate exposed backups/secrets/source.
INTERESTING_EXTS: Set[str] = {
    ".json", ".xml", ".bak", ".old", ".orig", ".sql", ".db", ".sqlite", ".config",
    ".conf", ".ini", ".env", ".log", ".yml", ".yaml", ".zip", ".tar", ".gz", ".rar",
    ".7z", ".git", ".swp", ".pem", ".key", ".p12", ".pfx", ".crt", ".cer",
    ".properties", ".tpl", ".inc", ".sh", ".ps1", ".dockerfile",
}

# Path fragments that point at management/introspection/exposed surface.
INTERESTING_PATHS: Tuple[str, ...] = (
    "/api/", "/api.", "/admin", "/debug", "/actuator", "/graphql", "/graphiql",
    "/.git", "/swagger", "/openapi", "/api-docs", "/internal", "/private",
    "/backup", "/.env", "/wp-json", "/console", "/metrics", "/phpinfo",
    "/.well-known", "/server-status", "/jolokia", "/.aws", "/config",
)

# A path segment is "id-like" if it is numeric, a long hex/uuid, or a hash.
_ID_SEG = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$")


def extract_params(url: str) -> List[str]:
    """Return the sorted unique query-parameter names present in *url*.
    
    Extracts:
    - Query-string parameters (e.g. ?id=123&name=abc)
    - Path parameters (e.g. /user/{id} or /product/123)
    """
    try:
        parts = urlsplit(url)
    except (ValueError, AttributeError):
        return []
    
    params = set()
    
    # Extract query-string parameters
    qs = parts.query
    params.update(k for k, _ in parse_qsl(qs, keep_blank_values=True))
    
    # Extract path parameters (including numeric IDs that look like parameters)
    path = parts.path.lower()
    segs = [s for s in path.split("/") if s]
    
    # Add common path parameter patterns: numeric IDs, UUIDs
    for seg in segs:
        # Numeric ID (e.g. 123, 456)
        if seg.isdigit():
            params.add("id")  # Generic ID parameter
        # UUID or long hex (e.g. 550e8400-e29b-41d4-a716-446655440000)
        elif len(seg) >= 8 and all(c in "0123456789abcdefABCDEF-" for c in seg):
            params.add("id")
        # Segment name matching common patterns
        elif any(seg.endswith(p) for p in ["id", "uuid", "hash", "key"]):
            params.add(seg)
    
    return sorted(params)


def extract_form_fields(html_content: str) -> List[str]:
    """Extract form field names from HTML content.
    
    Parses HTML and extracts all <input>, <textarea>, <select> field names.
    Returns sorted unique field names.
    """
    class FormFieldParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.fields = set()
            
        def handle_starttag(self, tag, attrs):
            attrs_dict = dict(attrs)
            if tag in ("input", "textarea", "select") and "name" in attrs_dict:
                self.fields.add(attrs_dict["name"])
    
    try:
        parser = FormFieldParser()
        parser.feed(html_content)
        return sorted(parser.fields)
    except Exception:
        return []


def endpoint_template(url: str) -> str:
    """Collapse an URL to a dedupe-friendly ``host/path`` template.

    Id-like segments become ``{id}`` so ``/user/123`` and ``/user/456`` map to the
    same endpoint. The scheme and query string are dropped (host is kept so two
    hosts don't merge)."""
    try:
        parts = urlsplit(url)
    except (ValueError, AttributeError):
        return url
    host = parts.netloc.lower()
    segs = [s for s in parts.path.split("/") if s != ""]
    norm = ["{id}" if _ID_SEG.match(s) else s.lower() for s in segs]
    path = "/" + "/".join(norm) if norm else "/"
    return f"{host}{path}"


def classify_url(url: str) -> List[str]:
    """Return signal tags for *url* (interesting extension/path/param classes)."""
    tags: Set[str] = set()
    try:
        parts = urlsplit(url)
    except (ValueError, AttributeError):
        return []
    path = parts.path.lower()
    dot = path.rfind(".")
    if dot != -1 and path[dot:] in INTERESTING_EXTS:
        tags.add("interesting_file")
    full = path + ("?" + parts.query if parts.query else "")
    for frag in INTERESTING_PATHS:
        if frag in full:
            tags.add("interesting_path")
            break
    for p in extract_params(url):
        cls = INTERESTING_PARAMS.get(p.lower())
        if cls:
            tags.add(f"param:{cls}")
    return sorted(tags)


@dataclass
class UrlIntel:
    """Aggregated intelligence over a set of URLs."""
    total_urls: int = 0
    unique_endpoints: List[str] = field(default_factory=list)
    param_frequency: Dict[str, int] = field(default_factory=dict)
    interesting_params: Dict[str, str] = field(default_factory=dict)  # name -> bug class
    interesting_files: List[str] = field(default_factory=list)
    interesting_paths: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "total_urls": self.total_urls,
            "unique_endpoints": self.unique_endpoints,
            "unique_endpoint_count": len(self.unique_endpoints),
            "param_frequency": self.param_frequency,
            "interesting_params": self.interesting_params,
            "interesting_files": self.interesting_files,
            "interesting_paths": self.interesting_paths,
        }


def mine_urls(urls: Iterable[str]) -> UrlIntel:
    """Aggregate a URL set into deduplicated endpoints + parameter intelligence."""
    intel = UrlIntel()
    endpoints: Set[str] = set()
    files: Set[str] = set()
    paths: Set[str] = set()
    seen = 0
    for url in urls:
        if not url or not isinstance(url, str):
            continue
        seen += 1
        endpoints.add(endpoint_template(url))
        for p in extract_params(url):
            intel.param_frequency[p] = intel.param_frequency.get(p, 0) + 1
            cls = INTERESTING_PARAMS.get(p.lower())
            if cls:
                intel.interesting_params[p] = cls
        for tag in classify_url(url):
            if tag == "interesting_file":
                files.add(url)
            elif tag == "interesting_path":
                paths.add(url)
    intel.total_urls = seen
    intel.unique_endpoints = sorted(endpoints)
    intel.interesting_files = sorted(files)
    intel.interesting_paths = sorted(paths)
    return intel
