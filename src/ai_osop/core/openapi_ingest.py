"""OpenAPI / Swagger ingestion (P1.3 recon multiplier).

An exposed API spec is the single richest recon artifact a target can leak: it
enumerates every endpoint, method, parameter, and request body — often including
internal/admin routes never linked from the UI. This module turns a spec (OpenAPI
3.x or Swagger 2.0) into a list of endpoint descriptors the recon agent can push
into the graph as first-class attack surface.

The parser (``parse_spec``) is pure and testable. ``SPEC_CANDIDATES`` lists the
conventional locations a spec is served from; the recon agent fetches these
(scope-gated) and feeds whatever it finds here.
"""
from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urljoin, urlsplit

# Conventional locations an API spec is exposed at (checked in order).
SPEC_CANDIDATES: List[str] = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/openapi.json",
    "/api/swagger.json", "/api/v1/openapi.json", "/docs/openapi.json",
]

_METHODS = ("get", "post", "put", "delete", "patch", "options", "head", "trace")


def is_spec(doc: Any) -> bool:
    """Heuristic: does *doc* look like an OpenAPI/Swagger document?"""
    return isinstance(doc, dict) and (
        "openapi" in doc or "swagger" in doc
    ) and isinstance(doc.get("paths"), dict)


def _schema_property_keys(schema: Any) -> List[str]:
    """Collect top-level property names from a JSON-schema-ish object."""
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if isinstance(props, dict):
        return sorted(props.keys())
    return []


def _body_keys(operation: Dict[str, Any]) -> List[str]:
    """Extract request-body field names for OpenAPI 3 (requestBody.content.*.schema)
    and Swagger 2 (a parameter with in=body carrying a schema)."""
    keys: List[str] = []
    rb = operation.get("requestBody")
    if isinstance(rb, dict):
        content = rb.get("content", {})
        if isinstance(content, dict):
            for media in content.values():
                if isinstance(media, dict):
                    keys.extend(_schema_property_keys(media.get("schema")))
    for p in operation.get("parameters", []) or []:
        if isinstance(p, dict) and p.get("in") == "body":
            keys.extend(_schema_property_keys(p.get("schema")))
    return sorted(set(keys))


def _base_url(spec: Dict[str, Any], base_url: str) -> str:
    """Resolve the server base URL: caller override > OpenAPI3 servers[0] >
    Swagger2 host+basePath > empty."""
    if base_url:
        return base_url.rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = servers[0].get("url", "")
        if u:
            return u.rstrip("/")
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = spec.get("basePath", "") or ""
        return f"{scheme}://{host}{base_path}".rstrip("/")
    return ""


def parse_spec(spec: Dict[str, Any], base_url: str = "") -> List[Dict[str, Any]]:
    """Parse an OpenAPI 3.x / Swagger 2.0 document into endpoint descriptors.

    Each descriptor: {url, method, path, parameters, body_keys, operation_id,
    summary}. ``parameters`` merges path-level and operation-level query/path/header
    parameter names; ``body_keys`` are request-body field names.
    """
    endpoints: List[Dict[str, Any]] = []
    if not isinstance(spec, dict):
        return endpoints
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return endpoints
    base = _base_url(spec, base_url)

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = [p for p in item.get("parameters", []) or [] if isinstance(p, dict)]
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            names: List[str] = []
            for p in shared_params + [q for q in op.get("parameters", []) or [] if isinstance(q, dict)]:
                nm = p.get("name")
                if nm and p.get("in") in (None, "query", "path", "header", "cookie"):
                    names.append(nm)
            url = urljoin(base + "/", path.lstrip("/")) if base else path
            endpoints.append({
                "url": url,
                "method": method.upper(),
                "path": path,
                "parameters": sorted(set(names)),
                "body_keys": _body_keys(op),
                "operation_id": op.get("operationId", ""),
                "summary": op.get("summary", ""),
            })
    return endpoints


def spec_candidate_urls(target: str) -> List[str]:
    """Return absolute candidate spec URLs for a target base (scheme+host)."""
    parts = urlsplit(target if "://" in target else f"http://{target}")
    origin = f"{parts.scheme}://{parts.netloc}"
    return [origin + c for c in SPEC_CANDIDATES]
