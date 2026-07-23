"""Parameter Miner — active hidden parameter discovery.

The assessment's Short-term Priority 3: a human researcher doesn't just
parse OpenAPI specs and HTML forms — they actively brute-force parameter
names against endpoints to find hidden inputs the documentation doesn't
mention. Tools like Arjun and Param Miner do this by sending parameter
guesses and observing response variations (content length, status code,
response time).

This module does the same: sends a dictionary of common parameter names
against a target endpoint and detects which ones the server accepts
(response changes from baseline). Accepted parameters are persisted as
endpoint metadata so the reasoning loop + scanners can target them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

# Common parameter names to brute-force. Grouped by category so the miner
# can prioritize high-value parameters first.
_PARAM_WORDLIST = [
    # High-value admin/debug params
    "admin", "debug", "test", "dev", "internal", "secret", "key", "token",
    "api_key", "apikey", "auth", "authentication", "authorization",
    # Injection-relevant params
    "url", "redirect", "redirect_url", "redirect_uri", "return_url", "returnUrl",
    "next", "callback", "webhook", "target", "dest", "destination", "to",
    "file", "filename", "path", "filepath", "page", "include", "require",
    "template", "render", "view", "document", "doc", "load",
    # SQL/DB params
    "id", "uid", "user_id", "userid", "account", "account_id", "order",
    "order_id", "query", "search", "filter", "sort", "column", "table",
    # Business logic params
    "role", "isAdmin", "is_admin", "admin_role", "role_id", "permission",
    "permissions", "privilege", "user_type", "account_type", "tier", "level",
    "price", "amount", "quantity", "total", "discount", "coupon", "voucher",
    "currency", "payment", "checkout", "cart", "order_total",
    # Tech-specific params
    "cmd", "command", "exec", "execute", "run", "action", "method",
    "format", "output", "type", "mode", "env", "config", "setting",
    "version", "branch", "ref", "commit", "sha", "tag",
    # IDOR/object params
    "user", "username", "email", "mail", "phone", "address", "name",
    "profile", "account_id", "customer_id", "tenant_id", "org_id",
    "resource", "resource_id", "object", "object_id", "item", "item_id",
    # SSRF params
    "proxy", "fetch", "retrieve", "source", "src", "href", "link",
    "image", "img", "avatar", "logo", "icon", "media", "upload",
    # Format/content params
    "json", "xml", "data", "payload", "body", "content", "raw",
    "accept", "content_type", "contentType", "mimetype",
]


@dataclass
class ParamMinerResult:
    """Result of mining an endpoint for hidden parameters."""
    target_url: str
    method: str
    baseline_status: int = 0
    baseline_length: int = 0
    discovered_params: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


async def mine_parameters(
    client: httpx.AsyncClient,
    target_url: str,
    method: str = "GET",
    existing_params: Optional[List[str]] = None,
    timeout: float = 8.0,
    max_params: int = 80,
) -> ParamMinerResult:
    """Actively probe an endpoint for hidden parameters.

    Sends a baseline request (no extra params), then sends each parameter
    name from the wordlist as a query parameter (for GET) or form field (for
    POST). Detects which parameters the server accepts by observing:

      1. Status code change (e.g. 200 → 400 = param rejected, 200 → 200 = accepted)
      2. Body length change (>10% = parameter likely processed)
      3. Response content change (error message mentioning the param name)

    Args:
        client: governed httpx client
        target_url: the endpoint to probe
        method: HTTP method (GET or POST)
        existing_params: params already discovered (skip to save requests)
        timeout: per-request timeout
        max_params: max parameters to probe (caps total requests)

    Returns:
        ParamMinerResult with the discovered parameter names.
    """
    result = ParamMinerResult(target_url=target_url, method=method)
    existing = set(existing_params or [])

    # 1. Baseline: send with a benign value to establish normal response
    try:
        if method.upper() == "GET":
            base_resp = await client.get(target_url, params={"_osop_baseline": "1"}, timeout=timeout)
        else:
            base_resp = await client.request(method, target_url, data={"_osop_baseline": "1"}, timeout=timeout)
        result.baseline_status = base_resp.status_code
        result.baseline_length = len(base_resp.text)
    except Exception:
        return result

    # 2. Probe each parameter name
    probed = 0
    for param in _PARAM_WORDLIST:
        if param in existing:
            continue
        if probed >= max_params:
            break
        probed += 1

        try:
            if method.upper() == "GET":
                resp = await client.get(target_url, params={param: "osop_probe"}, timeout=timeout)
            else:
                resp = await client.request(method, target_url, data={param: "osop_probe"}, timeout=timeout)
        except Exception:
            continue

        # Detection signals:
        detected = False

        # Signal 1: status code changed from baseline (and not to 404)
        if resp.status_code != result.baseline_status and resp.status_code != 404:
            # A status change (e.g. 200→400, 200→500) often means the param
            # was accepted but the value caused an error — the param EXISTS.
            if resp.status_code >= 400:
                detected = True

        # Signal 2: body length changed significantly (>10%)
        if result.baseline_length > 0:
            ratio = len(resp.text) / result.baseline_length
            if ratio < 0.9 or ratio > 1.1:
                detected = True

        # Signal 3: response body mentions the parameter name (reflected)
        if param.lower() in resp.text[:5000].lower():
            # But only if it's NOT in the baseline (avoid false positives
            # from the parameter name appearing in a nav link, etc.)
            if param.lower() not in base_resp.text[:5000].lower():
                detected = True

        if detected:
            result.discovered_params.append(param)

    result.evidence = {
        "baseline_status": result.baseline_status,
        "baseline_length": result.baseline_length,
        "params_probed": probed,
        "params_discovered": len(result.discovered_params),
        "discovered": result.discovered_params,
    }

    return result
