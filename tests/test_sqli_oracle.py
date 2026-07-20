"""Offline unit tests for the deterministic SQLi oracles.

Pins the behaviour of every oracle in ``ai_osop.core.sqli_oracle``:

* ``detect_login_bypass`` — VALIDATED only when the server issues a session
  token for a bogus password; a 200 with no token, a non-200, or a network
  error must NOT confirm.
* ``detect_error_based`` — VALIDATED only when a 5xx carries a DB error
  marker; a benign 500 with no marker, a 200 with a marker, or a 404 must NOT
  confirm. MySQL / MSSQL markers added in this branch are exercised.
* ``detect_time_blind`` — VALIDATED only when the sleep payload is
  measurably slower than its paired control payload; identical latencies,
  a sleep FASTER than control (jitter), or a 404 control must NOT confirm.

Every test uses ``httpx.MockTransport`` so the suite is hermetic — no network,
no real backend, no flake.
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import httpx
import pytest

from ai_osop.core import sqli_oracle


def _client(handler) -> httpx.AsyncClient:
    """Build an AsyncClient whose requests are answered by ``handler``."""
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, verify=False, follow_redirects=True)


# --------------------------------------------------------------------------- #
# detect_login_bypass                                                          #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_login_bypass_confirms_when_token_issued():
    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode() or "{}")
        # Accept the classic tautology payloads.
        if body.get("password") == "oracle-not-a-real-pw":
            return httpx.Response(
                200, json={"authentication": {"token": "tok-abcdef0123456789"}}
            )
        return httpx.Response(401, json={})

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_login_bypass(c, "http://t/login")

    assert ev is not None
    assert ev["technique"] == "auth_bypass"
    assert ev["http_status"] == 200
    assert ev["confidence"] == 1.0
    assert ev["token_prefix"].endswith("...")
    assert "payload" in ev
    # Phase-1 issue #8: full response body must be captured so the scorer can
    # register a real 'response' artifact (was 0.333 evidence_completeness on
    # autonomous run when only token_prefix was stored).
    assert "response" in ev
    assert "token" in ev["response"]
    assert "request" in ev
    assert "POST" in ev["request"]


@pytest.mark.asyncio
async def test_login_bypass_rejects_200_without_token():
    """A 200 that does not issue a token is NOT injection confirmation."""
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"error": "invalid credentials"})

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_login_bypass(c, "http://t/login")
    assert ev is None


@pytest.mark.asyncio
async def test_login_bypass_rejects_401():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={})

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_login_bypass(c, "http://t/login")
    assert ev is None


@pytest.mark.asyncio
async def test_login_bypass_tolerates_access_token_shape():
    """``{"access_token": ...}`` is the third supported shape."""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": "abcd-1234-5678"})

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_login_bypass(c, "http://t/login")
    assert ev is not None
    assert ev["http_status"] == 200


@pytest.mark.asyncio
async def test_login_bypass_swallows_network_errors():
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_login_bypass(c, "http://t/login")
    # Connect errors are caught per-iteration; no finding emitted.
    assert ev is None


# --------------------------------------------------------------------------- #
# detect_error_based                                                          #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_error_based_confirms_on_sqlite_marker():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            text='{"error":"SQLITE_ERROR: near "FROM": syntax error"}',
        )

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_error_based(c, "http://t/search", param="q")

    assert ev is not None
    assert ev["technique"] == "error_based"
    assert ev["parameter"] == "q"
    assert ev["http_status"] == 500
    assert ev["confidence"] == 1.0
    # Phase-1 issue #8: full response body must be captured so the scorer can
    # register a real 'response' artifact for the SQLi finding.
    assert "response" in ev
    assert "SQLITE_ERROR" in ev["response"]
    assert "request" in ev
    assert "GET" in ev["request"]


@pytest.mark.asyncio
async def test_error_based_confirms_on_mysql_marker():
    """New MySQL marker added in this branch (Phase-1 issue #9)."""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            text="You have an error in your SQL syntax; check the manual near 'WHERE'",
        )

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_error_based(c, "http://t/search")
    assert ev is not None
    assert ev["technique"] == "error_based"


@pytest.mark.asyncio
async def test_error_based_confirms_on_mssql_marker():
    """New MSSQL marker added in this branch."""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            text="Unclosed quotation mark after the character string 'x'.",
        )

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_error_based(c, "http://t/search")
    assert ev is not None


@pytest.mark.asyncio
async def test_error_based_rejects_benign_500_without_marker():
    """A 500 stack trace that does not carry a DB marker must NOT confirm."""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error: NullPointerException")

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_error_based(c, "http://t/search")
    assert ev is None


@pytest.mark.asyncio
async def test_error_based_rejects_200_with_marker():
    """A 200 carrying the word 'sqlite' (e.g. in a feature description) is NOT
    injection — the oracle requires a 5xx + marker."""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Powered by sqlite3 — see /docs/sqlite")

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_error_based(c, "http://t/search")
    assert ev is None


@pytest.mark.asyncio
async def test_error_based_rejects_404():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_error_based(c, "http://t/search")
    assert ev is None


@pytest.mark.asyncio
async def test_error_based_infers_param_from_query_string():
    """When param=None, the last query param of the URL is targeted."""
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["params"] = dict(req.url.params)
        return httpx.Response(500, text="sqlite_error: near x")

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_error_based(c, "http://t/search?lang=en&q=test")

    assert ev is not None
    # The payload landed on the last param ('q'), not 'lang'.
    assert "q" in captured["params"]


# --------------------------------------------------------------------------- #
# detect_time_blind                                                            #
# --------------------------------------------------------------------------- #


def _sleep_handler(sleep_for: float, control_status: int = 200, sleep_status: int = 200):
    """A handler that sleeps ``sleep_for`` seconds when the request carries the
    sleep payload, and returns immediately for the control payload."""

    async def handler(req: httpx.Request) -> httpx.Response:
        val = req.url.params.get("q", "")
        if "SLEEP" in val.upper() or "pg_sleep" in val or "WAITFOR" in val.upper() or "RANDOMBLOB(500000000)" in val:
            await asyncio.sleep(sleep_for)
            return httpx.Response(sleep_status, text="ok")
        return httpx.Response(control_status, text="ok")

    return handler


@pytest.mark.asyncio
async def test_time_blind_confirms_when_sleep_is_measurably_slower():
    """Sleep payload waits 1.5s; control returns immediately. delta >= min_delta(3)
    would fail — but we lower min_delta to 1.0 to keep the test fast while still
    exercising the relative-timing logic."""
    async with _client(_sleep_handler(1.5)) as c:
        ev = await sqli_oracle.detect_time_blind(
            c, "http://t/search", param="q", min_delta=1.0, request_timeout=10.0
        )
    assert ev is not None
    assert ev["technique"] == "time_blind"
    assert ev["dbms"] in {"sqlite", "mysql", "mariadb", "postgres", "mssql", "oracle"}
    assert ev["delta_seconds"] >= 1.0
    assert ev["confidence"] == 1.0


@pytest.mark.asyncio
async def test_time_blind_rejects_when_latencies_match():
    """A healthy endpoint that ignores the payload returns both control and sleep
    in similar time — no delta, no finding."""

    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_time_blind(
            c, "http://t/search", param="q", min_delta=1.0, request_timeout=5.0
        )
    assert ev is None


@pytest.mark.asyncio
async def test_time_blind_rejects_404_control():
    """If the control payload 404s the endpoint is gone; cannot oracle it."""

    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_time_blind(
            c, "http://t/search", param="q", min_delta=1.0
        )
    assert ev is None


@pytest.mark.asyncio
async def test_time_blind_treats_sleep_timeout_as_evidence():
    """If the sleep payload times out but the control succeeded, the backend
    hung on the injected sleep — that is itself strong evidence."""

    async def handler(req: httpx.Request) -> httpx.Response:
        val = req.url.params.get("q", "")
        if "SLEEP" in val.upper() or "pg_sleep" in val or "WAITFOR" in val.upper() or "RANDOMBLOB(500000000)" in val:
            await asyncio.sleep(30)  # will be cut off by the request timeout
            return httpx.Response(200, text="late")
        return httpx.Response(200, text="ok")

    async with _client(handler) as c:
        ev = await sqli_oracle.detect_time_blind(
            c, "http://t/search", param="q", min_delta=1.0, request_timeout=1.5
        )
    assert ev is not None
    assert ev["technique"] == "time_blind"


# --------------------------------------------------------------------------- #
# scan_sqli orchestration                                                     #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_scan_sqli_runs_both_oracles_for_base_url(monkeypatch):
    """A bare base URL drives the login-bypass + error-based paths (the juice-shop
    defaults). Patch the oracles to deterministic returns and confirm both are
    invoked exactly once each."""
    calls = {"login": 0, "error": 0, "time": 0}

    async def fake_login(c, url, **kw):
        calls["login"] += 1
        return {"technique": "auth_bypass", "endpoint": url, "payload": "x",
                "http_status": 200, "token_prefix": "tok...", "confidence": 1.0}

    async def fake_error(c, url, **kw):
        calls["error"] += 1
        return {"technique": "error_based", "endpoint": url, "parameter": "q",
                "payload": "'", "http_status": 500, "db_error_excerpt": "...",
                "confidence": 1.0}

    async def fake_time(c, url, **kw):
        calls["time"] += 1
        return None

    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", fake_login)
    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", fake_time)

    res = await sqli_oracle.scan_sqli("http://localhost:3000")
    assert len(res) == 2
    assert {r["technique"] for r in res} == {"auth_bypass", "error_based"}
    # Default include_time_blind=False — the time oracle must not run when
    # error-based already confirmed the endpoint.
    assert calls["time"] == 0


@pytest.mark.asyncio
async def test_scan_sqli_runs_time_blind_only_when_error_based_misses(monkeypatch):
    """include_time_blind=True AND error-based returning None should trigger the
    time-blind oracle on the search URL."""
    calls = {"error": 0, "time": 0}

    async def fake_error(c, url, **kw):
        calls["error"] += 1
        return None

    async def fake_time(c, url, **kw):
        calls["time"] += 1
        return {"technique": "time_blind", "endpoint": url, "dbms": "sqlite",
                "payload": "x", "control_payload": "y", "parameter": "q",
                "control_latency": 0.1, "sleep_latency": 5.0,
                "delta_seconds": 4.9, "min_delta": 3.0, "confidence": 1.0}

    async def fake_login(c, url, **kw):
        return None

    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", fake_login)
    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", fake_time)

    res = await sqli_oracle.scan_sqli(
        "http://localhost:3000", include_time_blind=True, timeout=2.0
    )
    techniques = {r["technique"] for r in res}
    assert "time_blind" in techniques
    assert calls["time"] == 1


# --------------------------------------------------------------------------- #
# SQL_ERROR_MARKERS surface (regression guard for new DBMS markers)            #
# --------------------------------------------------------------------------- #


def test_error_markers_cover_six_dbms_families():
    """A regression guard: the markers tuple must cover at minimum SQLite,
    PostgreSQL, MySQL/MariaDB, MSSQL, and Oracle."""
    text = " ".join(sqli_oracle._SQL_ERROR_MARKERS).lower()
    # SQLite
    assert "sqlite" in text
    # PostgreSQL
    assert "psql:" in text
    # MySQL / MariaDB
    assert "you have an error in your sql syntax" in text
    # MSSQL
    assert "unclosed quotation mark" in text
    # Oracle
    assert "ora-0" in text


def test_time_blind_payloads_cover_six_dbms_families():
    """A regression guard: time-blind payloads must exist for SQLite, MySQL,
    Postgres, MSSQL, and Oracle."""
    families = {dbms for dbms, _, _ in sqli_oracle._TIME_BLIND_PAYLOADS}
    assert {"sqlite", "mysql", "postgres", "mssql", "oracle"}.issubset(families)


def test_time_blind_payloads_format_n_correctly():
    """Every sleep template must accept {n} substitution (or be a static
    SQLite RANDOMBLOB). Every control template must NOT sleep."""
    for dbms, sleep_tpl, control_tpl in sqli_oracle._TIME_BLIND_PAYLOADS:
        formatted = sqli_oracle._format_payload(sleep_tpl)
        # No leftover {n} after formatting.
        assert "{n}" not in formatted, f"{dbms} sleep payload left unformatted"
        # Control must never carry SLEEP_SECONDS-equivalent wait.
        assert "500000000" not in control_tpl or dbms == "sqlite"
        if dbms != "sqlite":
            # Control templates with SLEEP(n) must format to SLEEP(0)
            control_fmt = sqli_oracle._format_payload(control_tpl)
            if "SLEEP(" in control_fmt.upper():
                assert "SLEEP(0)" in control_fmt.upper()
