"""Regression tests for the CRLF, CORS, and reflected-XSS deterministic oracles.

Same honesty contract as the existing injection oracles: each detector must
FIRE on a genuinely vulnerable target (objective in-band signal) and must NOT
fire on a hardened / benign one — no speculative assertions. The apps below are
real ASGI targets driven through httpx, so the tests exercise the exact oracle
code path (not a reimplementation).
"""

import httpx
import pytest

from ai_osop.core.injection_oracles import (
    _CORS_SENTINEL_ORIGIN,
    _CRLF_HEADER,
    detect_cors_misconfig,
    detect_crlf_injection,
    detect_reflected_xss,
)


def _client(app, base):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base)


async def _read_body(receive):
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    return body


# --- CRLF / HTTP response splitting (CWE-113) --------------------------------


def _qs(scope):
    from urllib.parse import parse_qs

    return parse_qs(scope.get("query_string", b"").decode())


async def _crlf_vulnerable_app(scope, receive, send):
    """Splits the `next` param into response headers (no CRLF sanitisation).

    A real vulnerable server writes the raw value into the header block; here we
    emulate that by parsing an embedded ``header: value`` out of the param and
    emitting it as a genuine response header — exactly what an attacker's CRLF
    payload achieves in the wild.
    """
    import re
    from urllib.parse import unquote

    raw = unquote((_qs(scope).get("next") or [""])[0])
    headers = [(b"content-type", b"text/plain")]
    # Anything after a CR/LF becomes injected header(s).
    m = re.search(r"[\r\n]+([\w-]+):\s*(.*)$", raw)
    if m:
        headers.append((m.group(1).lower().encode(), m.group(2).encode()))
    await send({"type": "http.response.start", "status": 302, "headers": headers})
    await send({"type": "http.response.body", "body": b""})


async def _crlf_hardened_app(scope, receive, send):
    """Strips CR/LF from the value before it ever reaches the header block."""
    from urllib.parse import unquote

    raw = unquote((_qs(scope).get("next") or [""])[0]).replace("\r", "").replace("\n", "")
    await send(
        {
            "type": "http.response.start",
            "status": 302,
            "headers": [(b"location", ("/" + raw[:20]).encode())],
        }
    )
    await send({"type": "http.response.body", "body": b""})


@pytest.mark.asyncio
async def test_crlf_fires_on_header_splitting_endpoint():
    async with _client(_crlf_vulnerable_app, "http://vuln.test") as c:
        ev = await detect_crlf_injection(c, "http://vuln.test/go?next=x", params=["next"])
    assert ev is not None
    assert ev["technique"] == "crlf_injection"
    assert _CRLF_HEADER in ev["injected_header"].lower()
    assert ev["confidence"] == 1.0


@pytest.mark.asyncio
async def test_crlf_no_fp_on_sanitising_endpoint():
    async with _client(_crlf_hardened_app, "http://safe.test") as c:
        ev = await detect_crlf_injection(c, "http://safe.test/go?next=x", params=["next"])
    assert ev is None


@pytest.mark.asyncio
async def test_crlf_returns_none_without_params():
    async with _client(_crlf_vulnerable_app, "http://vuln.test") as c:
        ev = await detect_crlf_injection(c, "http://vuln.test/go", params=[])
    assert ev is None


# --- CORS misconfiguration (CWE-942) ----------------------------------------


async def _cors_reflect_creds_app(scope, receive, send):
    """Reflects ANY Origin into ACAO and allows credentials — exploitable."""
    origin = b""
    for k, v in scope.get("headers", []):
        if k == b"origin":
            origin = v
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"access-control-allow-origin", origin),
                (b"access-control-allow-credentials", b"true"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": b"{}"})


async def _cors_wildcard_app(scope, receive, send):
    """Public API: `*` with NO credentials — the intended pattern, not a vuln."""
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"access-control-allow-origin", b"*"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": b"{}"})


async def _cors_reflect_no_creds_app(scope, receive, send):
    """Reflects Origin but WITHOUT credentials — not credential-exfil exploitable."""
    origin = b""
    for k, v in scope.get("headers", []):
        if k == b"origin":
            origin = v
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"access-control-allow-origin", origin),
            ],
        }
    )
    await send({"type": "http.response.body", "body": b"{}"})


@pytest.mark.asyncio
async def test_cors_fires_on_reflect_with_credentials():
    async with _client(_cors_reflect_creds_app, "http://vuln.test") as c:
        ev = await detect_cors_misconfig(c, "http://vuln.test/api/me")
    assert ev is not None
    assert ev["technique"] == "cors_misconfig"
    assert ev["acao"] == _CORS_SENTINEL_ORIGIN
    assert ev["acac"] == "true"


@pytest.mark.asyncio
async def test_cors_no_fp_on_wildcard_public_api():
    async with _client(_cors_wildcard_app, "http://safe.test") as c:
        ev = await detect_cors_misconfig(c, "http://safe.test/api/public")
    assert ev is None


@pytest.mark.asyncio
async def test_cors_no_fp_on_reflect_without_credentials():
    async with _client(_cors_reflect_no_creds_app, "http://safe2.test") as c:
        ev = await detect_cors_misconfig(c, "http://safe2.test/api/thing")
    assert ev is None


# --- Reflected XSS (CWE-79) --------------------------------------------------


async def _xss_unencoded_app(scope, receive, send):
    """Writes the `q` param straight into an HTML body — unencoded reflection."""
    from urllib.parse import unquote

    q = unquote((_qs(scope).get("q") or [""])[0])
    html = f"<html><body>Results for: {q}</body></html>".encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/html; charset=utf-8")],
        }
    )
    await send({"type": "http.response.body", "body": html})


async def _xss_encoded_app(scope, receive, send):
    """HTML-encodes the reflected value — safe, must NOT fire."""
    from html import escape
    from urllib.parse import unquote

    q = escape(unquote((_qs(scope).get("q") or [""])[0]))
    html = f"<html><body>Results for: {q}</body></html>".encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/html; charset=utf-8")],
        }
    )
    await send({"type": "http.response.body", "body": html})


async def _xss_json_app(scope, receive, send):
    """Reflects verbatim but as application/json — not an HTML sink, must NOT fire."""
    from urllib.parse import unquote

    q = unquote((_qs(scope).get("q") or [""])[0])
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": f'{{"q":"{q}"}}'.encode()})


@pytest.mark.asyncio
async def test_reflected_xss_fires_on_unencoded_html_reflection():
    async with _client(_xss_unencoded_app, "http://vuln.test") as c:
        ev = await detect_reflected_xss(c, "http://vuln.test/search?q=x", params=["q"])
    assert ev is not None
    assert ev["technique"] == "reflected_xss"
    assert ev["confidence"] == 1.0


@pytest.mark.asyncio
async def test_reflected_xss_no_fp_when_html_encoded():
    async with _client(_xss_encoded_app, "http://safe.test") as c:
        ev = await detect_reflected_xss(c, "http://safe.test/search?q=x", params=["q"])
    assert ev is None


@pytest.mark.asyncio
async def test_reflected_xss_no_fp_on_json_reflection():
    async with _client(_xss_json_app, "http://safe2.test") as c:
        ev = await detect_reflected_xss(c, "http://safe2.test/search?q=x", params=["q"])
    assert ev is None


# --- End-to-end wiring: run_generalized_injection surfaces the new findings ---
#
# Prove the new oracles are actually reached by the generalized scan and their
# evidence is minted into a Vulnerability with the correct taxonomy — not just
# that the oracle functions work in isolation.

from types import SimpleNamespace

import pytest as _pytest

from ai_osop.core import deterministic_scan as ds
from ai_osop.core import injection_oracles as io
from ai_osop.core.config import VulnClass


class _FakeDriver:
    def __init__(self, endpoints):
        self._endpoints = endpoints

    def session(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def run(self, q, **kw):
        return self

    async def __aiter__(self):
        for ep in self._endpoints:
            yield ep


def _graph(endpoints):
    captured = []
    gm = SimpleNamespace()
    gm._driver = _FakeDriver(endpoints)

    async def _add(v):
        captured.append(v)

    gm.add_vulnerability = _add
    gm.captured = captured
    return gm


async def _none(*a, **k):
    return None


@_pytest.mark.asyncio
async def test_generalized_injection_mints_crlf_cors_xss(monkeypatch):
    # Silence the network-touching oracles we are not exercising here.
    for name in (
        "detect_path_traversal",
        "detect_open_redirect",
        "detect_ssrf_reflected",
        "detect_xxe",
    ):
        monkeypatch.setattr(io, name, _none)

    async def crlf(c, url, *, params=None):
        return {
            "technique": "crlf_injection",
            "endpoint": url,
            "parameter": "next",
            "payload": "%0d%0ax",
            "proof": "p",
            "confidence": 1.0,
        }

    async def xss(c, url, *, params=None):
        return {
            "technique": "reflected_xss",
            "endpoint": url,
            "parameter": "q",
            "payload": "<x>",
            "proof": "p",
            "confidence": 1.0,
        }

    async def cors(c, url, **k):
        return {
            "technique": "cors_misconfig",
            "endpoint": url,
            "parameter": "Origin",
            "payload": "Origin: e",
            "acao": "e",
            "acac": "true",
            "proof": "p",
            "confidence": 1.0,
        }

    monkeypatch.setattr(io, "detect_crlf_injection", crlf)
    monkeypatch.setattr(io, "detect_reflected_xss", xss)
    monkeypatch.setattr(io, "detect_cors_misconfig", cors)

    async def _no_redir(c, base):
        return []

    monkeypatch.setattr(ds, "_harvest_redirectors", _no_redir)

    eps = [{"url": "http://t/search", "method": "GET", "path": "/search", "query_keys": ["q"]}]
    gm = _graph(eps)

    persisted, examined = await ds.run_generalized_injection("eng1", gm, per_check_timeout=5.0)

    by_class = {v.vuln_type for v in persisted}
    assert VulnClass.CRLF in by_class
    assert VulnClass.XSS in by_class
    assert VulnClass.CORS_MISCONFIG in by_class
    cwes = {v.cwe for v in persisted}
    assert {"CWE-113", "CWE-79", "CWE-942"} <= cwes
