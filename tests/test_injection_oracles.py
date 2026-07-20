"""Regression tests for the deterministic injection/redirection oracles.

Focus: the open-redirect allow-list-bypass path. The oracle must fire on a
redirector that reflects an attacker-controlled host into Location, and must NOT
fire on a hardened redirector that ignores the attacker input and lands on a
trusted host — even when an allow-list hint is supplied. This locks in the
honesty contract (objective sentinel-host signal, no false positives) so a future
change to the payload set or matching logic can't silently regress it.
"""
import httpx
import pytest

from ai_osop.core.injection_oracles import (
    detect_open_redirect,
    _REDIRECT_SENTINEL_HOST,
)

_HINT = "https://github.com/juice-shop/juice-shop"


def _client(app, base):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base)


async def _reflecting_app(scope, receive, send):
    """Vulnerable: reflects the `to` param straight into Location (open redirect)."""
    from urllib.parse import parse_qs

    to = (parse_qs(scope.get("query_string", b"").decode()).get("to") or [""])[0]
    await send({"type": "http.response.start", "status": 302,
                "headers": [(b"location", to.encode())]})
    await send({"type": "http.response.body", "body": b""})


async def _hardened_app(scope, receive, send):
    """Safe: always redirects to a fixed trusted host, ignoring attacker input."""
    await send({"type": "http.response.start", "status": 302,
                "headers": [(b"location", _HINT.encode())]})
    await send({"type": "http.response.body", "body": b""})


async def _no_redirect_app(scope, receive, send):
    """Safe: 200, never redirects."""
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"ok"})


@pytest.mark.asyncio
async def test_open_redirect_fires_on_reflecting_redirector():
    async with _client(_reflecting_app, "http://vuln.test") as c:
        ev = await detect_open_redirect(
            c, "http://vuln.test/redirect?to=x", params=["to"], allowlist_hints=[_HINT]
        )
    assert ev is not None
    assert ev["technique"] == "open_redirect"
    assert _REDIRECT_SENTINEL_HOST in ev["location"].lower()
    assert ev["confidence"] == 1.0


@pytest.mark.asyncio
async def test_open_redirect_no_fp_on_hardened_redirector():
    # Even WITH an allow-list hint, a redirector that lands on the trusted host
    # (not the sentinel) must not be reported.
    async with _client(_hardened_app, "http://safe.test") as c:
        ev = await detect_open_redirect(
            c, "http://safe.test/redirect?to=x", params=["to"], allowlist_hints=[_HINT]
        )
    assert ev is None


@pytest.mark.asyncio
async def test_open_redirect_no_fp_when_no_redirect():
    async with _client(_no_redirect_app, "http://safe2.test") as c:
        ev = await detect_open_redirect(
            c, "http://safe2.test/redirect?to=x", params=["to"], allowlist_hints=[_HINT]
        )
    assert ev is None


@pytest.mark.asyncio
async def test_open_redirect_returns_none_without_candidate_params():
    async with _client(_reflecting_app, "http://vuln.test") as c:
        ev = await detect_open_redirect(c, "http://vuln.test/redirect", params=[])
    assert ev is None
