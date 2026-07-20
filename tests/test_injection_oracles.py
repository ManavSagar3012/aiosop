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


# --- XXE: schema-aware external-entity detection -----------------------------
#
# Real XML endpoints validate against their own schema and reject a foreign
# root/field before the parser reflects anything, so a fixed <osop><data> payload
# misses them. These tests lock in the recall fix (target the app's OWN schema,
# derived from a sample body) AND the honesty contract (a hardened/entity-blocking
# parser that never reflects a local-file signature must NOT confirm).

from ai_osop.core.injection_oracles import detect_xxe, _xxe_schemas_from_sample

_STOCK_SAMPLE = (
    '<?xml version="1.0"?>'
    "<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
)


async def _stockcheck_reflecting_app(scope, receive, send):
    """Vulnerable but SCHEMA-VALIDATING: only accepts <stockCheck>, and reflects
    the productId content on error. Simulates the external entity having expanded
    into /etc/passwd content that then surfaces in the echoed error."""
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    text = body.decode("utf-8", "replace")
    if "<stockCheck>" not in text:  # foreign schema rejected outright
        resp, status = b'"Bad request"', 400
    elif "&xxe;" in text:
        # entity expands to passwd content, reflected in the validation error
        resp = b'"Invalid product ID: root:x:0:0:root:/root:/bin/bash"'
        status = 400
    else:
        resp, status = b"42 units", 200
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/xml")]})
    await send({"type": "http.response.body", "body": resp})


async def _stockcheck_hardened_app(scope, receive, send):
    """Safe: accepts the schema but the parser does NOT resolve external entities
    (or blocks them), so no local-file signature ever appears. Must not confirm."""
    await send({"type": "http.response.start", "status": 400,
                "headers": [(b"content-type", b"application/xml")]})
    await send({"type": "http.response.body",
                "body": b'"Entities are not allowed for security reasons"'})


def test_xxe_schema_derivation_from_sample():
    assert _xxe_schemas_from_sample(_STOCK_SAMPLE) == [("stockCheck", "productId")]
    assert _xxe_schemas_from_sample(None) == []
    assert _xxe_schemas_from_sample("not xml at all") == []


@pytest.mark.asyncio
async def test_xxe_generic_schema_misses_schema_validating_endpoint():
    """Without a sample, only the generic <osop> shape is tried — a schema
    validator rejects it, so the real XXE is (undesirably but honestly) missed.
    This is the gap the sample-driven path closes."""
    async with _client(_stockcheck_reflecting_app, "http://vuln.test") as c:
        ev = await detect_xxe(c, "http://vuln.test/stock")
    assert ev is None


@pytest.mark.asyncio
async def test_xxe_schema_aware_confirms_on_reflecting_endpoint():
    async with _client(_stockcheck_reflecting_app, "http://vuln.test") as c:
        ev = await detect_xxe(c, "http://vuln.test/stock", sample_xml=_STOCK_SAMPLE)
    assert ev is not None
    assert ev["technique"] == "xxe"
    assert "stockCheck" in ev["payload"] and "productId" in ev["payload"]


@pytest.mark.asyncio
async def test_xxe_no_fp_on_entity_blocking_parser():
    """Honesty contract: a parser that blocks entities / never reflects a local
    file must NOT confirm, even when the schema is known (the ginandjuice.shop
    case — schema present, but the confirmable channel is hardened)."""
    async with _client(_stockcheck_hardened_app, "http://safe.test") as c:
        ev = await detect_xxe(c, "http://safe.test/stock", sample_xml=_STOCK_SAMPLE)
    assert ev is None
