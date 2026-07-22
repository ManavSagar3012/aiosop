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

from ai_osop.core.injection_oracles import _REDIRECT_SENTINEL_HOST, detect_open_redirect

_HINT = "https://github.com/juice-shop/juice-shop"


def _client(app, base):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base)


async def _reflecting_app(scope, receive, send):
    """Vulnerable: reflects the `to` param straight into Location (open redirect)."""
    from urllib.parse import parse_qs

    to = (parse_qs(scope.get("query_string", b"").decode()).get("to") or [""])[0]
    await send(
        {"type": "http.response.start", "status": 302, "headers": [(b"location", to.encode())]}
    )
    await send({"type": "http.response.body", "body": b""})


async def _hardened_app(scope, receive, send):
    """Safe: always redirects to a fixed trusted host, ignoring attacker input."""
    await send(
        {"type": "http.response.start", "status": 302, "headers": [(b"location", _HINT.encode())]}
    )
    await send({"type": "http.response.body", "body": b""})


async def _no_redirect_app(scope, receive, send):
    """Safe: 200, never redirects."""
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
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

from ai_osop.core.injection_oracles import _xxe_schemas_from_sample, detect_xxe

_STOCK_SAMPLE = (
    '<?xml version="1.0"?>' "<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
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
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/xml")],
        }
    )
    await send({"type": "http.response.body", "body": resp})


async def _stockcheck_hardened_app(scope, receive, send):
    """Safe: accepts the schema but the parser does NOT resolve external entities
    (or blocks them), so no local-file signature ever appears. Must not confirm."""
    await send(
        {
            "type": "http.response.start",
            "status": 400,
            "headers": [(b"content-type", b"application/xml")],
        }
    )
    await send(
        {"type": "http.response.body", "body": b'"Entities are not allowed for security reasons"'}
    )


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


# --- Blind XXE via OAST out-of-band callback ---------------------------------
#
# The ginandjuice.shop stock-check parser DOES resolve external entities but
# reflects nothing in-band (numeric-validated fields), so in-band detection
# correctly returns None. The only honest proof is an out-of-band callback:
# plant_blind_xxe mints a provenance-carrying OAST token, sends an entity that
# fetches the callback URL, and asserts NOTHING itself — the finding is promoted
# only when the registry's reconcile() captures the hit. These tests prove the
# positive (vulnerable parser fires the callback -> confirmed blind XXE) and the
# honesty contract (a parser that never fetches -> no callback -> no finding).

from ai_osop.core.enums import VulnClass
from ai_osop.core.injection_oracles import _blind_xxe_bodies, plant_blind_xxe
from ai_osop.core.oast_correlation import OASTCorrelationRegistry


class _FakeOAST:
    """Minimal OAST server: mints tokens with provenance and records callbacks."""

    def __init__(self):
        self._tokens = {}
        self._interactions = []
        self._seq = 0
        self._n = 0

    async def register(self, label="", context=None):
        self._n += 1
        token = f"tok{self._n}"
        self._tokens[token] = context or {}
        return token, f"http://oast.test/{token}"

    def fire(self, token, source_ip="203.0.113.7"):
        self._seq += 1
        self._interactions.append(
            {
                "seq": self._seq,
                "token": token,
                "interaction_id": f"i{self._seq}",
                "kind": "http",
                "source_ip": source_ip,
                "method": "GET",
                "path": f"/{token}",
                "context": self._tokens.get(token, {}),
            }
        )

    async def drain(self, since=0, engagement_id=None):
        out = [
            i
            for i in self._interactions
            if i["seq"] > since
            and (not engagement_id or i["context"].get("engagement_id") == engagement_id)
        ]
        cursor = max([since] + [i["seq"] for i in out])
        return cursor, out


def _blind_app_factory(oast, *, vulnerable: bool):
    """Build an ASGI app simulating an XML parser. If vulnerable, it 'fetches'
    the SYSTEM entity's callback URL (fires the OAST server) exactly like a real
    entity-resolving parser would; if not, it ignores the DTD entirely."""
    import re

    async def app(scope, receive, send):
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body"):
                break
        text = body.decode("utf-8", "replace")
        if vulnerable:
            m = re.search(r'ENTITY\s+(?:%\s+)?xxe\s+SYSTEM\s+"http://oast\.test/(tok\d+)"', text)
            if m:
                oast.fire(m.group(1))
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/xml")],
            }
        )
        await send({"type": "http.response.body", "body": b"1 units"})

    return app


def test_blind_xxe_bodies_target_schema_and_callback():
    bodies = _blind_xxe_bodies("http://cb/tok1", "stockCheck", "productId")
    labels = {lb for lb, _ in bodies}
    assert labels == {"system-entity", "param-entity"}
    for _lb, b in bodies:
        assert "http://cb/tok1" in b
        assert "<stockCheck>" in b  # built against the app's own schema


@pytest.mark.asyncio
async def test_plant_blind_xxe_confirms_via_oob_callback():
    oast = _FakeOAST()
    reg = OASTCorrelationRegistry(oast)
    app = _blind_app_factory(oast, vulnerable=True)
    async with _client(app, "http://vuln.test") as c:
        planted = await plant_blind_xxe(
            c,
            "http://vuln.test/stock",
            oast_registry=reg,
            engagement_id="eng1",
            sample_xml=_STOCK_SAMPLE,
        )
    assert planted >= 1
    res = await reg.reconcile(engagement_id="eng1")
    assert any(v.vuln_type == VulnClass.XXE and v.validated for v in res.findings)


@pytest.mark.asyncio
async def test_plant_blind_xxe_no_finding_without_callback():
    """Honest true-negative: a parser that never fetches the entity produces no
    callback, so reconcile promotes nothing — exactly what must happen on a
    non-vulnerable target (no in-band guess is ever asserted)."""
    oast = _FakeOAST()
    reg = OASTCorrelationRegistry(oast)
    app = _blind_app_factory(oast, vulnerable=False)
    async with _client(app, "http://safe.test") as c:
        planted = await plant_blind_xxe(
            c,
            "http://safe.test/stock",
            oast_registry=reg,
            engagement_id="eng2",
            sample_xml=_STOCK_SAMPLE,
        )
    assert planted >= 1  # probes were sent
    res = await reg.reconcile(engagement_id="eng2")
    assert res.findings == []  # but nothing called back -> nothing promoted


@pytest.mark.asyncio
async def test_plant_blind_xxe_noop_without_registry():
    async with _client(_blind_app_factory(_FakeOAST(), vulnerable=True), "http://vuln.test") as c:
        planted = await plant_blind_xxe(
            c,
            "http://vuln.test/stock",
            oast_registry=None,
            engagement_id="e",
        )
    assert planted == 0
