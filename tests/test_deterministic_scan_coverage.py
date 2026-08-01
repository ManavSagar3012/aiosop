"""Coverage-focused tests for ai_osop.core.deterministic_scan.

Complements test_deterministic_scan.py by exercising the paths that suite leaves
cold: the pure helpers (_sub_last_id, _infer_shape), the crawlers
(_crawl_api_paths / _crawl_spec_paths / _harvest_redirectors / _crawl_param_links
edge cases), the mass-assignment oracle (_detect_mass_assignment with a
baseline-suppressed reflected field), and the generalized orchestrators
(run_generalized_massassign / run_generalized_jwt / run_generalized_idor /
run_generalized_injection / run_generalized_scan / bootstrap_discovery) with the
HTTP boundary mocked at httpx.MockTransport or at the oracle seam.

Assertions are on outputs — persisted Vulnerability objects, dedup/cap counts,
severity/class mappings, and seeded-endpoint sets — not on internal call counts.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import List

import httpx
import pytest

from ai_osop.core import deterministic_scan as ds
from ai_osop.core.enums import Severity, VulnClass

# --------------------------------------------------------------------------- #
# Shared doubles                                                               #
# --------------------------------------------------------------------------- #


class _FakeGraph:
    def __init__(self):
        self.persisted: List = []
        self.endpoints: List = []

    async def add_vulnerability(self, vuln) -> None:
        self.persisted.append(vuln)

    async def add_endpoint(self, ep) -> None:
        self.endpoints.append(ep)


class _FakeDriver:
    """Feeds _discovered_endpoints a fixed endpoint list via the neo4j seam."""

    def __init__(self, endpoints: list[dict]):
        self._endpoints = endpoints

    def session(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def run(self, q, **kw):
        self._q = q
        self._kw = kw
        return self

    async def __aiter__(self):
        for ep in self._endpoints:
            yield ep


def _graph_with_endpoints(endpoints: list[dict]) -> _FakeGraph:
    gm = _FakeGraph()
    gm._driver = _FakeDriver(endpoints)
    return gm


def _ep(**over):
    base = {
        "url": "http://t/x",
        "method": "GET",
        "path": "/x",
        "query_keys": [],
        "parameters": [],
        "body_schema_keys": [],
        "has_body": False,
        "content_type": "",
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# Pure helpers                                                                 #
# --------------------------------------------------------------------------- #


def test_sub_last_id_replaces_numeric_tail():
    assert ds._sub_last_id("http://t/api/Users/54", 99) == "http://t/api/Users/99"


def test_sub_last_id_replaces_template_and_wildcard_id():
    assert ds._sub_last_id("http://t/api/Users/{id}", 7) == "http://t/api/Users/7"
    assert ds._sub_last_id("http://t/api/Users/:id", 7) == "http://t/api/Users/7"
    assert ds._sub_last_id("http://t/api/objects/userId", 3) == "http://t/api/objects/3"


def test_sub_last_id_leaves_non_id_tail_unchanged():
    assert ds._sub_last_id("http://t/api/products", 5) == "http://t/api/products"
    # trailing slash stripped before inspect; 'orders' is not id-like
    assert ds._sub_last_id("http://t/api/orders/", 5) == "http://t/api/orders"


def test_infer_shape_login_returns_post_credentials():
    method, keys, has_body = ds._infer_shape("/rest/user/login")
    assert method == "POST"
    assert keys == ["email", "password"]
    assert has_body is True


def test_infer_shape_search_returns_get_q():
    method, keys, has_body = ds._infer_shape("/rest/products/search")
    assert method == "GET"
    assert keys == ["q"]
    assert has_body is False


def test_infer_shape_default_get_no_params():
    assert ds._infer_shape("/api/orders/1") == ("GET", [], False)


# --------------------------------------------------------------------------- #
# _crawl_api_paths                                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_crawl_api_paths_from_html_and_js_bundles():
    home = """
    <html><head><script src="/static/app.js"></script></head>
    <body>"/rest/user/login" and "/api/Users/1" live here</body></html>
    """
    app_js = 'fetch("/rest/products/search"); fetch("/api/Basket/9?x=1")'

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/":
            return httpx.Response(200, text=home)
        if req.url.path == "/static/app.js":
            return httpx.Response(200, text=app_js)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        paths = await ds._crawl_api_paths(c, "http://t")

    assert "/rest/user/login" in paths
    assert "/api/Users/1" in paths
    assert "/rest/products/search" in paths
    # query strings stripped, trailing slashes stripped
    assert "/api/Basket/9" in paths


@pytest.mark.asyncio
async def test_crawl_api_paths_handles_base_page_failure():
    class _Down:
        async def get(self, url, **kw):
            raise RuntimeError("connection refused")

    assert await ds._crawl_api_paths(_Down(), "http://t") == set()


# --------------------------------------------------------------------------- #
# _crawl_param_links — edge cases beyond the existing suite                    #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_crawl_param_links_one_level_deep_and_off_origin_filtering():
    home = """
    <html><body>
      <a href="/listing">listing</a>
      <a href="https://evil.example/x?u=1">off origin</a>
      <a href="mailto:x@y.z">mail</a>
      <a href="javascript:void(0)">js</a>
      <a href="#frag">frag</a>
      <a href="./local?a=1">dotslash</a>
    </body></html>
    """
    listing = '<a href="/detail?id=42">detail</a>'

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/":
            return httpx.Response(200, text=home)
        if req.url.path == "/listing":
            return httpx.Response(200, text=listing)
        return httpx.Response(200, text="<html></html>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        links = await ds._crawl_param_links(c, "http://t")

    by_path = {p: keys for p, _m, keys, _b in links}
    # ./local normalized to /local and discovered directly from home
    assert by_path["/local"] == ["a"]
    # /detail?id= discovered one level deep via the seed page /listing
    assert by_path["/detail"] == ["id"]
    # off-origin / mail / js / fragment links never became endpoints
    assert len(by_path) == 2


@pytest.mark.asyncio
async def test_crawl_param_links_returns_empty_when_home_unreachable():
    class _Down:
        async def get(self, url, **kw):
            raise RuntimeError("down")

    assert await ds._crawl_param_links(_Down(), "http://t") == []


# --------------------------------------------------------------------------- #
# _harvest_redirectors                                                         #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_harvest_redirectors_finds_off_origin_allowlist_hints():
    home = """
    <html><head><script src="/app.js"></script></head>
    <body><a href="/redirect?to=https://trusted.example/land">go</a></body></html>
    """
    js = 'var u = "./out?url=https://partner.example/x"; var v = "/redirect?to=https://t/self";'

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/":
            return httpx.Response(200, text=home)
        if req.url.path == "/app.js":
            return httpx.Response(200, text=js)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        out = await ds._harvest_redirectors(c, "http://t")

    # (endpoint, param) pairs aggregate hints from both the HTML and the bundle
    by_key = {(url.replace("http://t", ""), param): hints for url, param, hints in out}
    assert ("/redirect", "to") in by_key
    # "./out" normalized to "/out"
    assert ("/out", "url") in by_key
    # hints carry ONLY off-origin values (same-host https://t/self filtered out)
    all_hints = [h for hints in by_key.values() for h in hints]
    assert "https://trusted.example/land" in all_hints
    assert "https://partner.example/x" in all_hints
    assert not any("https://t/" in h for h in all_hints)


@pytest.mark.asyncio
async def test_harvest_redirectors_empty_when_base_down():
    class _Down:
        async def get(self, url, **kw):
            raise RuntimeError("down")

    assert await ds._harvest_redirectors(_Down(), "http://t") == []


# --------------------------------------------------------------------------- #
# _crawl_spec_paths                                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_crawl_spec_paths_parses_openapi_spec():
    spec = {
        "paths": {
            "/rest/user/login": {
                "post": {
                    "parameters": [{"name": "debug"}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"properties": {"email": {}, "password": {}}}
                            }
                        }
                    },
                },
                # non-HTTP verb key must be ignored
                "head": {},
            },
            "/rest/products/search": {"get": {"parameters": [{"name": "q"}]}},
        }
    }

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/openapi.json":
            return httpx.Response(200, json=spec, headers={"content-type": "application/json"})
        return httpx.Response(404, text="nope")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        out = await ds._crawl_spec_paths(c, "http://t")

    by_path = {p: (m, keys, body) for p, m, keys, body in out}
    assert "/rest/user/login" in by_path
    method, keys, has_body = by_path["/rest/user/login"]
    assert method == "POST" and has_body is True
    # parameter names + JSON body property names are merged
    assert "debug" in keys and "email" in keys and "password" in keys
    assert "/rest/products/search" in by_path
    assert by_path["/rest/products/search"][0] == "GET"
    assert "q" in by_path["/rest/products/search"][1]


@pytest.mark.asyncio
async def test_crawl_spec_paths_robots_and_sitemap_when_no_spec():
    robots = "User-agent: *\nDisallow: /admin/login\nDisallow: /internal*\n"
    sitemap = (
        '<?xml version="1.0"?><urlset>'
        "<loc>http://t/catalog/search?q=x</loc>"
        "<loc>http://t/about</loc>"
        "</urlset>"
    )

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(200, text=robots)
        if req.url.path == "/sitemap.xml":
            return httpx.Response(200, text=sitemap)
        return httpx.Response(404, text="no")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        out = await ds._crawl_spec_paths(c, "http://t")

    by_path = {p: (m, keys, body) for p, m, keys, body in out}
    # robots Disallow honored; wildcard entry skipped
    assert "/admin/login" in by_path
    assert by_path["/admin/login"][0] == "POST"  # _infer_shape: login -> POST
    assert "/internal*" not in by_path
    # sitemap loc parsed down to path; query stripped, shape inferred
    assert "/catalog/search" in by_path
    assert by_path["/catalog/search"][1] == ["q"]  # search -> q
    assert "/about" in by_path
    assert by_path["/about"] == ("GET", [], False)


# --------------------------------------------------------------------------- #
# _discovered_endpoints                                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_discovered_endpoints_empty_without_driver():
    assert await ds._discovered_endpoints(_FakeGraph(), "eng") == []


@pytest.mark.asyncio
async def test_discovered_endpoints_flows_through_driver():
    eps = [_ep(url="http://t/a", path="/a"), _ep(url="http://t/b", path="/b")]
    gm = _graph_with_endpoints(eps)
    out = await ds._discovered_endpoints(gm, "eng-1")
    assert len(out) == 2
    assert gm._driver._kw["eid"] == "eng-1"


# --------------------------------------------------------------------------- #
# run_deterministic_scan — taxonomy / unmapped fallbacks                       #
# --------------------------------------------------------------------------- #


def _fake_bench(check_ids):
    entries = [
        SimpleNamespace(check_id=c, name=f"name-{c}", owasp="A01", cwe="CWE-00", expected=True)
        for c in check_ids
    ]

    def _res(cid):
        async def _fn(target):
            return SimpleNamespace(validated=True, evidence={"k": cid}, confidence=0.77)

        return _fn

    return SimpleNamespace(
        MANIFEST=entries,
        CHECKS={c: _res(c) for c in check_ids},
        Target=lambda b, c: SimpleNamespace(),
    )


@pytest.mark.asyncio
async def test_suite_maps_taxonomy_and_falls_back_for_unmapped(monkeypatch):
    monkeypatch.setattr(ds, "_load_suite", lambda: _fake_bench(["sqli_login_bypass", "no_such_map"]))
    gm = _FakeGraph()

    persisted, validated, expected = await ds.run_deterministic_scan(
        "http://t", "eng-map", gm, per_check_timeout=5.0
    )

    assert (len(persisted), len(validated), expected) == (2, 2, 2)
    by_title = {v.title: v for v in persisted}
    mapped = by_title["name-sqli_login_bypass"]
    assert mapped.vuln_type == VulnClass.SQLI
    assert mapped.severity == Severity.CRITICAL
    assert mapped.confidence == 0.77
    assert mapped.evidence[0]["k"] == "sqli_login_bypass"
    unmapped = by_title["name-no_such_map"]
    assert unmapped.vuln_type == VulnClass.UNKNOWN
    assert unmapped.severity == Severity.HIGH
    assert "[A01]" in unmapped.description


# --------------------------------------------------------------------------- #
# _detect_mass_assignment + run_generalized_massassign                         #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_detect_mass_assignment_flags_baseline_suppressed_fields():
    """Injected privileged field reflected ONLY in the injection response ->
    evidence. A field also present in the control response is not accepted."""

    class _C:
        async def request(self, method, url, json=None, **kw):
            req = httpx.Request(method, url)
            if "role" in json:
                return httpx.Response(200, json={"ok": True, **json}, request=req)
            return httpx.Response(200, json={"ok": True, **json, "isAdmin": True}, request=req)

    ev = await ds._detect_mass_assignment(_C(), "http://t/api/Users", ["email", "password"])

    assert ev is not None
    # role is baseline-suppressed (absent from control) -> accepted
    assert "role" in ev["accepted_fields"] and ev["accepted_fields"]["role"] == "admin"
    # isDeluxe reflected only post-injection -> accepted
    assert "isDeluxe" in ev["accepted_fields"]
    # isAdmin already present in control -> suppressed as baseline noise
    assert "isAdmin" not in ev["accepted_fields"]
    assert ev["technique"] == "mass_assignment"
    assert ev["provenance"] == "reflected"
    assert ev["http_status"] == 200


@pytest.mark.asyncio
async def test_detect_mass_assignment_none_when_nothing_new_reflected():
    class _C:
        async def request(self, method, url, json=None, **kw):
            req = httpx.Request(method, url)
            # control and injection responses reflect identically -> no signal
            return httpx.Response(200, json={}, request=req)

    assert await ds._detect_mass_assignment(_C(), "http://t/api/Users", ["email"]) is None


@pytest.mark.asyncio
async def test_detect_mass_assignment_none_on_request_failure():
    class _C:
        async def request(self, method, url, json=None, **kw):
            raise RuntimeError("net down")

    assert await ds._detect_mass_assignment(_C(), "http://t/api/Users", ["email"]) is None


@pytest.mark.asyncio
async def test_run_generalized_massassign_persists_manual_confirm_lead():
    create_ep = _ep(
        url="http://t/api/users",
        method="POST",
        path="/api/users",
        has_body=True,
        body_schema_keys=["email", "password"],
    )
    # duplicate shape must collapse
    dup = dict(create_ep, url="http://t/api/users?src=2")
    # non-create POST must be excluded
    non_create = _ep(url="http://t/rest/login", method="POST", path="/rest/login",
                     has_body=True, body_schema_keys=["email"])
    gm = _graph_with_endpoints([create_ep, dup, non_create])

    async def fake_detect(c, url, body_keys, method="POST"):
        return {
            "technique": "mass_assignment",
            "endpoint": url,
            "accepted_fields": {"role": "admin"},
            "confidence": 0.5,
        }

    orig = ds._detect_mass_assignment
    ds._detect_mass_assignment = fake_detect
    try:
        persisted, examined = await ds.run_generalized_massassign(
            "eng-ma", gm, per_check_timeout=5.0
        )
    finally:
        ds._detect_mass_assignment = orig

    assert examined == 1  # deduped to one create-like candidate
    assert len(persisted) == 1
    v = persisted[0]
    assert v.cwe == "CWE-915"
    assert v.vuln_type == VulnClass.MASS_ASSIGNMENT
    assert v.severity == Severity.MEDIUM
    assert v.validated is False  # reflected-only lead — manual confirm
    assert v.confidence == 0.5
    assert v.evidence[0]["type"] == "mass_assignment"
    assert "role" in v.title


# --------------------------------------------------------------------------- #
# run_generalized_jwt                                                          #
# --------------------------------------------------------------------------- #


def _jwt_eps():
    return [
        _ep(url="http://t/rest/user/login", method="POST", path="/rest/user/login",
            has_body=True, body_schema_keys=["email", "password"]),
        _ep(url="http://t/rest/user/whoami", method="GET", path="/rest/user/whoami"),
    ]


@pytest.mark.asyncio
async def test_run_generalized_jwt_requires_login_and_identity_endpoints():
    gm = _graph_with_endpoints([_ep(url="http://t/api/x", path="/api/x")])
    persisted, seen = await ds.run_generalized_jwt("eng-j", gm)
    assert persisted == [] and seen == 0


@pytest.mark.asyncio
async def test_run_generalized_jwt_persists_confirmed_findings(monkeypatch):
    from ai_osop.core import jwt_tester as jt

    class _Target:
        def __init__(self, base, client):
            pass

        async def login(self, email, password):
            return "base-token"  # SQLi bypass succeeds on first try

        async def register(self, email, password):
            return True

    fake_bench = SimpleNamespace(Target=_Target)
    monkeypatch.setattr(ds, "_load_suite", lambda: fake_bench)

    confirmed = SimpleNamespace(
        confirmed=True, technique="alg_none", detail="alg:none token accepted"
    )
    unconfirmed = SimpleNamespace(
        confirmed=False, technique="weak_secret", detail="no secret hit"
    )

    class _Tester:
        def __init__(self, verify_url, base_token, method, timeout):
            assert base_token == "base-token"

        async def run(self):
            return [confirmed, unconfirmed]

    monkeypatch.setattr(jt, "JWTTester", _Tester)

    gm = _graph_with_endpoints(_jwt_eps())
    persisted, seen = await ds.run_generalized_jwt("eng-j", gm, per_check_timeout=5.0)

    assert seen == 1
    # only the CONFIRMED finding is persisted
    assert len(persisted) == 1
    v = persisted[0]
    assert v.cwe == "CWE-347"
    assert v.vuln_type == VulnClass.JWT_ABUSE
    assert v.severity == Severity.CRITICAL
    assert v.validated is True
    assert "alg_none" in v.title
    assert v.evidence[0]["technique"] == "alg_none"
    assert v.evidence[0]["verify_url"] == "http://t/rest/user/whoami"


@pytest.mark.asyncio
async def test_run_generalized_jwt_register_fallback_mints_token(monkeypatch):
    """When SQLi login raises, the register+login fallback path must mint the token."""
    from ai_osop.core import jwt_tester as jt

    class _Target:
        def __init__(self, base, client):
            pass

        async def login(self, email, password):
            if email == "' OR 1=1--":
                raise RuntimeError("no sqli bypass")
            return "fresh-token"

        async def register(self, email, password):
            return True

    monkeypatch.setattr(ds, "_load_suite", lambda: SimpleNamespace(Target=_Target))

    captured = {}

    class _Tester:
        def __init__(self, verify_url, base_token, method, timeout):
            captured["token"] = base_token

        async def run(self):
            return []

    monkeypatch.setattr(jt, "JWTTester", _Tester)

    gm = _graph_with_endpoints(_jwt_eps())
    persisted, seen = await ds.run_generalized_jwt("eng-j", gm, per_check_timeout=5.0)

    assert persisted == []
    assert seen == 1
    assert captured["token"] == "fresh-token"


@pytest.mark.asyncio
async def test_run_generalized_jwt_no_token_returns_nothing(monkeypatch):
    class _Target:
        def __init__(self, base, client):
            pass

        async def login(self, email, password):
            return None

        async def register(self, email, password):
            raise RuntimeError("registration broken")

    monkeypatch.setattr(ds, "_load_suite", lambda: SimpleNamespace(Target=_Target))

    gm = _graph_with_endpoints(_jwt_eps())
    persisted, seen = await ds.run_generalized_jwt("eng-j", gm, per_check_timeout=5.0)
    assert persisted == [] and seen == 0


# --------------------------------------------------------------------------- #
# run_generalized_idor                                                         #
# --------------------------------------------------------------------------- #


def _idor_eps():
    return [_ep(url="http://t/api/Users/54", path="/api/users/54")]


@pytest.mark.asyncio
async def test_run_generalized_idor_requires_id_bearing_endpoints():
    gm = _graph_with_endpoints([_ep(url="http://t/api/users", path="/api/users")])
    persisted, seen = await ds.run_generalized_idor("eng-i", gm)
    assert persisted == [] and seen == 0


@pytest.mark.asyncio
async def test_run_generalized_idor_confirms_cross_account_read(monkeypatch):
    from ai_osop.core import diff_auth_engine as dae

    class _Target:
        def __init__(self, base, client):
            pass

        async def register(self, email, password):
            return True

        async def login(self, email, password):
            return f"tok:{email}"

    def _bid(tok):
        return 54

    def _resp_ev(r):
        return {"status_code": r.status_code, "body": {}}

    fake_bench = SimpleNamespace(Target=_Target, _bid_from_token=_bid, _resp_evidence=_resp_ev)
    monkeypatch.setattr(ds, "_load_suite", lambda: fake_bench)

    class _Engine:
        def __init__(self, session_memory=None):
            pass

        async def compare(self, identity_a_evidence, identity_b_evidence, resource,
                          expected_allowed, anonymous_evidence=None):
            # the attacker baseline must be labeled for evidence provenance
            assert identity_b_evidence["user_label"] == "attacker"
            return SimpleNamespace(
                confidence=0.9, category="cross_account", evidence_diff="identical body"
            )

    monkeypatch.setattr(dae, "DifferentialAuthEngine", _Engine)

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 54}, request=req)

    orig_client = httpx.AsyncClient

    class _MockClient(orig_client):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(**kw)

    httpx.AsyncClient = _MockClient
    try:
        gm = _graph_with_endpoints(_idor_eps())
        persisted, seen = await ds.run_generalized_idor("eng-i", gm, per_check_timeout=5.0)
    finally:
        httpx.AsyncClient = orig_client

    assert seen == 1
    assert len(persisted) == 1
    v = persisted[0]
    assert v.cwe == "CWE-639"
    assert v.vuln_type == VulnClass.IDOR
    assert v.severity == Severity.HIGH
    assert v.validated is True
    # victim id substituted into the probed URL
    assert "/api/Users/54" in v.title
    assert v.evidence[0]["provenance"] == "diff_auth"
    assert v.evidence[0]["category"] == "cross_account"


@pytest.mark.asyncio
async def test_run_generalized_idor_low_confidence_is_dropped(monkeypatch):
    """A finding below the 0.5 confidence floor must not persist."""
    from ai_osop.core import diff_auth_engine as dae

    class _Target:
        def __init__(self, base, client):
            pass

        async def register(self, email, password):
            return True

        async def login(self, email, password):
            return "tok"

    fake_bench = SimpleNamespace(
        Target=_Target,
        _bid_from_token=lambda t: 54,
        _resp_evidence=lambda r: {"status_code": r.status_code},
    )
    monkeypatch.setattr(ds, "_load_suite", lambda: fake_bench)

    class _Engine:
        def __init__(self, session_memory=None):
            pass

        async def compare(self, **kw):
            return SimpleNamespace(confidence=0.3, category="weak")

    monkeypatch.setattr(dae, "DifferentialAuthEngine", _Engine)

    orig_client = httpx.AsyncClient

    class _MockClient(orig_client):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(
                lambda req: httpx.Response(200, json={}, request=req)
            )
            super().__init__(**kw)

    httpx.AsyncClient = _MockClient
    try:
        gm = _graph_with_endpoints(_idor_eps())
        persisted, seen = await ds.run_generalized_idor("eng-i", gm, per_check_timeout=5.0)
    finally:
        httpx.AsyncClient = orig_client

    assert persisted == []
    assert seen == 1


# --------------------------------------------------------------------------- #
# run_generalized_injection                                                    #
# --------------------------------------------------------------------------- #


def _patch_injection_oracles(monkeypatch, *, traversal=None, redirect=None, ssrf=None,
                             xxe=None, plant=None):
    from ai_osop.core import injection_oracles as io

    if traversal is not None:
        monkeypatch.setattr(io, "detect_path_traversal", traversal)
    if redirect is not None:
        monkeypatch.setattr(io, "detect_open_redirect", redirect)
    if ssrf is not None:
        monkeypatch.setattr(io, "detect_ssrf_reflected", ssrf)
    if xxe is not None:
        monkeypatch.setattr(io, "detect_xxe", xxe)
    if plant is not None:
        monkeypatch.setattr(io, "plant_blind_xxe", plant)


async def _none(*a, **kw):
    return None


@pytest.mark.asyncio
async def test_run_generalized_injection_persists_per_technique_taxonomy(monkeypatch):
    async def fake_traversal(c, url, params=None, **kw):
        return {"technique": "path_traversal", "endpoint": url, "payload": "../../../etc/passwd",
                "proof": "root:x:0 signature", "confidence": 1.0}

    async def fake_ssrf(c, url, params=None, **kw):
        return {"technique": "ssrf_reflected", "endpoint": url, "payload": "http://169.254.169.254/",
                "confidence": 0.9}

    _patch_injection_oracles(monkeypatch, traversal=fake_traversal, redirect=_none,
                             ssrf=fake_ssrf, xxe=_none)
    monkeypatch.setattr(ds, "_harvest_redirectors", _none_harvest)

    eps = [_ep(url="http://t/api/file", path="/api/file", query_keys=["path"])]
    gm = _graph_with_endpoints(eps)

    persisted, examined = await ds.run_generalized_injection("eng-inj", gm, per_check_timeout=5.0)

    assert examined == 1
    assert len(persisted) == 2
    by_tech = {v.evidence[0]["type"]: v for v in persisted}
    trav = by_tech["path_traversal"]
    assert trav.cwe == "CWE-22" and trav.vuln_type == VulnClass.LFI
    assert trav.severity == Severity.HIGH and trav.validated is True
    ssrf_v = by_tech["ssrf_reflected"]
    assert ssrf_v.cwe == "CWE-918" and ssrf_v.vuln_type == VulnClass.SSRF
    assert ssrf_v.severity == Severity.HIGH
    assert ssrf_v.confidence == 0.9


async def _none_harvest(*a, **kw):
    return []


@pytest.mark.asyncio
async def test_run_generalized_injection_xxe_and_blind_plant(monkeypatch):
    async def fake_xxe(c, url, method="POST", sample_xml=None, **kw):
        # the reconstructed schema-shaped sample must ride through
        assert sample_xml == '<?xml version="1.0"?><stock><productId>1</productId></stock>'
        return {"technique": "xxe", "endpoint": url, "payload": "<!ENTITY xxe SYSTEM ...>",
                "proof": "system-file signature in response", "confidence": 1.0}

    planted = []

    async def fake_plant(c, url, *, oast_registry, engagement_id, method="POST",
                         sample_xml=None, **kw):
        planted.append((url, engagement_id))

    _patch_injection_oracles(monkeypatch, traversal=_none, redirect=_none, ssrf=_none,
                             xxe=fake_xxe, plant=fake_plant)
    monkeypatch.setattr(ds, "_harvest_redirectors", _none_harvest)

    eps = [
        _ep(url="http://t/catalog/product/stock", method="POST",
            path="/catalog/product/stock", has_body=True,
            body_schema_keys=["productId"]),
    ]
    gm = _graph_with_endpoints(eps)
    registry = object()  # any non-None registry enables the blind plant

    persisted, examined = await ds.run_generalized_injection(
        "eng-xxe", gm, per_check_timeout=5.0, oast_registry=registry
    )

    assert examined == 1
    assert len(persisted) == 1
    v = persisted[0]
    assert v.cwe == "CWE-611" and v.vuln_type == VulnClass.XXE
    assert v.severity == Severity.HIGH and v.validated is True
    assert planted == [("http://t/catalog/product/stock", "eng-xxe")]


@pytest.mark.asyncio
async def test_run_generalized_injection_skips_blind_plant_without_registry(monkeypatch):
    planted = []

    async def fake_plant(*a, **kw):
        planted.append(1)

    _patch_injection_oracles(monkeypatch, traversal=_none, redirect=_none, ssrf=_none,
                             xxe=_none, plant=fake_plant)
    monkeypatch.setattr(ds, "_harvest_redirectors", _none_harvest)

    eps = [_ep(url="http://t/import/xml", method="POST", path="/import/xml",
               has_body=True, body_schema_keys=["feed"])]
    gm = _graph_with_endpoints(eps)

    persisted, examined = await ds.run_generalized_injection(
        "eng-noob", gm, per_check_timeout=5.0, oast_registry=None
    )
    assert examined == 1
    assert persisted == []
    assert planted == []


@pytest.mark.asyncio
async def test_run_generalized_injection_dedicated_redirector_pass(monkeypatch):
    async def fake_redirect(c, url, params=None, allowlist_hints=None, **kw):
        if url == "http://t/redirect":
            assert params == ["to"]
            assert allowlist_hints == ["https://trusted.example/x"]
            return {"technique": "open_redirect", "endpoint": url,
                    "payload": "https://trusted.example/x@evil.example",
                    "confidence": 1.0}
        return None

    _patch_injection_oracles(monkeypatch, traversal=_none, redirect=fake_redirect,
                             ssrf=_none, xxe=_none)

    async def fake_harvest(c, base):
        return [("http://t/redirect", "to", ["https://trusted.example/x"])]

    monkeypatch.setattr(ds, "_harvest_redirectors", fake_harvest)

    # an endpoint that is a GET-shape generic injection candidate (examined for
    # traversal/ssrf/redirect with no hit) and yields a base URL for harvesting
    eps = [_ep(url="http://t/home", path="/home")]
    gm = _graph_with_endpoints(eps)

    persisted, examined = await ds.run_generalized_injection("eng-redir", gm, per_check_timeout=5.0)

    # examined counts the GET-shape candidate plus the harvested redirector;
    # only the redirector oracle produces a finding
    assert examined == 2
    assert len(persisted) == 1
    v = persisted[0]
    assert v.cwe == "CWE-601"
    assert v.vuln_type == VulnClass.BROKEN_ACCESS_CONTROL
    assert v.severity == Severity.MEDIUM
    assert v.validated is True


# --------------------------------------------------------------------------- #
# run_generalized_scan — aggregation                                           #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_generalized_scan_aggregates_all_passes(monkeypatch):
    def _v(tag):
        return SimpleNamespace(title=tag)

    async def fake_sqli(eid, gm, **kw):
        return [_v("sqli")], 12

    async def fake_ma(eid, gm, **kw):
        return [_v("ma")], 0

    async def fake_jwt(eid, gm, **kw):
        return [_v("jwt")], 0

    async def fake_idor(eid, gm, **kw):
        return [], 0

    async def fake_inj(eid, gm, **kw):
        assert kw.get("oast_registry") is sentinel_registry
        return [_v("inj1"), _v("inj2")], 0

    monkeypatch.setattr(ds, "run_generalized_sqli", fake_sqli)
    monkeypatch.setattr(ds, "run_generalized_massassign", fake_ma)
    monkeypatch.setattr(ds, "run_generalized_jwt", fake_jwt)
    monkeypatch.setattr(ds, "run_generalized_idor", fake_idor)
    monkeypatch.setattr(ds, "run_generalized_injection", fake_inj)

    sentinel_registry = object()
    all_v, examined = await ds.run_generalized_scan(
        "eng-all", _FakeGraph(), oast_registry=sentinel_registry
    )

    assert examined == 12  # sqli's endpoints_examined is the returned count
    assert [v.title for v in all_v] == ["sqli", "ma", "jwt", "inj1", "inj2"]


# --------------------------------------------------------------------------- #
# bootstrap_discovery — merge order, filtering, seeding                        #
# --------------------------------------------------------------------------- #


def _run_bootstrap(monkeypatch, handler, *, common, spec=None, crawled=None, param_links=None):
    import httpx as _hm

    monkeypatch.setattr(ds, "_COMMON_ENDPOINTS", common)

    async def _spec(c, base):
        return spec or []

    async def _api(c, base):
        return crawled or set()

    async def _param(c, base):
        return param_links or []

    monkeypatch.setattr(ds, "_crawl_spec_paths", _spec)
    monkeypatch.setattr(ds, "_crawl_api_paths", _api)
    monkeypatch.setattr(ds, "_crawl_param_links", _param)

    orig = _hm.AsyncClient

    class _MockClient(_hm.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = _hm.MockTransport(handler)
            super().__init__(**kw)

    _hm.AsyncClient = _MockClient
    return orig, _hm


@pytest.mark.asyncio
async def test_bootstrap_merges_spec_crawl_and_param_link_sources(monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        live = {
            "/wordlist/api/x": (200, "application/json", "{}"),
            "/spec/real": (200, "application/json", "{}"),
            "/js/found": (200, "application/json", "{}"),
            "/catalog": (200, "text/html", "<html>cat</html>"),
        }
        if p in live:
            code, ct, body = live[p]
            return httpx.Response(code, text=body, headers={"content-type": ct})
        return httpx.Response(404, text="no")

    orig, hm = _run_bootstrap(
        monkeypatch,
        handler,
        common=[("/wordlist/api/x", "GET", [], False)],
        spec=[("/spec/real", "POST", ["email"], True)],
        crawled={"/js/found"},
        param_links=[("/catalog", "GET", ["category"], False)],
    )
    try:
        gm = _FakeGraph()
        seeded = await ds.bootstrap_discovery("http://t", "eng-b", gm, timeout=2.0)
    finally:
        hm.AsyncClient = orig

    assert seeded == 4
    by_path = {e.path: e for e in gm.endpoints}
    # spec entry carries its exact shape (POST + body keys)
    assert by_path["/spec/real"].method == "POST"
    assert by_path["/spec/real"].body_schema_keys == ["email"]
    # js-literal crawl entry gets the inferred shape
    assert by_path["/js/found"].method == "GET"
    # param-carrying HTML link is kept despite non-API path + text/html
    assert by_path["/catalog"].query_keys == ["category"]
    assert by_path["/catalog"].method == "GET"


@pytest.mark.asyncio
async def test_bootstrap_drops_spa_catchall_and_duplicates(monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        # everything exists — but "plain" paths return marketing HTML
        return httpx.Response(200, text="<html>spa</html>",
                              headers={"content-type": "text/html"})

    orig, hm = _run_bootstrap(
        monkeypatch,
        handler,
        common=[("/plain", "GET", [], False)],
        # the spec shape for /api/dup arrives before the JS-literal crawl and
        # must win over the inferred shape (spec is merged ahead of the crawl)
        spec=[("/api/dup", "POST", ["email"], True)],
        crawled={"/also-plain", "/api/dup"},
        param_links=[],
    )
    try:
        gm = _FakeGraph()
        seeded = await ds.bootstrap_discovery("http://t", "eng-b2", gm, timeout=2.0)
    finally:
        hm.AsyncClient = orig

    by_path = {e.path: e for e in gm.endpoints}
    # paramless HTML paths are SPA catch-alls -> dropped
    assert "/plain" not in by_path
    assert "/also-plain" not in by_path
    # /api path prefix survives the filter; spec shape wins the dedup
    assert by_path is not None and "/api/dup" in by_path
    assert by_path["/api/dup"].method == "POST"
    assert seeded == 1


# --------------------------------------------------------------------------- #
# run_generalized_sqli — remaining gating and sqlmap escalation                #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_sqli_login_like_endpoint_routes_to_login_bypass(monkeypatch):
    from ai_osop.core import sqli_oracle

    async def fake_login_bypass(c, url, **kw):
        return {
            "technique": "auth_bypass",
            "endpoint": url,
            "payload": "' OR 1=1--",
            "confidence": 1.0,
        }

    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", fake_login_bypass)
    monkeypatch.setattr(sqli_oracle, "detect_error_based", _none)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", _none)

    eps = [_ep(url="http://t/rest/user/login", method="POST", path="/rest/user/login",
               has_body=True, body_schema_keys=["email", "password"])]
    gm = _graph_with_endpoints(eps)

    persisted, _ = await ds.run_generalized_sqli("eng-l", gm, per_check_timeout=5.0)

    assert len(persisted) == 1
    v = persisted[0]
    # auth_bypass technique escalates severity to CRITICAL
    assert v.severity == Severity.CRITICAL
    assert v.vuln_type == VulnClass.SQLI
    assert "auth_bypass" in v.title
    assert v.evidence[0]["technique"] == "auth_bypass"


@pytest.mark.asyncio
async def test_sqli_timeouts_and_oracle_errors_become_datapoints(monkeypatch):
    from ai_osop.core import sqli_oracle

    async def _hang(c, url, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(sqli_oracle, "detect_error_based", _hang)
    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", _hang)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", _hang)

    eps = [_ep(url="http://t/s1", path="/s1", query_keys=["q"]),
           _ep(url="http://t/s2", path="/s2", query_keys=["q"])]
    gm = _graph_with_endpoints(eps)

    persisted, examined = await ds.run_generalized_sqli("eng-hang", gm, per_check_timeout=0.2)
    # every oracle timed out on every candidate; nothing persists, count is the
    # full examined surface
    assert persisted == []
    assert examined == 2


@pytest.mark.asyncio
async def test_sqli_sqlmap_escalation_produces_tool_demonstrated_finding(monkeypatch):
    from ai_osop.core import sqli_oracle, sqlmap_confirm as sc

    async def fake_error(c, url, *, param=None, **kw):
        return {"technique": "error_based", "endpoint": url, "parameter": "q",
                "payload": "'", "confidence": 1.0}

    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", _none)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", _none)

    monkeypatch.setattr(sc, "sqlmap_available", lambda: True)

    sm_kwargs = {}

    async def fake_sqlmap_confirm(url, *, param=None, data=None, timeout=None):
        sm_kwargs.update(url=url, param=param, data=data)
        return {"injectable": True, "parameter": "q", "dbms": "SQLite",
                "techniques": ["error-based", "UNION query"], "payloads": ["' AND 1=1"]}

    monkeypatch.setattr(sc, "sqlmap_confirm", fake_sqlmap_confirm)

    eps = [_ep(url="http://t/rest/products/search", path="/rest/products/search",
               query_keys=["q"])]
    gm = _graph_with_endpoints(eps)

    persisted, _ = await ds.run_generalized_sqli(
        "eng-sm", gm, per_check_timeout=5.0, confirm_with_sqlmap=True
    )

    assert len(persisted) == 1
    v = persisted[0]
    # sqlmap-confirmed: escalated tool_source, real (non-simulated) finding
    assert v.tool_source == "sqlmap"
    assert v.validated is True
    assert v.simulated is False
    assert v.confidence == 0.98
    assert v.severity == Severity.CRITICAL
    ev = v.evidence[0]
    assert ev["provenance"] == "sqlmap"
    assert ev["dbms"] == "SQLite"
    assert ev["oracle_prefilter"] == "error_based"
    # sqlmap was aimed at the SAME point the oracle flagged
    assert sm_kwargs["url"] == "http://t/rest/products/search"
    assert sm_kwargs["param"] == "q"


@pytest.mark.asyncio
async def test_sqli_sqlmap_negative_falls_back_to_oracle_finding(monkeypatch):
    from ai_osop.core import sqli_oracle, sqlmap_confirm as sc

    async def fake_error(c, url, *, param=None, **kw):
        return {"technique": "error_based", "endpoint": url, "parameter": "q",
                "payload": "'", "confidence": 1.0}

    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", _none)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", _none)

    monkeypatch.setattr(sc, "sqlmap_available", lambda: True)

    async def fake_sqlmap_confirm(url, *, param=None, data=None, timeout=None):
        return {"injectable": False}

    monkeypatch.setattr(sc, "sqlmap_confirm", fake_sqlmap_confirm)

    eps = [_ep(url="http://t/rest/products/search", path="/rest/products/search",
               query_keys=["q"])]
    gm = _graph_with_endpoints(eps)

    persisted, _ = await ds.run_generalized_sqli(
        "eng-sm2", gm, per_check_timeout=5.0, confirm_with_sqlmap=True
    )

    assert len(persisted) == 1
    v = persisted[0]
    # sqlmap said no -> the in-band oracle finding stands, non-escalated source
    assert v.tool_source == "deterministic_scan_generalized"
    assert v.severity == Severity.HIGH  # error_based != auth_bypass
    assert v.evidence[0]["provenance"] == "http"
