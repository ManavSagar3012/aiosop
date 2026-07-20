"""Offline unit tests for the deterministic scan backbone.

Verifies that ``run_deterministic_scan`` and ``run_generalized_sqli``:

1. Only persist findings whose oracle returned ``validated=True`` — the
   honesty contract at deterministic_scan.py:96.
2. Tag every persisted finding with ``provenance="deterministic_oracle"``
   (suite path) or ``provenance="http"`` (generalized path).
3. Skip silently on a persist failure (a single bad graph write must not
   sink the rest — deterministic_scan.py:124-125).
4. Drive the time-blind oracle from the generalized path (new on this branch).
5. Cap and DEDUPE candidates in the generalized path.

The benchmark ``bench`` module is loaded only inside the suite-path test via a
monkeypatched stub — no real Juice Shop container is required.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from ai_osop.core import deterministic_scan as ds
from ai_osop.core.models import Vulnerability


# --------------------------------------------------------------------------- #
# Test doubles                                                                 #
# --------------------------------------------------------------------------- #


class _FakeGraph:
    """Records every add_vulnerability call; configurable failure on demand."""

    def __init__(self, *, fail_on: int | None = None):
        self.persisted: List[Vulnerability] = []
        self.calls = 0
        self._fail_on = fail_on

    async def add_vulnerability(self, vuln: Vulnerability) -> None:
        self.calls += 1
        if self._fail_on is not None and self.calls == self._fail_on:
            raise RuntimeError("simulated graph write failure")
        self.persisted.append(vuln)


class _CheckResult:
    def __init__(self, validated: bool, evidence: dict | None = None,
                 confidence: float = 1.0):
        self.validated = validated
        self.evidence = evidence or {}
        self.confidence = confidence


def _fake_bench(expected_total: int = 3):
    """Build a fake ``bench`` module exposing MANIFEST, CHECKS, Target."""
    entries = [
        SimpleNamespace(
            check_id=f"check_{i}",
            name=f"check {i}",
            owasp="A03",
            cwe="CWE-89",
            expected=True,
        )
        for i in range(expected_total)
    ]
    # check_0 validates; check_1 does not (must be skipped); check_2 validates.
    results = {
        "check_0": _CheckResult(True, {"payload": "p0", "request": "r0"}),
        "check_1": _CheckResult(False),
        "check_2": _CheckResult(True, {"payload": "p2", "request": "r2"}),
    }

    class _Target:
        def __init__(self, base_url, client):
            self.base_url = base_url
            self.client = client

    async def _check_fn_factory(check_id):
        async def _fn(target):
            return results[check_id]
        return _fn

    fake = SimpleNamespace(
        MANIFEST=entries,
        CHECKS={e.check_id: asyncio.coroutine(lambda cid=e.check_id: None) for e in entries}
        if False
        else None,
        Target=_Target,
    )
    # CHECKS cannot use comprehension binding cleanly; build explicitly.
    fake.CHECKS = {
        "check_0": _sync_coro(_CheckResult(True, {"payload": "p0", "request": "r0"})),
        "check_1": _sync_coro(_CheckResult(False)),
        "check_2": _sync_coro(_CheckResult(True, {"payload": "p2", "request": "r2"})),
    }
    return fake


def _sync_coro(result):
    """Return an async callable that yields ``result`` regardless of input."""

    async def _fn(target):
        return result

    return _fn


# --------------------------------------------------------------------------- #
# run_deterministic_scan                                                       #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_suite_persists_only_validated_findings(monkeypatch):
    """check_1 returns validated=False -> must NOT be persisted. check_0 and
    check_2 return validated=True -> must be persisted."""
    monkeypatch.setattr(ds, "_load_suite", lambda: _fake_bench(expected_total=3))
    gm = _FakeGraph()

    persisted, validated_ids, expected_total = await ds.run_deterministic_scan(
        "http://t", "eng-test", gm, per_check_timeout=5.0
    )

    assert expected_total == 3
    assert sorted(validated_ids) == ["check_0", "check_2"]
    assert len(persisted) == 2
    assert len(gm.persisted) == 2
    # Every persisted finding carries provenance + validated=True.
    for v in gm.persisted:
        assert v.validated is True
        assert v.tool_source == "deterministic_scan"
        assert v.evidence[0]["provenance"] == "deterministic_oracle"
        assert v.simulated is False


@pytest.mark.asyncio
async def test_suite_skips_silently_on_persist_failure(monkeypatch):
    """A persist failure on one finding must NOT sink the rest (regression for
    the `except Exception: pass` swallow at deterministic_scan.py:124-125)."""
    monkeypatch.setattr(ds, "_load_suite", lambda: _fake_bench(expected_total=3))
    # Fail on the 2nd persist call; 1st and 3rd should still succeed.
    gm = _FakeGraph(fail_on=2)

    persisted, validated_ids, expected_total = await ds.run_deterministic_scan(
        "http://t", "eng-test", gm, per_check_timeout=5.0
    )

    assert expected_total == 3
    # Two were validated by the oracle.
    assert sorted(validated_ids) == ["check_0", "check_2"]
    # But only one survived persistence (the failed one is dropped silently).
    assert len(persisted) == 1
    assert len(gm.persisted) == 1


@pytest.mark.asyncio
async def test_suite_times_out_instead_of_hanging(monkeypatch):
    """A wedged check must be cut off by per_check_timeout, becoming a datapoint
    not a hang."""
    import asyncio as _asyncio

    async def _hang(target):
        await _asyncio.sleep(60)

    fake = SimpleNamespace(
        MANIFEST=[SimpleNamespace(check_id="hang", name="hang", owasp="A", cwe="CWE-89", expected=True)],
        CHECKS={"hang": _hang},
        Target=lambda b, c: SimpleNamespace(),
    )
    monkeypatch.setattr(ds, "_load_suite", lambda: fake)
    gm = _FakeGraph()

    persisted, validated, expected = await ds.run_deterministic_scan(
        "http://t", "eng-test", gm, per_check_timeout=0.5
    )
    assert expected == 1
    assert validated == []
    assert persisted == []


# --------------------------------------------------------------------------- #
# run_generalized_sqli                                                         #
# --------------------------------------------------------------------------- #


class _FakeDriver:
    """Drives ``_discovered_endpoints`` to return a fixed list of endpoints."""

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


def _graph_with_endpoints(endpoints: list[dict]) -> SimpleNamespace:
    """Build a graph_memory double whose _driver yields ``endpoints``."""
    gm = _FakeGraph()
    gm._driver = _FakeDriver(endpoints)
    return gm


@pytest.mark.asyncio
async def test_generalized_drives_time_blind_when_error_based_misses(monkeypatch):
    """New on this branch: the generalized path must run detect_time_blind on a
    GET-like candidate when neither error_based nor login_bypass confirms."""
    from ai_osop.core import sqli_oracle

    calls = {"error": 0, "login": 0, "time": 0}

    async def fake_error(c, url, *, param=None):
        calls["error"] += 1
        return None

    async def fake_login(c, url, **kw):
        calls["login"] += 1
        return None

    async def fake_time(c, url, *, param=None, **kw):
        calls["time"] += 1
        return {
            "technique": "time_blind", "endpoint": url, "parameter": "q",
            "dbms": "postgres", "payload": "1'; SELECT pg_sleep(5)--",
            "control_payload": "1'; SELECT pg_sleep(0)--",
            "control_latency": 0.1, "sleep_latency": 5.0,
            "delta_seconds": 4.9, "min_delta": 3.0, "confidence": 1.0,
        }

    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", fake_login)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", fake_time)

    eps = [{"url": "http://t/search", "method": "GET", "path": "/search",
            "query_keys": ["q"], "has_body": False}]
    gm = _graph_with_endpoints(eps)

    persisted, examined = await ds.run_generalized_sqli(
        "eng-test", gm, per_check_timeout=5.0
    )

    assert calls["error"] == 1
    assert calls["login"] == 0  # not login_like
    assert calls["time"] == 1   # new on this branch
    assert len(persisted) == 1
    v = persisted[0]
    assert v.vuln_type.value == "sqli"
    assert v.evidence[0]["technique"] == "time_blind"
    assert v.evidence[0]["dbms"] == "postgres"
    assert v.validated is True
    assert v.tool_source == "deterministic_scan_generalized"


@pytest.mark.asyncio
async def test_generalized_skips_time_blind_after_error_based_confirms(monkeypatch):
    """If error_based already confirmed, the time oracle must NOT run (avoid
    redundant slow requests)."""
    from ai_osop.core import sqli_oracle

    calls = {"error": 0, "time": 0}

    async def fake_error(c, url, *, param=None):
        calls["error"] += 1
        return {"technique": "error_based", "endpoint": url, "parameter": "q",
                "payload": "'", "http_status": 500, "db_error_excerpt": "...",
                "confidence": 1.0}

    async def fake_time(c, url, **kw):
        calls["time"] += 1
        return None

    async def fake_login(c, url, **kw):
        return None

    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", fake_login)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", fake_time)

    eps = [{"url": "http://t/search", "method": "GET", "path": "/search",
            "query_keys": ["q"], "has_body": False}]
    gm = _graph_with_endpoints(eps)

    persisted, _ = await ds.run_generalized_sqli("eng-test", gm, per_check_timeout=5.0)
    assert len(persisted) == 1
    assert calls["time"] == 0


@pytest.mark.asyncio
async def test_generalized_dedupes_by_shape(monkeypatch):
    """The same path with different id values must collapse to one candidate
    (MAX_CANDIDATES=60 budget guard at deterministic_scan.py:174)."""
    from ai_osop.core import sqli_oracle

    captured_urls: list[str] = []

    async def fake_error(c, url, *, param=None):
        captured_urls.append(url)
        return None

    async def fake_login(c, url, **kw):
        return None

    async def fake_time(c, url, **kw):
        return None

    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", fake_login)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", fake_time)

    # Five endpoints with identical (method, path, params) — must dedupe to 1.
    eps = [
        {"url": f"http://t/search?x={i}", "method": "GET", "path": "/search",
         "query_keys": ["q"], "has_body": False}
        for i in range(5)
    ]
    gm = _graph_with_endpoints(eps)

    await ds.run_generalized_sqli("eng-test", gm, per_check_timeout=5.0)
    assert len(captured_urls) == 1


@pytest.mark.asyncio
async def test_generalized_caps_at_sixty_candidates(monkeypatch):
    """Even with 100 distinct shapes, only MAX_CANDIDATES=60 are scanned."""
    from ai_osop.core import sqli_oracle

    scan_count = 0

    async def fake_error(c, url, *, param=None):
        nonlocal scan_count
        scan_count += 1
        return None

    async def fake_login(c, url, **kw):
        return None

    async def fake_time(c, url, **kw):
        return None

    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", fake_login)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", fake_time)

    eps = [
        {"url": f"http://t/path{i}/search", "method": "GET", "path": f"/path{i}/search",
         "query_keys": ["q"], "has_body": False}
        for i in range(100)
    ]
    gm = _graph_with_endpoints(eps)

    await ds.run_generalized_sqli("eng-test", gm, per_check_timeout=2.0)
    assert scan_count == 60


# --------------------------------------------------------------------------- #
# bootstrap_discovery                                                          #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_bootstrap_seeds_present_api_endpoints():
    """An endpoint returning a non-404 with /api or /rest path is seeded; a 404
    is skipped; an SPA catch-all HTML is skipped."""
    seeded: list = []

    class _GM:
        async def add_endpoint(self, ep):
            seeded.append(ep)

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/api/users":
            return httpx.Response(200, text='[{"id":1}]',
                                  headers={"content-type": "application/json"})
        if path == "/rest/products/search":
            return httpx.Response(200, text='{"data":[]}',
                                  headers={"content-type": "application/json"})
        if path == "/missing":
            return httpx.Response(404, text="not found")
        # SPA catch-all HTML
        return httpx.Response(200, text="<html></html>",
                              headers={"content-type": "text/html"})

    # Patch the module's _COMMON_ENDPOINTS to include only the test paths so
    # we don't depend on the production list.
    saved = ds._COMMON_ENDPOINTS
    ds._COMMON_ENDPOINTS = [
        ("/api/users", "GET", [], False),
        ("/rest/products/search", "GET", ["q"], False),
        ("/missing", "GET", [], False),
        ("/spa", "GET", [], False),
    ]
    try:
        # Patch httpx.AsyncClient globally for this test so bootstrap_discovery
        # uses our MockTransport-backed client without a real network call.
        import httpx as _httpx_mod
        orig_async_client = _httpx_mod.AsyncClient

        class _MockClient(_httpx_mod.AsyncClient):
            def __init__(self, *a, **kw):
                kw["transport"] = _httpx_mod.MockTransport(handler)
                super().__init__(**kw)

        _httpx_mod.AsyncClient = _MockClient
        try:
            count = await ds.bootstrap_discovery(
                "http://t", "eng-test", _GM(), timeout=2.0
            )
        finally:
            _httpx_mod.AsyncClient = orig_async_client
    finally:
        ds._COMMON_ENDPOINTS = saved

    assert count == 2
    paths = {e.path for e in seeded}
    assert paths == {"/api/users", "/rest/products/search"}


@pytest.mark.asyncio
async def test_crawl_param_links_extracts_href_and_string_literals():
    """_crawl_param_links must find parametrized links exposed two ways:
      (a) classic HTML href/action attributes, and
      (b) quoted path+query STRING LITERALS embedded for a JS framework
          (e.g. "Gin":"/catalog?category=Gin") — how ginandjuice.shop exposes
          its injectable ?category= surface. An attribute-only crawler misses (b).
    A quoted string that is NOT a path+query (plain text, a bare path) must be
    ignored so the extractor doesn't manufacture phantom endpoints."""

    home = """
    <html><body>
      <a href="/blog/post?postId=3">a post</a>
      <script>window.__NAV__ = {
        "Gin":"/catalog?category=Gin",
        "Accessories":"/catalog?category=Accessories",
        "label":"just some text, not a url",
        "bare":"/about"
      };</script>
    </body></html>
    """

    def handler(req: httpx.Request) -> httpx.Response:
        # Home carries the links; any followed sub-page is empty.
        if req.url.path in ("", "/"):
            return httpx.Response(200, text=home,
                                  headers={"content-type": "text/html"})
        return httpx.Response(200, text="<html></html>",
                              headers={"content-type": "text/html"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as c:
        links = await ds._crawl_param_links(c, "http://t")

    by_path = {p: keys for p, _m, keys, _b in links}
    # href-based param link found
    assert "/blog/post" in by_path and by_path["/blog/post"] == ["postId"]
    # string-literal param link found (the React case)
    assert "/catalog" in by_path and by_path["/catalog"] == ["category"]
    # non-URL string and paramless path must NOT become endpoints
    assert not any(p not in ("/blog/post", "/catalog") for p in by_path)


# --------------------------------------------------------------------------- #
# auth passthrough — injected client threading (Phase 3.5)                     #
# --------------------------------------------------------------------------- #


class _SentinelClient:
    """Duck-typed stand-in for an auth-aware SessionClient.

    Records the probes it received and whether anyone closed it. The generalized
    surface oracles only call .get/.post/.request, so this minimal surface is
    enough to prove the client is threaded through — and ``closed`` proves the
    caller-owns-lifecycle contract (a scan must never close an injected client).
    """

    def __init__(self):
        self.requests: list = []
        self.closed = False

    async def get(self, url, **kw):
        self.requests.append(("GET", url))
        return httpx.Response(200, text="ok", request=httpx.Request("GET", url))

    async def post(self, url, **kw):
        self.requests.append(("POST", url))
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    async def request(self, method, url, **kw):
        self.requests.append((method, url))
        return httpx.Response(200, text="ok", request=httpx.Request(method, url))

    async def aclose(self):
        self.closed = True

    # Fail loudly if the scan ever tries to use us as an async context manager
    # (which would imply it thinks it owns our lifecycle).
    async def __aenter__(self):  # pragma: no cover - guard
        raise AssertionError("scan must not enter injected client as a context manager")

    async def __aexit__(self, *exc):  # pragma: no cover - guard
        return False


@pytest.mark.asyncio
async def test_scan_client_uses_injected_client_and_never_closes_it():
    """``_scan_client(client)`` must yield the injected client unchanged and leave
    closing it to the caller."""
    sentinel = _SentinelClient()
    async with ds._scan_client(sentinel) as c:
        assert c is sentinel
    assert sentinel.closed is False


@pytest.mark.asyncio
async def test_scan_client_builds_and_owns_client_when_none():
    """With no injected client, ``_scan_client`` builds a real httpx.AsyncClient
    and closes it on exit (the historical, unauthenticated path)."""
    async with ds._scan_client(None) as c:
        assert isinstance(c, httpx.AsyncClient)
        assert c.is_closed is False
    assert c.is_closed is True


@pytest.mark.asyncio
async def test_generalized_sqli_threads_injected_client_to_oracles(monkeypatch):
    """When a client is injected, the SQLi oracles must receive that exact object
    — proving probes ride the authenticated session, not a fresh cookie-less one."""
    from ai_osop.core import sqli_oracle

    seen = {"client": None}

    async def fake_error(c, url, *, param=None):
        seen["client"] = c
        return None

    async def fake_login(c, url, **kw):
        return None

    async def fake_time(c, url, *, param=None, **kw):
        return None

    monkeypatch.setattr(sqli_oracle, "detect_error_based", fake_error)
    monkeypatch.setattr(sqli_oracle, "detect_login_bypass", fake_login)
    monkeypatch.setattr(sqli_oracle, "detect_time_blind", fake_time)

    eps = [{"url": "http://t/search", "method": "GET", "path": "/search",
            "query_keys": ["q"], "has_body": False}]
    gm = _graph_with_endpoints(eps)
    sentinel = _SentinelClient()

    await ds.run_generalized_sqli("eng-test", gm, per_check_timeout=5.0, client=sentinel)

    assert seen["client"] is sentinel
    assert sentinel.closed is False


@pytest.mark.asyncio
async def test_generalized_scan_threads_client_only_to_surface_oracles(monkeypatch):
    """The orchestrator must pass an injected client to the surface oracles (SQLi,
    mass-assignment, injection) but NOT to the identity-managing ones (JWT, IDOR),
    which own their own auth model."""
    got: dict = {}

    async def fake_sqli(eid, gm, **kw):
        got["sqli"] = kw.get("client", "MISSING")
        return [], 0

    async def fake_ma(eid, gm, **kw):
        got["ma"] = kw.get("client", "MISSING")
        return [], 0

    async def fake_jwt(eid, gm, **kw):
        got["jwt_has_client"] = "client" in kw
        return [], 0

    async def fake_idor(eid, gm, **kw):
        got["idor_has_client"] = "client" in kw
        return [], 0

    async def fake_inj(eid, gm, **kw):
        got["inj"] = kw.get("client", "MISSING")
        return [], 0

    monkeypatch.setattr(ds, "run_generalized_sqli", fake_sqli)
    monkeypatch.setattr(ds, "run_generalized_massassign", fake_ma)
    monkeypatch.setattr(ds, "run_generalized_jwt", fake_jwt)
    monkeypatch.setattr(ds, "run_generalized_idor", fake_idor)
    monkeypatch.setattr(ds, "run_generalized_injection", fake_inj)

    sentinel = _SentinelClient()
    await ds.run_generalized_scan("eng-test", _FakeGraph(), client=sentinel)

    # surface oracles receive the exact injected client
    assert got["sqli"] is sentinel
    assert got["ma"] is sentinel
    assert got["inj"] is sentinel
    # identity-managing oracles are called WITHOUT a client kwarg
    assert got["jwt_has_client"] is False
    assert got["idor_has_client"] is False
