"""Tests for SPA/JS endpoint harvesting.

Covers the decisive discovery gap on SPAs (e.g. OWASP Juice Shop): routes and
API paths embedded in JS bundles and inline scripts that are invisible if the
crawler only follows server-rendered <a href> links.
"""

from typing import Any, Dict, List, Optional

import pytest

from ai_osop.core.spa_harvester import (
    HarvestResult,
    endpoint_candidates_from_html,
    endpoint_candidates_from_js_text,
    merge_candidates,
)

JS_BUNDLE_SNIPPET = """
const a = "/rest/products/search?q=";
const b = "https://target.local/rest/user/login";
var cfg = {'apiHost': 'https://api.target.local/v1', 'basePath': '/api'};
fetch(`${this.hostServer}/rest/user/info`);
axios.get("/api/version");
this.$router.push("/account/profile");
"""


HTML_SNIPPET = """
<html>
  <head>
    <script src="/static/main.abc.js"></script>
    <script src="https://cdn.other/lib.js"></script>
  </head>
  <body>
    <a href="/about">About</a>
    <a href="https://out-of-scope.evil/phish">Phish</a>
    <form action="/rest/user/login" method="post">
      <input type="text" name="email">
      <input type="password" name="password">
    </form>
    <script>
      const internal = "/rest/products/search?q=apple";
      window.apiBase = "https://target.local/rest/";
      window.endpoints = ["/rest/user/login", "/rest/products/search"];
    </script>
  </body>
</html>
"""


def test_js_text_extraction_finds_absolute_and_relative_api_routes():
    """Router literals, fetch calls, and template-literal API paths are extracted."""
    found = endpoint_candidates_from_js_text(JS_BUNDLE_SNIPPET, base_url="https://target.local/")
    urls = {c.url for c in found}
    assert any("/rest/products/search" in u and "q=" in u for u in urls)
    assert any("https://target.local/rest/user/login" in u for u in urls)
    assert any("/api/version" in u for u in urls)
    # template-literal hostServer missing literal protocol — still captures path+param
    assert any("/rest/user/info" in u for u in urls)


def test_html_extraction_harvests_scripts_and_inline_strings():
    """HTML <script> src and inline JS strings both contribute candidates."""
    found = endpoint_candidates_from_html(HTML_SNIPPET, base_url="https://target.local/")
    urls = {c.url for c in found}
    assert any("/static/main.abc.js" in u for u in urls)
    assert any("Phish" not in u for u in urls)  # out-of-scope link dropped by host logic
    assert any("/rest/user/login" in u for u in urls)
    assert any("/rest/products/search" in u for u in urls)


def test_merge_candidates_dedupes_and_carries_source_and_evidence():
    """Same path found from HTML and JS merges; differing param sets stay distinct.

    `/rest/products/search` must remain in the corpus with a `q` query parameter
    (the surface the SQLi scanner needs) and with `productId` (a separate form).
    """
    html_found = endpoint_candidates_from_html(
        HTML_SNIPPET, base_url="https://target.local/"
    )
    js_found = endpoint_candidates_from_js_text(
        JS_BUNDLE_SNIPPET, base_url="https://target.local/"
    )
    merged = merge_candidates(html_found, js_found)

    urls = {c.url for c in merged}
    assert any(u.endswith("/rest/user/login") for u in urls)
    assert any("target.local" in c.url for c in merged if c.url.startswith("https://"))

    # The parameter contract for a merged search endpoint differs between
    # observations; both variants must be persisted, not collapsed.
    variants = [c for c in merged if "/rest/products/search" in c.url]
    params_seen = {p for c in variants for p in c.parameters}
    assert "q" in params_seen
    assert "productId" in params_seen
    assert any(len(c.sources) >= 2 for c in variants), "multi-source evidence retained"
    assert any("q=apple" in c.url for c in variants), "query string preserved on absolute URL"


@pytest.mark.asyncio
async def test_spa_harvester_pipeline_fetches_js_and_emits_endpoints():
    """Integration-style: harvester follows main bundle reference and returns Endpoint objects."""
    from unittest.mock import AsyncMock, MagicMock

    class _FakeClient:
        async def get(self, url: str, **kw: Any) -> MagicMock:
            resp = MagicMock()
            resp.text = JS_BUNDLE_SNIPPET if url.endswith("main.abc.js") else HTML_SNIPPET
            resp.status_code = 200
            resp.headers = {}
            resp.raise_for_status = lambda: None
            return resp

    class _Graph:
        def __init__(self):
            self.added: List[Any] = []

        async def add_endpoint(self, ep: Any) -> None:
            self.added.append(ep)

    from ai_osop.core.spa_harvester import SpaHarvestConfig, harvest_spa_endpoints

    graph = _Graph()
    client = _FakeClient()
    cfg = SpaHarvestConfig(max_bundle_fetches=3, js_route_limit=50)
    result = await harvest_spa_endpoints(
        "https://target.local",
        client=client,
        graph=graph,
        engagement_id="eng-test",
        cfg=cfg,
    )

    assert len(graph.added) > 0
    assert any("rest/products/search" in e.url for e in graph.added)
    assert any("q" in (e.query_keys or []) for e in graph.added)
    assert result.js_files_seen >= 1
    assert result.endpoints_persisted == len(graph.added)
