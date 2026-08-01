"""Regression test for SPA/XHR route extraction from JS bundles.

Guards the recon fix (commit e49075ee, AIOSOP-RECON-JS-TEMPLATE-ROUTE-2026-07-26):
Angular/SPA API calls are template literals like

    `${this.hostServer}/rest/products/search?q=${e}`

so the route path is NOT preceded by a quote and the original quoted
``js_route_pattern`` could never see it. The confirmed OWASP Juice Shop SQLi
endpoint (/rest/products/search, param q) was therefore invisible to recon and
never scanned.

This test pins the two behaviours the fix depends on:
1. template-literal REST/API routes are extracted, and
2. the FIRST literal query-param is captured PER ROUTE (not a global param
   soup assigned to every endpoint).

Run: .venv/Scripts/python.exe tests/test_js_route_extraction.py
"""

import re

# The exact patterns used in recon_agent._active_crawl_target.
JS_ROUTE_PATTERN = re.compile(r"""["'`](/(?:[A-Za-z0-9_.\-]+/?)+(?:\?[^"'`\s<>]*)?)["'`]""")
JS_API_ROUTE_PATTERN = re.compile(r"""(/(?:rest|api)/[A-Za-z0-9_/\-]+)(?:\?([A-Za-z0-9_]+)=)?""")


def extract(js_text):
    """Mirror of the recon extraction: route -> sorted param list."""
    route_params = {}
    for m in JS_API_ROUTE_PATTERN.finditer(js_text):
        rp = route_params.setdefault(m.group(1), set())
        if m.group(2):
            rp.add(m.group(2))
    for route in JS_ROUTE_PATTERN.findall(js_text):
        route_params.setdefault(route, set())
    return {k: sorted(v) for k, v in route_params.items()}


def test_template_literal_route_with_param():
    # The real shape from Juice Shop's minified bundle.
    js = r"""get(`${this.hostServer}/rest/products/search?q=${e}`)"""
    out = extract(js)
    assert "/rest/products/search" in out, f"search route missing: {out}"
    assert out["/rest/products/search"] == ["q"], f"wrong params: {out['/rest/products/search']}"


def test_login_post_route_extracted():
    js = r"""this.http.post(`${this.hostServer}/rest/user/login`,e)"""
    out = extract(js)
    assert "/rest/user/login" in out, f"login route missing: {out}"


def test_params_are_per_route_not_global():
    # productId appears on one route; it must NOT leak onto the search route.
    js = r"""a(`${h}/rest/products/search?q=${x}`);b(`${h}/api/Products?productId=${y}`)"""
    out = extract(js)
    assert out["/rest/products/search"] == ["q"], out
    assert out["/api/Products"] == ["productId"], out
    # the search route must not carry productId (the old global-scrape bug)
    assert "productId" not in out["/rest/products/search"]


def test_quoted_route_still_matched():
    js = r"""const r="/rest/admin";"""
    out = extract(js)
    assert "/rest/admin" in out, out
    assert out["/rest/admin"] == [], out


if __name__ == "__main__":
    test_template_literal_route_with_param()
    test_login_post_route_extracted()
    test_params_are_per_route_not_global()
    test_quoted_route_still_matched()
    print("js route extraction self-check OK: template-literal routes + per-route params")
