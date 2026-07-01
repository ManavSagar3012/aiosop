"""Tests for the P1 URL-intelligence recon multiplier."""
from ai_osop.core.url_intelligence import (
    INTERESTING_PARAMS,
    classify_url,
    endpoint_template,
    extract_params,
    mine_urls,
)


def test_extract_params_pulls_query_keys():
    assert extract_params("http://t/a?redirect=x&debug=1") == ["debug", "redirect"]
    assert extract_params("http://t/a") == []
    assert extract_params("not a url") == []


def test_endpoint_template_collapses_id_segments():
    # numeric, uuid, and long-hex segments all collapse to {id}
    assert endpoint_template("https://t.com/user/123/orders/9") == "t.com/user/{id}/orders/{id}"
    assert endpoint_template("https://t.com/u/9f86d081884c7d659a2feaa0c55ad015") == "t.com/u/{id}"
    # query string dropped; two different ids dedupe to one template
    a = endpoint_template("https://t.com/item/1?x=1")
    b = endpoint_template("https://t.com/item/2?y=2")
    assert a == b == "t.com/item/{id}"


def test_classify_url_flags_interesting():
    assert "interesting_file" in classify_url("http://t/backup.sql")
    assert "interesting_path" in classify_url("http://t/api/v1/users")
    assert "param:open_redirect" in classify_url("http://t/go?redirect=http://evil")
    assert "param:ssrf" in classify_url("http://t/fetch?url=http://169.254.169.254")
    assert classify_url("http://t/index.html") == []


def test_mine_urls_dedupes_and_prioritises():
    urls = [
        "https://t.com/user/1?id=1",
        "https://t.com/user/2?id=2",          # same endpoint template as above
        "https://t.com/go?redirect=/evil",     # open-redirect param
        "https://t.com/fetch?url=http://x",     # ssrf param
        "https://t.com/db-backup.sql",          # interesting file
        "https://t.com/api/internal/debug",     # interesting path
    ]
    intel = mine_urls(urls)

    assert intel.total_urls == 6
    # /user/1 and /user/2 collapse -> fewer unique endpoints than input URLs
    assert "t.com/user/{id}" in intel.unique_endpoints
    assert len(intel.unique_endpoints) < len(urls)
    # high-signal params surfaced with their bug class
    assert intel.interesting_params.get("redirect") == "open_redirect"
    assert intel.interesting_params.get("url") == "ssrf"
    # frequency counts the repeated 'id' param
    assert intel.param_frequency.get("id") == 2
    # files/paths captured
    assert any("db-backup.sql" in u for u in intel.interesting_files)
    assert any("/api/internal/debug" in u for u in intel.interesting_paths)


def test_interesting_params_catalog_is_sane():
    # spot-check the catalog maps the classic high-impact params
    for p in ("redirect", "url", "file", "cmd", "id"):
        assert p in INTERESTING_PARAMS
