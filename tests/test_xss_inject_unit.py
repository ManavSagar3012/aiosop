"""Offline unit tests for the xss_scan payload injector (pure, no network)."""

from ai_osop.agents.vuln_agent import VulnAnalysisAgent as V


def test_inject_query_fuzzes_last_param():
    assert V._inject_payload("http://h/s?a=1&b=2", "PWN") == "http://h/s?a=1&b=PWN"


def test_inject_named_param():
    assert V._inject_payload("http://h/s?a=1&b=2", "PWN", param="a") == "http://h/s?a=PWN&b=2"


def test_inject_spa_hash_route():
    # Juice Shop's DOM-XSS sink lives in the fragment query.
    assert V._inject_payload("http://h/#/search?q=test", "PWN") == "http://h/#/search?q=PWN"


def test_inject_explicit_placeholder_is_encoded():
    # Spaces must be percent-encoded so the URL stays well-formed.
    assert V._inject_payload("http://h/x?u=OSOPINJECT", "a b") == "http://h/x?u=a%20b"


def test_inject_no_query_appends_default_q():
    assert V._inject_payload("http://h/path", "PWN") == "http://h/path?q=PWN"
