"""Scheme selection for autonomous-discovery target URLs (benchmark 2026-07-04)."""

from ai_osop.orchestrator.engagement_manager import EngagementManager as EM


def test_localhost_is_http():
    assert EM._domain_to_url("localhost:3000") == "http://localhost:3000/"


def test_private_range_is_http():
    assert EM._domain_to_url("192.168.1.10:8080") == "http://192.168.1.10:8080/"
    assert EM._domain_to_url("10.0.0.5") == "http://10.0.0.5/"
    assert EM._domain_to_url("172.16.0.9") == "http://172.16.0.9/"


def test_public_domain_is_https():
    assert EM._domain_to_url("example.com") == "https://example.com/"
    assert EM._domain_to_url("app.target.io") == "https://app.target.io/"


def test_explicit_scheme_respected():
    assert EM._domain_to_url("http://foo.com/") == "http://foo.com/"
    assert EM._domain_to_url("https://foo.com") == "https://foo.com/"


def test_public_172_not_private():
    # 172.32 is outside the private 172.16-31 range -> https
    assert EM._domain_to_url("172.32.0.1") == "https://172.32.0.1/"
