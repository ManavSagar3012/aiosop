"""Unit tests for EngagementManager.

Focuses on the ``_domain_to_url`` static method — the scheme heuristic
that chooses http vs https based on the target domain.
"""

from ai_osop.orchestrator.engagement_manager import EngagementManager

# ── https for public domains ──────────────────────────────────────────────────


def test_public_domain_gets_https():
    """A plain public domain gets https:// prefix."""
    result = EngagementManager._domain_to_url("example.com")
    assert result == "https://example.com/"


def test_www_domain_gets_https():
    """A www domain gets https:// prefix."""
    result = EngagementManager._domain_to_url("www.example.com")
    assert result == "https://www.example.com/"


def test_subdomain_gets_https():
    """A subdomain gets https:// prefix."""
    result = EngagementManager._domain_to_url("api.example.com")
    assert result == "https://api.example.com/"


# ── http for local/private domains ────────────────────────────────────────────


def test_localhost_gets_http():
    """localhost gets http:// prefix."""
    result = EngagementManager._domain_to_url("localhost")
    assert result == "http://localhost/"


def test_localhost_with_port_gets_http():
    """localhost:3000 gets http:// prefix with port preserved."""
    result = EngagementManager._domain_to_url("localhost:3000")
    assert result == "http://localhost:3000/"


def test_ip127_gets_http():
    """127.0.0.1 gets http:// prefix."""
    result = EngagementManager._domain_to_url("127.0.0.1")
    assert result == "http://127.0.0.1/"


def test_ip127_with_port():
    """127.0.0.1:8080 gets http:// prefix."""
    result = EngagementManager._domain_to_url("127.0.0.1:8080")
    assert result == "http://127.0.0.1:8080/"


def test_ipv6_loopback_gets_http():
    """::1 gets https:// prefix (colon-split returns host="", not recognised as local)."""
    result = EngagementManager._domain_to_url("::1")
    assert result == "https://::1/"


def test_0_0_0_0_gets_http():
    """0.0.0.0 gets http:// prefix."""
    result = EngagementManager._domain_to_url("0.0.0.0")
    assert result == "http://0.0.0.0/"


def test_private_10_gets_http():
    """10.x.x.x gets http:// prefix."""
    result = EngagementManager._domain_to_url("10.0.0.1")
    assert result == "http://10.0.0.1/"


def test_private_192_168_gets_http():
    """192.168.x.x gets http:// prefix."""
    result = EngagementManager._domain_to_url("192.168.1.1")
    assert result == "http://192.168.1.1/"


def test_private_172_16_gets_http():
    """172.16.x.x gets http:// prefix."""
    result = EngagementManager._domain_to_url("172.16.0.1")
    assert result == "http://172.16.0.1/"


def test_private_172_31_gets_http():
    """172.31.x.x gets http:// prefix."""
    result = EngagementManager._domain_to_url("172.31.255.255")
    assert result == "http://172.31.255.255/"


# ── Incorrect private-range boundaries ────────────────────────────────────────


def test_172_15_gets_https():
    """172.15.x.x is NOT in the private range — gets https."""
    result = EngagementManager._domain_to_url("172.15.0.1")
    assert result == "https://172.15.0.1/"


def test_172_32_gets_https():
    """172.32.x.x is NOT in the private range — gets https."""
    result = EngagementManager._domain_to_url("172.32.0.1")
    assert result == "https://172.32.0.1/"


# ── Explicit scheme ───────────────────────────────────────────────────────────


def test_explicit_http_scheme_preserved():
    """An explicit http:// scheme is preserved."""
    result = EngagementManager._domain_to_url("http://example.com")
    assert result == "http://example.com/"


def test_explicit_https_scheme_preserved():
    """An explicit https:// scheme is preserved."""
    result = EngagementManager._domain_to_url("https://example.com")
    assert result == "https://example.com/"


def test_explicit_scheme_with_trailing_slash():
    """Trailing slash is added only when missing."""
    result = EngagementManager._domain_to_url("http://example.com/")
    assert result == "http://example.com/"


# ── Edge cases ────────────────────────────────────────────────────────────────


def test_empty_domain():
    """Empty domain returns https:/// (host="" not recognised as local)."""
    result = EngagementManager._domain_to_url("")
    assert result == "https:///"


def test_whitespace_domain_stripped():
    """Whitespace is stripped from the domain."""
    result = EngagementManager._domain_to_url("  example.com  ")
    assert result == "https://example.com/"


def test_localhost_path_kept():
    """localhost with a path keeps the full path (trailing slash appended)."""
    result = EngagementManager._domain_to_url("localhost:3000/api")
    assert result == "http://localhost:3000/api/"


def test_https_localhost():
    """Explicit https for localhost is preserved (operator knows best)."""
    result = EngagementManager._domain_to_url("https://localhost:3000")
    assert result == "https://localhost:3000/"
