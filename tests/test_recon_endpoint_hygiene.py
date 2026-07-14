"""Recon endpoint hygiene: malformed-URL rejection + scope gating.

Regression for two live-audit findings:
  * malformed extraction (/core/  https:/cdn.jsdelivr.net/chart.js) stored as endpoints
  * scope bleed (www.syfe.com, cdn.prod.website-files.com stored despite uat-only scope)
"""

from ai_osop.agents.recon_agent import ReconAgent, normalize_endpoint_url
from ai_osop.core.models import ScopeDefinition


def test_normalize_rejects_malformed():
    bad = [
        "https://uat-bugbounty.nonprod.syfe.com/core/    https:/cdn.jsdelivr.net/npm/chart.js",
        "https://host/a/\thttps://evil/x",
        "not-a-url",
        "ftp://host/x",
        "",
        None,
        "https:///nohost",
    ]
    for u in bad:
        assert normalize_endpoint_url(u) is None, u


def test_normalize_keeps_valid_including_url_query_param():
    keep = [
        "https://uat-bugbounty.nonprod.syfe.com/api/items",
        "https://uat-bugbounty.nonprod.syfe.com/graphql",
        # a real, high-value param whose VALUE is a URL — must NOT be rejected
        "https://uat-bugbounty.nonprod.syfe.com/_next/image?url=https://cdn/x.png&q=75",
        "http://host/path?redirect=https://other/cb",
    ]
    for u in keep:
        assert normalize_endpoint_url(u) == u.strip(), u


def test_scope_enforcer_gates_offscope_hosts():
    enf = ReconAgent._build_scope_enforcer(
        {"scope": ScopeDefinition(engagement_id="e", domains=["uat-bugbounty.nonprod.syfe.com"]).model_dump()}
    )
    assert enf is not None
    assert enf.validate_target("https://uat-bugbounty.nonprod.syfe.com/core") is True
    for off in ("https://www.syfe.com/", "https://cdn.prod.website-files.com/x.js"):
        try:
            assert enf.validate_target(off) is False, off
        except Exception:
            pass  # raising OutOfScope is also a rejection


def test_host_in_scope_is_flat_and_non_raising():
    # _persist_endpoint uses host_in_scope (not the recursive validate_target),
    # which must never raise and must reject off-scope + accept in-scope hosts.
    enf = ReconAgent._build_scope_enforcer(
        {"scope": ScopeDefinition(engagement_id="e", domains=["uat-bugbounty.nonprod.syfe.com"]).model_dump()}
    )
    assert enf.host_in_scope("uat-bugbounty.nonprod.syfe.com") is True
    assert enf.host_in_scope("api.uat-bugbounty.nonprod.syfe.com") is True  # subdomain
    assert enf.host_in_scope("www.syfe.com") is False
    assert enf.host_in_scope("cdn.prod.website-files.com") is False
    assert enf.host_in_scope(None) is False
    assert enf.host_in_scope("") is False


def test_build_scope_enforcer_none_without_scope():
    assert ReconAgent._build_scope_enforcer({}) is None


if __name__ == "__main__":
    test_normalize_rejects_malformed()
    test_normalize_keeps_valid_including_url_query_param()
    test_scope_enforcer_gates_offscope_hosts()
    test_build_scope_enforcer_none_without_scope()
    print("recon endpoint-hygiene tests OK")
