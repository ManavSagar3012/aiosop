"""Phase 0.2 — HackerOne report -> finding_type classification.

The live sync path previously hardcoded finding_type="unknown", starving the P2b
learning loop of real category signal. It now classifies from the H1 report:
CWE first (most reliable), then weakness name, then title/vulnerability_information.
These tests lock that behavior AND that the classifier's output aligns with the
hypothesis-category taxonomy so ingested outcomes actually feed calibration.
"""
import pytest

from ai_osop.adapters.bug_bounty_adapter import BugBountyAdapter
from ai_osop.core.taxonomy import category_for_finding_type, HYPOTHESIS_CATEGORIES


@pytest.fixture
def adapter():
    return BugBountyAdapter()


def _report_with_cwe(cwe):
    return {"relationships": {"weakness": {"data": {"attributes": {"cwe": cwe}}}}}


def _report_with_weakness(name):
    return {"relationships": {"weakness": {"data": {"attributes": {"name": name}}}}}


def _report_with_title(title, info=""):
    return {"attributes": {"title": title, "vulnerability_information": info}}


@pytest.mark.parametrize("cwe,expected", [
    ("CWE-79", "xss"),
    ("CWE-89", "sqli"),
    ("CWE-918", "ssrf"),
    ("CWE-639", "idor"),
    ("CWE-285", "idor"),
    ("CWE-352", "csrf"),
    ("CWE-94", "rce"),
    ("CWE-601", "open_redirect"),
])
def test_cwe_first_classification(adapter, cwe, expected):
    assert adapter._parse_finding_type_from_h1_report(_report_with_cwe(cwe)) == expected


@pytest.mark.parametrize("name,expected", [
    ("Cross-site Scripting (XSS)", "xss"),
    ("Server-Side Request Forgery", "ssrf"),
    ("Insecure Direct Object Reference (IDOR)", "idor"),
    ("GraphQL introspection", "graphql"),
])
def test_weakness_name_classification(adapter, name, expected):
    assert adapter._parse_finding_type_from_h1_report(_report_with_weakness(name)) == expected


@pytest.mark.parametrize("title,expected", [
    ("Account takeover via password reset", "ato"),
    ("Privilege escalation to admin", "privesc"),
    ("Race condition in coupon redemption", "race_condition"),
    ("JWT signature not verified", "jwt_abuse"),
    ("Prototype pollution in merge()", "prototype_pollution"),
])
def test_title_fallback_classification(adapter, title, expected):
    assert adapter._parse_finding_type_from_h1_report(_report_with_title(title)) == expected


def test_unclassifiable_is_unknown(adapter):
    assert adapter._parse_finding_type_from_h1_report(_report_with_title("Something vague")) == "unknown"


def test_classifier_outputs_align_with_taxonomy(adapter):
    """The auth/authz-family classifier outputs must feed a real hypothesis category
    (this is what makes the H1 signal actually reach calibration)."""
    for ft in ("idor", "ato", "privesc", "jwt_abuse", "oauth2", "ssrf", "open_redirect",
               "xss", "stored_xss", "dom_xss", "csrf", "graphql", "race_condition",
               "business_logic", "cloud_vuln"):
        assert category_for_finding_type(ft) in HYPOTHESIS_CATEGORIES, ft
    # Injection-family outputs intentionally fall through (no hypothesis category).
    for ft in ("sqli", "rce", "xxe", "ssti", "deserialization", "path_traversal", "nosql_injection"):
        assert category_for_finding_type(ft) not in HYPOTHESIS_CATEGORIES, ft
