"""
Regression tests for DifferentialAuthEngine ownership-proof precision.

Surfaced by the Juice Shop capability benchmark (2026-07-04): the ownership
match used a naive substring check of ``resource.value`` against the whole
response body. For short/numeric identifiers (basket id "1") or path values
("/"), that substring appears in almost any response, so the engine emitted a
0.9-confidence "IDOR" on public/identical responses — a triage-failing false
positive on the single most common IDOR shape (small integer IDs).

These tests pin the intended behavior:
  1. A public/identical response with a short/numeric resource value must NOT be
     reported (ownership proof must not trip on incidental substrings).
  2. A genuine cross-account read (attacker's response structurally contains the
     victim's owned object id) MUST still be reported with high confidence.
"""

import asyncio

from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
from ai_osop.core.models import Resource


def _run(coro):
    return asyncio.run(coro)


def _res(value, engagement_id="t"):
    return Resource(
        id=f"r:{value}",
        type="basket",
        value=str(value),
        owner_identity_id="victim@x",
        metadata={},
        engagement_id=engagement_id,
    )


def test_public_identical_short_value_is_not_flagged():
    """FALSE-POSITIVE GUARD: identical public responses + short numeric value."""
    engine = DifferentialAuthEngine(session_memory=None)
    identical = {"status_code": 200, "body": {"status": "success", "data": []}}
    finding = _run(
        engine.compare(
            identity_a_evidence=identical,
            identity_b_evidence={**identical, "user_label": "attacker"},
            resource=_res("1"),  # short numeric id -> must not substring-match
            expected_allowed=False,
            anonymous_evidence=identical,  # attacker sees what anon sees => public
        )
    )
    assert finding is None, f"expected suppression, got {finding}"


def test_path_value_slash_is_not_flagged():
    """FALSE-POSITIVE GUARD: '/' value against HTML body (the benchmark's case)."""
    engine = DifferentialAuthEngine(session_memory=None)
    html = {"status_code": 200, "body": "<html><body>welcome</body></html>"}
    finding = _run(
        engine.compare(
            identity_a_evidence=html,
            identity_b_evidence={**html, "user_label": "attacker"},
            resource=_res("/"),
            expected_allowed=False,
            anonymous_evidence=html,
        )
    )
    assert finding is None, f"expected suppression for public page, got {finding}"


def test_nested_id_cross_account_detected():
    """TRUE-POSITIVE: real APIs wrap the object under data/result; ownership proof
    must see the id at depth (this is the live Juice Shop basket shape, which the
    benchmark under-scored to 0.5 before this fix)."""
    engine = DifferentialAuthEngine(session_memory=None)
    owner = {
        "status_code": 200,
        "body": {"status": "success", "data": {"id": 15, "UserId": 33, "Products": []}},
    }
    attacker = {
        "status_code": 200,
        "body": {"status": "success", "data": {"id": 15, "UserId": 33, "Products": []}},
        "user_label": "attacker",
    }
    anon = {"status_code": 401, "body": {"error": "unauthorized"}}
    finding = _run(
        engine.compare(
            identity_a_evidence=owner,
            identity_b_evidence=attacker,
            resource=_res("15"),  # numeric id, nested under data
            expected_allowed=False,
            anonymous_evidence=anon,
        )
    )
    assert finding is not None, "nested-id cross-account read must be reported"
    assert finding.confidence >= 0.8, f"expected high confidence, got {finding.confidence}"


def test_true_cross_account_read_still_detected():
    """TRUE-POSITIVE PRESERVED: attacker response structurally holds victim's id."""
    engine = DifferentialAuthEngine(session_memory=None)
    owner = {"status_code": 200, "body": {"id": 42, "email": "victim@x", "items": ["a"]}}
    attacker = {
        "status_code": 200,
        "body": {"id": 42, "email": "victim@x", "items": ["a"]},
        "user_label": "attacker",
    }
    anon = {"status_code": 401, "body": {"error": "unauthorized"}}
    finding = _run(
        engine.compare(
            identity_a_evidence=owner,
            identity_b_evidence=attacker,
            resource=_res("42"),
            expected_allowed=False,
            anonymous_evidence=anon,
        )
    )
    assert finding is not None, "genuine cross-account read must be reported"
    assert finding.confidence >= 0.8, f"expected high confidence, got {finding.confidence}"
