"""Unit tests for PhaseMonitor._select_injection_targets POST-body support.

JS-001 (login SQLi) was missed because active-injection selection only considered
query-string (`?`) endpoints and never built a POST body, so a JSON login's
`email` param was never fuzzed. These lock the deterministic selection/payload
wiring (AIOSOP-SQLI-POSTBODY-JS001). End-to-end recall movement is verified
separately by a live engagement, not here.
"""

from __future__ import annotations

import json

from ai_osop.orchestrator.phase_monitor import PhaseMonitor

_select = PhaseMonitor._select_injection_targets


def test_json_body_endpoint_yields_post_target_with_json_data():
    records = [
        {
            "url": "https://juice/rest/user/login",
            "method": "POST",
            "has_body": True,
            "body_keys": ["email", "password"],
            "content_type": "application/json",
            "query_keys": [],
            "technologies": [],
        }
    ]
    targets = _select(records, max_targets=12)
    assert len(targets) == 1
    t = targets[0]
    assert t["method"] == "POST"
    assert "data" in t, "body endpoint must carry an injectable POST body"
    body = json.loads(t["data"])  # JSON content-type -> compact JSON body
    assert "email" in body and "password" in body
    assert " " not in t["data"]  # whitespace-free per the bridge sanitizer
    # url is stripped of any query for a pure body target
    assert t["url"].endswith("/rest/user/login")


def test_form_body_endpoint_yields_urlencoded_data():
    records = [
        {
            "url": "https://x/login",
            "method": "POST",
            "has_body": True,
            "body_keys": ["email", "password"],
            "content_type": "application/x-www-form-urlencoded",
            "query_keys": [],
            "technologies": [],
        }
    ]
    t = _select(records)[0]
    assert t["data"] == "email=test&password=test"
    assert t["method"] == "POST"


def test_query_param_endpoint_unchanged_and_carries_no_body():
    records = [
        {
            "url": "https://x/rest/products/search?q=test",
            "method": "GET",
            "has_body": False,
            "body_keys": [],
            "content_type": "",
            "technologies": [],
        }
    ]
    t = _select(records)[0]
    assert "data" not in t  # query targets don't get a POST body
    assert "q=test" in t["url"]
    assert t["method"] == "GET"


def test_get_endpoint_without_any_params_is_excluded():
    records = [
        {
            "url": "https://x/about",
            "method": "GET",
            "has_body": False,
            "body_keys": [],
            "content_type": "",
            "technologies": [],
        }
    ]
    assert _select(records) == []


def test_endpoint_with_both_query_and_body_yields_two_targets():
    records = [
        {
            "url": "https://x/api/thing?id=1",
            "method": "POST",
            "has_body": True,
            "body_keys": ["email"],
            "content_type": "application/json",
            "query_keys": ["id"],
            "technologies": [],
        }
    ]
    targets = _select(records)
    kinds = sorted("body" if "data" in t else "query" for t in targets)
    assert kinds == ["body", "query"]
