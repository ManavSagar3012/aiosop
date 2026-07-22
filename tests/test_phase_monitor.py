"""Unit tests for PhaseMonitor.

Focuses on the _select_injection_targets static method.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ai_osop.orchestrator.phase_monitor import PhaseMonitor


def _record(
    url: str,
    method: str = "GET",
    *,
    has_body: bool = False,
    body_keys: Optional[List[str]] = None,
    content_type: str = "",
    technologies: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "url": url,
        "method": method,
        "has_body": has_body,
        "body_keys": body_keys or [],
        "content_type": content_type,
        "technologies": technologies or [],
    }


def test_empty_records():
    assert PhaseMonitor._select_injection_targets([]) == []


def test_records_with_no_url():
    records = [{"url": None, "method": "GET"}, {"url": "", "method": "POST"}]
    assert PhaseMonitor._select_injection_targets(records) == []


def test_records_with_no_query_params():
    records = [_record("https://example.com/")]
    assert PhaseMonitor._select_injection_targets(records) == []


def test_single_get_with_query_param():
    records = [_record("https://example.com/page?id=42")]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 1
    t = targets[0]
    assert "id" in t["url"]
    assert t["method"] == "GET"
    assert "data" not in t


def test_multiple_get_params():
    records = [_record("https://example.com/search?q=test&sort=asc&page=2")]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 1
    t = targets[0]
    assert "q" in t["url"]
    assert "sort" in t["url"]
    assert t["method"] == "GET"


def test_dedup_same_path_same_params():
    records = [
        _record("https://example.com/product?id=1"),
        _record("https://example.com/product?id=2"),
    ]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 1


def test_different_paths_both_included():
    records = [
        _record("https://example.com/product?id=1"),
        _record("https://example.com/item?id=5"),
    ]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 2


def test_scoring_prefers_injectable_hints():
    records = [
        _record("https://example.com/A?foo=1"),
        _record("https://example.com/B?id=1"),
        _record("https://example.com/C?q=hello"),
    ]
    targets = PhaseMonitor._select_injection_targets(records, max_targets=3)
    assert len(targets) == 3
    urls = [t["url"] for t in targets]
    id_pos = next(i for i, u in enumerate(urls) if "id=" in u)
    q_pos = next(i for i, u in enumerate(urls) if "q=" in u)
    foo_pos = next(i for i, u in enumerate(urls) if "foo=" in u)
    assert id_pos < foo_pos
    assert q_pos < foo_pos


def test_more_params_higher_score():
    records = [
        _record("https://example.com/A?foo=1"),
        _record("https://example.com/B?bar=1&baz=2&qux=3"),
    ]
    targets = PhaseMonitor._select_injection_targets(records, max_targets=3)
    urls = [t["url"] for t in targets]
    bar_pos = next(i for i, u in enumerate(urls) if "bar=" in u)
    foo_pos = next(i for i, u in enumerate(urls) if "foo=" in u)
    assert bar_pos < foo_pos


def test_body_param_target():
    records = [
        _record(
            "https://example.com/api/login",
            method="POST",
            has_body=True,
            body_keys=["email", "password"],
            content_type="application/json",
        )
    ]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 1
    t = targets[0]
    assert t["method"] == "POST"
    assert "data" in t


def test_body_param_form_content():
    records = [
        _record(
            "https://example.com/form",
            method="POST",
            has_body=True,
            body_keys=["name", "email"],
            content_type="application/x-www-form-urlencoded",
        )
    ]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 1
    t = targets[0]
    assert "data" in t
    assert "=" in t["data"]


def test_body_only_endpoint_no_query():
    records = [
        _record(
            "https://example.com/api/orders",
            method="PUT",
            has_body=True,
            body_keys=["item", "quantity"],
        )
    ]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 1
    t = targets[0]
    assert t["method"] == "PUT"
    assert "?" not in t["url"]


def test_body_and_query_params_both_produce_targets():
    records = [
        _record(
            "https://example.com/api/items?page=1",
            method="POST",
            has_body=True,
            body_keys=["name", "price"],
        )
    ]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 2


def test_max_targets_cap():
    records = [_record(f"https://example.com/page-{i}?p={i}") for i in range(50)]
    targets = PhaseMonitor._select_injection_targets(records, max_targets=10)
    assert len(targets) == 10


def test_technologies_carried_through():
    records = [_record("https://example.com/api?id=1", technologies=["react", "express"])]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 1
    assert targets[0]["technologies"] == ["react", "express"]


def test_unspecified_method_defaults_to_get():
    records = [{"url": "https://example.com/page?q=hello"}]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 1
    assert targets[0]["method"] == "GET"


def test_has_body_with_empty_keys():
    records = [_record("https://example.com/post", method="POST", has_body=True, body_keys=[])]
    targets = PhaseMonitor._select_injection_targets(records)
    assert len(targets) == 0
