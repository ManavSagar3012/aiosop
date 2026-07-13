"""Injection-target param-key filtering: drop recon extractor noise, keep real params.

Regression for the live-audit finding where sqlmap was fed junk keys
(/graphql?A=&92=&-2=&null=) and wasted its whole budget probing params that don't
exist, so real params were never tested.
"""

from ai_osop.orchestrator.phase_monitor import (
    PhaseMonitor,
    _is_probable_param_key,
)


def test_key_classifier():
    # Real params kept
    for good in ("id", "q", "productId", "utm_source", "catalogId", "search", "user_id", "a[b]"):
        assert _is_probable_param_key(good), good
    # Extractor noise dropped
    for bad in ("92", "10", "256", "-2", "-1", "null", "undefined", "", "  ", "true"):
        assert not _is_probable_param_key(bad), bad


def test_graphql_junk_params_dropped():
    # The exact shape observed against the live target: a real path but only
    # junk query keys -> no injectable params -> target correctly skipped.
    records = [
        {"url": "https://t/graphql", "method": "GET",
         "query_keys": ["A", "92", "10", "-2", "null", "M"]},
        {"url": "https://t/core/equity100", "method": "GET",
         "query_keys": ["id", "site", "92", "null", "key"]},
    ]
    from urllib.parse import urlparse

    targets = PhaseMonitor._select_injection_targets(records, max_targets=25)
    by_path = {urlparse(t["url"]).path: t["url"] for t in targets}
    # graphql had only junk -> dropped entirely
    assert "/graphql" not in by_path
    # equity100 kept, but only the real keys survive in the probe URL
    eq = next(u for p, u in by_path.items() if p == "/core/equity100")
    assert "id=test" in eq and "key=test" in eq and "site=test" in eq
    assert "92=" not in eq and "null=" not in eq


if __name__ == "__main__":
    test_key_classifier()
    test_graphql_junk_params_dropped()
    print("injection param-filter tests OK")
