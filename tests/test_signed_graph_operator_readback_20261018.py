"""Graph operator readback may never trust a stale ROE or foreign entry."""

import inspect

from ai_osop.api.routers import intelligence


def test_graph_readback_uses_signed_scope_before_and_after_graph_awaits():
    source = inspect.getsource(intelligence.get_full_graph)
    assert "authority = await _current_graph_authority" in source
    assert "await _recheck_graph_authority(session_id, operator, authority)" in source
    assert 'n.get("engagement_id") == session_id' in source
    assert "_MAX_GRAPH + 1" in source


def test_unscoped_attack_path_entry_rejected_and_bounded():
    source = inspect.getsource(intelligence.get_attack_paths)
    assert "engagement_id:$sid" in source
    assert "Entry node not in signed engagement" in source
    assert "not 1 <= max_depth <= 8" in source
    assert '"finding_verified": False' in source


def test_signed_authority_comparison_rejects_tenant_and_policy_changes():
    source = inspect.getsource(intelligence._recheck_graph_authority)
    assert "_current_graph_authority(session_id, operator) != expected" in source
    assert "status_code=409" in source
