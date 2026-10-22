"""Read-only 0022 route and fail-closed reviewer/source contract tests."""

import inspect

from ai_osop.api.routers import verified_finding_reviews as reviews


def test_readback_is_get_only_and_requires_senior_dependency():
    routes = [
        route
        for route in reviews.router.routes
        if "finding-effect-verifications/{finding_id}" in route.path
    ]
    assert len(routes) == 1
    assert routes[0].methods == {"GET"}
    assert "_senior_reviewer" in repr(
        inspect.signature(reviews.read_current_independent_finding_effect)
    )


def test_readback_never_promotes_cached_db_row_and_uses_live_checks():
    source = inspect.getsource(reviews._process_review)
    assert 'qualification_mode == "read_verified"' in source
    assert "read_independent_target_effect_verification(" in source
    assert "trusted_current_verifier=current_dispatch_session_verifier" in source
    assert "trusted_report_source_check=current_signed_report_source_check" in source
    assert "trusted_anonymous_signed_dispatch_check=anonymous_signed_dispatch" in source
    assert "result = _empty_effect()" in source
    assert '"SELECT verdict_sha256 FROM independent_target_effect_verifications "' in source
    assert "SELECT signed_verdict_json" not in source


def test_no_private_evidence_or_final_release_in_get_contract():
    source = inspect.getsource(reviews.read_current_independent_finding_effect)
    assert 'qualification_mode="read_verified"' in source
    assert "read_only=True" in source
    assert "signed_verdict_json" not in source
    assert "report_release_approved=True" not in source
