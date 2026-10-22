"""Adversarial API readback response boundaries; no target or application DB."""

import inspect

from ai_osop.api.routers import verified_finding_reviews as route


def test_readback_never_forwards_extra_private_witness_fields():
    source = inspect.getsource(route._process_review)
    assert "set(result)" in source and '"verification_id"' in source
    assert '"verification_sha256"' in source
    assert '"report_source_evidence_sha256"' in source
    assert (
        '"signed_verdict_json"'
        not in source[
            source.index("if not isinstance(result, dict):") : source.index(
                'elif qualification_mode == "read":'
            )
        ]
    )


def test_stale_finding_digest_and_report_source_fail_closed():
    source = inspect.getsource(route._process_review)
    assert 'result.get("verification_sha256") != existing' in source
    assert "!= payload.report_source_evidence_sha256" in source
    assert 'r"itefv-[0-9a-f]{32}"' in source and "re.fullmatch(" in source
    assert "result = _empty_effect()" in source


def test_live_reviewer_and_signed_roe_are_refenced_after_observer_await():
    source = inspect.getsource(route._process_review)
    ledger = source.index("result = await read_independent_target_effect_verification(")
    assert source.index("await FlowArtifactReviewStore._reviewer_fence(", ledger) > ledger
    assert source.index("refreshed = await guard_sql(", ledger) > ledger
    assert "trusted_anonymous_signed_dispatch_check=anonymous_signed_dispatch" in source
