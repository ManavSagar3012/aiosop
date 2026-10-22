"""Final release source verification must recheck the same signed ROE."""

import inspect

from ai_osop.api.routers import report_attestations


def test_source_verification_followed_by_current_signed_authority_readback():
    source = inspect.getsource(report_attestations._verified_final_release_candidate)
    source_verification = source.index("await _verify_signed_finding_sources(")
    source_guard = source.index("current_signed = await guard_sql(", source_verification)
    return_point = source.index("return verified, loaded, signed", source_guard)
    assert source_verification < source_guard < return_point
    assert "expected_version=signed.version" in source[source_guard:return_point]


def test_tenant_signer_and_policy_rotation_are_fatal_not_a_release():
    source = inspect.getsource(report_attestations._verified_final_release_candidate)
    assert "current_signed.session_id != session_id" in source
    assert "current_signed.authorization_id != signed.authorization_id" in source
    assert "current_signed.policy_sha256 != signed.policy_sha256" in source
    assert "status_code=403" in source
    assert "status_code=409" in source
    assert "_independent_target_authority_available" not in source
