"""A provider's generic verified/certified claims are data, never authority.

No provider or app DB is contacted. The signed receipt reconciliation path is
tested elsewhere; this test pins the public result/metadata sanitization.
"""

import copy

from ai_osop.mcp.protocol import (
    MCPExecuteResponse,
    MCPProviderProvenance,
    _strip_untrusted_provider_authority_flags,
)


def test_generic_provider_verified_certified_and_released_are_not_public_authority():
    original = {
        "verified": True,
        "certified": True,
        "independently_verified": True,
        "owner_verified": True,
        "evidence_verified": True,
        "release_approved": True,
        "provider_receipt_verified": True,
        "target_effect_verified": True,
        "title": "provider reported scanner observations",
        "facts": [
            {
                "verified": {"source": "untrusted"},
                "certified": "vendor-claim",
                "production_certified": 1,
                "safe_to_automatically_retry": True,
                "target_effect_verified": False,
                "status": "provider_success",
            }
        ],
        "provider_provenance": {"status_source": "independent_target_owner"},
    }
    preserved = copy.deepcopy(original)
    sanitized = _strip_untrusted_provider_authority_flags(original)
    assert original == preserved
    assert sanitized == {
        "title": "provider reported scanner observations",
        "facts": [{"target_effect_verified": False, "status": "provider_success"}],
    }


def test_false_generic_provider_flags_may_remain_but_not_become_proof():
    false_values = {
        key: False
        for key in (
            "verified",
            "certified",
            "owner_verified",
            "evidence_verified",
            "release_approved",
            "target_effect_verified",
        )
    }
    assert _strip_untrusted_provider_authority_flags(false_values) == false_values
    response = MCPExecuteResponse(
        request_id="req-local-original",
        status="success",
        result=_strip_untrusted_provider_authority_flags(
            {**false_values, "verified": True, "certified": True}
        ),
        provider_provenance=MCPProviderProvenance(),
    )
    assert response.provider_provenance.target_effect_verified is False
    assert "verified" not in response.result
    assert "certified" not in response.result
    assert response.result["target_effect_verified"] is False
