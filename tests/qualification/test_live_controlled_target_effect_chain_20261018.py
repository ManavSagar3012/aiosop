"""Controlled, entirely offline observer protocol qualification.

The pre-existing witness fixture simulates a production-shaped signed
receipt. Passing this test does NOT certify a real external verifier, target,
session ledger, independent operator, or PostgreSQL 0022 promotion.
"""

import pytest

from ai_osop.core import independent_target_effect_observer as observer
from tests.test_independent_target_effect_observer_20261018 import witness, NONCE  # noqa: F401
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401
from tests.qualification.controlled_target_effect_fixture_20261018 import LocalPrivateRecord


@pytest.mark.asyncio
async def test_locally_instrumented_roles_are_private_and_distinct(witness):
    target = LocalPrivateRecord()
    source = target.request("account_a")
    cross_identity = target.request("account_b")
    anonymous = target.request("anonymous")
    assert source == cross_identity == (200, target.private_text)
    assert anonymous == (403, b"")
    assert target.private_text not in repr(witness.outer).encode()
    assert witness.owner_signer.public_key() != witness.observer_signer.public_key()

    # Exercise the actual production signature/lineage verifier on an
    # independently signed LOCAL synthetic fixture, not on external evidence.
    raw, signature = witness.seal()
    result = await observer.verify_independent_target_effect_claims(
        observer_claims_json=raw, observer_signature_b64url=signature,
        expected_nonce=NONCE, **witness.ctx,
    )
    assert result.finding_verified is False
    assert result.report_release_approved is False
    assert result.validation_state == "independent_observation_pending_durable_admission"
    assert target.private_text not in result.observer_claims_json
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.verify_independent_target_effect_claims(
            observer_claims_json=raw, observer_signature_b64url=signature,
            expected_nonce=NONCE, **witness.ctx,
        )


@pytest.mark.asyncio
async def test_revoked_target_and_signed_receipt_are_not_reusable(witness):
    target = LocalPrivateRecord()
    target.revoke()
    assert target.request("account_a") == (404, b"")
    assert target.request("account_b") == (404, b"")
    assert target.request("anonymous") == (404, b"")
    witness.ctx["trusted_current_authority_check"].return_value = False
    raw, signature = witness.seal()
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.verify_independent_target_effect_claims(
            observer_claims_json=raw, observer_signature_b64url=signature,
            expected_nonce=NONCE, **witness.ctx,
        )


@pytest.mark.asyncio
async def test_distinct_signing_role_cannot_impersonate_observer(witness):
    raw, _ = witness.seal()
    from tests.test_independent_target_effect_observer_20261018 import _url64
    forged = _url64(witness.owner_signer.sign(observer._EFFECT_DOMAIN + raw))
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.verify_independent_target_effect_claims(
            observer_claims_json=raw, observer_signature_b64url=forged,
            expected_nonce=NONCE, **witness.ctx,
        )
