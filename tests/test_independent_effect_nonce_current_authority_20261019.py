"""Adversarial current LIVE witness trust and nonce admission races.

Uses the existing deterministic two-signature fixture and an isolated SQL
transaction surrogate; no application database or external target requests.
"""

from __future__ import annotations

import base64
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.memory import independent_target_effect_verifications as ledger
from tests.test_independent_target_effect_verifications_20261018 import (
    _challenge,
    ready,  # noqa: F401 - shared deterministic cryptographic fixture
)
from tests.test_independent_target_effect_observer_20261018 import witness  # noqa: F401
from tests.test_independent_target_effect_observer_20261018 import witness  # noqa: F401
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


def _rotate(ready, key_name: str) -> None:
    replacement = Ed25519PrivateKey.from_private_bytes(bytes(range(164, 196)))
    ready.case.config[key_name] = base64.b64encode(
        replacement.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    # Keep the same key IDs and operator IDs, testing rotation of actual bytes
    # even when the registry metadata otherwise still looks familiar.
    ready.case.set_config()


@pytest.mark.asyncio
@pytest.mark.parametrize("key_name", ["observer_public_key_b64", "owner_public_key_b64"])
async def test_rotation_after_core_verification_rejects_new_registry_old_signature(
    ready, monkeypatch, key_name
):
    challenge = await _challenge(ready)
    original = ledger._current_witness_trust

    def rotate_between_verifier_and_snapshot(**kwargs):
        _rotate(ready, key_name)
        return original(**kwargs)

    monkeypatch.setattr(ledger, "_current_witness_trust", rotate_between_verifier_and_snapshot)
    with pytest.raises(ledger.IndependentTargetEffectDenied):
        await ledger.admit_independent_target_effect_verification(
            ready.state, **ready.input, **challenge
        )
    assert ready.state.promotions == []
    assert ready.state.qualification["status"] == "UNKNOWN"


@pytest.mark.asyncio
@pytest.mark.parametrize("key_name", ["observer_public_key_b64", "owner_public_key_b64"])
async def test_last_signed_dispatch_callback_cannot_rotate_live_verifier_before_insert(
    ready, key_name
):
    challenge = await _challenge(ready)
    original = ready.input["trusted_anonymous_signed_dispatch_check"]
    calls = 0

    async def rotate_on_final_dispatch(*args):
        nonlocal calls
        calls += 1
        result = await original(*args)
        if calls == 2:
            _rotate(ready, key_name)
        return result

    ready.input["trusted_anonymous_signed_dispatch_check"] = rotate_on_final_dispatch
    with pytest.raises(ledger.IndependentTargetEffectDenied):
        await ledger.admit_independent_target_effect_verification(
            ready.state, **ready.input, **challenge
        )
    assert calls >= 2
    assert ready.state.promotions == []


@pytest.mark.asyncio
async def test_nonce_expiring_during_final_signed_dispatch_cannot_promote(ready, monkeypatch):
    challenge = await _challenge(ready)
    original = ready.input["trusted_anonymous_signed_dispatch_check"]
    real_clock = time.time
    calls = 0

    async def expire_on_final_dispatch(*args):
        nonlocal calls
        calls += 1
        result = await original(*args)
        if calls == 2:
            # Model an awaited signer call lasting beyond the immutable
            # 60-second PostgreSQL challenge without editing any stored row.
            monkeypatch.setattr(ledger.time, "time", lambda: real_clock() + 65)
        return result

    ready.input["trusted_anonymous_signed_dispatch_check"] = expire_on_final_dispatch
    with pytest.raises(ledger.IndependentTargetEffectDenied):
        await ledger.admit_independent_target_effect_verification(
            ready.state, **ready.input, **challenge
        )
    assert calls >= 2
    assert ready.state.promotions == []


@pytest.mark.asyncio
@pytest.mark.parametrize("backdated", ["observer", "owner"])
async def test_fresh_signed_nonce_cannot_certify_pre_challenge_observations(ready, backdated):
    challenge = await _challenge(ready)
    before_challenge = ready.state.challenges[challenge["challenge_id"]]["issued_at"] - 20
    if backdated == "observer":
        ready.case.outer["issued_at"] = before_challenge
        ready.case.outer["expires_at"] = before_challenge + 60
    else:
        ready.case.owner["observed_at"] = before_challenge
    signed_claims, signed_signature = ready.case.seal()
    challenge["observer_claims_json"] = signed_claims
    challenge["observer_signature_b64url"] = signed_signature

    with pytest.raises(ledger.IndependentTargetEffectDenied):
        await ledger.admit_independent_target_effect_verification(
            ready.state, **ready.input, **challenge
        )
    assert ready.state.promotions == []


@pytest.mark.asyncio
async def test_readback_last_senior_fence_cannot_return_verification_after_key_revocation(
    ready, monkeypatch
):
    challenge = await _challenge(ready)
    inserted = await ledger.admit_independent_target_effect_verification(
        ready.state, **ready.input, **challenge
    )
    assert inserted["status"] == "VERIFIED"
    original = ledger._fresh

    async def revoke_during_final_senior_fence(*args, **kwargs):
        result = await original(*args, **kwargs)
        _rotate(ready, "owner_public_key_b64")
        return result

    monkeypatch.setattr(ledger, "_fresh", revoke_during_final_senior_fence)
    readback = await ledger.read_independent_target_effect_verification(
        ready.state,
        engagement_id=ready.input["engagement_id"],
        flow_id=ready.input["flow_id"],
        finding_id=ready.input["finding_id"],
        evidence_sha256=inserted["verification_sha256"],
        authorization_version=ready.input["authorization_version"],
        reviewer_sub=ready.input["reviewer_sub"],
        reviewer_role=ready.input["reviewer_role"],
        reviewer_token_sha256=ready.input["reviewer_token_sha256"],
        reviewer_expires_at=ready.input["reviewer_expires_at"],
        trusted_current_verifier=ready.input["trusted_current_verifier"],
        trusted_report_source_check=ready.input["trusted_report_source_check"],
        trusted_anonymous_signed_dispatch_check=ready.input[
            "trusted_anonymous_signed_dispatch_check"
        ],
    )
    assert readback["status"] == "UNKNOWN"
    assert readback["finding_verified"] is False
    assert readback["report_release_approved"] is False
