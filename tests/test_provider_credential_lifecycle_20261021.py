"""Synthetic authority signatures; no vault, database, provider or remote calls."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import replace
from typing import Any, Awaitable, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.provider_credential_lifecycle import (
    _DOMAIN,
    _canonical,
    _policy_digest,
    _reference_digest,
    CredentialLifecycleDenied,
    CredentialLifecycleVerifier,
    CredentialReadinessRequest,
)


NOW = 1792584000
KINDS = ("profile", "flow", "principal", "policy", "vault", "budget")
HASH = lambda value: hashlib.sha256(value.encode("ascii")).hexdigest()


def _run(coroutine: Awaitable[Any]) -> Any:
    return asyncio.run(coroutine)


def _base() -> tuple[CredentialReadinessRequest, dict[str, dict[str, Any]]]:
    policy = {
        "provider": "openai",
        "model": "openai/model-a",
        "operations": ["completion"],
        "allowed_roles": ["vuln_analysis"],
        "capabilities": ["text_completion"],
        "max_output_tokens": 1024,
        "budget_source": "signed_postgres_roe",
    }
    for field in ("operations", "allowed_roles", "capabilities"):
        policy[field] = sorted(policy[field])
    digest = _policy_digest(policy)
    r = CredentialReadinessRequest(
        engagement_id="eng-tenant-a",
        flow_id="flow-tenant-a",
        flow_revision=4,
        authorization_version=5,
        authorization_id="auth-current",
        authorization_sha256=HASH("roe-v5"),
        owner_sub="owner-a",
        actor_sub="owner-a",
        task_id="task-model-1",
        agent_role="vuln_analysis",
        ref_id="pcref-" + "a" * 32,
        reference_sha256="0" * 64,
        reference_revision=4,
        generation=2,
        provider="openai",
        slot="primary",
        policy_review_id="provider-review-" + "b" * 32,
        policy_sha256=digest,
        model="openai/model-a",
        operation="completion",
        cost_request_micro_usd=1000,
        purpose="rotate",
    )
    r = replace(r, reference_sha256=_reference_digest(r))
    proofs = {
        "profile": {
            "ref_id": r.ref_id,
            "reference_sha256": r.reference_sha256,
            "reference_revision": 4,
            "generation": 2,
            "provider": "openai",
            "slot": "primary",
            "owner_sub": "owner-a",
            "policy_review_id": r.policy_review_id,
            "policy_sha256": r.policy_sha256,
            "flow_revision": 4,
            "authorization_version": 5,
            "authorization_id": "auth-current",
            "authorization_sha256": r.authorization_sha256,
            "status": "approved",
            "revoked": False,
            "senior_sub": "reviewer-a",
            "senior_active": True,
            "profile_valid_until": NOW + 3600,
        },
        "flow": {
            "owner_sub": "owner-a",
            "flow_revision": 4,
            "authorization_version": 5,
            "authorization_id": "auth-current",
            "authorization_sha256": r.authorization_sha256,
            "status": "running",
            "revoked": False,
        },
        "principal": {
            "actor_sub": "owner-a",
            "role": "operator",
            "disabled": False,
            "bearer_expires_at": NOW + 600,
        },
        "policy": {
            "review_id": r.policy_review_id,
            "policy_sha256": r.policy_sha256,
            "creator_sub": "owner-a",
            "provider": "openai",
            "status": "approved",
            "revoked": False,
            "senior_sub": "reviewer-b",
            "senior_active": True,
            "policy": policy,
        },
        "vault": {
            "ref_id": r.ref_id,
            "reference_revision": 4,
            "generation": 2,
            "provider": "openai",
            "slot": "primary",
            "credential_material": "present",
            "vault_state": "active",
            "credential_version_sha256": HASH("material-v2"),
            "credential_valid_until": NOW + 3600,
            "previous_generation": 1,
            "previous_vault_state": "revoked",
            "previous_credential_version_sha256": HASH("material-v1"),
        },
        "budget": {
            "task_id": "task-model-1",
            "agent_role": "vuln_analysis",
            "model": "openai/model-a",
            "operation": "completion",
            "budget_source": "signed_postgres_roe",
            "budget_state": "within_current_limit",
            "authorization_version": 5,
            "authorization_sha256": r.authorization_sha256,
            "flow_revision": 4,
            "available_micro_usd": 2000,
        },
    }
    return r, proofs


def _service(
    request: CredentialReadinessRequest,
    proofs: dict[str, dict[str, Any]],
    *,
    timestamp: int = NOW,
    max_age_seconds: int = 15,
) -> tuple[
    CredentialLifecycleVerifier,
    dict[str, Ed25519PrivateKey],
    dict[str, Callable[[CredentialReadinessRequest, str], Awaitable[bytes]]],
    dict[str, bytes],
]:
    keys = {kind: Ed25519PrivateKey.generate() for kind in KINDS}
    raw_override = {}

    def sign(kind: str, nonce: str) -> bytes:
        claims = {
            "engagement_id": request.engagement_id,
            "flow_id": request.flow_id,
            "nonce": nonce,
            "issued_at": timestamp,
            "expires_at": timestamp + 10,
            **proofs[kind],
        }
        raw = _canonical(claims)
        sig = keys[kind].sign(_DOMAIN + kind.encode() + b"\x00" + raw)
        return json.dumps(
            {
                "claims": claims,
                "signature_b64": base64.b64encode(sig).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    readers = {}
    for kind in KINDS:

        async def reader(r: CredentialReadinessRequest, nonce: str, name: str = kind) -> bytes:
            if name in raw_override:
                return raw_override[name]
            return sign(name, nonce)

        readers[kind] = reader
    verifier = CredentialLifecycleVerifier(
        public_keys={kind: k.public_key() for kind, k in keys.items()},
        readers=readers,
        max_age_seconds=max_age_seconds,
        clock=lambda: NOW,
    )
    return verifier, keys, readers, raw_override


def test_six_independent_current_signers_attest_rotation_readiness_without_dispatch() -> None:
    request, proofs = _base()
    verifier, _, _, _ = _service(request, proofs)
    decision = _run(verifier.assess(request))
    assert decision.rotation_readiness_verified
    assert decision.independently_attested_vault_presence
    assert decision.generation == 2
    assert not decision.provider_accepts_credential_verified
    assert not decision.provider_contacted
    assert not decision.budget_reserved
    assert not decision.dispatch_authorized
    assert decision.proof_expires_at == NOW + 10


@pytest.mark.parametrize(
    "kind,field,bad",
    [
        ("profile", "status", "pending"),
        ("profile", "revoked", True),
        ("profile", "reference_revision", 3),
        ("profile", "generation", 3),
        ("profile", "owner_sub", "other-owner"),
        ("profile", "senior_sub", "owner-a"),
        ("profile", "senior_active", False),
        ("profile", "profile_valid_until", NOW - 1),
        ("profile", "reference_sha256", "0" * 64),
        ("flow", "status", "paused"),
        ("flow", "revoked", True),
        ("flow", "flow_revision", 5),
        ("flow", "authorization_sha256", "1" * 64),
        ("principal", "actor_sub", "foreign"),
        ("principal", "role", "viewer"),
        ("principal", "disabled", True),
        ("principal", "bearer_expires_at", NOW),
        ("policy", "status", "revoked"),
        ("policy", "revoked", True),
        ("policy", "provider", "anthropic"),
        ("policy", "policy_sha256", "0" * 64),
        ("policy", "senior_sub", "owner-a"),
        ("policy", "senior_active", False),
        ("vault", "credential_material", "absent"),
        ("vault", "credential_material", True),
        ("vault", "vault_state", "revoked"),
        ("vault", "credential_valid_until", NOW - 2),
        ("vault", "credential_version_sha256", "0" * 64),
        ("vault", "credential_version_sha256", HASH("roe-v5")),
        ("vault", "reference_revision", 3),
        ("vault", "generation", 1),
        ("vault", "previous_vault_state", "present"),
        ("vault", "previous_generation", 0),
        ("vault", "previous_credential_version_sha256", HASH("material-v2")),
        ("budget", "budget_state", "pending"),
        ("budget", "available_micro_usd", 999),
        ("budget", "available_micro_usd", True),
        ("budget", "authorization_version", 4),
        ("budget", "task_id", "task-other"),
        ("budget", "agent_role", "recon"),
    ],
)
def test_authenticated_but_stale_cross_tenant_rotated_revoked_or_cost_denied(
    kind: str, field: str, bad: Any
) -> None:
    request, proofs = _base()
    proofs[kind][field] = bad
    verifier, _, _, _ = _service(request, proofs)
    with pytest.raises(CredentialLifecycleDenied):
        _run(verifier.assess(request))


def test_policy_allowed_role_and_model_must_match_exact_canonical_policy() -> None:
    request, proofs = _base()
    proofs["policy"]["policy"] = {
        **proofs["policy"]["policy"],
        "allowed_roles": ["recon"],
    }
    with pytest.raises(CredentialLifecycleDenied):
        _run(_service(request, proofs)[0].assess(request))


@pytest.mark.parametrize(
    "bad_policy",
    [
        {"provider": []},
        {"capabilities": [["text_completion"]]},
        {"max_output_tokens": True},
        {"allowed_roles": ["fake-role"]},
        {"operations": ["completion", "completion"]},
    ],
)
def test_signed_malformed_policy_cannot_bypass_canonical_digest(bad_policy: dict[str, Any]) -> None:
    request, proofs = _base()
    proofs["policy"]["policy"] = {**proofs["policy"]["policy"], **bad_policy}
    with pytest.raises(CredentialLifecycleDenied):
        _run(_service(request, proofs)[0].assess(request))


def test_signature_overread_or_forged_provider_claim_cannot_be_self_asserted() -> None:
    request, proofs = _base()
    verifier, keys, readers, overrides = _service(request, proofs)
    # A caller cannot replace the vault authority with a forged payload.
    overrides["vault"] = b'{"credential_material":true}'
    with pytest.raises(CredentialLifecycleDenied):
        _run(verifier.assess(request))
    # A profile-signed vault attestation cannot impersonate the vault signer.
    overrides.clear()

    async def wrong_signer(r: CredentialReadinessRequest, nonce: str) -> bytes:
        claims = {
            "engagement_id": r.engagement_id,
            "flow_id": r.flow_id,
            "nonce": nonce,
            "issued_at": NOW,
            "expires_at": NOW + 10,
            **proofs["vault"],
        }
        signature = keys["profile"].sign(_DOMAIN + b"vault\x00" + _canonical(claims))
        return json.dumps(
            {
                "claims": claims,
                "signature_b64": base64.b64encode(signature).decode(),
            }
        ).encode()

    readers["vault"] = wrong_signer
    verifier = CredentialLifecycleVerifier(
        public_keys={k: key.public_key() for k, key in keys.items()},
        readers=readers,
        clock=lambda: NOW,
    )
    with pytest.raises(CredentialLifecycleDenied):
        _run(verifier.assess(request))


@pytest.mark.parametrize(
    "issued,expires",
    [
        (NOW - 16, NOW - 1),
        (NOW - 30, NOW + 1),
        (NOW + 3, NOW + 9),
        (NOW, NOW + 31),
    ],
)
def test_signed_stale_future_or_overlong_observations_denied(issued: int, expires: int) -> None:
    request, proofs = _base()
    verifier, keys, readers, _ = _service(request, proofs)

    async def stale(r: CredentialReadinessRequest, nonce: str) -> bytes:
        claims = {
            "engagement_id": r.engagement_id,
            "flow_id": r.flow_id,
            "nonce": nonce,
            "issued_at": issued,
            "expires_at": expires,
            **proofs["vault"],
        }
        sig = keys["vault"].sign(_DOMAIN + b"vault\x00" + _canonical(claims))
        return json.dumps(
            {"claims": claims, "signature_b64": base64.b64encode(sig).decode()}
        ).encode()

    readers["vault"] = stale
    verifier = CredentialLifecycleVerifier(
        public_keys={k: v.public_key() for k, v in keys.items()},
        readers=readers,
        clock=lambda: NOW,
    )
    with pytest.raises(CredentialLifecycleDenied):
        _run(verifier.assess(request))


def test_proof_challenge_mismatch_rejected() -> None:
    request, proofs = _base()
    verifier, keys, readers, _ = _service(request, proofs)

    async def replay(r: CredentialReadinessRequest, nonce: str) -> bytes:
        claims = {
            "engagement_id": r.engagement_id,
            "flow_id": r.flow_id,
            "nonce": "0" * 32,
            "issued_at": NOW,
            "expires_at": NOW + 10,
            **proofs["vault"],
        }
        sig = keys["vault"].sign(_DOMAIN + b"vault\x00" + _canonical(claims))
        raw = json.dumps(
            {"claims": claims, "signature_b64": base64.b64encode(sig).decode()}
        ).encode()
        return raw

    readers["vault"] = replay
    verifier = CredentialLifecycleVerifier(
        public_keys={k: v.public_key() for k, v in keys.items()},
        readers=readers,
        clock=lambda: NOW,
    )
    with pytest.raises(CredentialLifecycleDenied):
        _run(verifier.assess(request))


@pytest.mark.parametrize(
    "bad_json",
    [
        b'{"claims":{},"signature_b64":"","signature_b64":""}',
        b'{"claims":{"issued_at":NaN},"signature_b64":""}',
        b"x" * 8193,
        b"{}",
    ],
)
def test_oversized_duplicate_and_nonfinite_evidence_refused(bad_json: bytes) -> None:
    request, proofs = _base()
    verifier, _, _, overrides = _service(request, proofs)
    overrides["vault"] = bad_json
    with pytest.raises(CredentialLifecycleDenied):
        _run(verifier.assess(request))


def test_missing_authority_key_collision_and_timeout_fail_closed() -> None:
    request, proofs = _base()
    verifier, keys, readers, _ = _service(request, proofs)
    with pytest.raises(CredentialLifecycleDenied):
        CredentialLifecycleVerifier(
            public_keys={"vault": keys["vault"].public_key()},
            readers=readers,
        )
    with pytest.raises(CredentialLifecycleDenied):
        CredentialLifecycleVerifier(
            public_keys={
                kind: (keys["profile"] if kind == "vault" else keys[kind]).public_key()
                for kind in KINDS
            },
            readers=readers,
        )

    async def missing(r: CredentialReadinessRequest, nonce: str) -> bytes:
        raise ConnectionError("offline")

    readers["vault"] = missing
    verifier = CredentialLifecycleVerifier(
        public_keys={k: v.public_key() for k, v in keys.items()},
        readers=readers,
        clock=lambda: NOW,
    )
    with pytest.raises(CredentialLifecycleDenied):
        _run(verifier.assess(request))


def test_unsigned_caller_metadata_or_symbolic_reference_has_no_attestation_path() -> None:
    request, proofs = _base()
    with pytest.raises(CredentialLifecycleDenied):
        _run(_service(request, proofs)[0].assess(replace(request, reference_revision=5)))
    with pytest.raises(CredentialLifecycleDenied):
        _run(_service(request, proofs)[0].assess(replace(request, engagement_id="eng-other")))
    with pytest.raises(CredentialLifecycleDenied):
        _run(_service(request, proofs)[0].assess(replace(request, purpose="rotate", generation=1)))
    with pytest.raises(CredentialLifecycleDenied):
        _run(_service(request, proofs)[0].assess(replace(request, actor_sub="foreign-user")))
