"""Synthetic independent-authority qualification for proposed dispatch guard.

Read-only local signing fixtures, no actual PostgreSQL, vault, API key, model,
network, Docker, external provider, target or Git operation.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.provider_credential_dispatch_guard import (
    _DOMAIN, _canonical, DispatchBinding, DispatchPermit,
    ProviderCredentialDispatchGuard, ProviderDispatchDenied,
)
from ai_osop.core.provider_credential_lifecycle import (
    CredentialReadinessDecision,
)


NOW = 1792584000
KINDS = ("vault_material", "vault_revocation", "route_key", "reservation")
ROUTE_HASH = "a" * 64
DEPLOY_HASH = "b" * 64


def _original_signed_readiness_fixture() -> Any:
    # Reuse the earlier worker's real seven-root signed test fixture, not a
    # mock that simply returns "vault=True".
    source = (
        Path(__file__).resolve().parent
        / "test_provider_lifecycle_runtime_join_20261021.py"
    )
    spec = importlib.util.spec_from_file_location("_dispatch_readiness_fixture", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ca = module.ca_pem.__wrapped__()
    return module._bundle(ca)


def _fixture() -> tuple[
    ProviderCredentialDispatchGuard, DispatchBinding,
    Dict[str, Dict[str, Any]], Dict[str, Any]
]:
    readiness, req, existing_proofs, previous = _original_signed_readiness_fixture()
    binding = DispatchBinding(
        readiness_request=req,
        route_policy_sha256=ROUTE_HASH,
        route_deployment_sha256=DEPLOY_HASH,
        call_id="call-genuine-reservation",
    )
    # The original fixture's current vault version is a nonsecret opaque hash.
    # Avoid any raw credential in this proof; it is deliberately NOT a key hash.
    from hashlib import sha256
    version = sha256(b"current-secret-v3").hexdigest()
    evidence: Dict[str, Dict[str, Any]] = {
        "vault_material": {
            "credential_version_sha256": version,
            "vault_revision": 101,
            "observed_revocation_revision": 72,
            "material_state": "active",
        },
        "vault_revocation": {
            "credential_version_sha256": version,
            "vault_revision": 101,
            "revocation_revision": 73,
            "current_revoked": False,
            "previous_generation": 2,
            "previous_revoked": True,
        },
        "route_key": {
            "credential_version_sha256": version,
            "vault_revision": 101,
            "revocation_revision": 73,
            "key_binding_state": "live_runtime_credential_version_matches_vault",
            "runtime_route_generation": 3,
        },
        "reservation": {
            "reservation_status": "committed",
            "usage_revision": 31,
            "lease_generation": 7,
            "reserved_micro_usd": 400,
            "ledger_issuer": "signed_postgres_model_usage",
        },
    }
    keys = {kind: Ed25519PrivateKey.generate() for kind in KINDS}
    control: Dict[str, Any] = {
        "calls": [], "sign_as": {}, "nonce_override": {},
        "extra": {}, "raw_override": {}, "status": {}, "timestamp_offset": {},
    }

    def signer(kind: str, context: DispatchBinding, nonce: str) -> bytes:
        claims = {
            **ProviderCredentialDispatchGuard._shared(context, nonce),
            "issued_at": NOW + control["timestamp_offset"].get(kind, 0),
            "expires_at": NOW + 8 + control["timestamp_offset"].get(kind, 0),
            **evidence[kind],
            **control["extra"].get(kind, {}),
        }
        if kind in control["nonce_override"]:
            claims["nonce"] = control["nonce_override"][kind]
        private = keys[control["sign_as"].get(kind, kind)]
        signature = private.sign(
            _DOMAIN + kind.encode("ascii") + b"\x00" + _canonical(claims)
        )
        return json.dumps(
            {
                "claims": claims,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            },
            separators=(",", ":"),
        ).encode("ascii")

    def reader(kind: str) -> Any:
        async def read(context: DispatchBinding, nonce: str) -> bytes:
            control["calls"].append(kind)
            if kind in control["status"]:
                raise OSError("synthetic witness transport offline")
            return control["raw_override"].get(kind, signer(kind, context, nonce))
        return read

    guard = ProviderCredentialDispatchGuard(
        readiness=readiness,
        signer_keys={k: key.public_key() for k, key in keys.items()},
        readers={k: reader(k) for k in KINDS},
        clock=lambda: NOW,
    )
    control["keys"] = keys
    control["readiness"] = readiness
    control["existing_proofs"] = existing_proofs
    control["original"] = previous
    return guard, binding, evidence, control


def _check_fail(
    guard: ProviderCredentialDispatchGuard,
    binding: DispatchBinding,
) -> None:
    mock_paid = AsyncMock()
    async def guarded() -> None:
        ticket = await guard.authorize_reserved(binding)
        await guard.consume_for_send(ticket)
        await mock_paid()
    with pytest.raises(ProviderDispatchDenied):
        asyncio.run(guarded())
    mock_paid.assert_not_awaited()


def test_independent_signed_post_commit_gate_is_single_use_without_provider_io() -> None:
    guard, binding, _, control = _fixture()
    permit = asyncio.run(guard.authorize_reserved(binding))
    assert control["calls"] == list(KINDS)
    assert permit.call_id == binding.call_id
    assert permit.route_policy_sha256 == ROUTE_HASH
    assert permit.proof_expires_at == NOW + 8
    assert "token" not in repr(permit)
    assert "current-secret-v3" not in repr(permit)
    asyncio.run(guard.consume_for_send(permit))
    with pytest.raises(ProviderDispatchDenied):
        asyncio.run(guard.consume_for_send(permit))
    with pytest.raises(ProviderDispatchDenied):
        asyncio.run(guard.authorize_reserved(binding))


@pytest.mark.parametrize("kind,field,value", [
    ("vault_material", "material_state", "stale"),
    ("vault_material", "vault_revision", 99),
    ("vault_material", "observed_revocation_revision", 80),
    ("vault_material", "credential_version_sha256", "c" * 64),
    ("vault_revocation", "credential_version_sha256", "d" * 64),
    ("vault_revocation", "vault_revision", 100),
    ("vault_revocation", "current_revoked", True),
    ("vault_revocation", "revocation_revision", 70),
    ("vault_revocation", "previous_generation", 1),
    ("vault_revocation", "previous_revoked", False),
    ("route_key", "credential_version_sha256", "d" * 64),
    ("route_key", "vault_revision", 99),
    ("route_key", "revocation_revision", 74),
    ("route_key", "key_binding_state", "caller_boolean"),
    ("route_key", "runtime_route_generation", 2),
    ("reservation", "reservation_status", "pending"),
    ("reservation", "reserved_micro_usd", 299),
    ("reservation", "usage_revision", 0),
    ("reservation", "lease_generation", 0),
    ("reservation", "ledger_issuer", "symbolic_review"),
])
def test_unsafe_signed_material_revocation_route_key_or_ledger_denied_before_paid(
    kind: str, field: str, value: Any,
) -> None:
    guard, binding, evidence, _ = _fixture()
    evidence[kind][field] = value
    _check_fail(guard, binding)


@pytest.mark.parametrize("kind", KINDS)
def test_offline_service_or_lost_ack_burns_reservation_without_paid_call(kind: str) -> None:
    guard, binding, _, control = _fixture()
    control["status"][kind] = "ACK lost"
    _check_fail(guard, binding)
    control["status"].pop(kind)
    _check_fail(guard, binding)
    # Same committed call-id must not be resurrected after uncertain outcome.
    assert binding.call_id in guard._burned


@pytest.mark.parametrize("kind", KINDS)
def test_cross_signed_root_forgery_never_calls_provider(kind: str) -> None:
    guard, binding, _, control = _fixture()
    control["sign_as"][kind] = "reservation" if kind != "reservation" else "route_key"
    _check_fail(guard, binding)


@pytest.mark.parametrize("kind", KINDS)
def test_wrong_nonce_fails_even_with_valid_service_signature(kind: str) -> None:
    guard, binding, _, control = _fixture()
    control["nonce_override"][kind] = "a" * 32
    _check_fail(guard, binding)


@pytest.mark.parametrize("kind", KINDS)
def test_extra_fields_including_fake_secrets_are_denied_and_never_logged(kind: str) -> None:
    guard, binding, _, control = _fixture()
    control["extra"][kind] = {"api_key": "sk-synthetic-never-display"}
    with pytest.raises(ProviderDispatchDenied) as caught:
        asyncio.run(guard.authorize_reserved(binding))
    assert "sk-synthetic-never-display" not in str(caught.value)
    assert "sk-synthetic-never-display" not in repr(caught.value)


@pytest.mark.parametrize("kind", KINDS)
def test_old_or_future_signed_observation_fails_closed(kind: str) -> None:
    guard, binding, _, control = _fixture()
    control["timestamp_offset"][kind] = 60
    _check_fail(guard, binding)


@pytest.mark.parametrize("kind", KINDS)
def test_corrupt_json_duplicate_fields_or_signed_envelope_denied(kind: str) -> None:
    guard, binding, _, control = _fixture()
    control["raw_override"][kind] = (
        b'{"claims": {}, "claims": {}, "signature_b64": ""}'
    )
    _check_fail(guard, binding)


def test_signed_tenant_task_policy_and_route_are_not_caller_assertions() -> None:
    guard, binding, _, control = _fixture()
    old_reader = guard._readers["route_key"]
    original = binding
    # The host reader observes an earlier different Task, while caller
    # supplies an otherwise structurally valid current Task.
    async def stale(context: DispatchBinding, nonce: str) -> bytes:
        changed = replace(
            context,
            readiness_request=replace(
                context.readiness_request, task_id="task-other",
            ),
        )
        return await old_reader(changed, nonce)
    guard._readers["route_key"] = stale
    _check_fail(guard, original)
    # Missing host signature cannot be replaced with a request-field echo.
    assert control["calls"].count("route_key") == 1


@pytest.mark.parametrize("field,value", [
    ("engagement_id", "eng-other-tenant"),
    ("flow_id", "flow-other"),
    ("flow_revision", 8),
    ("authorization_sha256", "f" * 64),
    ("authorization_version", 10),
    ("ref_id", "pcref-" + "e" * 32),
    ("reference_revision", 8),
    ("generation", 4),
    ("policy_sha256", "f" * 64),
    ("task_id", "task-other"),
    ("model", "openai/different"),
    ("operation", "embedding"),
    ("cost_request_micro_usd", 1000),
])
def test_independently_signed_stale_route_or_task_claim_rejected(
    field: str, value: Any,
) -> None:
    guard, binding, _, _ = _fixture()
    old_reader = guard._readers["route_key"]

    async def wrong_binding(context: DispatchBinding, nonce: str) -> bytes:
        other_request = replace(context.readiness_request, **{field: value})
        return await old_reader(
            replace(context, readiness_request=other_request), nonce
        )

    guard._readers["route_key"] = wrong_binding
    _check_fail(guard, binding)


@pytest.mark.parametrize("kind,member,value", [
    ("profile", "status", "revoked"),
    ("profile", "reference_revision", 99),
    ("flow", "revoked", True),
    ("principal", "disabled", True),
    ("policy", "revoked", True),
    ("vault", "generation", 2),
    ("vault_revocation", "credential_revoked", True),
    ("budget", "budget_state", "blocked"),
])
def test_forged_independent_dispatch_witnesses_cannot_override_real_readiness(
    kind: str, member: str, value: Any,
) -> None:
    guard, binding, _, control = _fixture()
    # Seven-root source remains genuinely signed, but reports current
    # revoke/rotation/stale status. Four extra positive proofs must be ignored.
    control["existing_proofs"][kind][member] = value
    _check_fail(guard, binding)
    assert control["calls"] == []


def test_route_policy_or_deployed_key_drift_denied() -> None:
    guard, binding, _, control = _fixture()
    reader = guard._readers["route_key"]
    async def old_route(context: DispatchBinding, nonce: str) -> bytes:
        return await reader(
            replace(context, route_deployment_sha256="c" * 64), nonce
        )
    guard._readers["route_key"] = old_route
    _check_fail(guard, binding)


def test_expired_or_forged_permit_is_never_usable() -> None:
    guard, binding, _, _ = _fixture()
    permit = asyncio.run(guard.authorize_reserved(binding))
    guard._clock = lambda: NOW + 11
    with pytest.raises(ProviderDispatchDenied):
        asyncio.run(guard.consume_for_send(permit))
    with pytest.raises(ProviderDispatchDenied):
        asyncio.run(guard.consume_for_send(permit))


def test_advisory_readiness_cannot_be_replaced_with_unverified_positive_flag() -> None:
    guard, binding, _, control = _fixture()
    control["readiness"].assess = AsyncMock(
        return_value=CredentialReadinessDecision(
            ref_id=binding.readiness_request.ref_id,
            reference_revision=binding.readiness_request.reference_revision,
            generation=binding.readiness_request.generation,
            purpose=binding.readiness_request.purpose,
            proof_expires_at=NOW + 8,
            independently_attested_vault_presence=False,
        )
    )
    _check_fail(guard, binding)
    assert control["calls"] == []


def test_new_witness_cannot_rollback_below_already_current_readiness_source_revision() -> None:
    guard, binding, _, control = _fixture()
    # Independently signed prior readiness roots now observe newer vault and
    # revocation sources. Four separately signed but older version witnesses
    # cannot authorize a dispatched route from those older snapshots.
    material = control["existing_proofs"]["vault"]
    revoked = control["existing_proofs"]["vault_revocation"]
    material["vault_revision"] = 102
    material["observed_revocation_revision"] = 74
    revoked["vault_revision"] = 102
    revoked["revocation_revision"] = 74
    _check_fail(guard, binding)
    assert control["calls"] == list(KINDS)


def test_missing_enrolled_signer_roots_and_role_collision_denied() -> None:
    guard, _, _, control = _fixture()
    with pytest.raises(ProviderDispatchDenied):
        ProviderCredentialDispatchGuard(
            readiness=control["readiness"], signer_keys={}, readers={},
        )
    signers = {kind: s.public_key() for kind, s in control["keys"].items()}
    signers["route_key"] = signers["reservation"]
    with pytest.raises(ProviderDispatchDenied):
        ProviderCredentialDispatchGuard(
            readiness=control["readiness"], signer_keys=signers,
            readers=guard._readers,
        )
    # Cannot enroll the vault's existing material signer again as a
    # supposedly independent ledger signing identity.
    signers = {kind: s.public_key() for kind, s in control["keys"].items()}
    signers["reservation"] = control["original"]["signer"]["vault"].public_key()
    with pytest.raises(ProviderDispatchDenied):
        ProviderCredentialDispatchGuard(
            readiness=control["readiness"], signer_keys=signers,
            readers=guard._readers,
        )


def test_readiness_alone_cannot_issue_dispatch_permit() -> None:
    guard, binding, _, control = _fixture()
    # A positive signed seven-root vault assessment remains advisory.
    ready = asyncio.run(control["readiness"].assess(binding.readiness_request))
    assert ready.independently_attested_vault_presence
    assert ready.dispatch_authorized is False
    assert ready.budget_reserved is False
    assert not guard._issued
    with pytest.raises(ProviderDispatchDenied):
        asyncio.run(
            guard.consume_for_send(
                DispatchPermit(
                    call_id=binding.call_id, route_policy_sha256=ROUTE_HASH,
                    route_deployment_sha256=DEPLOY_HASH,
                    proof_expires_at=NOW + 5, _token="forged",
                )
            )
        )


def test_missing_reservation_id_refuses_without_any_authority_io() -> None:
    guard, binding, _, control = _fixture()
    _check_fail(guard, replace(binding, call_id=""))
    assert not control["calls"]


def test_ack_loss_after_synthetic_send_never_retries_without_reconciliation() -> None:
    guard, binding, _, _ = _fixture()
    fake_provider = AsyncMock(side_effect=TimeoutError("synthetic provider ACK lost"))

    async def one_send() -> None:
        permit = await guard.authorize_reserved(binding)
        await guard.consume_for_send(permit)
        await fake_provider()

    with pytest.raises(TimeoutError):
        asyncio.run(one_send())
    fake_provider.assert_awaited_once()
    with pytest.raises(ProviderDispatchDenied):
        asyncio.run(guard.authorize_reserved(binding))
    fake_provider.assert_awaited_once()


def test_protected_route_does_not_expose_env_key_or_log_value(caplog: Any) -> None:
    """The entire new module is nonsecret, even in fatal/error diagnostics."""
    guard, binding, evidence, control = _fixture()
    evidence["route_key"]["key_binding_state"] = "no_live_material"
    secret = "sk-only-synthetic-value-should-not-appear"
    caplog.clear()
    with pytest.raises(ProviderDispatchDenied) as failure:
        asyncio.run(guard.authorize_reserved(binding))
    assert secret not in str(failure.value)
    assert secret not in caplog.text
    assert secret not in repr(guard)
    assert not hasattr(guard, "api_key")
    assert not hasattr(guard, "credential_env")
