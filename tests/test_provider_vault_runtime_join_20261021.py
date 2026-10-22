"""Synthetic host-only provider factory qualification; no live vault or provider."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core import host_vault_guard_admission as host
from ai_osop.core import llm_client as llm
from ai_osop.core import provider_vault_runtime_join as join
from ai_osop.core.host_vault_guard_admission import HostVaultGuardAdmission
from ai_osop.core.provider_credential_dispatch_guard import (
    ProviderCredentialDispatchGuard,
)
from ai_osop.memory.model_usage import (
    ModelOutcomeUncertain,
    ModelUsageLedger,
)


NOW = 1792584000


def _signed(private: Ed25519PrivateKey, domain: bytes, claims: dict[str, Any]) -> bytes:
    body = join._canonical(claims)
    return json.dumps(
        {
            "claims": claims,
            "signature_b64": base64.b64encode(private.sign(domain + body)).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("ascii")


def _source_fixture() -> dict[str, Any]:
    source = Path(__file__).with_name("test_host_vault_guard_admission_20261021.py")
    spec = importlib.util.spec_from_file_location("_runtime_host_fixture", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._fixture()


@pytest.fixture
def enrolled(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    f = _source_fixture()
    gate = HostVaultGuardAdmission(**f["options"])
    signer = Ed25519PrivateKey.generate()
    receipt_signer = signer
    clock = [NOW]
    enrollment = {
        "schema": join._FENCE_SCHEMA,
        "deployment_id": gate._claims["deployment_id"],
        "ledger_public_root_sha256": join._public_sha(signer.public_key()),
        "ledger_readback_service_sha256": gate._claims["ledger_readback_service_sha256"],
        "shared_revocation_fence_sha256": gate._claims["shared_revocation_fence_sha256"],
        "issued_at": NOW,
        "expires_at": NOW + 8,
    }
    control: dict[str, Any] = {
        "extra": {},
        "wrong_signer": False,
        "offline": False,
        "seen": set(),
        "claim_count": 0,
    }

    async def read_claim(binding: Any, nonce: str) -> bytes:
        control["claim_count"] += 1
        if control["offline"]:
            raise ConnectionError("Simulated lost CAS ACK")
        # This in-memory source is explicitly test-only. Production must
        # implement durable, linearizable CAS before signing this receipt.
        if binding.call_id in control["seen"]:
            raise RuntimeError("Simulated durable duplicate")
        control["seen"].add(binding.call_id)
        claims = {
            **ProviderCredentialDispatchGuard._shared(binding, nonce),
            "schema": join._FENCE_SCHEMA,
            "deployment_id": enrollment["deployment_id"],
            "ledger_readback_service_sha256": enrollment["ledger_readback_service_sha256"],
            "shared_revocation_fence_sha256": enrollment["shared_revocation_fence_sha256"],
            "claim_state": "committed_atomic_one_use",
            "usage_revision": 31,
            "vault_revision": 101,
            "revocation_revision": 73,
            "credential_version_sha256": f["proofs"]["vault_material"]["credential_version_sha256"],
            "previous_generation": binding.readiness_request.generation - 1,
            "previous_revoked": binding.readiness_request.generation > 1,
            "issued_at": NOW,
            "expires_at": NOW + 4,
            **control["extra"],
        }
        chosen = Ed25519PrivateKey.generate() if control["wrong_signer"] else receipt_signer
        return _signed(chosen, join._FENCE_RECEIPT_DOMAIN, claims)

    signed_enrollment = _signed(f["signer"], join._FENCE_ENROLL_DOMAIN, enrollment)
    options = {
        "admission": gate,
        "ledger_public_key": signer.public_key(),
        "ledger_root_sha256": enrollment["ledger_public_root_sha256"],
        "signed_host_enrollment": signed_enrollment,
        "claim_reader": read_claim,
        "clock": lambda: clock[0],
    }
    monkeypatch.setattr(host, "configured_routes", lambda: f["routes"])
    monkeypatch.setattr(join, "configured_routes", lambda: f["routes"])
    monkeypatch.setattr(llm, "configured_routes", lambda: f["routes"])
    monkeypatch.setattr(llm, "catalog_mode", lambda: "off")
    monkeypatch.setattr(llm, "configured_model_role_policy", lambda: None)
    monkeypatch.setattr(llm.settings, "mock_llm", False)
    monkeypatch.setattr(
        llm.RequestContext,
        "get",
        lambda: {
            "engagement_id": f["binding"].readiness_request.engagement_id,
            "task_id": f["binding"].readiness_request.task_id,
        },
    )
    provider_completion = AsyncMock(side_effect=AssertionError("provider sent"))
    provider_embedding = AsyncMock(side_effect=AssertionError("embedding sent"))
    monkeypatch.setattr(llm.litellm, "acompletion", provider_completion)
    monkeypatch.setattr(llm.litellm, "aembedding", provider_embedding)
    provider_env_reads: list[str] = []
    original_get = os.environ.get

    def env_read(key: str, default: Any = None) -> Any:
        if key in {"TEST_NEVER_READ_ACTUAL_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"}:
            provider_env_reads.append(key)
            raise AssertionError("Provider credential was accessed")
        return original_get(key, default)

    monkeypatch.setattr(os.environ, "get", env_read)
    f.update(
        {
            "gate": gate,
            "signer": signer,
            "clock": clock,
            "enrollment": enrollment,
            "fence_options": options,
            "control": control,
            "completion": provider_completion,
            "embedding": provider_embedding,
            "provider_env_reads": provider_env_reads,
        }
    )
    return f


def _binding(
    f: dict[str, Any],
    wrapper: join.ProviderVaultRuntimeJoin,
    call_id: str = "call-genuine-reservation",
) -> Any:
    r = f["binding"].readiness_request
    return asyncio.run(
        wrapper.binding_factory(
            r.engagement_id,
            r.task_id,
            r.model,
            r.operation,
            f["route"],
            call_id,
        )
    )


def _no_send(f: dict[str, Any]) -> None:
    f["completion"].assert_not_awaited()
    f["embedding"].assert_not_awaited()
    assert not f["provider_env_reads"]


def test_missing_host_and_missing_fence_always_build_pending_client(
    enrolled: dict[str, Any],
) -> None:
    absent = join.ProviderVaultRuntimeJoin()
    health = absent.health()
    assert health.code == "PENDING_HOST_ENROLLMENT"
    assert health.provider_dispatch_authorized is False
    pending = absent.construct_client(usage_store=None)
    assert pending._vault_guard_required is True
    assert pending._vault_guard is None
    host_only = join.ProviderVaultRuntimeJoin(admission=enrolled["gate"])
    assert host_only.health().code == "PENDING_DURABLE_CALL_FENCE"
    pending = host_only.construct_client(usage_store=None)
    assert pending._vault_guard_required and pending._vault_binding_factory is None
    with pytest.raises(Exception):
        asyncio.run(pending._provider_call("completion", "openai/mock", 1))
    assert enrolled["control"]["claim_count"] == 0
    _no_send(enrolled)


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_root",
        "wrong_host",
        "expired",
        "wrong_deployment",
        "wrong_readback",
        "wrong_fence",
        "duplicate_json",
    ),
)
def test_forged_or_expired_fence_enrollment_fails_before_install(
    enrolled: dict[str, Any],
    mutation: str,
) -> None:
    f = enrolled
    args = dict(f["fence_options"])
    claims = dict(f["enrollment"])
    if mutation == "wrong_root":
        args["ledger_public_key"] = f["gate"]._root
        args["ledger_root_sha256"] = host._hash_public(f["gate"]._root)
        claims["ledger_public_root_sha256"] = args["ledger_root_sha256"]
    elif mutation == "wrong_host":
        claims["deployment_id"] = "other-host"
    elif mutation == "expired":
        claims["expires_at"] = NOW - 1
    elif mutation == "wrong_deployment":
        claims["deployment_id"] = "other-instance"
    elif mutation == "wrong_readback":
        claims["ledger_readback_service_sha256"] = "a" * 64
    elif mutation == "wrong_fence":
        claims["shared_revocation_fence_sha256"] = "b" * 64
    else:
        args["signed_host_enrollment"] = b'{"claims":{},"claims":{},"signature_b64":"no"}'
    if mutation != "duplicate_json":
        args["signed_host_enrollment"] = _signed(f["signer"], join._FENCE_ENROLL_DOMAIN, claims)
    with pytest.raises(join.ProviderVaultRuntimeDenied):
        join.EnrolledOneUseCallFence(**args)
    _no_send(f)


def test_synthetically_signed_host_fence_constructs_guarded_client_and_claims_once(
    enrolled: dict[str, Any],
) -> None:
    f = enrolled
    fence = join.EnrolledOneUseCallFence(**f["fence_options"])
    wrapper = join.ProviderVaultRuntimeJoin(admission=f["gate"], call_fence=fence)
    health = wrapper.health()
    assert health.code == "HOST_ENROLLED_DISPATCH_UNPROVEN"
    assert health.shared_call_fence_enrolled
    assert health.provider_dispatch_authorized is False
    ledger = ModelUsageLedger.__new__(ModelUsageLedger)
    client = wrapper.construct_client(usage_store=ledger)
    assert type(client) is llm.LiteLLMClient
    assert client._vault_guard_required is True
    assert client._vault_guard is f["guard"]
    assert client._vault_binding_factory.__self__ is wrapper
    binding = _binding(f, wrapper)
    assert binding.call_id == "call-genuine-reservation"
    assert f["control"]["claim_count"] == 1
    assert f["control"]["claim_count"] == 1
    assert f["control"]["seen"] == {"call-genuine-reservation"}
    with pytest.raises(join.ProviderVaultRuntimeDenied, match="already claimed"):
        _binding(f, wrapper)
    _no_send(f)


def test_two_join_instances_cannot_reclaim_shared_host_call_id(
    enrolled: dict[str, Any],
) -> None:
    f = enrolled
    one = join.ProviderVaultRuntimeJoin(
        admission=f["gate"],
        call_fence=join.EnrolledOneUseCallFence(**f["fence_options"]),
    )
    two = join.ProviderVaultRuntimeJoin(
        admission=f["gate"],
        call_fence=join.EnrolledOneUseCallFence(**f["fence_options"]),
    )
    assert _binding(f, one).call_id == "call-genuine-reservation"
    # The second independently constructed local fence has no local burn,
    # so only the host-level persistent CAS contract can stop this replay.
    with pytest.raises(join.ProviderVaultRuntimeDenied):
        _binding(f, two)
    assert f["control"]["claim_count"] == 2
    assert "call-genuine-reservation" in two._fence._burned
    _no_send(f)


def test_parallel_claims_serialize_to_one_host_receipt(
    enrolled: dict[str, Any],
) -> None:
    f = enrolled
    wrapper = join.ProviderVaultRuntimeJoin(
        admission=f["gate"],
        call_fence=join.EnrolledOneUseCallFence(**f["fence_options"]),
    )
    r = f["binding"].readiness_request

    async def twice() -> list[Any]:
        async def attempt() -> Any:
            return await wrapper.binding_factory(
                r.engagement_id,
                r.task_id,
                r.model,
                r.operation,
                f["route"],
                "call-genuine-reservation",
            )

        return await asyncio.gather(attempt(), attempt(), return_exceptions=True)

    result = asyncio.run(twice())
    assert sum(type(x) is join.ProviderVaultRuntimeDenied for x in result) == 1
    assert sum(type(x) is type(f["binding"]) for x in result) == 1
    assert f["control"]["claim_count"] == 1
    _no_send(f)


@pytest.mark.parametrize(
    "bad",
    (
        "offline",
        "forged_signer",
        "stale",
        "wrong_nonce",
        "wrong_task",
        "wrong_deployment",
        "revoked",
        "bad_previous_generation",
        "previous_not_revoked",
        "older_vault",
        "older_revocation",
        "newer_mismatched_revocation",
        "missing_receipt_state",
        "invalid_usage",
        "wrong_version",
        "wrong_readback_service",
    ),
)
def test_untrusted_current_receipt_denied_and_call_burned(
    enrolled: dict[str, Any],
    bad: str,
) -> None:
    f = enrolled
    control = f["control"]
    if bad == "offline":
        control["offline"] = True
    elif bad == "forged_signer":
        control["wrong_signer"] = True
    else:
        replacements = {
            "stale": {"expires_at": NOW - 1},
            "wrong_nonce": {"nonce": "f" * 32},
            "wrong_task": {"task_id": "task-other"},
            "wrong_deployment": {"deployment_id": "other-host"},
            "wrong_readback_service": {"ledger_readback_service_sha256": "9" * 64},
            "revoked": {"claim_state": "revoked"},
            "bad_previous_generation": {"previous_generation": 1},
            "previous_not_revoked": {"previous_revoked": False},
            "older_vault": {"vault_revision": 1},
            "older_revocation": {"revocation_revision": 1},
            "newer_mismatched_revocation": {"revocation_revision": 74},
            "missing_receipt_state": {"claim_state": None},
            "invalid_usage": {"usage_revision": 0},
            "wrong_version": {"credential_version_sha256": "e" * 64},
        }
        control["extra"] = replacements[bad]
    wrapper = join.ProviderVaultRuntimeJoin(
        admission=f["gate"],
        call_fence=join.EnrolledOneUseCallFence(**f["fence_options"]),
    )
    with pytest.raises(join.ProviderVaultRuntimeDenied):
        _binding(f, wrapper)
    assert "call-genuine-reservation" in wrapper._fence._burned
    control["offline"] = False
    control["wrong_signer"] = False
    control["extra"] = {}
    with pytest.raises(join.ProviderVaultRuntimeDenied, match="already claimed"):
        _binding(f, wrapper)
    _no_send(f)


def test_actual_litellm_dispatch_denies_signed_fence_forgery_before_key_or_provider(
    enrolled: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    f = enrolled
    f["control"]["wrong_signer"] = True
    wrapper = join.ProviderVaultRuntimeJoin(
        admission=f["gate"],
        call_fence=join.EnrolledOneUseCallFence(**f["fence_options"]),
    )
    ledger = ModelUsageLedger.__new__(ModelUsageLedger)
    reserve = AsyncMock(return_value="call-genuine-reservation")
    settle = AsyncMock(return_value=True)
    monkeypatch.setattr(ledger, "reserve", reserve)
    monkeypatch.setattr(ledger, "settle", settle)
    client = wrapper.construct_client(usage_store=ledger)
    with pytest.raises(ModelOutcomeUncertain, match="not authorized"):
        asyncio.run(
            client._provider_call_admitted(
                "completion",
                f["binding"].readiness_request.model,
                1,
                messages=[{"role": "user", "content": "no network"}],
                max_tokens=32,
            )
        )
    reserve.assert_awaited_once()
    settle.assert_awaited_once()
    assert settle.await_args.kwargs["delivered"] is False
    assert f["control"]["claim_count"] == 1
    _no_send(f)


def test_expiry_and_route_drift_block_new_client_or_claim(
    enrolled: dict[str, Any],
) -> None:
    f = enrolled
    fence = join.EnrolledOneUseCallFence(**f["fence_options"])
    wrapper = join.ProviderVaultRuntimeJoin(admission=f["gate"], call_fence=fence)
    f["clock"][0] = NOW + 10
    assert wrapper.health().code == "PENDING_CURRENT_HOST_AUTHORITY"
    with pytest.raises(join.ProviderVaultRuntimeDenied, match="expired"):
        _binding(f, wrapper)
    with pytest.raises(join.ProviderVaultRuntimeDenied):
        wrapper.construct_client(usage_store=ModelUsageLedger.__new__(ModelUsageLedger))
    f["clock"][0] = NOW
    f["routes"].policy_sha256 = "0" * 64
    with pytest.raises(join.ProviderVaultRuntimeDenied, match="route policy"):
        wrapper.construct_client(usage_store=ModelUsageLedger.__new__(ModelUsageLedger))
    _no_send(f)


@pytest.mark.parametrize(
    "forbidden",
    ("vault_guard", "vault_guard_required", "vault_binding_factory", "api_key", "credential_env"),
)
def test_host_client_protected_overrides_never_accepted(
    enrolled: dict[str, Any],
    forbidden: str,
) -> None:
    wrapper = join.ProviderVaultRuntimeJoin()
    with pytest.raises(join.ProviderVaultRuntimeDenied):
        wrapper.construct_client(**{"usage_store": None, forbidden: "untrusted"})
    _no_send(enrolled)
