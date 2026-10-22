"""Synthetic-only and failure-first host vault constructor admission tests.

All private signers exist only inside each test fixture and are not host
enrollment. No real API key, provider, paid API, app DB, host vault or network.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core import host_vault_guard_admission as admission
from ai_osop.core import llm_client as llm
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.host_vault_guard_admission import (
    HostVaultAdmissionDenied,
    HostVaultGuardAdmission,
    pending_guarded_client,
)
from ai_osop.core.provider_credential_dispatch_guard import DispatchBinding
from ai_osop.core.provider_routing import ProviderRoute
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelUsageLedger


NOW = 1792584000
TEST_SOURCE = Path(__file__).with_name("test_provider_dispatch_guard_20261021.py")


def _guard_fixture() -> tuple[Any, Any, Any, Any]:
    spec = importlib.util.spec_from_file_location("_host_only_synthetic_guard", TEST_SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._fixture()


def _signed_manifest(
    guard: Any,
    *,
    private: Ed25519PrivateKey,
    replacement: Dict[str, Any] | None = None,
) -> bytes:
    claims: Dict[str, Any] = {
        "schema": admission._SCHEMA,
        "audience": admission._AUDIENCE,
        "deployment_id": "internal-ai-osop-instance",
        "issued_at": NOW,
        "expires_at": NOW + 9,
        "route_policy_sha256": "a" * 64,
        "binding_source_sha256": "b" * 64,
        "runtime_key_service_sha256": "c" * 64,
        "ledger_readback_service_sha256": "d" * 64,
        "shared_revocation_fence_sha256": "e" * 64,
        "authority_root_sha256": admission._existing_authority_roots(guard),
    }
    claims.update(replacement or {})
    signature = private.sign(admission._DOMAIN + admission._canonical(claims))
    return json.dumps(
        {
            "claims": claims,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _fixture() -> Dict[str, Any]:
    guard, binding, proofs, control = _guard_fixture()
    signer = Ed25519PrivateKey.generate()
    route = ProviderRoute(
        model=binding.readiness_request.model,
        provider=binding.readiness_request.provider,
        operations=("completion", "embedding"),
        credential_env="TEST_NEVER_READ_ACTUAL_KEY",
        api_base=None,
        allowed_roles=(binding.readiness_request.agent_role,),
        capabilities=("text_completion", "embeddings"),
        max_output_tokens=128,
        budget_source="signed_postgres_roe",
    )
    routes = SimpleNamespace(
        version=2,
        policy_sha256="a" * 64,
        resolve=MagicMock(return_value=route),
    )
    real_deployment = llm._vault_route_deployment_sha256(route)

    async def host_reader(
        engagement: str, task: str, model: str, op: str, chosen: Any, call: str
    ) -> DispatchBinding:
        return replace(
            binding,
            call_id=call,
            route_deployment_sha256=real_deployment,
            readiness_request=replace(binding.readiness_request, operation=op),
        )

    host_reader_spy = AsyncMock(side_effect=host_reader)
    manifest = _signed_manifest(guard, private=signer)
    options = {
        "pinned_host_public_key": signer.public_key(),
        "pinned_host_root_sha256": admission._hash_public(signer.public_key()),
        "signed_enrollment": manifest,
        "guard": guard,
        "trusted_binding_reader": host_reader_spy,
        "expected_deployment_id": "internal-ai-osop-instance",
        "expected_binding_source_sha256": "b" * 64,
        "expected_runtime_key_service_sha256": "c" * 64,
        "expected_ledger_readback_service_sha256": "d" * 64,
        "expected_shared_revocation_fence_sha256": "e" * 64,
        "clock": lambda: NOW,
    }
    return {
        "guard": guard,
        "binding": binding,
        "proofs": proofs,
        "control": control,
        "signer": signer,
        "route": route,
        "routes": routes,
        "manifest": manifest,
        "options": options,
        "reader": host_reader_spy,
    }


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    """Actively bar every cost, env-key, and network boundary."""
    paid = AsyncMock(side_effect=AssertionError("paid provider called"))
    embedded = AsyncMock(side_effect=AssertionError("embedding provider called"))
    transport = MagicMock(side_effect=AssertionError("HTTP client initialized"))
    reserve = AsyncMock(side_effect=AssertionError("model cost reserved"))
    settle = AsyncMock(side_effect=AssertionError("model usage settled"))
    monkeypatch.setattr(llm.litellm, "acompletion", paid)
    monkeypatch.setattr(llm.litellm, "aembedding", embedded)
    monkeypatch.setattr(llm.httpx, "AsyncClient", transport)
    monkeypatch.setattr(llm.settings, "mock_llm", False)
    monkeypatch.setattr(llm, "catalog_mode", lambda: "off")
    monkeypatch.setattr(
        llm.RequestContext,
        "get",
        lambda: {"engagement_id": "eng-denied", "task_id": "task-denied"},
    )
    read_keys: list[str] = []
    getter = os.environ.get

    def not_an_env_key(name: str, default: Any = None) -> Any:
        if name in ("TEST_NEVER_READ_ACTUAL_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            read_keys.append(name)
            raise AssertionError("Provider environment credential touched")
        return getter(name, default)

    monkeypatch.setattr(os.environ, "get", not_an_env_key)
    ledger = SimpleNamespace(reserve=reserve, settle=settle)
    return {
        "paid": paid,
        "embed": embedded,
        "transport": transport,
        "reserve": reserve,
        "settle": settle,
        "env_keys": read_keys,
        "ledger": ledger,
        "monkeypatch": monkeypatch,
    }


def _assert_no_effects(state: Dict[str, Any]) -> None:
    state["paid"].assert_not_awaited()
    state["embed"].assert_not_awaited()
    state["transport"].assert_not_called()
    state["reserve"].assert_not_awaited()
    state["settle"].assert_not_awaited()
    assert state["env_keys"] == []


def test_no_enrolled_host_anchor_denies_without_guard_or_provider(
    isolated: Dict[str, Any],
) -> None:
    with pytest.raises(HostVaultAdmissionDenied, match="Independently pinned"):
        HostVaultGuardAdmission()
    client = pending_guarded_client(usage_store=isolated["ledger"])
    assert client._vault_guard_required is True
    assert client._vault_guard is None
    isolated["monkeypatch"].setattr(llm, "configured_routes", lambda: None)
    with pytest.raises(ModelBudgetExceeded):
        asyncio.run(client.complete([{"role": "user", "content": "do not send"}]))
    _assert_no_effects(isolated)


@pytest.mark.parametrize("operation", ("completion", "embedding"))
def test_guarded_pending_mode_never_reaches_provider_or_env(
    isolated: Dict[str, Any], operation: str
) -> None:
    isolated["monkeypatch"].setattr(llm, "configured_routes", lambda: None)
    client = pending_guarded_client(usage_store=isolated["ledger"])
    with pytest.raises(ModelBudgetExceeded):
        if operation == "completion":
            asyncio.run(client._provider_call("completion", "openai/mock", 1, messages=[]))
        else:
            asyncio.run(client._provider_call("embedding", "openai/mock", 1, input=["x"]))
    _assert_no_effects(isolated)


@pytest.mark.parametrize(
    "invalid",
    [
        "missing_signer",
        "wrong_pin",
        "fake_guard",
        "missing_reader",
        "wrong_deployment",
        "wrong_source",
        "wrong_runtime_service",
        "wrong_ledger_service",
        "wrong_revocation_fence",
        "wrong_root",
    ],
)
def test_no_valid_separately_pinned_host_enrollment_denies(
    invalid: str, isolated: Dict[str, Any]
) -> None:
    f = _fixture()
    o = dict(f["options"])
    if invalid == "missing_signer":
        o["pinned_host_public_key"] = None
    elif invalid == "wrong_pin":
        o["pinned_host_root_sha256"] = "f" * 64
    elif invalid == "fake_guard":
        o["guard"] = SimpleNamespace(authorize_reserved=AsyncMock(return_value=True))
    elif invalid == "missing_reader":
        o["trusted_binding_reader"] = None
    elif invalid == "wrong_deployment":
        o["expected_deployment_id"] = "other-runtime"
    elif invalid == "wrong_source":
        o["expected_binding_source_sha256"] = "f" * 64
    elif invalid == "wrong_runtime_service":
        o["expected_runtime_key_service_sha256"] = "f" * 64
    elif invalid == "wrong_ledger_service":
        o["expected_ledger_readback_service_sha256"] = "f" * 64
    elif invalid == "wrong_revocation_fence":
        o["expected_shared_revocation_fence_sha256"] = "f" * 64
    else:
        o["pinned_host_public_key"] = Ed25519PrivateKey.generate().public_key()
        o["pinned_host_root_sha256"] = admission._hash_public(o["pinned_host_public_key"])
    with pytest.raises(HostVaultAdmissionDenied):
        HostVaultGuardAdmission(**o)
    _assert_no_effects(isolated)


@pytest.mark.parametrize(
    "claim, replacement",
    [
        ("audience", "public-api-user"),
        ("schema", "older-caller-advisory"),
        ("deployment_id", "attacker-runtime"),
        ("route_policy_sha256", "0" * 64),
        ("runtime_key_service_sha256", "0" * 64),
        ("ledger_readback_service_sha256", "0" * 64),
        ("shared_revocation_fence_sha256", "0" * 64),
        ("issued_at", NOW - 100),
        ("issued_at", NOW + 100),
        ("expires_at", NOW - 1),
        ("expires_at", NOW + 100),
    ],
)
def test_signed_wrong_scope_or_expired_manifest_cannot_construct(
    claim: str, replacement: Any, isolated: Dict[str, Any]
) -> None:
    f = _fixture()
    o = dict(f["options"])
    o["signed_enrollment"] = _signed_manifest(
        f["guard"], private=f["signer"], replacement={claim: replacement}
    )
    with pytest.raises(HostVaultAdmissionDenied):
        HostVaultGuardAdmission(**o)
    _assert_no_effects(isolated)


def test_cross_role_root_reuse_denies() -> None:
    f = _fixture()
    o = dict(f["options"])
    public = f["guard"]._readiness._revocation_key
    o["pinned_host_public_key"] = public
    o["pinned_host_root_sha256"] = admission._hash_public(public)
    with pytest.raises(HostVaultAdmissionDenied):
        HostVaultGuardAdmission(**o)


def test_untrusted_duplicate_signed_fields_and_unsigned_override_denied() -> None:
    f = _fixture()
    o = dict(f["options"])
    o["signed_enrollment"] = b'{"claims":{},"claims":{},"signature_b64":"no"}'
    with pytest.raises(HostVaultAdmissionDenied):
        HostVaultGuardAdmission(**o)
    o["signed_enrollment"] = f["manifest"] + b" attacker"
    with pytest.raises(HostVaultAdmissionDenied):
        HostVaultGuardAdmission(**o)


def test_positive_synthetic_signature_still_never_marks_provider_ready(
    isolated: Dict[str, Any],
) -> None:
    f = _fixture()
    gate = HostVaultGuardAdmission(**f["options"])
    admission_state = gate.preflight()
    assert admission_state.host_enrollment_signature_verified is True
    assert admission_state.root_count == 11
    assert admission_state.provider_ready_verified is False
    assert admission_state.provider_contacted is False
    assert admission_state.budget_reserved is False
    assert admission_state.dispatch_authorized is False
    with pytest.raises(HostVaultAdmissionDenied, match="committed"):
        asyncio.run(gate.require_provider_ready_without_reservation())
    assert f["reader"].await_count == 0
    _assert_no_effects(isolated)


def test_lease_expires_and_enrolled_roots_cannot_be_rotated_silently() -> None:
    f = _fixture()
    now = [NOW]
    o = dict(f["options"])
    o["clock"] = lambda: now[0]
    gate = HostVaultGuardAdmission(**o)
    gate.preflight()
    now[0] += 11
    with pytest.raises(HostVaultAdmissionDenied):
        gate.constructor_kwargs()
    now[0] = NOW
    gate.preflight()
    f["guard"]._keys["route_key"] = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(HostVaultAdmissionDenied):
        gate.preflight()


def test_synthetically_enrolled_host_constructs_guarded_only_not_provider_ready(
    isolated: Dict[str, Any],
) -> None:
    f = _fixture()
    isolated["monkeypatch"].setattr(admission, "configured_routes", lambda: f["routes"])
    isolated["monkeypatch"].setattr(llm, "configured_routes", lambda: f["routes"])
    host = HostVaultGuardAdmission(**f["options"])
    ledger = ModelUsageLedger.__new__(ModelUsageLedger)  # no initializer / PG
    client = host.construct_client(usage_store=ledger, max_tokens=64)
    assert type(client) is LiteLLMClient  # imported below
    assert client._vault_guard_required is True
    assert client._vault_guard is f["guard"]
    assert client._vault_binding_factory.__self__ is host
    # This factory is still not evidence of a current vault key or committed
    # signed reservation. We never call its full signed dispatch in this test.
    with pytest.raises(HostVaultAdmissionDenied):
        host.construct_client(usage_store=isolated["ledger"])
    with pytest.raises(HostVaultAdmissionDenied):
        host.construct_client(usage_store=ledger, vault_guard_required=False)
    _assert_no_effects(isolated)


@pytest.mark.parametrize("route_drift", ("missing", "v1", "policy"))
def test_signed_enrollment_cannot_install_mismatched_production_route(
    route_drift: str,
) -> None:
    f = _fixture()
    routes = f["routes"]
    if route_drift == "v1":
        routes.version = 1
    elif route_drift == "policy":
        routes.policy_sha256 = "f" * 64
    original = admission.configured_routes
    try:
        admission.configured_routes = lambda: None if route_drift == "missing" else routes
        gate = HostVaultGuardAdmission(**f["options"])
        with pytest.raises(HostVaultAdmissionDenied):
            gate.construct_client(usage_store=ModelUsageLedger.__new__(ModelUsageLedger))
    finally:
        admission.configured_routes = original


@pytest.mark.parametrize(
    "wrong",
    ["task", "model", "operation", "call", "route_policy", "route_deployment", "provider"],
)
def test_host_binding_factory_denies_stale_source_or_wrong_task(
    wrong: str, isolated: Dict[str, Any]
) -> None:
    f = _fixture()
    gate = HostVaultGuardAdmission(**f["options"])
    isolated["monkeypatch"].setattr(admission, "configured_routes", lambda: f["routes"])
    ref = f["binding"].readiness_request

    async def wrong_source(*args: Any) -> DispatchBinding:
        current = await f["reader"].side_effect(*args)
        if wrong == "task":
            return replace(
                current, readiness_request=replace(current.readiness_request, task_id="task-wrong")
            )
        if wrong == "model":
            return replace(
                current, readiness_request=replace(current.readiness_request, model="other")
            )
        if wrong == "operation":
            return replace(
                current, readiness_request=replace(current.readiness_request, operation="embedding")
            )
        if wrong == "call":
            return replace(current, call_id="call-wrong")
        if wrong == "route_policy":
            return replace(current, route_policy_sha256="f" * 64)
        if wrong == "route_deployment":
            return replace(current, route_deployment_sha256="f" * 64)
        return replace(
            current, readiness_request=replace(current.readiness_request, provider="deepseek")
        )

    gate._reader = wrong_source
    with pytest.raises(HostVaultAdmissionDenied):
        asyncio.run(
            gate.binding_factory(
                ref.engagement_id,
                ref.task_id,
                ref.model,
                "completion",
                f["route"],
                "call-genuine-reservation",
            )
        )
    _assert_no_effects(isolated)


def test_host_binding_factory_returns_only_readback_never_mints_proofs(
    isolated: Dict[str, Any],
) -> None:
    f = _fixture()
    isolated["monkeypatch"].setattr(admission, "configured_routes", lambda: f["routes"])
    gate = HostVaultGuardAdmission(**f["options"])
    ref = f["binding"].readiness_request
    bound = asyncio.run(
        gate.binding_factory(
            ref.engagement_id,
            ref.task_id,
            ref.model,
            "completion",
            f["route"],
            "call-genuine-reservation",
        )
    )
    assert type(bound) is DispatchBinding
    assert f["reader"].await_count == 1
    # The helper has not called 11 signed readbacks or a budget endpoint.
    assert f["control"]["calls"] == []
    assert bound.route_deployment_sha256 == llm._vault_route_deployment_sha256(f["route"])
    _assert_no_effects(isolated)


@pytest.mark.parametrize(
    "forbidden",
    ["vault_guard", "vault_binding_factory", "vault_guard_required"],
)
def test_pending_constructor_never_allows_untrusted_host_guard_override(
    forbidden: str,
) -> None:
    with pytest.raises(HostVaultAdmissionDenied):
        pending_guarded_client(**{forbidden: False})
