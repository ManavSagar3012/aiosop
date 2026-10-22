"""Production LiteLLM method-body guard integration with synthetic authorities.

The local environment lacks litellm/neo4j, so this module compiles the
UNMODIFIED statements of the current production LiteLLMClient methods into
an isolated class namespace. Provider, catalog and ledger effects are mocks;
host signed authorities are actual Ed25519 code from the existing guard
qualification. These are not real app, vault, DB or paid-provider executions.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import importlib.util
import json
import re
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.provider_credential_dispatch_guard import (
    DispatchBinding,
    ProviderCredentialDispatchGuard,
)


SOURCE = Path(__file__).resolve().parents[1] / "src/ai_osop/core/llm_client.py"


class BudgetDenied(Exception):
    pass


class OutcomeUnknown(Exception):
    pass


class RouteDenied(Exception):
    pass


def _guard_fixture() -> tuple[Any, Any, Any, Any]:
    source = Path(__file__).with_name("test_provider_dispatch_guard_20261021.py")
    spec = importlib.util.spec_from_file_location("_vault_prod_boundary_fixture", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._fixture()


def _actual_class(runtime: dict[str, Any]) -> type:
    """Use exact production method AST; only replace external imports/effects."""
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "LiteLLMClient")
    wanted = {
        "__init__",
        "_provider_call",
        "_provider_call_admitted",
        "complete",
        "get_embedding",
    }
    body = []
    for child in node.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name in wanted:
            body.append(copy.deepcopy(child))
    cls = ast.ClassDef(
        name="ActualLiteLLMClient",
        bases=[],
        keywords=[],
        body=body,
        decorator_list=[],
    )
    digest = next(
        copy.deepcopy(n)
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_vault_route_deployment_sha256"
    )
    unit = ast.Module(
        body=[
            ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
            digest,
            cls,
        ],
        type_ignores=[],
    )
    env = {
        **runtime,
        "asyncio": asyncio,
        "json": json,
        "hashlib": __import__("hashlib"),
        "re": re,
        "time": time,
        "ProviderCredentialDispatchGuard": ProviderCredentialDispatchGuard,
        "DispatchBinding": DispatchBinding,
        "ModelBudgetExceeded": BudgetDenied,
        "ModelOutcomeUncertain": OutcomeUnknown,
        "ProviderRouteDenied": RouteDenied,
        "ProviderRouteUnavailable": RouteDenied,
        "ProviderCatalogModelAbsent": RouteDenied,
    }
    exec(compile(ast.fix_missing_locations(unit), str(SOURCE), "exec"), env)
    return env["ActualLiteLLMClient"]


def _harness(*, mode: str = "required", configured: bool = True) -> dict[str, Any]:
    guard, example, proofs, control = _guard_fixture()
    steps: list[str] = []
    route = SimpleNamespace(
        provider="openai",
        model="openai/test-model",
        operations=("completion", "embedding"),
        credential_env="OPENAI_API_KEY",
        api_base=None,
        allowed_roles=("vuln_analysis",),
        capabilities=("text_completion", "embeddings"),
        max_output_tokens=512,
        budget_source="signed_postgres_roe",
    )

    def credential() -> dict[str, str]:
        steps.append("read-key")
        return {"api_key": "synthetic-host-deployment-key", "num_retries": 0}

    route.provider_kwargs = credential

    async def authorize_task(**kwargs: Any) -> Any:
        raise AssertionError("contextmanager factory should be used")

    @asynccontextmanager
    async def admitted(**kwargs: Any) -> Any:
        steps.append("v2-task-authorized")
        assert kwargs["model"] == route.model
        assert kwargs["task_id"] == example.readiness_request.task_id
        yield {"authoritative_task_role": "vuln_analysis"}

    routes = SimpleNamespace(
        routes=(route,),
        version=2,
        policy_sha256="a" * 64,
        resolve=lambda model, op: (
            route
            if model == route.model and op in route.operations
            else (_ for _ in ()).throw(RouteDenied("not permitted"))
        ),
        authorize_task=admitted,
    )
    reserve = AsyncMock()
    settle = AsyncMock(return_value=True)

    async def reserved(*args: Any) -> str:
        steps.append("reserve")
        assert (
            args
            == (
                example.readiness_request.engagement_id,
                example.readiness_request.task_id,
                route.model,
                "completion",
            )
            or args[-1] == "embedding"
        )
        return example.call_id

    reserve.side_effect = reserved
    ledger = SimpleNamespace(reserve=reserve, settle=settle)
    provider = AsyncMock()

    async def completion(**kwargs: Any) -> Any:
        steps.append("provider")
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="inert completion"))],
            usage=None,
        )

    provider.side_effect = completion
    embedding = AsyncMock(return_value={"data": [{"embedding": [0.5]}]})

    def _logger(*args: Any, **kwargs: Any) -> None:
        steps.append("log")

    catalog = SimpleNamespace(verify=AsyncMock(return_value=None))
    runtime: dict[str, Any] = {
        "settings": SimpleNamespace(
            llm_primary_model=route.model,
            llm_fallback_model="openai/fallback",
            llm_temperature=0.4,
            llm_max_tokens=100,
            mock_llm=False,
            llm_completion_timeout=10,
            llm_embedding_model=route.model,
            llm_api_key=None,
            llm_api_base=None,
        ),
        "BestEffortProvenance": lambda sink: SimpleNamespace(submit=lambda action: None),
        "configured_routes": lambda: routes if configured else None,
        "RequestContext": SimpleNamespace(
            get=lambda: {
                "engagement_id": example.readiness_request.engagement_id,
                "task_id": example.readiness_request.task_id,
            }
        ),
        "configured_model_role_policy": lambda: None,
        "reject_caller_reasoning_overrides": lambda kwargs: None,
        "verify_embedding_request": lambda _: None,
        "catalog_mode": lambda: "off",
        "configured_catalog": lambda: catalog,
        "litellm": SimpleNamespace(acompletion=provider, aembedding=embedding),
        "llm_logger": SimpleNamespace(warning=_logger, error=_logger),
        "sanitize_messages": lambda m: m,
        "action_provenance": lambda *args, **kwargs: {"engagement_id": None},
        "safe_label": lambda value: value,
        "provider_usage": lambda _: {
            "input_tokens": 0,
            "output_tokens": 0,
            "billed_cost_usd": None,
            "cost_source": "unavailable",
        },
    }
    cls = _actual_class(runtime)
    # Compute digest from the actual production helper, never a fixture
    # hardcoded route hash disconnected from current route fields.
    actual_digest = cls._provider_call_admitted.__globals__["_vault_route_deployment_sha256"]

    async def factory(
        engagement: str,
        task: str,
        model: str,
        operation: str,
        actual_route: Any,
        call: str,
    ) -> DispatchBinding:
        steps.append("host-binding")
        assert (engagement, task, model) == (
            example.readiness_request.engagement_id,
            example.readiness_request.task_id,
            route.model,
        )
        return replace(
            example,
            route_deployment_sha256=actual_digest(actual_route),
            call_id=call,
            readiness_request=replace(example.readiness_request, operation=operation),
        )

    wrapped_factory = AsyncMock(side_effect=factory)
    # The actual guard's signed source readers are invoked by its own
    # cryptographic verifier. No verifier or guard method is replaced.
    if mode == "required":
        client = cls(
            usage_store=ledger,
            vault_guard_required=True,
            vault_guard=guard,
            vault_binding_factory=wrapped_factory,
        )
    elif mode == "pending":
        client = cls(usage_store=ledger, vault_guard_required=True)
    else:
        client = cls(usage_store=ledger)
    return dict(
        client=client,
        guard=guard,
        binding=example,
        proofs=proofs,
        control=control,
        steps=steps,
        routes=routes,
        route=route,
        provider=provider,
        embedding=embedding,
        ledger=ledger,
        factory=wrapped_factory,
        runtime=runtime,
        catalog=catalog,
        cls=cls,
    )


def _call(h: dict[str, Any], *, embedding: bool = False, **kwargs: Any) -> Any:
    if embedding:
        return asyncio.run(
            h["client"]._provider_call(
                "embedding", "openai/test-model", 1, input=["synthetic inert text"], **kwargs
            )
        )
    return asyncio.run(
        h["client"].complete([{"role": "user", "content": "inert content"}], **kwargs)
    )


def test_real_guarded_v2_dispatch_orders_reservation_signed_evidence_key_and_provider() -> None:
    h = _harness()
    real_reservation_reader = h["guard"]._readers["reservation"]

    async def observed_signed_reservation(*args: Any) -> bytes:
        result = await real_reservation_reader(*args)
        h["steps"].append("signed-ledger-proof")
        return result

    h["guard"]._readers["reservation"] = observed_signed_reservation
    result = _call(h)
    assert result == "inert completion"
    assert h["provider"].await_count == 1
    assert h["ledger"].reserve.await_count == 1
    assert h["ledger"].settle.await_count == 1
    assert h["ledger"].settle.await_args.kwargs == {"delivered": True}
    steps = h["steps"]
    assert steps.index("v2-task-authorized") < steps.index("reserve")
    assert steps.index("reserve") < steps.index("host-binding")
    assert steps.index("host-binding") < steps.index("signed-ledger-proof")
    assert steps.index("signed-ledger-proof") < steps.index("read-key")
    assert steps.index("host-binding") < steps.index("read-key")
    assert steps.index("read-key") < steps.index("provider")
    assert h["control"]["calls"] == [
        "vault_material",
        "vault_revocation",
        "route_key",
        "reservation",
    ]


def test_real_guarded_embedding_denies_without_independent_embedding_policy() -> None:
    h = _harness()
    # The genuinely signed source fixture authorizes only completion. Its
    # signed role/policy/Task cannot be relabeled to embedding by a caller.
    with pytest.raises(OutcomeUnknown):
        _call(h, embedding=True)
    h["provider"].assert_not_awaited()
    h["embedding"].assert_not_awaited()
    assert "reserve" in h["steps"]
    assert "read-key" not in h["steps"]
    h["ledger"].settle.assert_awaited_once_with(
        h["binding"].call_id,
        h["binding"].readiness_request.engagement_id,
        None,
        delivered=False,
    )


@pytest.mark.parametrize(
    "mode,has_routes",
    [
        ("pending", True),
        ("pending", False),
        ("required", False),
    ],
)
def test_unenrolled_or_missing_v2_route_denies_before_reserve_key_read_or_send(
    mode: str,
    has_routes: bool,
) -> None:
    h = _harness(mode=mode, configured=has_routes)
    with pytest.raises(BudgetDenied):
        _call(h)
    h["ledger"].reserve.assert_not_awaited()
    h["provider"].assert_not_awaited()
    h["embedding"].assert_not_awaited()
    assert "read-key" not in h["steps"]
    assert "host-binding" not in h["steps"]


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("vault_material", "material_state", "stale"),
        ("vault_revocation", "current_revoked", True),
        ("vault_revocation", "previous_revoked", False),
        ("route_key", "credential_version_sha256", "f" * 64),
        ("route_key", "runtime_route_generation", 1),
        ("route_key", "key_binding_state", "unverified"),
        ("reservation", "reservation_status", "uncommitted"),
        ("reservation", "reserved_micro_usd", 1),
    ],
)
def test_signed_invalid_material_key_rotation_or_reservation_never_reaches_provider(
    kind: str,
    field: str,
    value: Any,
) -> None:
    h = _harness()
    h["proofs"][kind][field] = value
    with pytest.raises(OutcomeUnknown):
        _call(h)
    h["ledger"].reserve.assert_awaited_once()
    h["ledger"].settle.assert_awaited_once_with(
        h["binding"].call_id,
        h["binding"].readiness_request.engagement_id,
        None,
        delivered=False,
    )
    h["provider"].assert_not_awaited()
    h["embedding"].assert_not_awaited()
    assert "read-key" not in h["steps"]


def test_signed_root_witness_outage_or_lost_ack_fails_closed_and_never_falls_back() -> None:
    h = _harness()
    h["control"]["status"]["route_key"] = "lost-ack"
    with pytest.raises(OutcomeUnknown):
        _call(h)
    h["provider"].assert_not_awaited()
    h["ledger"].reserve.assert_awaited_once()
    assert h["ledger"].settle.await_count == 1
    assert "read-key" not in h["steps"]
    assert h["guard"]._burned == {h["binding"].call_id}


@pytest.mark.parametrize("problem", ["wrong_policy", "wrong_route", "wrong_task", "wrong_call"])
def test_factory_is_only_an_input_until_independently_pinned_binding_verified(
    problem: str,
) -> None:
    h = _harness()

    async def forged(*args: Any) -> DispatchBinding:
        real = await h["factory"].side_effect(*args)
        if problem == "wrong_policy":
            return replace(real, route_policy_sha256="f" * 64)
        if problem == "wrong_route":
            return replace(real, route_deployment_sha256="f" * 64)
        if problem == "wrong_task":
            return replace(
                real, readiness_request=replace(real.readiness_request, task_id="task-forged")
            )
        return replace(real, call_id="call-wrong")

    h["factory"].side_effect = forged
    with pytest.raises(OutcomeUnknown):
        _call(h)
    h["provider"].assert_not_awaited()
    assert "read-key" not in h["steps"]


@pytest.mark.parametrize(
    "attack", ["vault_guard", "vault_binding_factory", "api_key", "vault_dispatch_permit"]
)
def test_caller_cannot_override_guard_via_litellm_kwargs(attack: str) -> None:
    h = _harness()
    with pytest.raises(RouteDenied):
        _call(h, **{attack: "untrusted-user-override"})
    h["ledger"].reserve.assert_not_awaited()
    h["provider"].assert_not_awaited()
    assert "read-key" not in h["steps"]


def test_ledger_refusal_never_fetches_environment_key_or_witness() -> None:
    h = _harness()
    h["ledger"].reserve.side_effect = BudgetDenied("inert PG denial")
    with pytest.raises(BudgetDenied):
        _call(h)
    h["provider"].assert_not_awaited()
    assert "read-key" not in h["steps"]
    h["factory"].assert_not_awaited()


def test_guarded_provider_timeout_is_unknown_and_never_retries() -> None:
    h = _harness()
    h["provider"].side_effect = TimeoutError("synthetic paid provider ACK lost")
    with pytest.raises(OutcomeUnknown):
        _call(h)
    h["provider"].assert_awaited_once()
    h["ledger"].settle.assert_awaited_once_with(
        h["binding"].call_id,
        h["binding"].readiness_request.engagement_id,
        None,
        delivered=False,
    )


def test_one_use_permit_ack_loss_after_key_selection_still_blocks_network_send() -> None:
    h = _harness()

    async def lost_ack(_permit: Any) -> None:
        raise OSError("synthetic consume ACK lost")

    h["guard"].consume_for_send = AsyncMock(side_effect=lost_ack)
    with pytest.raises(OutcomeUnknown):
        _call(h)
    assert "read-key" in h["steps"]  # only AFTER the signed 11-root admission
    h["provider"].assert_not_awaited()
    h["guard"].consume_for_send.assert_awaited_once()
    h["ledger"].settle.assert_awaited_once_with(
        h["binding"].call_id,
        h["binding"].readiness_request.engagement_id,
        None,
        delivered=False,
    )


def test_key_selection_error_does_not_leak_provider_material_or_trigger_fallback(
    caplog: Any,
) -> None:
    h = _harness()
    secret = "sk-synthetic-should-never-appear-in-error-or-logs"

    def fail_key() -> None:
        raise RuntimeError(secret)

    h["route"].provider_kwargs = fail_key
    with pytest.raises(OutcomeUnknown) as error:
        _call(h)
    assert secret not in str(error.value)
    assert secret not in caplog.text
    h["provider"].assert_not_awaited()
    h["ledger"].settle.assert_awaited_once()
    assert h["steps"].count("host-binding") == 1


def test_model_settlement_lost_ack_after_pre_send_guard_denial_never_sends() -> None:
    h = _harness()
    h["control"]["status"]["vault_material"] = "offline"
    h["ledger"].settle.side_effect = OSError("synthetic SQL ACK lost")
    with pytest.raises(OutcomeUnknown):
        _call(h)
    h["provider"].assert_not_awaited()
    h["ledger"].reserve.assert_awaited_once()
    h["ledger"].settle.assert_awaited_once()
    assert "read-key" not in h["steps"]


@pytest.mark.parametrize("cancel_at", ("authorization", "consume"))
def test_postcommit_cancellation_marks_unknown_and_sends_nothing(cancel_at: str) -> None:
    h = _harness()
    if cancel_at == "authorization":
        h["guard"].authorize_reserved = AsyncMock(side_effect=asyncio.CancelledError())
    else:
        h["guard"].consume_for_send = AsyncMock(side_effect=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        _call(h)
    h["provider"].assert_not_awaited()
    h["embedding"].assert_not_awaited()
    h["ledger"].reserve.assert_awaited_once()
    h["ledger"].settle.assert_awaited_once_with(
        h["binding"].call_id,
        h["binding"].readiness_request.engagement_id,
        None,
        delivered=False,
    )
    assert ("read-key" in h["steps"]) is (cancel_at == "consume")


def test_guarded_route_resolver_null_denies_before_reservation_or_key_access() -> None:
    h = _harness()
    h["routes"].resolve = lambda model, operation: None
    with pytest.raises(BudgetDenied):
        _call(h)
    h["provider"].assert_not_awaited()
    h["ledger"].reserve.assert_not_awaited()
    h["factory"].assert_not_awaited()
    assert "read-key" not in h["steps"]


def test_guarded_catalog_failure_after_postcommit_does_not_send_or_retry() -> None:
    h = _harness()
    h["client"]._provider_call_admitted.__globals__["catalog_mode"] = lambda: "enforce"
    h["catalog"].verify.side_effect = RuntimeError("catalog offline")
    with pytest.raises(OutcomeUnknown):
        _call(h)
    h["catalog"].verify.assert_awaited_once()
    h["provider"].assert_not_awaited()
    assert h["steps"].index("reserve") < h["steps"].index("read-key")
    h["ledger"].settle.assert_awaited_once()


def test_default_unprotected_mode_preserves_existing_router_behavior() -> None:
    h = _harness(mode="off")
    assert _call(h) == "inert completion"
    h["provider"].assert_awaited_once()
    h["ledger"].reserve.assert_awaited_once()
    h["factory"].assert_not_awaited()
    assert "read-key" in h["steps"]


def test_default_opt_out_preserves_existing_v1_route_preflight_without_guard() -> None:
    h = _harness(mode="off")
    h["routes"].version = 1
    h["route"].validate_deployment = lambda: "synthetic-only-local-key"
    assert _call(h) == "inert completion"
    h["provider"].assert_awaited_once()
    h["ledger"].reserve.assert_awaited_once()
    h["factory"].assert_not_awaited()
    assert "read-key" in h["steps"]


def test_disabled_mode_rejects_silent_host_guard_configuration() -> None:
    h = _harness(mode="off")
    with pytest.raises(ValueError):
        h["cls"](usage_store=h["ledger"], vault_guard=h["guard"])
    with pytest.raises(ValueError):
        h["cls"](usage_store=h["ledger"], vault_guard_required="false")


def _real_litellm_harness(monkeypatch: Any, *, enrolled: bool = True) -> dict[str, Any]:
    """Import and execute the true LiteLLMClient where Poetry deps exist.

    All external provider, route, auth and ledger effects are replaced before
    invoking the real method; never opens a provider or app database.
    """
    pytest.importorskip("litellm")
    pytest.importorskip("neo4j")
    from ai_osop.core import llm_client as real

    h = _harness()
    monkeypatch.setattr(real, "configured_routes", lambda: h["routes"])
    monkeypatch.setattr(real, "configured_model_role_policy", lambda: None)
    monkeypatch.setattr(real, "catalog_mode", lambda: "off")
    monkeypatch.setattr(
        real.RequestContext,
        "get",
        lambda: {
            "engagement_id": h["binding"].readiness_request.engagement_id,
            "task_id": h["binding"].readiness_request.task_id,
        },
    )
    monkeypatch.setattr(real.litellm, "acompletion", h["provider"])
    monkeypatch.setattr(real.litellm, "aembedding", h["embedding"])
    monkeypatch.setattr(real.settings, "mock_llm", False)
    client_kwargs: dict[str, Any] = {
        "primary_model": h["route"].model,
        "fallback_model": "openai/fallback",
        "max_tokens": 100,
        "usage_store": h["ledger"],
        "vault_guard_required": True,
    }
    if enrolled:
        client_kwargs.update(vault_guard=h["guard"], vault_binding_factory=h["factory"])
    h["real_client"] = real.LiteLLMClient(**client_kwargs)
    h["real_module"] = real
    return h


def test_full_imported_litellm_real_class_enrolled_guarded_mock_provider(
    monkeypatch: Any,
) -> None:
    h = _real_litellm_harness(monkeypatch)
    result = asyncio.run(h["real_client"].complete([{"role": "user", "content": "synthetic"}]))
    assert result == "inert completion"
    h["provider"].assert_awaited_once()
    h["ledger"].reserve.assert_awaited_once()
    h["ledger"].settle.assert_awaited_once()
    assert h["steps"].index("host-binding") < h["steps"].index("read-key")
    assert h["steps"].index("read-key") < h["steps"].index("provider")


def test_full_imported_litellm_real_class_signed_revocation_prevents_paid_mock(
    monkeypatch: Any,
) -> None:
    h = _real_litellm_harness(monkeypatch)
    h["proofs"]["vault_revocation"]["current_revoked"] = True
    with pytest.raises(h["real_module"].ModelOutcomeUncertain):
        asyncio.run(h["real_client"].complete([{"role": "user", "content": "synthetic"}]))
    h["provider"].assert_not_awaited()
    h["ledger"].settle.assert_awaited_once()
    assert "read-key" not in h["steps"]


def test_full_imported_litellm_real_class_absent_root_does_not_read_key(
    monkeypatch: Any,
) -> None:
    h = _real_litellm_harness(monkeypatch, enrolled=False)
    with pytest.raises(h["real_module"].ModelBudgetExceeded):
        asyncio.run(h["real_client"].complete([{"role": "user", "content": "synthetic"}]))
    h["provider"].assert_not_awaited()
    h["ledger"].reserve.assert_not_awaited()
    assert "read-key" not in h["steps"]
