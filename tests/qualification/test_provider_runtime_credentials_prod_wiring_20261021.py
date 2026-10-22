"""Current provider credential wiring, offline source-backed qualification.

These tests execute *actual current production function bodies* extracted from
the original source with I/O boundaries substituted by read-only stubs. The
environment here does not have full LiteLLM/Neo4j dependencies. No production
imports, application DB, target/provider calls, Docker or vault access occur.

Passing this suite documents a real *missing* vault-to-dispatch enforcement
join. It must not be interpreted as positive production credential readiness.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import re
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest


ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / "src/ai_osop/api/main.py"
PROFILE_API = ROOT / "src/ai_osop/api/routers/provider_credential_profile_refs.py"
POLICY_API = ROOT / "src/ai_osop/api/routers/provider_route_policy_reviews.py"
PROFILE_STORE = ROOT / "src/ai_osop/memory/provider_credential_profile_refs.py"
PROVIDER_ROUTING = ROOT / "src/ai_osop/core/provider_routing.py"
LLM = ROOT / "src/ai_osop/core/llm_client.py"
VAULT = ROOT / "src/ai_osop/core/provider_credential_lifecycle.py"
INVOICES = ROOT / "src/ai_osop/api/routers/provider_invoices.py"


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _named(tree: ast.Module, name: str, *, parent: str = "") -> ast.AST:
    candidates: list[ast.stmt] = tree.body
    if parent:
        cls = next(
            n for n in candidates if isinstance(n, ast.ClassDef) and n.name == parent
        )
        candidates = cls.body
    return next(
        n
        for n in candidates
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and n.name == name
    )


def _compile_original(
    path: Path,
    names: tuple[str, ...],
    namespace: dict[str, Any],
    *,
    parent: str = "",
) -> dict[str, Any]:
    """Compile only named ORIGINAL functions; retain their exact statements.

    We remove API decorators/default injection dependencies (not function
    statements). Dynamic annotations are postponed. This is not full ASGI.
    """
    tree = _tree(path)
    functions: list[ast.stmt] = []
    for name in names:
        node = copy.deepcopy(_named(tree, name, parent=parent))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.decorator_list = []
            if name in ("change_provider_credential_profile_ref",):
                # FastAPI query/dependency defaults are evaluated at
                # registration; provide no-op placeholder constructors.
                pass
        functions.append(node)
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")],
                             level=0), *functions],
        type_ignores=[],
    )
    exec(compile(ast.fix_missing_locations(module), str(path), "exec"), namespace)
    return namespace


def _calls(node: ast.AST, name: str) -> bool:
    return any(
        isinstance(call, ast.Call)
        and isinstance(call.func, (ast.Name, ast.Attribute))
        and (call.func.id if isinstance(call.func, ast.Name) else call.func.attr) == name
        for call in ast.walk(node)
    )


def _references(node: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def test_actual_mounts_and_runtime_constructor_have_no_lifecycle_adapter() -> None:
    tree = _tree(MAIN)
    mounts = [
        ast.unparse(n)
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "include_router"
    ]
    assert any("provider_credential_profile_refs.router" in m for m in mounts)
    assert any("provider_route_policy_reviews.router" in m for m in mounts)
    assert any("provider_invoices.router" in m for m in mounts)
    constructors = [
        ast.unparse(n)
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "LiteLLMClient"
    ]
    assert any("ModelUsageLedger(session_memory)" in c for c in constructors)
    assert not any("HostVaultRuntimeReadinessAdapter" in c for c in constructors)
    assert not _references(tree, "HostVaultRuntimeReadinessAdapter")


def test_production_provider_and_admin_modules_do_not_use_advisory_vault_gate() -> None:
    """Check both imported symbols and dynamic references in every runtime module."""
    for path in (MAIN, PROFILE_API, POLICY_API, PROFILE_STORE, PROVIDER_ROUTING, LLM, INVOICES):
        parsed = _tree(path)
        source = ast.unparse(parsed)
        assert "HostVaultRuntimeReadinessAdapter" not in source, path.name
        assert "CredentialLifecycleVerifier" not in source, path.name
        assert "provider_credential_lifecycle" not in source, path.name
    tree = _tree(LLM)
    assert _calls(_named(tree, "_provider_call_admitted", parent="LiteLLMClient"), "reserve")
    assert _calls(_named(tree, "_provider_call_admitted", parent="LiteLLMClient"), "settle")
    assert _calls(_named(tree, "_provider_call_admitted", parent="LiteLLMClient"), "provider_kwargs")
    assert _calls(_named(tree, "_provider_call_admitted", parent="LiteLLMClient"), "acompletion")
    assert _calls(_named(tree, "_provider_call_admitted", parent="LiteLLMClient"), "aembedding")
    assert _calls(_named(tree, "_provider_call", parent="LiteLLMClient"), "authorize_task")


def test_actual_mounted_profile_post_forwards_symbolic_metadata_only() -> None:
    """Execute the mounted handler's body with synthetic store, actor and body."""
    changes = []
    storage = SimpleNamespace(
        perform=AsyncMock(
            return_value={
                "ref_id": "pcref-" + "c" * 32,
                "reference_revision": 5,
                "generation": 3,
                "status": "pending",
                "server_reference_only": True,
                "credential_available_verified": False,
                "execution_enabled": False,
                "route_activated": False,
                "operation_recorded": True,
                "idempotent_replay": False,
            }
        )
    )

    class RefDenied(Exception):
        status = 503

    def body() -> Any:
        fields = {
            "operation_id": "pcop-" + "a" * 32,
            "ref_id": "pcref-" + "c" * 32,
            "expected_ref_revision": 4,
            "provider": "openai",
            "slot": "primary",
            "policy_review_id": "provider-review-" + "d" * 32,
            "policy_sha256": "0" * 64,
        }
        return SimpleNamespace(
            operation="rotate",
            model_dump=lambda **kwargs: dict(fields),
        )

    async def fake_body(_req: Any) -> Any:
        changes.append("metadata_parsed")
        return body()

    def _headers(resp: Any) -> None:
        resp.headers["Cache-Control"] = "private, no-store"

    namespace: dict[str, Any] = {
        "Query": lambda **kwargs: None,
        "Depends": lambda *args, **kwargs: None,
        "_ENG": r"^eng-[A-Za-z0-9._:-]{1,60}$",
        "_SHA": r"^[0-9a-f]{64}$",
        "_operator_principal": lambda: None,
        "_body": fake_body,
        "_headers": _headers,
        "_scope": lambda actor: {"actor": actor["sub"], "role": actor["role"]},
        "_store": lambda: storage,
        "CredentialProfileDenied": RefDenied,
        "HTTPException": RuntimeError,
    }
    _compile_original(PROFILE_API, ("_invoke", "change_provider_credential_profile_ref"), namespace)
    resp = SimpleNamespace(headers={}, status_code=200)
    result = asyncio.run(
        namespace["change_provider_credential_profile_ref"](
            flow_id="flow-example", response=resp, request=object(),
            expected_engagement_id="eng-example", expected_revision=4,
            expected_authorization_version=7, expected_authorization_id="auth-v7",
            expected_authorization_sha256="1" * 64,
            actor={"sub": "owner", "role": "operator"},
        )
    )
    assert changes == ["metadata_parsed"]
    assert result["status"] == "pending"
    assert result["credential_available_verified"] is False
    assert result["route_activated"] is False
    assert result["execution_enabled"] is False
    assert resp.headers["Cache-Control"] == "private, no-store"
    storage.perform.assert_awaited_once()
    passed = storage.perform.await_args.kwargs
    assert passed["operation"] == "rotate"
    assert passed["expected_ref_revision"] == 4
    assert passed["flow_id"] == "flow-example"
    assert passed["engagement_id"] == "eng-example"
    assert passed["version"] == 7
    assert "vault" not in passed and "api_key" not in passed
    assert resp.status_code == 200


def test_rotation_transition_remains_pending_in_durable_store_source() -> None:
    """Pin real 0028 rotation CAS semantics; this executes no database SQL."""
    tree = _tree(PROFILE_STORE)
    perform = _named(tree, "perform", parent="ProviderCredentialProfileRefStore")
    lines = ast.get_source_segment(PROFILE_STORE.read_text(encoding="utf-8"), perform)
    assert lines is not None
    assert 'if operation == "rotate":' in lines
    assert 'row["status"] != "approved"' in lines
    assert 'generation = row["generation"] + 1' in lines
    assert 'new_status, new_senior = "pending", None' in lines
    assert "reference_revision=reference_revision+1" in lines
    assert "WHERE id=:id AND engagement_id=:eng" in lines
    assert "flow_id=:flow AND reference_revision=:expected" in lines
    assert not _calls(perform, "HostVaultRuntimeReadinessAdapter")


def test_original_profile_projection_cannot_promote_review_to_available_credential() -> None:
    namespace = _compile_original(PROFILE_STORE, ("_public",), {})
    row = {
        "id": "pcref-" + "a" * 32, "engagement_id": "eng-example",
        "flow_id": "flow-example", "provider": "openai", "slot": "primary",
        "policy_review_id": "provider-review-" + "b" * 32,
        "policy_sha256": "1" * 64, "reference_sha256": "2" * 64,
        "reference_revision": 2, "generation": 5, "status": "approved",
        "flow_revision": 9, "authorization_version": 2,
        "authorization_id": "auth2", "authorization_sha256": "3" * 64,
        "senior_sub": "independent-reviewer",
        "created_at": SimpleNamespace(isoformat=lambda: "2026-10-21"),
        "updated_at": SimpleNamespace(isoformat=lambda: "2026-10-21"),
    }
    public = namespace["_public"](row)
    assert public["status"] == "approved"
    assert public["senior_reviewed"] is True
    assert public["credential_available_verified"] is False
    assert public["credential_rotated"] is False
    assert public["execution_enabled"] is False
    assert public["policy_current_approval_verified"] is False
    assert public["provider_contacted"] is False
    assert public["credentials_stored"] is False
    assert not any(key in public for key in ("api_key", "secret", "credential_value"))


def test_actual_provider_capability_catalog_is_explicitly_not_execution_authority() -> None:
    parsed = _tree(INVOICES)
    provider_catalog = next(
        node for node in ast.walk(parsed)
        if isinstance(node, ast.AsyncFunctionDef)
        and any("capabilit" in ast.unparse(d).lower() for d in node.decorator_list)
    )
    source = ast.get_source_segment(INVOICES.read_text(encoding="utf-8"), provider_catalog)
    assert source is not None
    assert '"provider_currently_available_verified": False' in source
    assert '"signed_budget_admission_still_required": True' in source
    assert not _calls(provider_catalog, "HostVaultRuntimeReadinessAdapter")


class LocalBudgetExceeded(Exception):
    pass


class LocalOutcomeUncertain(Exception):
    pass


class LocalRouteDenied(LocalBudgetExceeded):
    pass


def _dispatch_harness(
    *,
    route_present: bool = True,
    ledger: Any = None,
    context: Any = None,
) -> tuple[Any, dict[str, Any]]:
    """Compile ORIGINAL _provider_call/_admitted methods, stub all external I/O."""
    synthetic_route = SimpleNamespace(
        provider="openai",
        provider_kwargs=lambda: {"api_key": "synthetic-only-provider-fixture"},
    )
    route = SimpleNamespace(
        version=1,
        resolve=lambda model, operation: synthetic_route,
    ) if route_present else None
    completion = AsyncMock(return_value=SimpleNamespace(choices=[], usage=None))
    embedding = AsyncMock(return_value={"data": [{"embedding": [0.1]}]})
    namespace: dict[str, Any] = {
        "configured_routes": lambda: route,
        "configured_model_role_policy": lambda: None,
        "reject_caller_reasoning_overrides": lambda kwargs: None,
        "verify_embedding_request": lambda texts: None,
        "catalog_mode": lambda: "off",
        "RequestContext": SimpleNamespace(
            get=lambda: context if context is not None
            else {"engagement_id": "eng-fixture", "task_id": "task-fixture"}
        ),
        "ModelBudgetExceeded": LocalBudgetExceeded,
        "ModelOutcomeUncertain": LocalOutcomeUncertain,
        "ProviderRouteDenied": LocalRouteDenied,
        "ProviderRouteUnavailable": LocalRouteDenied,
        "asyncio": asyncio,
        "re": re,
        "time": time,
        "litellm": SimpleNamespace(acompletion=completion, aembedding=embedding),
        "llm_logger": SimpleNamespace(warning=lambda *args, **kwargs: None),
    }
    _compile_original(
        LLM, ("_provider_call", "_provider_call_admitted"),
        namespace, parent="LiteLLMClient",
    )
    client = SimpleNamespace(
        _usage_store=ledger,
        _provider_call_admitted=None,
        _provenance_recorder=SimpleNamespace(submit=lambda action: None),
    )

    async def _admitted(*args: Any, **kwargs: Any) -> Any:
        return await namespace["_provider_call_admitted"](client, *args, **kwargs)

    client._provider_call_admitted = _admitted
    return client, {
        "call": namespace["_provider_call"],
        "acompletion": completion,
        "aembedding": embedding,
    }


@pytest.mark.parametrize("cause", ("missing", "refused", "error", "invalid_call_id", "invalid_context"))
def test_actual_dispatch_with_bad_or_missing_ledger_never_contacts_provider(
    cause: str,
) -> None:
    reserve = AsyncMock(return_value="call-synthetic1")
    settle = AsyncMock(return_value=True)
    ledger = SimpleNamespace(reserve=reserve, settle=settle)
    if cause == "missing":
        ledger = None
    elif cause == "refused":
        reserve.side_effect = LocalBudgetExceeded("signed budget rejected")
    elif cause == "error":
        reserve.side_effect = OSError("simulated offline SQL")
    elif cause == "invalid_call_id":
        reserve.return_value = None
    context = {"engagement_id": "eng-fixture", "task_id": "task-fixture"}
    if cause == "invalid_context":
        context["task_id"] = ""
    client, runtime = _dispatch_harness(ledger=ledger, context=context)
    with pytest.raises(LocalBudgetExceeded):
        asyncio.run(
            runtime["call"](
                client, "completion", "openai/test-fixture", 1,
                messages=[{"role": "user", "content": "inert"}], max_tokens=5,
            )
        )
    runtime["acompletion"].assert_not_awaited()
    runtime["aembedding"].assert_not_awaited()
    if ledger is not None:
        settle.assert_not_awaited()
    if cause in ("missing", "invalid_context"):
        reserve.assert_not_awaited()


def test_current_v1_dispatch_does_not_call_mocked_denied_vault_when_ledger_accepts() -> None:
    """A synthetic provider response exposes the missing vault enforcement.

    This demonstrates the *gap*, not an authorized real provider call. The
    source is executed with a fake provider returning an inert object.
    """
    ledger = SimpleNamespace(
        reserve=AsyncMock(return_value="call-synthetic123"),
        settle=AsyncMock(return_value=True),
    )
    client, runtime = _dispatch_harness(ledger=ledger)
    denied_vault = AsyncMock(side_effect=PermissionError("vault root unavailable"))
    client._host_vault_runtime_readiness = denied_vault
    result = asyncio.run(
        runtime["call"](
            client, "completion", "openai/test-fixture", 1,
            messages=[{"role": "user", "content": "inert"}], max_tokens=5,
        )
    )
    assert result is runtime["acompletion"].return_value
    ledger.reserve.assert_awaited_once_with(
        "eng-fixture", "task-fixture", "openai/test-fixture", "completion"
    )
    ledger.settle.assert_awaited_once()
    runtime["acompletion"].assert_awaited_once()
    assert runtime["acompletion"].await_args.kwargs["api_key"] == (
        "synthetic-only-provider-fixture"
    )
    denied_vault.assert_not_awaited()


def test_ledger_ready_is_only_budget_authority_not_vault_currentness() -> None:
    """No provider credential signal is present in ledger reserve contract."""
    parsed = _tree(ROOT / "src/ai_osop/memory/model_usage.py")
    reserve = _named(parsed, "reserve", parent="ModelUsageLedger")
    assert isinstance(reserve, ast.AsyncFunctionDef)
    arg_names = [arg.arg for arg in reserve.args.args]
    assert arg_names == ["self", "engagement_id", "task_id", "model", "operation"]
    assert not _references(reserve, "vault")
    assert not _references(reserve, "credential_profile")
    assert _calls(reserve, "_guard")
    assert _calls(reserve, "_verify_provider_execution_lease")


def test_unenrolled_host_vault_adapter_denies_before_any_backend_reader() -> None:
    """Actual verifier rejects missing trust roots, never opens a network."""
    from ai_osop.core.provider_credential_lifecycle import (
        CredentialLifecycleDenied, CredentialLifecycleVerifier,
        HostVaultRuntimeReadinessAdapter,
    )

    with pytest.raises(CredentialLifecycleDenied):
        CredentialLifecycleVerifier(public_keys={}, readers={})
    with pytest.raises(CredentialLifecycleDenied):
        HostVaultRuntimeReadinessAdapter(
            other_public_keys={}, other_readers={},
            vault_public_key=None, revocation_public_key=None,
            material_channel=None, revocation_channel=None,
            minimum_vault_revision=1, minimum_revocation_revision=1,
        )


def test_positive_vault_readiness_decision_is_advisory_without_spend_authority() -> None:
    from ai_osop.core.provider_credential_lifecycle import CredentialReadinessDecision

    witness = CredentialReadinessDecision(
        ref_id="pcref-" + "a" * 32, reference_revision=5,
        generation=3, purpose="rotate", proof_expires_at=1792589000,
    )
    assert witness.independently_attested_vault_presence is True
    assert witness.rotation_readiness_verified is True
    assert witness.budget_reserved is False
    assert witness.dispatch_authorized is False
    assert witness.provider_contacted is False
    assert witness.provider_accepts_credential_verified is False

