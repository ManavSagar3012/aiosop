"""Read-only qualification of the *actual* app LiteLLM constructor and host guard.

No application lifespan, database engine, provider SDK request, vault network,
live signing keys, or external target is touched. A runtime result from a
synthetic ledger/route is not evidence of a deployed host signer or key.
"""

from __future__ import annotations

import ast
import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core import llm_client as llm_module
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.provider_credential_dispatch_guard import (
    ProviderCredentialDispatchGuard,
    ProviderDispatchDenied,
)
from ai_osop.core.provider_routing import ProviderRouteDenied
from ai_osop.memory.model_usage import ModelBudgetExceeded


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/ai_osop"
MAIN = SRC / "api/main.py"
ORCHESTRATOR = SRC / "orchestrator/orchestrator.py"
CLIENT = SRC / "core/llm_client.py"
STORE = SRC / "memory/model_usage.py"
GUARD = SRC / "core/provider_credential_dispatch_guard.py"
LIFECYCLE = SRC / "core/provider_credential_lifecycle.py"


def _constructor_calls(path: Path) -> list[ast.Call]:
    parsed = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        n
        for n in ast.walk(parsed)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "LiteLLMClient"
    ]


def _budget() -> Any:
    return SimpleNamespace(
        reserve=AsyncMock(return_value="call-synthetic-prohibited"),
        settle=AsyncMock(return_value=True),
    )


def _routes(version: int) -> Any:
    route = SimpleNamespace(
        model="openai/mock-model",
        provider="openai",
        operations=("completion", "embedding"),
        capabilities=("text_completion", "embeddings"),
        allowed_roles=("vuln_analysis",),
        max_output_tokens=128,
        validate_deployment=MagicMock(
            side_effect=AssertionError("environment credential read forbidden")
        ),
        provider_kwargs=MagicMock(
            side_effect=AssertionError("environment key selected before guard")
        ),
    )
    return SimpleNamespace(
        version=version,
        routes=(route,),
        resolve=MagicMock(return_value=route),
        authorize_task=MagicMock(
            side_effect=AssertionError("cannot authorize without enrolled guard")
        ),
    )


@pytest.fixture
def no_effects(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Install effect-denying patches before exercising actual client methods."""
    paid = AsyncMock(side_effect=AssertionError("paid completion attempted"))
    embed = AsyncMock(side_effect=AssertionError("paid embedding attempted"))
    local_embed = AsyncMock(side_effect=AssertionError("loopback embed attempted"))
    transport = MagicMock(side_effect=AssertionError("HTTP transport attempted"))
    catalog = SimpleNamespace(
        verify=AsyncMock(side_effect=AssertionError("remote catalog queried"))
    )
    monkeypatch.setattr(llm_module.litellm, "acompletion", paid)
    monkeypatch.setattr(llm_module.litellm, "aembedding", embed)
    monkeypatch.setattr(llm_module, "_local_ollama_embedding", local_embed)
    monkeypatch.setattr(llm_module.httpx, "AsyncClient", transport)
    monkeypatch.setattr(llm_module, "configured_catalog", lambda: catalog)
    monkeypatch.setattr(llm_module, "catalog_mode", lambda: "off")
    monkeypatch.setattr(llm_module.settings, "mock_llm", False)
    monkeypatch.setattr(llm_module, "configured_model_role_policy", lambda: None)
    monkeypatch.setattr(
        llm_module.RequestContext,
        "get",
        lambda: {"engagement_id": "eng-offline", "task_id": "task-offline"},
    )
    ledger = _budget()
    return {
        "paid": paid,
        "embedding": embed,
        "local_embedding": local_embed,
        "transport": transport,
        "catalog": catalog,
        "ledger": ledger,
        "monkeypatch": monkeypatch,
    }


def _deny_all(out: dict[str, Any], routes: Any = None) -> None:
    out["ledger"].reserve.assert_not_awaited()
    out["ledger"].settle.assert_not_awaited()
    out["paid"].assert_not_awaited()
    out["embedding"].assert_not_awaited()
    out["local_embedding"].assert_not_awaited()
    out["transport"].assert_not_called()
    out["catalog"].verify.assert_not_awaited()
    if routes is not None:
        routes.resolve.assert_not_called()
        routes.routes[0].validate_deployment.assert_not_called()
        routes.routes[0].provider_kwargs.assert_not_called()


def test_only_direct_litellm_constructor_is_nonproduction_with_pending_production_guard() -> None:
    matched = [
        (path.relative_to(SRC).as_posix(), call)
        for path in SRC.rglob("*.py")
        for call in _constructor_calls(path)
    ]
    assert len(matched) == 1
    assert matched[0][0] == "api/main.py"
    constructor = matched[0][1]
    assert ast.unparse(constructor) == (
        "LiteLLMClient(usage_store=ModelUsageLedger(session_memory))"
    )
    # A direct unguarded constructor is permitted only in the explicit
    # development/test branch. All other deployment modes use the separately
    # implemented mandatory-deny pending guard until independently enrolled.
    parsed = ast.parse(MAIN.read_text(encoding="utf-8"))
    branch = next(
        node
        for node in ast.walk(parsed)
        if isinstance(node, ast.If)
        and any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "pending_guarded_client"
            for child in node.orelse
            for call in ast.walk(child)
        )
    )
    assert any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "LiteLLMClient"
        for child in branch.body
        for call in ast.walk(child)
    )
    assert "development" in ast.unparse(branch.test)
    # The import of the offline host helper is NOT enrollment of a trusted
    # host root, provider credential, protected binding reader, or vault.
    for forbidden in (
        "vault_guard_required=True",
        "vault_binding_factory=",
        "ProviderCredentialDispatchGuard(",
        "HostVaultRuntimeReadinessAdapter(",
    ):
        assert forbidden not in MAIN.read_text(encoding="utf-8")


def test_orchestrator_receives_app_client_but_does_not_instantiate_or_replace() -> None:
    orch = ast.parse(ORCHESTRATOR.read_text(encoding="utf-8"))
    klass = next(n for n in orch.body if isinstance(n, ast.ClassDef) and n.name == "Orchestrator")
    init = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    assert "llm_client" in [a.arg for a in init.args.args]
    assert any(
        isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Attribute) and t.attr == "llm_client" for t in n.targets)
        and isinstance(n.value, ast.Name)
        and n.value.id == "llm_client"
        for n in ast.walk(init)
    )
    assert not _constructor_calls(ORCHESTRATOR)
    main = ast.parse(MAIN.read_text(encoding="utf-8"))
    constructors = [
        n
        for n in ast.walk(main)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "Orchestrator"
    ]
    assert len(constructors) == 1
    assert any(
        kw.arg == "llm_client" and isinstance(kw.value, ast.Name) and kw.value.id == "llm_client"
        for kw in constructors[0].keywords
    )


def test_evaluate_exact_app_constructor_in_process_without_opening_any_db(
    no_effects: dict[str, Any],
) -> None:
    """Execute original constructor expression with mock ledger, no app lifespan."""
    original = _constructor_calls(MAIN)[0]
    captured: list[Any] = []
    memory = object()

    def local_ledger(source: Any) -> Any:
        captured.append(source)
        return no_effects["ledger"]

    expression = ast.Expression(body=original)
    construction = eval(
        compile(ast.fix_missing_locations(expression), str(MAIN), "eval"),
        {
            "LiteLLMClient": LiteLLMClient,
            "ModelUsageLedger": local_ledger,
            "session_memory": memory,
        },
    )
    assert type(construction) is LiteLLMClient
    assert captured == [memory]
    assert construction._usage_store is no_effects["ledger"]
    assert construction._vault_guard_required is False
    assert construction._vault_guard is None
    assert construction._vault_binding_factory is None
    _deny_all(no_effects)


def test_no_production_enrolled_host_signer_reader_or_reservation_authority() -> None:
    """Grounded *source-wiring* assertion, not runtime vault availability."""
    active_sources = [p for p in SRC.rglob("*.py") if p not in {CLIENT, GUARD, LIFECYCLE}]
    for path in active_sources:
        src = path.read_text(encoding="utf-8")
        assert "HostVaultRuntimeReadinessAdapter(" not in src, path
        assert "ProviderCredentialDispatchGuard(" not in src, path
        assert "vault_guard_required=True" not in src, path
        assert "vault_binding_factory=" not in src, path
    reserve = ast.parse(STORE.read_text(encoding="utf-8"))
    klass = next(
        n for n in reserve.body if isinstance(n, ast.ClassDef) and n.name == "ModelUsageLedger"
    )
    method = next(
        n for n in klass.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "reserve"
    )
    assert [a.arg for a in method.args.args] == [
        "self",
        "engagement_id",
        "task_id",
        "model",
        "operation",
    ]
    # A committed call ID is not itself the independently signed readback
    # required by ProviderCredentialDispatchGuard.
    assert "vault" not in ast.unparse(method).lower()
    assert not any(isinstance(n, ast.FunctionDef) and "vault" in n.name.lower() for n in klass.body)


@pytest.mark.parametrize("selected", [None, 1, 2], ids=["absent", "legacy-v1", "signed-v2"])
@pytest.mark.parametrize(
    "entrypoint", ["complete", "_provider_call", "_provider_call_admitted", "embedding"]
)
def test_guarded_pending_mode_denies_before_env_ledger_http_and_provider(
    no_effects: dict[str, Any],
    selected: Any,
    entrypoint: str,
) -> None:
    routes = _routes(selected) if selected else None
    no_effects["monkeypatch"].setattr(llm_module, "configured_routes", lambda: routes)
    client = LiteLLMClient(
        primary_model="openai/mock-model",
        fallback_model="openai/fallback",
        max_tokens=64,
        usage_store=no_effects["ledger"],
        vault_guard_required=True,
    )

    async def do_work() -> Any:
        if entrypoint == "complete":
            return await client.complete(
                [{"role": "user", "content": "synthetic / no provider request"}]
            )
        if entrypoint == "embedding":
            return await client.get_embedding("synthetic embedding")
        if entrypoint == "_provider_call_admitted":
            return await client._provider_call_admitted(
                "completion",
                "openai/mock-model",
                1,
                messages=[],
            )
        return await client._provider_call(
            "completion",
            "openai/mock-model",
            1,
            messages=[],
            max_tokens=64,
        )

    with pytest.raises(ModelBudgetExceeded):
        asyncio.run(do_work())
    _deny_all(no_effects, routes)
    assert client._vault_guard_required is True


def test_missing_host_six_separate_sources_cannot_be_replaced_by_caller_boolean() -> None:
    with pytest.raises(ProviderDispatchDenied, match="Host-enrolled"):
        ProviderCredentialDispatchGuard(readiness=None, signer_keys={}, readers={})


@pytest.mark.parametrize("entrypoint", ["complete", "embedding"])
def test_guarded_pending_never_reads_process_environment_provider_key(
    no_effects: dict[str, Any],
    entrypoint: str,
) -> None:
    """Watch the actual environment-get boundary, not only route-key mocks."""
    routes = _routes(2)
    monkeypatch = no_effects["monkeypatch"]
    monkeypatch.setattr(llm_module, "configured_routes", lambda: routes)
    client = LiteLLMClient(
        primary_model="openai/mock-model",
        max_tokens=64,
        usage_store=no_effects["ledger"],
        vault_guard_required=True,
    )
    original_get = os.environ.get
    forbidden_reads: list[str] = []

    def guarded_env_get(name: str, default: Any = None) -> Any:
        if name in {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_API_KEY"}:
            forbidden_reads.append(name)
            raise AssertionError("Environment provider key access is forbidden")
        return original_get(name, default)

    monkeypatch.setattr(os.environ, "get", guarded_env_get)
    with pytest.raises(ModelBudgetExceeded):
        if entrypoint == "complete":
            asyncio.run(client.complete([{"role": "user", "content": "inert"}]))
        else:
            asyncio.run(client.get_embedding("inert query"))
    assert forbidden_reads == []
    _deny_all(no_effects, routes)


@pytest.mark.parametrize("source", ["vault_guard", "vault_binding_factory", "both"])
def test_fake_host_signer_and_fake_reader_rejected_before_any_budget_or_network(
    no_effects: dict[str, Any],
    source: str,
) -> None:
    routes = _routes(2)
    no_effects["monkeypatch"].setattr(llm_module, "configured_routes", lambda: routes)
    fake_guard = SimpleNamespace(
        authorize_reserved=AsyncMock(return_value=True),
        consume_for_send=AsyncMock(return_value=True),
    )
    fake_factory = AsyncMock(return_value=SimpleNamespace(dispatch_authorized=True))
    kwargs: dict[str, Any] = {}
    if source in ("vault_guard", "both"):
        kwargs["vault_guard"] = fake_guard
    if source in ("vault_binding_factory", "both"):
        kwargs["vault_binding_factory"] = fake_factory
    client = LiteLLMClient(
        primary_model="openai/mock-model",
        max_tokens=64,
        usage_store=no_effects["ledger"],
        vault_guard_required=True,
        **kwargs,
    )
    with pytest.raises(ModelBudgetExceeded):
        asyncio.run(client.complete([{"role": "user", "content": "synthetic"}]))
    fake_guard.authorize_reserved.assert_not_awaited()
    fake_guard.consume_for_send.assert_not_awaited()
    fake_factory.assert_not_awaited()
    _deny_all(no_effects, routes)


@pytest.mark.parametrize(
    "untrusted_key",
    [
        "vault_guard_required",
        "vault_guard",
        "vault_binding_factory",
        "vault_dispatch_binding",
        "vault_dispatch_permit",
        "api_key",
    ],
)
def test_untrusted_completion_kwargs_cannot_deactivate_guard_or_get_provider(
    no_effects: dict[str, Any],
    untrusted_key: str,
) -> None:
    routes = _routes(2)
    no_effects["monkeypatch"].setattr(llm_module, "configured_routes", lambda: routes)
    client = LiteLLMClient(
        primary_model="openai/mock-model",
        max_tokens=64,
        usage_store=no_effects["ledger"],
        vault_guard_required=True,
    )
    with pytest.raises(ModelBudgetExceeded):
        asyncio.run(
            client.complete(
                [{"role": "user", "content": "inert text"}],
                **{untrusted_key: False if untrusted_key == "vault_guard_required" else "allow"},
            )
        )
    assert client._vault_guard_required is True
    _deny_all(no_effects, routes)


@pytest.mark.parametrize(
    "untrusted_key",
    [
        "vault_guard_required",
        "vault_guard",
        "vault_binding_factory",
        "vault_dispatch_permit",
        "api_key",
    ],
)
def test_kwargs_cannot_toggle_unselected_guard_on_direct_provider_method(
    no_effects: dict[str, Any],
    untrusted_key: str,
) -> None:
    # A caller to the v2 direct method cannot set a class constructor mode.
    # This is not evidence legacy/no-route calls are globally guarded.
    routes = _routes(2)
    no_effects["monkeypatch"].setattr(llm_module, "configured_routes", lambda: routes)
    client = LiteLLMClient(
        primary_model="openai/mock-model",
        max_tokens=64,
        usage_store=no_effects["ledger"],
    )
    with pytest.raises(ProviderRouteDenied, match="override"):
        asyncio.run(
            client._provider_call_admitted(
                "completion",
                "openai/mock-model",
                1,
                messages=[],
                **{untrusted_key: True},
            )
        )
    assert client._vault_guard_required is False
    no_effects["ledger"].reserve.assert_not_awaited()
    no_effects["paid"].assert_not_awaited()
    routes.routes[0].provider_kwargs.assert_not_called()
    no_effects["transport"].assert_not_called()


def test_api_route_handlers_do_not_construct_host_guard_from_request_fields() -> None:
    # This is a repository source assertion, not a proof of arbitrary future
    # plug-ins or custom deployments. Request bodies cannot install host roots.
    api_dir = SRC / "api"
    relevant = [MAIN, *(api_dir / "routers").glob("*.py")]
    for path in relevant:
        source = path.read_text(encoding="utf-8")
        for forbidden in (
            "vault_binding_factory=",
            "vault_guard_required=True",
            "ProviderCredentialDispatchGuard(",
            "HostVaultRuntimeReadinessAdapter(",
        ):
            assert forbidden not in source, (str(path), forbidden)
