"""Production API constructor selection: mandatory host-vault guard pending.

The tests execute the original unchanged-at-runtime main.py constructor
*statement AST*, not a copy of the desired condition. Storage, host vault,
provider, catalog, and HTTP effects are exclusively inert mocks. No FastAPI
lifespan, real ModelUsageLedger engine, real keys, paid provider, or DB.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core import llm_client as real
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.memory.model_usage import ModelBudgetExceeded


SOURCE = Path(__file__).resolve().parents[1] / "src/ai_osop/api/main.py"


def _bootstrap_branch() -> ast.If:
    """Find the one production constructor branch in the actual lifespan."""
    module = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    lifespan = next(
        node
        for node in module.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "lifespan"
    )
    branches = [
        node
        for node in ast.walk(lifespan)
        if isinstance(node, ast.If)
        and any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id == "pending_guarded_client"
            for child in ast.walk(node)
        )
    ]
    assert len(branches) == 1, "Production constructor must fail closed explicitly"
    return branches[0]


def _construct_actual_main_branch(
    environment: str,
    *,
    ledger: Any = None,
) -> Dict[str, Any]:
    """Execute exact main bootstrap branch with a synthetic no-DB ledger."""
    token = object()
    use_store = (
        ledger
        if ledger is not None
        else SimpleNamespace(
            reserve=AsyncMock(side_effect=AssertionError("budget reserve attempted")),
            settle=AsyncMock(side_effect=AssertionError("budget settle attempted")),
        )
    )
    ledger_calls = []

    def make_ledger(session_memory: Any) -> Any:
        assert session_memory is token
        ledger_calls.append(session_memory)
        return use_store

    source = ast.Module(body=[copy.deepcopy(_bootstrap_branch())], type_ignores=[])
    globals_: Dict[str, Any] = {
        "settings": SimpleNamespace(environment=environment),
        "session_memory": token,
        "ModelUsageLedger": make_ledger,
        "LiteLLMClient": LiteLLMClient,
    }
    exec(compile(ast.fix_missing_locations(source), str(SOURCE), "exec"), globals_)
    assert ledger_calls == [token]
    client = globals_.get("llm_client")
    assert type(client) is LiteLLMClient
    assert client._usage_store is use_store
    return {"client": client, "ledger": use_store, "source": source}


@pytest.fixture
def locked_effects(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    """Make even an accidental credential read, reservation or send observable."""
    send_completion = AsyncMock(side_effect=AssertionError("PAID completion attempted"))
    send_embedding = AsyncMock(side_effect=AssertionError("PAID embedding attempted"))
    local_embedding = AsyncMock(side_effect=AssertionError("Local embedding attempted"))
    catalog = SimpleNamespace(
        verify=AsyncMock(side_effect=AssertionError("Catalog network attempted"))
    )
    http_client = MagicMock(side_effect=AssertionError("HTTP/network client attempted"))
    reserve = AsyncMock(side_effect=AssertionError("Model usage reserve attempted"))
    settle = AsyncMock(side_effect=AssertionError("Model usage settle attempted"))
    ledger = SimpleNamespace(reserve=reserve, settle=settle)
    monkeypatch.setattr(real.litellm, "acompletion", send_completion)
    monkeypatch.setattr(real.litellm, "aembedding", send_embedding)
    monkeypatch.setattr(real, "_local_ollama_embedding", local_embedding)
    monkeypatch.setattr(real.httpx, "AsyncClient", http_client)
    monkeypatch.setattr(real, "configured_catalog", lambda: catalog)
    monkeypatch.setattr(real, "catalog_mode", lambda: "off")
    monkeypatch.setattr(real.settings, "mock_llm", False)
    monkeypatch.setattr(real, "configured_model_role_policy", lambda: None)
    monkeypatch.setattr(
        real.RequestContext,
        "get",
        lambda: {"engagement_id": "eng-inert", "task_id": "task-inert"},
    )

    observed_api_keys = []
    original_env_get = os.environ.get

    def checked_env_get(name: str, default: Any = None) -> Any:
        if name in {
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "DEEPSEEK_API_KEY",
            "OSOP_LLM_API_KEY",
            "TEST_PROVIDER_SECRET",
        }:
            observed_api_keys.append(name)
            raise AssertionError("Provider credential environment read")
        return original_env_get(name, default)

    monkeypatch.setattr(os.environ, "get", checked_env_get)
    return {
        "completion": send_completion,
        "embedding": send_embedding,
        "local_embedding": local_embedding,
        "catalog": catalog,
        "http_client": http_client,
        "reserve": reserve,
        "settle": settle,
        "ledger": ledger,
        "env_reads": observed_api_keys,
        "monkeypatch": monkeypatch,
    }


def _no_effects(effects: Dict[str, Any]) -> None:
    effects["completion"].assert_not_awaited()
    effects["embedding"].assert_not_awaited()
    effects["local_embedding"].assert_not_awaited()
    effects["catalog"].verify.assert_not_awaited()
    effects["http_client"].assert_not_called()
    effects["reserve"].assert_not_awaited()
    effects["settle"].assert_not_awaited()
    assert effects["env_reads"] == []


def _synthetic_route(
    effects: Dict[str, Any],
    *,
    version: Optional[int],
) -> Optional[SimpleNamespace]:
    if version is None:
        effects["monkeypatch"].setattr(real, "configured_routes", lambda: None)
        return None
    route = SimpleNamespace(
        model="openai/mock",
        provider="openai",
        operations=("completion", "embedding"),
        allowed_roles=("vuln_analysis",),
        capabilities=("text_completion", "embeddings"),
        max_output_tokens=128,
        provider_kwargs=MagicMock(side_effect=AssertionError("Provider API key retrieved")),
        validate_deployment=MagicMock(
            side_effect=AssertionError("Provider deployment key retrieved")
        ),
    )
    routes = SimpleNamespace(
        version=version,
        routes=(route,),
        resolve=MagicMock(side_effect=AssertionError("Route resolution bypassed guarded denial")),
        authorize_task=MagicMock(
            side_effect=AssertionError("Task authority bypassed guarded denial")
        ),
        policy_sha256="a" * 64,
    )
    effects["monkeypatch"].setattr(real, "configured_routes", lambda: routes)
    return routes


@pytest.mark.parametrize(
    "deployment",
    [
        "production",
        "prod",
        "PrOd",
        "PRODUCTION",
        " production ",
        "staging",
        "unknown",
        "",
        "development-typo",
    ],
)
def test_actual_main_uses_mandatory_guarded_pending_for_non_development_modes(
    deployment: str,
    locked_effects: Dict[str, Any],
) -> None:
    client = _construct_actual_main_branch(deployment, ledger=locked_effects["ledger"])["client"]
    assert client._vault_guard_required is True
    assert client._vault_guard is None
    assert client._vault_binding_factory is None
    _no_effects(locked_effects)


@pytest.mark.parametrize("deployment", ["development", "dev", "test", "testing", " DEV "])
def test_explicit_local_modes_preserve_old_ledger_bound_constructor(
    deployment: str,
    locked_effects: Dict[str, Any],
) -> None:
    client = _construct_actual_main_branch(deployment, ledger=locked_effects["ledger"])["client"]
    assert client._vault_guard_required is False
    assert client._vault_guard is None
    assert client._vault_binding_factory is None
    assert client._usage_store is locked_effects["ledger"]
    _no_effects(locked_effects)


@pytest.mark.parametrize("version", [None, 1, 2], ids=["none", "legacy", "signed-v2"])
@pytest.mark.parametrize(
    "entrypoint", ["complete", "embedding", "_provider_call", "_provider_call_admitted"]
)
def test_production_pending_denies_every_actual_litellm_presend_path_without_effects(
    version: Optional[int],
    entrypoint: str,
    locked_effects: Dict[str, Any],
) -> None:
    routes = _synthetic_route(locked_effects, version=version)
    client = _construct_actual_main_branch("production", ledger=locked_effects["ledger"])["client"]

    async def call() -> Any:
        if entrypoint == "complete":
            return await client.complete(
                [{"role": "user", "content": "inert request"}],
                model="openai/mock",
            )
        if entrypoint == "embedding":
            return await client.get_embedding("inert input", model="openai/mock")
        if entrypoint == "_provider_call":
            return await client._provider_call(
                "completion",
                "openai/mock",
                attempt=1,
                messages=[],
                max_tokens=12,
            )
        return await client._provider_call_admitted(
            "completion",
            "openai/mock",
            attempt=1,
            messages=[],
        )

    with pytest.raises(ModelBudgetExceeded):
        asyncio.run(call())
    _no_effects(locked_effects)
    if routes is not None:
        routes.resolve.assert_not_called()
        routes.routes[0].provider_kwargs.assert_not_called()
        routes.routes[0].validate_deployment.assert_not_called()


@pytest.mark.parametrize(
    "untrusted",
    [
        "vault_guard_required",
        "vault_guard",
        "vault_binding_factory",
        "vault_dispatch_permit",
        "vault_dispatch_binding",
        "api_key",
        "mock_response",
        "fallbacks",
        "http_client",
    ],
)
def test_untrusted_model_kwargs_cannot_switch_off_pending_guard(
    untrusted: str,
    locked_effects: Dict[str, Any],
) -> None:
    _synthetic_route(locked_effects, version=2)
    client = _construct_actual_main_branch("prod", ledger=locked_effects["ledger"])["client"]
    with pytest.raises(ModelBudgetExceeded):
        asyncio.run(
            client.complete(
                [{"role": "user", "content": "inert request"}],
                **{untrusted: False if untrusted == "vault_guard_required" else "bypass"},
            )
        )
    assert client._vault_guard_required is True
    _no_effects(locked_effects)


def test_bootstrap_code_cannot_read_env_root_or_claim_host_enrolled() -> None:
    """Real source branch is a deliberate pending DENY, not environment trust."""
    branch = _bootstrap_branch()
    raw = ast.unparse(branch)
    assert "pending_guarded_client" in raw
    assert "ModelUsageLedger(session_memory)" in raw
    assert "vault_guard_required" not in raw
    assert "ProviderCredentialDispatchGuard" not in raw
    assert "HostVaultGuardAdmission" not in raw
    assert "os.environ" not in raw
    assert "HostVaultRuntimeReadinessAdapter" not in raw
    assert "vault_binding_factory" not in raw
    assert "LiteLLMClient(" in raw


def test_mock_response_in_production_is_not_signed_provider_readiness(
    locked_effects: Dict[str, Any],
) -> None:
    # The existing mock model path can return local test output before
    # _provider_call. This is not a paid provider execution or certified
    # readiness; do not promote it to authenticated model delivery.
    client = _construct_actual_main_branch("production", ledger=locked_effects["ledger"])["client"]
    locked_effects["monkeypatch"].setattr(real.settings, "mock_llm", True)
    output = asyncio.run(client.complete([{"role": "user", "content": "synthetic"}]))
    assert output.startswith("[MOCK REASONING]")
    assert client._vault_guard_required is True
    _no_effects(locked_effects)
