"""Local Ollama routes cannot redirect model calls outside loopback."""

import json

import httpx
import pytest

from ai_osop.core.llm_client import _local_ollama_embedding
from ai_osop.core.provider_capability_discovery import (
    ProviderCatalogDiscovery,
    ProviderCatalogModelAbsent,
)
from ai_osop.core.provider_routing import ProviderRouteDenied, configured_routes


def _route(endpoint: str) -> dict:
    return {
        "provider": "ollama",
        "model": "ollama/qwen2.5:3b",
        "operations": ["completion"],
        "credential_env": "",
        "api_base": endpoint,
    }


def test_local_ollama_route_needs_no_paid_credential(monkeypatch) -> None:
    monkeypatch.setenv(
        "OSOP_VERIFIED_PROVIDER_ROUTES_JSON",
        json.dumps({"version": 1, "routes": [_route("http://127.0.0.1:11434")]}),
    )
    route = configured_routes().resolve("ollama/qwen2.5:3b", "completion")
    assert route.provider_kwargs() == {
        "num_retries": 0,
        "num_ctx": 4096,
        "api_base": "http://127.0.0.1:11434",
    }


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:11434",
        "http://127.0.0.2:11434",
        "http://127.0.0.1:11435",
        "http://169.254.169.254:11434",
        "https://example.org",
        "http://127.0.0.1:11434/path",
    ],
)
def test_ollama_route_rejects_other_destinations(monkeypatch, endpoint: str) -> None:
    monkeypatch.setenv(
        "OSOP_VERIFIED_PROVIDER_ROUTES_JSON",
        json.dumps({"version": 1, "routes": [_route(endpoint)]}),
    )
    with pytest.raises(ProviderRouteDenied):
        configured_routes()


def test_v2_ollama_route_still_requires_signed_task(monkeypatch) -> None:
    route = {
        **_route("http://127.0.0.1:11434"),
        "allowed_roles": ["recon"],
        "capabilities": ["text_completion"],
        "max_output_tokens": 4096,
        "budget_source": "signed_postgres_roe",
    }
    monkeypatch.setenv(
        "OSOP_VERIFIED_PROVIDER_ROUTES_JSON",
        json.dumps({"version": 2, "routes": [route]}),
    )
    with pytest.raises(ProviderRouteDenied, match="Authoritative capability"):
        configured_routes().resolve("ollama/qwen2.5:3b", "completion")


@pytest.mark.asyncio
async def test_local_embedding_rejects_wrong_dimensions(monkeypatch) -> None:
    original_client = httpx.AsyncClient
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"embeddings": [[0.2] * 768]})
    )
    monkeypatch.setattr(
        "ai_osop.core.llm_client.httpx.AsyncClient",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )
    with pytest.raises(ValueError, match="invalid dimensions"):
        await _local_ollama_embedding("ollama/qwen3-embedding:4b", ["test"])


@pytest.mark.asyncio
async def test_local_catalog_only_accepts_listed_model(monkeypatch) -> None:
    monkeypatch.setenv("OSOP_PROVIDER_CATALOG_MODE", "enforce")
    monkeypatch.setenv(
        "OSOP_VERIFIED_PROVIDER_ROUTES_JSON",
        json.dumps(
            {
                "version": 1,
                "routes": [
                    _route("http://127.0.0.1:11434"),
                    {**_route("http://127.0.0.1:11434"), "model": "ollama/other"},
                ],
            }
        ),
    )
    original_client = httpx.AsyncClient
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, json={"models": [{"model": "qwen2.5:3b"}]}
        )
    )
    monkeypatch.setattr(
        "ai_osop.core.provider_capability_discovery.httpx.AsyncClient",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )
    catalog = ProviderCatalogDiscovery()
    routes = configured_routes().routes
    await catalog.verify(routes[0])
    with pytest.raises(ProviderCatalogModelAbsent):
        await catalog.verify(routes[1])
