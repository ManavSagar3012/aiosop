"""Opt-in, read-only model catalog qualification at official provider origins.

OpenAI GET https://api.openai.com/v1/models and Anthropic GET
https://api.anthropic.com/v1/models are credential-scoped model listings.
A successful listing confirms the model ID was advertised at observation time;
it does not prove invocation availability, operation support, pricing or a
provider-enforced spend cap. Errors or stale caches are never positive proof.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, TYPE_CHECKING

import httpx

from ai_osop.core.provider_routing import ProviderRouteDenied

if TYPE_CHECKING:
    from ai_osop.core.provider_routing import ProviderRoute

_MODE_ENV = "OSOP_PROVIDER_CATALOG_MODE"
_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/models",
    "anthropic": "https://api.anthropic.com/v1/models",
}
_MAX_BYTES = 65536
_MAX_MODELS = 512
_MAX_PAGES = 3
_TTL = 60
_CURSOR = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,89}\Z")


class ProviderCatalogDenied(ProviderRouteDenied):
    """A model listing cannot authorize this route."""


class ProviderCatalogUnavailable(ProviderCatalogDenied):
    """No independently checked, current provider catalog is available."""


class ProviderCatalogModelAbsent(ProviderCatalogDenied):
    """Fresh, complete provider listing did not advertise this exact model."""


def catalog_mode() -> str:
    mode = os.environ.get(_MODE_ENV, "off")
    if mode not in {"off", "enforce"}:
        raise ProviderCatalogUnavailable("Model catalog mode is misconfigured")
    return mode


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProviderCatalogUnavailable("Ambiguous provider model catalog")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> Any:
    raise ProviderCatalogUnavailable("Invalid provider catalog JSON")


def _page(raw: bytes, provider: str) -> Dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_object,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ProviderCatalogUnavailable("Malformed provider model catalog") from exc
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise ProviderCatalogUnavailable("Incomplete provider model catalog")
    if provider == "openai":
        if document.get("object") != "list" or "has_more" in document:
            raise ProviderCatalogUnavailable("Incomplete OpenAI model listing")
    else:
        if type(document.get("has_more")) is not bool:
            raise ProviderCatalogUnavailable("Incomplete Anthropic model listing")
    if len(document["data"]) > _MAX_MODELS:
        raise ProviderCatalogUnavailable("Provider model listing exceeds bounds")
    return document


@dataclass(frozen=True)
class CatalogSnapshot:
    provider: str
    models: frozenset[str]
    checked_at: float
    expires_at: float
    pages: int


class ProviderCatalogDiscovery:
    """Bounded process-local TTL cache; nothing is persisted to the model ledger."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], CatalogSnapshot] = {}
        self._lock = asyncio.Lock()
        self._status: dict[tuple[str, str], str] = {}

    @staticmethod
    def _identity(route: "ProviderRoute", credential: Optional[str] = None) -> tuple[str, str]:
        # A custom URL may be a real model server, but it is not the official
        # provider's catalog. Never probe it or treat it as authenticated.
        if route.provider == "ollama":
            if route.api_base != "http://127.0.0.1:11434":
                raise ProviderCatalogUnavailable("Local model catalog endpoint is invalid")
            route.validate_deployment()
            if credential not in (None, ""):
                raise ProviderCatalogUnavailable("Local model catalog credential is invalid")
            return ("ollama", "loopback-11434")
        if route.provider not in _ENDPOINTS or route.api_base is not None:
            raise ProviderCatalogUnavailable("Official model catalog unsupported for route")
        current = route.validate_deployment()
        if credential is not None and credential != current:
            raise ProviderCatalogUnavailable("Provider credential rotated during preflight")
        credential = current
        return (route.provider, hashlib.sha256(credential.encode("utf-8")).hexdigest())

    async def _fetch(self, route: "ProviderRoute", credential: str) -> CatalogSnapshot:
        provider = route.provider
        if provider == "ollama":
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(5.0), follow_redirects=False, trust_env=False
                ) as client:
                    async with client.stream("GET", "http://127.0.0.1:11434/api/tags") as response:
                        if (
                            response.status_code != 200
                            or response.headers.get("content-type", "").split(";", 1)[0].lower()
                            != "application/json"
                        ):
                            raise ProviderCatalogUnavailable("Local model listing unavailable")
                        raw = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(raw) + len(chunk) > _MAX_BYTES:
                                raise ProviderCatalogUnavailable("Local model listing exceeds bound")
                            raw.extend(chunk)
                document = json.loads(raw, object_pairs_hook=_object, parse_constant=_invalid_constant)
                entries = document.get("models") if isinstance(document, dict) else None
                if not isinstance(entries, list) or len(entries) > _MAX_MODELS:
                    raise ProviderCatalogUnavailable("Local model listing malformed")
                models: set[str] = set()
                for entry in entries:
                    name = entry.get("model") if isinstance(entry, dict) else None
                    if not isinstance(name, str) or not _MODEL.fullmatch(name) or name in models:
                        raise ProviderCatalogUnavailable("Local model listing malformed")
                    models.add(name)
            except (httpx.HTTPError, OSError, TimeoutError, ValueError, TypeError) as exc:
                raise ProviderCatalogUnavailable("Local model listing unavailable") from exc
            now = time.monotonic()
            return CatalogSnapshot("ollama", frozenset(models), now, now + _TTL, 1)
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if provider == "openai":
            headers["Authorization"] = "Bearer " + credential
        elif provider == "anthropic":
            headers["x-api-key"] = credential
            headers["anthropic-version"] = "2023-06-01"
        else:
            raise ProviderCatalogUnavailable("Unsupported provider catalog")
        models: set[str] = set()
        cursor: Optional[str] = None
        visited: set[str] = set()
        pages = 0
        # Only literal hardcoded HTTPS443 origins, never operator-supplied
        # api_base, DNS/IP, redirect locations, proxies, or env-configured URLs.
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(5.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                for _ in range(_MAX_PAGES):
                    params: dict[str, Any] = {}
                    if provider == "anthropic":
                        params["limit"] = 100
                        if cursor is not None:
                            params["after_id"] = cursor
                    async with client.stream(
                        "GET",
                        _ENDPOINTS[provider],
                        params=params,
                        headers=headers,
                    ) as response:
                        if response.status_code != 200:
                            raise ProviderCatalogUnavailable("Provider model listing unavailable")
                        if (
                            response.headers.get("content-type", "").split(";", 1)[0].lower()
                            != "application/json"
                            or response.headers.get("content-encoding", "identity").lower()
                            != "identity"
                        ):
                            raise ProviderCatalogUnavailable(
                                "Unsupported provider catalog response"
                            )
                        raw = bytearray()
                        # httpx.MockTransport's JSON responses may already
                        # have a cached body. Identity encoding is required
                        # above, so the bounded decoded stream is equivalent.
                        async for chunk in response.aiter_bytes():
                            if len(raw) + len(chunk) > _MAX_BYTES:
                                raise ProviderCatalogUnavailable(
                                    "Provider catalog response too large"
                                )
                            raw.extend(chunk)
                    page = _page(bytes(raw), provider)
                    pages += 1
                    for entry in page["data"]:
                        if (
                            not isinstance(entry, dict)
                            or entry.get("object" if provider == "openai" else "type") != "model"
                            or not isinstance(entry.get("id"), str)
                            or not _MODEL.fullmatch(entry["id"])
                            or entry["id"] in models
                        ):
                            raise ProviderCatalogUnavailable("Malformed or duplicate model ID")
                        models.add(entry["id"])
                        if len(models) > _MAX_MODELS:
                            raise ProviderCatalogUnavailable("Provider model catalog exceeds limit")
                    if provider == "openai" or not page["has_more"]:
                        if provider == "anthropic" and page.get("last_id") not in (None, ""):
                            if not isinstance(page["last_id"], str):
                                raise ProviderCatalogUnavailable("Invalid catalog pagination")
                        break
                    next_id = page.get("last_id")
                    if (
                        not page["data"]
                        or not isinstance(next_id, str)
                        or not _CURSOR.fullmatch(next_id)
                        or next_id in visited
                        or next_id != page["data"][-1]["id"]
                    ):
                        raise ProviderCatalogUnavailable("Provider catalog pagination invalid")
                    visited.add(next_id)
                    cursor = next_id
                else:
                    raise ProviderCatalogUnavailable("Provider model catalog pagination incomplete")
        except (httpx.HTTPError, OSError, TimeoutError) as exc:
            raise ProviderCatalogUnavailable(
                "Provider model catalog transport unavailable"
            ) from exc
        now = time.monotonic()
        return CatalogSnapshot(provider, frozenset(models), now, now + _TTL, pages)

    @staticmethod
    def _id(route: "ProviderRoute") -> str:
        prefix = route.provider + "/"
        return route.model[len(prefix) :] if route.model.startswith(prefix) else route.model

    async def verify(
        self,
        route: "ProviderRoute",
        *,
        credential: Optional[str] = None,
    ) -> CatalogSnapshot:
        if catalog_mode() != "enforce":
            raise ProviderCatalogUnavailable("Provider catalog verification is disabled")
        try:
            identity = self._identity(route, credential)
            credential = credential if credential is not None else route.validate_deployment()
            now = time.monotonic()
            snapshot = self._cache.get(identity)
            if snapshot is None or snapshot.expires_at <= now:
                async with self._lock:
                    snapshot = self._cache.get(identity)
                    if snapshot is None or snapshot.expires_at <= time.monotonic():
                        try:
                            snapshot = await self._fetch(route, credential)
                        except ProviderRouteDenied:
                            self._status[identity] = "unavailable"
                            raise
                        self._cache[identity] = snapshot
            self._status[identity] = "checked_fresh"
            if self._id(route) not in snapshot.models:
                raise ProviderCatalogModelAbsent("Configured model absent from provider catalog")
            return snapshot
        except ProviderCatalogDenied:
            raise
        except ProviderRouteDenied as exc:
            raise ProviderCatalogUnavailable(
                "Provider model catalog cannot validate route"
            ) from exc

    def status(self, route: "ProviderRoute") -> dict[str, Any]:
        if catalog_mode() != "enforce":
            return {"catalog_status": "disabled", "provider_catalog_verified": False}
        try:
            identity = self._identity(route)
        except ProviderRouteDenied:
            return {"catalog_status": "unavailable", "provider_catalog_verified": False}
        snapshot = self._cache.get(identity)
        if snapshot is None:
            return {
                "catalog_status": self._status.get(identity, "unchecked"),
                "provider_catalog_verified": False,
            }
        if snapshot.expires_at <= time.monotonic():
            return {
                "catalog_status": (
                    "stale_refresh_failed"
                    if self._status.get(identity) == "unavailable"
                    else "stale"
                ),
                "provider_catalog_verified": False,
                "catalog_age_seconds": max(0, int(time.monotonic() - snapshot.checked_at)),
                "catalog_ttl_seconds": _TTL,
            }
        present = self._id(route) in snapshot.models
        return {
            "catalog_status": "served_in_listing" if present else "absent_in_listing",
            "provider_catalog_verified": present,
            "catalog_age_seconds": max(0, int(time.monotonic() - snapshot.checked_at)),
            "catalog_ttl_seconds": _TTL,
        }


_catalog = ProviderCatalogDiscovery()


def configured_catalog() -> ProviderCatalogDiscovery:
    return _catalog
