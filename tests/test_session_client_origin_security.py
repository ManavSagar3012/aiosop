"""Credentials remain confined to their imported origin and cookie policy."""

from typing import Any

import httpx
import pytest

from ai_osop.auth.session_client import SessionClient
from ai_osop.auth.session_store import UserSession
from ai_osop.core.exceptions import ScopeValidationError


def _client(monkeypatch: pytest.MonkeyPatch, handler: Any, **kwargs: Any) -> SessionClient:
    original = httpx.AsyncClient

    def factory(**options: Any) -> httpx.AsyncClient:
        return original(**options, transport=httpx.MockTransport(handler))

    monkeypatch.setattr("ai_osop.auth.session_client.httpx.AsyncClient", factory)
    session = UserSession(engagement_id="eng-test", user_label="test", **kwargs)
    return SessionClient(session=session)


@pytest.mark.asyncio
async def test_secure_cookie_never_sent_over_http(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []

    async def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie", ""))
        return httpx.Response(200)

    async with _client(
        monkeypatch,
        handle,
        metadata_blob={"origin": "http://lab.test"},
        cookies=[{"name": "sid", "value": "synthetic", "domain": "lab.test", "secure": True}],
    ) as client:
        await client.get("http://lab.test/")
    assert seen == [""]


@pytest.mark.asyncio
async def test_cross_origin_redirect_denied_before_credentials_leave(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = []

    async def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(302, headers={"location": "https://outside.test/"})

    async with _client(
        monkeypatch,
        handle,
        metadata_blob={"origin": "https://lab.test"},
        csrf_token="synthetic",
        extra_headers={"X-API-Key": "synthetic"},
    ) as client:
        with pytest.raises(ScopeValidationError):
            await client.get("https://lab.test/")
    assert seen == ["lab.test"]


@pytest.mark.asyncio
async def test_intermediate_cookie_rotation_survives_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(
                302, headers={"location": "/end", "set-cookie": "sid=rotated; Secure; Path=/"}
            )
        assert request.headers["cookie"] == "sid=rotated"
        return httpx.Response(200)

    async with _client(monkeypatch, handle, metadata_blob={"origin": "https://lab.test"}) as client:
        await client.get("https://lab.test/start")
        assert client.cookies_dirty is True
        assert client.session.cookies[0]["value"] == "rotated"
        assert client.session.cookies[0]["secure"] is True


@pytest.mark.asyncio
async def test_unknown_origin_denied_without_a_request(monkeypatch: pytest.MonkeyPatch) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Must not contact an unbound origin")

    async with _client(monkeypatch, handle, bearer_token="synthetic") as client:
        with pytest.raises(ScopeValidationError):
            await client.get("https://unbound.test/")


@pytest.mark.asyncio
async def test_rotated_cookie_keeps_response_directory_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"set-cookie": "sid=scoped; Secure"})

    async with _client(monkeypatch, handle, metadata_blob={"origin": "https://lab.test"}) as client:
        await client.get("https://lab.test/account/login")
        assert client.session.cookies[0]["path"] == "/account"
