"""Bound the actual mounted 0039 mutating JSON before FastAPI body parsing.

All fixtures are inert API/store mocks: no application DB or agent execution.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from ai_osop.api.routers import operator_global_library as library
from ai_osop.api.routers.flow_artifacts import _operator


_URL = "/operator/library/documents"
_OWNER = {
    "sub": "operator-signed",
    "role": "operator",
    "claims": {"exp": 2147483647, "iss": "https://idp.example.test"},
}
_VALID = b'{"title":"inert","doc_type":"guide","content":"original text"}'


def _app(monkeypatch: pytest.MonkeyPatch):
    app = FastAPI()
    app.include_router(library.router)
    app.dependency_overrides[_operator] = lambda: _OWNER
    store = type("MockStore", (), {})()
    store.create = AsyncMock(return_value={"id": "lib-" + "a" * 32})
    store.update = AsyncMock(return_value={"revision": 2})
    store.delete = AsyncMock(return_value={"status": "tombstoned"})
    monkeypatch.setattr(library, "_store", lambda: store)
    return app, store


def test_original_registered_mutations_have_preparser_route():
    from ai_osop.api.main import app

    mutations = {
        (route.path, method)
        for route in app.routes
        if isinstance(route, library._BoundedUserLibraryRoute)
        for method in (getattr(route, "methods", set()) or set())
    }
    identifier = "/{document_id}"
    assert (_URL, "POST") in mutations
    assert (_URL + identifier, "PUT") in mutations
    assert (_URL + identifier, "DELETE") in mutations


def test_current_original_utf8_body_preserved_and_strict_bad_json_denied(monkeypatch):
    app, store = _app(monkeypatch)
    with TestClient(app) as client:
        ok = client.post(_URL, content=_VALID, headers={"Content-Type": "application/json"})
        assert ok.status_code == 201
        store.create.assert_awaited_once()
        assert store.create.await_args.kwargs["content"] == "original text"
        store.create.reset_mock()
        for invalid in (
            b'{"title":"first","title":"last","doc_type":"guide","content":"text"}',
            b'{"title":"first","doc_type":"guide","content":"text","extra":{"x":1,"x":2}}',
            b'{"title":"a","doc_type":"guide","content":"b","unknown":NaN}',
            b'{"title":"a","doc_type":"guide","content":"b","unknown":Infinity}',
            b'{"title":"a","doc_type":"guide","content":"b","unknown":1e309}',
            b'{"title":"\xff","doc_type":"guide","content":"x"}',
            b"[]",
            b"",
        ):
            response = client.post(
                _URL, content=invalid, headers={"Content-Type": "application/json"}
            )
            assert response.status_code in (413, 422)
        assert store.create.await_count == 0


def test_oversized_wire_does_not_invoke_handler_and_media_type_required(monkeypatch):
    app, store = _app(monkeypatch)
    with TestClient(app) as client:
        assert (
            client.post(
                _URL, content=b"A" * 100_000, headers={"Content-Type": "application/json"}
            ).status_code
            == 413
        )
        assert (
            client.post(_URL, content=_VALID, headers={"Content-Type": "text/plain"}).status_code
            == 415
        )
        assert (
            client.request(
                "DELETE",
                _URL + "/lib-" + "a" * 32,
                content=b"{" + b" " * 70_000 + b"}",
                headers={"Content-Type": "application/json"},
            ).status_code
            == 413
        )
    store.create.assert_not_awaited()
    store.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_chunked_no_contentlength_stream_is_bounded(monkeypatch):
    app, store = _app(monkeypatch)

    async def endless_inert_bytes():
        yield b'{"title":"x","doc_type":"guide","content":"'
        for _ in range(90):
            yield b"a" * 1024
        yield b'"}'

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            _URL, content=endless_inert_bytes(), headers={"Content-Type": "application/json"}
        )
    assert response.status_code == 413
    store.create.assert_not_awaited()
