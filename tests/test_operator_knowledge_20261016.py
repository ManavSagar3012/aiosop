"""Bounded inert operator knowledge HTTP and store guard regression tests."""

import hashlib
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from ai_osop.api.routers import operator_knowledge as api
from ai_osop.memory.operator_knowledge import (
    KnowledgeDenied,
    OperatorKnowledgeStore,
    _valid_content,
    _valid_page,
)


@pytest.fixture
def app(monkeypatch):
    application = FastAPI()
    application.include_router(api.router)
    application.dependency_overrides[api._operator] = lambda: {
        "sub": "owner-one",
        "role": "operator",
    }
    store = SimpleNamespace(
        create=AsyncMock(return_value={"id": "knowledge-" + "a" * 32}),
        list=AsyncMock(return_value={"items": [], "has_more": False}),
        search=AsyncMock(return_value={"items": [], "has_more": False}),
        get=AsyncMock(return_value={"untrusted_content": "sample"}),
        update=AsyncMock(return_value={"revision": 2}),
        delete=AsyncMock(return_value={"deleted": True}),
    )
    monkeypatch.setattr(api, "_store", lambda: store)
    return application, store


@pytest.mark.asyncio
async def test_http_crud_scope_cas_and_search(app):
    application, store = app
    base = "/flows/flow-one/operator-knowledge"
    scope = "?expected_revision=3&expected_authorization_version=2"
    doc = "knowledge-" + "a" * 32
    body = {"title": "Example", "doc_type": "guide", "content": "inert notes"}
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(base + scope, json=body)
        assert created.status_code == 201
        assert created.headers["cache-control"] == "private, no-store"
        store.create.assert_awaited_once_with("flow-one", "owner-one", 3, 2, **body)
        assert (await client.get(base + scope)).status_code == 200
        assert (await client.get(base + "/search" + scope + "&query=needle")).status_code == 200
        store.search.assert_awaited_once_with(
            "flow-one", "owner-one", 3, 2, query="needle", limit=20, offset=0, doc_type=None
        )
        assert (await client.get(base + "/" + doc + scope)).json()["untrusted_content"] == "sample"
        updated = await client.put(
            base + "/" + doc + scope, json={**body, "expected_document_revision": 1}
        )
        assert updated.status_code == 200
        store.update.assert_awaited_once_with(
            "flow-one", "owner-one", 3, 2, doc, expected_revision=1, **body
        )
        deleted = await client.request(
            "DELETE", base + "/" + doc + scope, json={"expected_document_revision": 2}
        )
        assert deleted.status_code == 200
        store.delete.assert_awaited_once_with(
            "flow-one", "owner-one", 3, 2, doc, expected_revision=2
        )


@pytest.mark.asyncio
async def test_http_rejects_unbounded_missing_fence_and_propagates_denial(app):
    application, store = app
    base = "/flows/flow-one/operator-knowledge"
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get(base)).status_code == 422
        assert (
            await client.get(
                base + "?expected_revision=0&expected_authorization_version=1&limit=51"
            )
        ).status_code == 422
        assert (
            await client.post(
                base + "?expected_revision=0&expected_authorization_version=1",
                json={"title": "x", "doc_type": "guide", "content": "z" * 8193},
            )
        ).status_code == 422
        store.get.side_effect = KnowledgeDenied(409, "Authorization changed")
        response = await client.get(
            base
            + "/knowledge-"
            + "a" * 32
            + "?expected_revision=1&expected_authorization_version=1"
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "Authorization changed"


def test_utf8_hash_byte_cap_and_bounded_pagination():
    value, size, digest = _valid_content("é" * 4096)
    assert size == 8192
    assert digest == hashlib.sha256(value.encode()).hexdigest()
    for bad in ("é" * 4097, "", "\x00", "\ud800"):
        with pytest.raises(KnowledgeDenied):
            _valid_content(bad)
    for limit, offset in ((51, 0), (1, 1001), (True, 0)):
        with pytest.raises(KnowledgeDenied):
            _valid_page(limit, offset)


@pytest.mark.asyncio
async def test_store_fence_failure_prevents_document_query(monkeypatch):
    class Session:
        def __init__(self):
            self.executed = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        def begin(self):
            return self

        async def execute(self, *_):
            self.executed = True
            raise AssertionError("No document query permitted")

    session = Session()
    store = OperatorKnowledgeStore(SimpleNamespace(_async_session=lambda: session))

    async def deny(*_args, **_kwargs):
        raise KnowledgeDenied(403, "Signed scope revoked")

    monkeypatch.setattr(store, "_fence", deny)
    with pytest.raises(KnowledgeDenied, match="Signed scope revoked"):
        await store.list("flow-one", "owner-one", 3, 2)
    assert not session.executed
