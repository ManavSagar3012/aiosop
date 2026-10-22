"""Original routed global-library authorization is user-owned and inert."""

from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.routers import operator_global_library as library
from ai_osop.api.routers.flow_artifacts import _operator


def _app(principal=None):
    app = FastAPI()
    app.include_router(library.router)
    if principal is not None:
        app.dependency_overrides[_operator] = lambda: principal
    return app


def test_real_auth_dependency_requires_bearer_header():
    with TestClient(_app()) as client:
        assert client.get("/operator/library/documents").status_code in (401, 403)
        assert client.post(
            "/operator/library/documents",
            json={"title": "t", "doc_type": "guide", "content": "notes"},
        ).status_code in (401, 403)


def test_production_app_registers_global_user_routes_without_flow_delegation():
    from ai_osop.api.main import app

    registered = {
        (route.path, method)
        for route in app.routes
        for method in (getattr(route, "methods", None) or [])
    }
    base = "/operator/library/documents"
    assert (base, "GET") in registered
    assert (base, "POST") in registered
    assert (base + "/{document_id}", "GET") in registered
    assert (base + "/{document_id}", "PUT") in registered
    assert (base + "/{document_id}", "DELETE") in registered
    assert all("/flows/" not in path for path, method in registered if path.startswith(base))


def test_principal_namespace_never_comes_from_body_or_query(monkeypatch):
    principal = {
        "sub": "oidc-verified-mapped-actor",
        "role": "operator",
        "claims": {"exp": 2147483647, "iss": "https://idp.example.test"},
    }
    fake = type("FakeStore", (), {})()
    fake.create = AsyncMock(return_value={"id": "lib-" + "1" * 32})
    fake.get = AsyncMock(return_value={"id": "lib-" + "1" * 32})
    fake.search = AsyncMock(return_value={"items": [], "has_more": False})
    fake.update = AsyncMock(return_value={"id": "lib-" + "1" * 32, "revision": 2})
    fake.delete = AsyncMock(return_value={"id": "lib-" + "1" * 32, "status": "tombstoned"})
    monkeypatch.setattr(library, "_store", lambda: fake)
    identifier = "lib-" + "1" * 32
    with TestClient(_app(principal)) as client:
        create = client.post(
            "/operator/library/documents?owner=bob&issuer=forged",
            json={"title": "Notes", "doc_type": "guide", "content": "inert only"},
        )
        assert create.status_code == 201
        assert create.headers["cache-control"] == "private, no-store"
        signed_issuer, signed_subject = fake.create.await_args.args
        assert signed_issuer == "https://idp.example.test"
        assert len(signed_subject) == 64 and signed_subject != "bob"
        assert fake.create.await_args.kwargs == {
            "title": "Notes",
            "doc_type": "guide",
            "content": "inert only",
        }
        listing = client.get("/operator/library/documents?query=notes")
        assert listing.status_code == 200
        assert fake.search.await_args.args == (signed_issuer, signed_subject)
        fetched = client.get("/operator/library/documents/" + identifier)
        assert fetched.status_code == 200
        assert fake.get.await_args.args == (signed_issuer, signed_subject, identifier)
        updated = client.put(
            "/operator/library/documents/" + identifier,
            json={
                "title": "new",
                "doc_type": "answer",
                "content": "new original",
                "expected_revision": 1,
            },
        )
        assert updated.status_code == 200
        assert fake.update.await_args.args == (signed_issuer, signed_subject, identifier, 1)
        deleted = client.request(
            "DELETE",
            "/operator/library/documents/" + identifier,
            json={"expected_revision": 2},
        )
        assert deleted.status_code == 200
        assert fake.delete.await_args.args == (signed_issuer, signed_subject, identifier, 2)


def test_global_library_excludes_development_api_keys_and_unattributed_subject():
    for principal in (
        {"sub": "shared-development-token", "role": "dev_api_token"},
        {"sub": "bob", "role": "operator", "claims": {}},
        {"sub": "bob", "role": "viewer", "claims": {"exp": 2147483647}},
    ):
        with TestClient(_app(principal)) as client:
            assert client.get("/operator/library/documents").status_code == 403


def test_library_rejects_forged_model_authority_and_oversized_page(monkeypatch):
    fake = AsyncMock()
    monkeypatch.setattr(library, "_store", fake)
    principal = {"sub": "bob", "role": "operator", "claims": {"exp": 2147483647}}
    with TestClient(_app(principal)) as client:
        assert (
            client.post(
                "/operator/library/documents",
                json={
                    "title": "x",
                    "doc_type": "guide",
                    "content": "notes",
                    "approved_for_agent_context": True,
                },
            ).status_code
            == 422
        )
        assert client.get("/operator/library/documents?limit=100000").status_code == 422
        assert (
            client.put(
                "/operator/library/documents/lib-" + "1" * 32,
                json={
                    "title": "t",
                    "doc_type": "answer",
                    "content": "hi",
                    "expected_revision": False,
                },
            ).status_code
            == 422
        )
        fake.assert_not_called()
