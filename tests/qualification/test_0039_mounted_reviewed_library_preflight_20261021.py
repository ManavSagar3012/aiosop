"""Mounted 0039 preflight: synthetic JWT and synthetic host signer are not enrollment."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt

from ai_osop.api import deps, main
from ai_osop.api.routers import reviewed_library_flow_import as routes
from ai_osop.core.config import settings
from ai_osop.memory.reviewed_library_flow_import import (
    PendingLibraryFlowCitation,
    ReviewedLibraryFlowImport,
)

SECRET = "only-synthetic-0039-reviewer-test-jwt"
FLOW = "flow-review-preflight"
BODY = {
    "engagement_id": "eng-owned-test",
    "flow_owner": "owner-123",
    "expected_flow_revision": 7,
    "task_id": "task-current-scoped",
    "authorization_id": "roe-owned-v1",
    "authorization_version": 3,
    "authorization_sha256": "a" * 64,
    "global_document_id": "lib-" + "b" * 32,
    "global_revision": 2,
    "global_sha256": "c" * 64,
}


def token(role="operator", sub="owner-123"):
    now = int(time.time())
    return jwt.encode(
        {"sub": sub, "role": role, "iat": now - 2, "exp": now + 200},
        SECRET,
        algorithm="HS256",
    )


@pytest.fixture
def isolated(monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret", SECRET)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    app = FastAPI()
    app.include_router(routes.router)
    return app


@pytest.mark.asyncio
async def test_mounted_route_denies_unenrolled_host_before_original_db_or_any_signer(
    isolated, monkeypatch
):
    signed = {"Authorization": "Bearer " + token()}
    monkeypatch.setitem(deps.state, "orchestrator", None)
    uri = f"/flows/{FLOW}/reviewed-library-import/preflight"
    async with AsyncClient(
        transport=ASGITransport(app=isolated), base_url="http://testserver"
    ) as c:
        for headers, expected in (({}, 401), ({"Authorization": "Bearer " + token("viewer")}, 403)):
            result = await c.post(uri, headers=headers, json=BODY)
            assert result.status_code == expected
        pending = await c.post(uri, headers=signed, json=BODY)
        assert pending.status_code == 503
        assert "not enrolled" in pending.text
        forged = await c.post(uri, headers=signed, json={**BODY, "flow_owner": "other"})
        assert forged.status_code == 403
        extra = await c.post(uri, headers=signed, json={**BODY, "reviewer_signature": "fake"})
        assert extra.status_code == 422
    assert any(
        r.path == "/flows/{flow_id}/reviewed-library-import/preflight" for r in main.app.routes
    )


@pytest.mark.asyncio
async def test_fixture_proves_bound_principal_and_metadata_only_not_real_signed_import(
    isolated, monkeypatch
):
    # This mock does NOT establish independent Ed25519 roots or a live PG.
    # It qualifies only routing and absence of original bytes in the response.
    maker = object()
    monkeypatch.setitem(
        deps.state,
        "orchestrator",
        SimpleNamespace(session_memory=SimpleNamespace(_async_session=maker)),
    )
    service = ReviewedLibraryFlowImport()
    service._enrolled_shape = True
    service._library = SimpleNamespace(_maker=maker)
    service.inspect_pending_citation = AsyncMock(
        return_value=PendingLibraryFlowCitation(
            source_id=BODY["global_document_id"],
            original_revision=2,
            original_sha256=BODY["global_sha256"],
            source_kind="guide",
            engagement_id=BODY["engagement_id"],
            flow_id=FLOW,
            flow_revision=7,
        )
    )
    routes.install_host_reviewed_library_preflight(isolated, service)
    with pytest.raises(Exception):
        routes.install_host_reviewed_library_preflight(isolated, service)
    uri = f"/flows/{FLOW}/reviewed-library-import/preflight"
    async with AsyncClient(
        transport=ASGITransport(app=isolated), base_url="http://testserver"
    ) as c:
        result = await c.post(uri, headers={"Authorization": "Bearer " + token()}, json=BODY)
        assert result.status_code == 200, result.text
        data = result.json()
        assert data["status"] == "pending_atomic_reviewed_bind"
        assert data["approved_for_agent_context"] is False
        assert data["operator_knowledge_created"] is False
        assert data["safe_for_execution"] is False
        assert "content" not in data and "issuer" not in data
    request = service.inspect_pending_citation.await_args.args[0]
    assert request.principal_subject == "owner-123"
    assert request.issuer == "local-jwt"
    assert request.flow_id == FLOW
