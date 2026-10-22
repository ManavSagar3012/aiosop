"""Mounted metadata-only global+Flow search and negative provenance contracts."""

from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.api.routers import unified_knowledge_search as search
from ai_osop.memory.operator_knowledge import KnowledgeDenied

_OWNER = {
    "sub": "operator-a",
    "role": "operator",
    "claims": {"exp": 2147483647, "iss": "https://identity.example.test"},
}
_SHA = "a" * 64
_FLOW = "flow-a123"
_QUERY = "/operator/search/knowledge?query=readme"


def _row(source: str):
    result = {
        "id": "lib-" + "1" * 32 if source == "global" else "knowledge-" + "2" * 32,
        "title": "Readme",
        "doc_type": "guide",
        "revision": 1,
        "sha256": _SHA,
        "content_bytes": 12,
        "created_at": "2026-10-21T10:00:00Z",
        "approved_for_agent_context": False,
        "content_classification": (
            "untrusted_user_text" if source == "global" else "untrusted_operator_text"
        ),
    }
    if source == "flow":
        result["flow_id"] = _FLOW
    else:
        result["version_created_at"] = "2026-10-21T10:00:00Z"
    return result


def _app(monkeypatch, global_page=None, flow_page=None):
    app = FastAPI()
    app.include_router(search.router)
    app.dependency_overrides[_operator] = lambda: _OWNER
    monkeypatch.setitem(state, "orchestrator", type("Orch", (), {"session_memory": object()})())
    global_search = AsyncMock(
        return_value=global_page or {"items": [_row("global")], "has_more": False}
    )
    flow_search = AsyncMock(return_value=flow_page or {"items": [_row("flow")], "has_more": False})
    monkeypatch.setattr(
        search,
        "OperatorGlobalLibrary",
        lambda memory: type("Global", (), {"search": global_search})(),
    )
    monkeypatch.setattr(
        search, "OperatorKnowledgeStore", lambda memory: type("Flow", (), {"search": flow_search})()
    )
    return app, global_search, flow_search


def test_mounted_main_registers_truthful_metadata_route():
    from ai_osop.api.main import app

    assert any(
        route.path == "/operator/search/knowledge"
        and "GET" in (getattr(route, "methods", None) or [])
        for route in app.routes
    )


def test_default_global_search_uses_signed_principal_and_returns_no_content(monkeypatch):
    app, global_search, flow_search = _app(monkeypatch)
    with TestClient(app) as client:
        response = client.get(_QUERY)
    assert response.status_code == 200
    data = response.json()
    assert response.headers["Cache-Control"] == "private, no-store"
    assert set(data["sources"]) == {"user_global_0039"}
    assert global_search.await_count == 1
    assert flow_search.await_count == 0
    args = global_search.await_args
    assert args.args[0] == _OWNER["claims"]["iss"]
    assert args.args[1] != _OWNER["sub"]  # derived cryptographic owner namespace
    row = data["sources"]["user_global_0039"]["items"][0]
    assert row["sha256"] == _SHA
    assert row["source"] == "user_global_0039"
    assert row["approved_for_agent_context"] is False
    assert row["verified_target_evidence"] is False
    assert "content" not in row and "owner_id" not in row
    assert data["independent_target_effect_verified"] is False
    assert data["synthesis_performed"] is False
    assert data["atomic_cross_source_snapshot"] is False


def test_both_sources_read_under_distinct_existing_scope_fences(monkeypatch):
    app, global_search, flow_search = _app(monkeypatch)
    url = _QUERY + f"&flow_id={_FLOW}&expected_flow_revision=4&expected_authorization_version=8"
    with TestClient(app) as client:
        response = client.get(url)
    assert response.status_code == 200
    data = response.json()
    assert len(data["sources"]) == 2
    flow_search.assert_awaited_once()
    assert flow_search.await_args.args == (_FLOW, _OWNER["sub"], 4, 8)
    assert flow_search.await_args.kwargs["query"] == "readme"
    flow_row = data["sources"]["flow_local_0019_0038"]["items"][0]
    assert flow_row["flow_id"] == _FLOW
    assert flow_row["trust"] == "untrusted_human_text"
    assert flow_row["reportable"] is False
    assert global_search.await_count == 1


def test_missing_flow_fence_rejected_before_any_library_read(monkeypatch):
    app, global_search, flow_search = _app(monkeypatch)
    with TestClient(app) as client:
        for suffix in (
            "&flow_id=flow-a123",
            "&expected_flow_revision=2",
            "&flow_id=flow-a123&expected_flow_revision=2",
            "&flow_id=../../other&expected_flow_revision=2&expected_authorization_version=3",
            "&query=%00",
        ):
            response = client.get(_QUERY + suffix)
            assert response.status_code == 422
    global_search.assert_not_awaited()
    flow_search.assert_not_awaited()


def test_flow_revocation_denial_is_not_partial_global_success(monkeypatch):
    app, global_search, flow_search = _app(monkeypatch)
    flow_search.side_effect = KnowledgeDenied(403, "internal Flow secret")
    with TestClient(app) as client:
        response = client.get(
            _QUERY + f"&flow_id={_FLOW}&expected_flow_revision=2&expected_authorization_version=3"
        )
    assert response.status_code == 403
    assert "internal Flow secret" not in response.text
    assert global_search.await_count == 1


def test_positive_provider_authority_and_wrong_source_identity_fail_closed(monkeypatch):
    forged = _row("global")
    forged["approved_for_agent_context"] = True
    app, _, _ = _app(monkeypatch, global_page={"items": [forged], "has_more": False})
    with TestClient(app) as client:
        assert client.get(_QUERY).status_code == 503
    app, _, _ = _app(
        monkeypatch,
        global_page={"items": [_row("global")], "has_more": False},
        flow_page={"items": [{**_row("flow"), "flow_id": "flow-foreign"}], "has_more": False},
    )
    with TestClient(app) as client:
        assert (
            client.get(
                _QUERY
                + f"&flow_id={_FLOW}&expected_flow_revision=2&expected_authorization_version=3"
            ).status_code
            == 503
        )


def test_source_id_prefix_cannot_be_rebound_by_provider_metadata(monkeypatch):
    foreign_prefix = {**_row("global"), "id": "knowledge-" + "f" * 32}
    app, _, _ = _app(
        monkeypatch,
        global_page={"items": [foreign_prefix], "has_more": False},
    )
    with TestClient(app) as client:
        assert client.get(_QUERY).status_code == 503


def test_global_metadata_cannot_borrow_foreign_flow_identity(monkeypatch):
    row = {**_row("global"), "flow_id": "flow-foreign"}
    app, _, _ = _app(monkeypatch, global_page={"items": [row], "has_more": False})
    with TestClient(app) as client:
        assert client.get(_QUERY).status_code == 503


def test_duplicate_or_oversized_source_page_denied(monkeypatch):
    original = _row("global")
    for rows in ([original, original], [original] * 11):
        app, _, _ = _app(monkeypatch, global_page={"items": rows, "has_more": False})
        with TestClient(app) as client:
            assert client.get(_QUERY).status_code == 503
