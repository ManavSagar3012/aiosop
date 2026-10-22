"""Printable engagement reports expose only authorized, verified aggregates."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from ai_osop.api.deps import state
from ai_osop.api.routers.engagements import router
from ai_osop.core.config import settings
from ai_osop.core.models import ScopeDefinition, SessionState


class _QueryRows:
    def __init__(self, rows):
        self.rows = rows

    def __aiter__(self):
        return self._rows()

    async def _rows(self):
        for row in self.rows:
            yield row


class _GraphSession:
    def __init__(self, graph):
        self.graph = graph

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def run(self, query, parameters):
        self.graph.calls.append((query, parameters))
        if self.graph.error is not None:
            raise self.graph.error
        return _QueryRows(self.graph.rows)


class _Graph:
    def __init__(self):
        self.rows = []
        self.calls = []
        self.error = None
        self._driver = SimpleNamespace(session=lambda: _GraphSession(self))


@pytest.fixture
def report_harness(monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret", "signed-report-test-secret")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "environment", "development")

    engagement_id = "eng-report-one"
    owned = SessionState(
        session_id=engagement_id,
        scope=ScopeDefinition(
            engagement_id=engagement_id,
            domains=["sensitive.example"],
            authorization_ref="signed-roe-secret-sentinel",
        ),
        roe={"api_key": "SECRET-ROE-VALUE-ALWAYS-HIDDEN"},
        phase="vulnerability_discovery",
        created_by="alice",
    )
    graph = _Graph()
    memory = SimpleNamespace(load_session_state=AsyncMock(return_value=owned))
    orch = SimpleNamespace(
        _sessions={engagement_id: owned},
        session_memory=memory,
        graph_memory=graph,
    )
    monkeypatch.setitem(state, "orchestrator", orch)
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    def auth(sub="alice", role="operator"):
        token = jwt.encode(
            {
                "sub": sub,
                "role": role,
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            },
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        return {"Authorization": f"Bearer {token}"}

    return SimpleNamespace(
        client=client, auth=auth, graph=graph, orch=orch,
        memory=memory, session=owned, session_id=engagement_id,
    )


def test_verified_summary_only_counts_sanitized_evidence(report_harness):
    h = report_harness
    h.graph.rows = [
        {
            "severity": "CRITICAL", "evidence": "Bearer SECRET-TOKEN-SENTINEL",
            "title": "https://untrusted.example/payload?token=SECRET",
            "description": "<script>alert('unsafe')</script>",
        },
        {"severity": "high", "secret": "LOCAL-STORAGE-PASSWORD"},
        {"severity": "UNTRUSTED: PASSWORD-SENTINEL"},
    ]
    response = h.client.get(f"/engagements/{h.session_id}/report", headers=h.auth())
    assert response.status_code == 200
    payload = response.json()
    assert payload["availability"] == "limited_verified_summary"
    assert payload["verified_record_count"] == 3
    assert "Graph-validated records with stored evidence: 3" in payload["markdown"]
    assert "Critical: 1" in payload["markdown"]
    assert "High: 1" in payload["markdown"]
    assert "Unclassified: 1" in payload["markdown"]
    assert "html" not in payload and "body_html" not in payload
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert len(payload["markdown"]) < 3000
    serialized = response.text
    for forbidden in (
        "SECRET", "<script>", "https://untrusted", "signed-roe",
        "LOCAL-STORAGE", "PASSWORD-SENTINEL", "sensitive.example",
    ):
        assert forbidden not in serialized
    query, params = h.graph.calls[0]
    assert "v.engagement_id = $sid" in query
    assert "v.validated = true" in query
    assert "v.evidence IS NOT NULL" in query
    assert "v.severity AS severity" in query
    assert params == {"sid": h.session_id, "limit": 201}


def test_no_verified_data_returns_availability_notice_not_fabricated_findings(report_harness):
    h = report_harness
    response = h.client.get(f"/engagements/{h.session_id}/report", headers=h.auth())
    assert response.status_code == 200
    report = response.json()
    assert report["availability"] == "no_verified_evidence"
    assert report["verified_record_count"] == 0
    assert "NO VERIFIED REPORT DATA" in report["markdown"]
    assert "No findings, risk rating, security clearance" in report["markdown"]
    assert "Critical: 0" not in report["markdown"]


@pytest.mark.parametrize("sub,role,expected", [
    ("mallory", "operator", 403),
    ("alice", "viewer", 403),
    ("alice", "operator", 200),
    ("bob", "senior_operator", 200),
])
def test_report_authorization_scopes_operator_and_senior(
    report_harness, sub, role, expected,
):
    h = report_harness
    response = h.client.get(
        f"/engagements/{h.session_id}/report", headers=h.auth(sub, role),
    )
    assert response.status_code == expected
    if expected != 200:
        assert not h.graph.calls


def test_report_refuses_query_token_and_missing_header(report_harness):
    h = report_harness
    bearer = h.auth()["Authorization"].split(" ", 1)[1]
    assert h.client.get(
        f"/engagements/{h.session_id}/report?token={bearer}",
    ).status_code == 403
    assert h.client.get(
        f"/engagements/{h.session_id}/report?token={bearer}",
        headers=h.auth(),
    ).status_code == 403
    assert h.client.get(f"/engagements/{h.session_id}/report").status_code == 403
    assert not h.graph.calls


def test_cached_owner_cannot_override_revoked_durable_ownership(report_harness):
    h = report_harness
    updated = h.session.model_copy(update={"created_by": "bob"})
    h.memory.load_session_state.return_value = updated
    response = h.client.get(
        f"/engagements/{h.session_id}/report", headers=h.auth(),
    )
    assert response.status_code == 403
    assert not h.graph.calls


def test_failed_durable_session_lookup_never_uses_cached_session(report_harness):
    h = report_harness
    h.memory.load_session_state.side_effect = RuntimeError("DB_PASSWORD_IN_EXCEPTION")
    response = h.client.get(
        f"/engagements/{h.session_id}/report", headers=h.auth(),
    )
    assert response.status_code == 503
    assert "DB_PASSWORD_IN_EXCEPTION" not in response.text
    assert not h.graph.calls


@pytest.mark.parametrize("rows", [
    [{"severity": "critical"}] * 201,
])
def test_report_never_silently_truncates_verified_counts(report_harness, rows):
    h = report_harness
    h.graph.rows = rows
    response = h.client.get(
        f"/engagements/{h.session_id}/report", headers=h.auth(),
    )
    assert response.status_code == 503
    assert "Critical: 200" not in response.text


def test_graph_unavailable_fails_closed_without_exception_detail(report_harness):
    h = report_harness
    h.graph.error = RuntimeError("GRAPH_APIKEY_LEAK_SENTINEL")
    response = h.client.get(
        f"/engagements/{h.session_id}/report", headers=h.auth(),
    )
    assert response.status_code == 503
    assert "GRAPH_APIKEY_LEAK_SENTINEL" not in response.text


@pytest.mark.parametrize("session_id", [
    "report%0AAuthorization%3A%20Bearer%20stolen", "a" * 120, "x%2Fetc",
])
def test_report_rejects_unsafe_engagement_identifiers(report_harness, session_id):
    h = report_harness
    response = h.client.get(
        f"/engagements/{session_id}/report", headers=h.auth(),
    )
    assert response.status_code in {404, 422}
    assert not h.graph.calls
