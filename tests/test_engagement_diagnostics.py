"""Exercise diagnostics provenance, ownership and sensitive-data boundaries."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers.diagnostics import router
from ai_osop.core.config import AgentType
from ai_osop.core.models import AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.observability.engagement_diagnostics import build_engagement_diagnostics


def _session(session_id: str, owner: str) -> SessionState:
    return SessionState(
        session_id=session_id,
        scope=ScopeDefinition(engagement_id=session_id, domains=["example.com"]),
        phase="vulnerability_discovery",
        created_by=owner,
    )


def _event(engagement_id: str = "eng-one") -> AuditEvent:
    return AuditEvent(
        event_id="evt-example",
        timestamp=datetime(2026, 10, 12, 12, 15, tzinfo=timezone.utc),
        event_type="task_retry",
        severity="warning",
        actor_type="system",
        actor_id="orchestrator",
        action={"task_id": "task-123", "password": "never-return-this-secret"},
        result={"token": "never-return-this-token"},
        context={"authorization": "never-return-this-header"},
        integrity_hash="digest-test",
        engagement_id=engagement_id,
    )


@pytest.fixture
def diagnostics_client():
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[verify_token] = lambda: {"sub": "alice", "role": "operator"}
    store = SimpleNamespace(query_audit_log=AsyncMock(return_value=[_event()]))
    orch = SimpleNamespace(
        _sessions={"eng-one": _session("eng-one", "alice"), "eng-two": _session("eng-two", "bob")},
        _tasks={},
        session_memory=store,
    )
    old_orch = state.get("orchestrator")
    state["orchestrator"] = orch
    with TestClient(app) as client:
        yield client, app, orch, store
    state["orchestrator"] = old_orch


def test_diagnostics_returns_owned_recent_events_without_payloads(diagnostics_client) -> None:
    client, _, orch, store = diagnostics_client
    now = datetime.utcnow()
    task = Task(
        id="task-123",
        type="recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-one",
        status="running",
        retry_count=2,
        max_retries=3,
        started_at=now - timedelta(minutes=10),
        timeout_seconds=60,
        payload={"password": "never-return-payload"},
        result={"access_token": "never-return-result"},
    )
    foreign_task = task.model_copy(update={"id": "task-other", "engagement_id": "eng-two"})
    orch._tasks = {task.id: task, foreign_task.id: foreign_task}

    response = client.get("/engagements/eng-one/diagnostics?limit=5")

    assert response.status_code == 200
    data = response.json()
    assert data["phase"] == "vulnerability_discovery"
    assert data["tasks"]["status_counts"] == {"running": 1}
    assert data["tasks"]["retried"] == 1
    assert data["tasks"]["overdue_running"] == 1
    assert data["tasks"]["items"][0]["task_id"] == "task-123"
    assert data["audit"]["events"][0]["task_id"] == "task-123"
    assert data["audit"]["events"][0]["integrity_hash"] == "digest-test"
    assert "never-return" not in response.text
    assert "task-other" not in response.text
    store.query_audit_log.assert_awaited_once_with("eng-one", limit=5)


def test_diagnostics_rejects_unauthorized_engagement_before_read(diagnostics_client) -> None:
    client, _, _, store = diagnostics_client

    response = client.get("/engagements/eng-two/diagnostics")

    assert response.status_code == 403
    store.query_audit_log.assert_not_awaited()


def test_diagnostics_missing_engagement_and_invalid_limits(diagnostics_client) -> None:
    client, _, _, store = diagnostics_client
    assert client.get("/engagements/missing/diagnostics").status_code == 404
    assert client.get("/engagements/eng-one/diagnostics?limit=0").status_code == 422
    assert client.get("/engagements/eng-one/diagnostics?limit=201").status_code == 422
    store.query_audit_log.assert_not_awaited()


def test_diagnostics_allows_senior_operator(diagnostics_client) -> None:
    client, app, _, store = diagnostics_client
    app.dependency_overrides[verify_token] = lambda: {"sub": "admin", "role": "senior_operator"}

    response = client.get("/engagements/eng-two/diagnostics")

    assert response.status_code == 200
    assert response.json()["engagement_id"] == "eng-two"
    store.query_audit_log.assert_awaited_once_with("eng-two", limit=50)


def test_diagnostics_requires_valid_auth(diagnostics_client) -> None:
    client, app, _, store = diagnostics_client

    def unauthorized() -> None:
        raise HTTPException(status_code=401, detail="Invalid token")

    app.dependency_overrides[verify_token] = unauthorized
    assert client.get("/engagements/eng-one/diagnostics").status_code == 401
    store.query_audit_log.assert_not_awaited()


def test_diagnostics_degrades_when_audit_database_is_unavailable(diagnostics_client) -> None:
    client, _, _, store = diagnostics_client
    store.query_audit_log.side_effect = RuntimeError("internal database credential")

    response = client.get("/engagements/eng-one/diagnostics")

    assert response.status_code == 200
    assert response.json()["audit"]["available"] is False
    assert response.json()["audit"]["events"] == []
    assert "internal database credential" not in response.text


def test_formatter_caps_tasks_and_filters_foreign_audit_events() -> None:
    tasks = [
        Task(id=f"task-{n}", type="recon", agent_type=AgentType.RECON, engagement_id="eng-one")
        for n in range(4)
    ]
    event = _event()
    foreign_event = _event("eng-two")
    result = build_engagement_diagnostics(
        "eng-one",
        "reconnaissance",
        tasks,
        [foreign_event, event],
        event_limit=1,
        task_limit=2,
    )
    assert result["tasks"]["total"] == 4
    assert result["tasks"]["truncated"] is True
    assert len(result["tasks"]["items"]) == 2
    assert result["audit"]["events_returned"] == 1
    assert result["audit"]["events"][0]["event_id"] == event.event_id
