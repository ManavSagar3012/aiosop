"""Senior source discovery is PostgreSQL-derived, bounded and secret-free."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.deps import state
from ai_osop.api.routers import findings
from ai_osop.auth.session_store import SessionStore
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState
from ai_osop.memory.session_memory import SessionMemory


class Result:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class DB:
    def __init__(self, rows):
        self.rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def execute(self, stmt):
        return Result(self.rows)


def setup(monkeypatch, *, rows=None, active=True):
    rows = rows if rows is not None else [SimpleNamespace(
        id="task-source-1", flow_id=None, engagement_id="eng-owned",
        payload={"_authorization_version": 4, "url": "https://authorized.example/",
                 "user_label": "source-a", "private_cookie": "SHOULD_NOT_LEAK"},
        result={"workflow_id": "wf-owned", "status": "workflow_recorded",
                "request": "SECRET_REQUEST"},
    )]
    memory = SessionMemory.__new__(SessionMemory)
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=4))
    memory.load_flow = AsyncMock(return_value=FlowRecord(
        id="flow-owned", engagement_id="eng-owned", revision=8,
        objective="Senior signed research", status="running" if active else "paused",
    ))
    memory.load_session_state = AsyncMock(return_value=SessionState(
        session_id="eng-owned", phase="reconnaissance",
        scope=ScopeDefinition(engagement_id="eng-owned", domains=["authorized.example"],
                              authorization_ref="signed-roe"),
    ))
    memory._async_session = lambda: DB(rows)
    store = SessionStore.__new__(SessionStore)
    store.list_sessions = AsyncMock(return_value=[
        SimpleNamespace(engagement_id="eng-owned", user_label="source-a",
                        cookies=[{"name": "s"}], local_storage={},
                        is_expired=lambda **_: False),
        SimpleNamespace(engagement_id="eng-owned", user_label="target-b",
                        cookies=[{"name": "t"}], local_storage={},
                        is_expired=lambda **_: False),
        SimpleNamespace(engagement_id="eng-other", user_label="foreign",
                        cookies=[{"name": "f"}], local_storage={},
                        is_expired=lambda **_: False),
    ])
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(
        session_memory=memory, session_store=store,
    ))
    monkeypatch.setattr(findings, "assert_engagement_access", AsyncMock())
    return memory, store


@pytest.mark.asyncio
async def test_owner_senior_can_list_original_pg_source_ids_without_secrets(monkeypatch):
    memory, store = setup(monkeypatch)
    record = await findings.list_signed_replay_sources(
        "eng-owned", "flow-owned", operator={"role": "senior_operator"}
    )
    assert record == {
        "flow_id": "flow-owned", "flow_revision": 8, "authorization_version": 4,
        "sources": [{"source_task_id": "task-source-1",
                     "workflow_id": "wf-owned", "source_user_label": "source-a"}],
        "identities": ["source-a", "target-b"],
    }
    assert "SHOULD_NOT_LEAK" not in str(record)
    assert "SECRET_REQUEST" not in str(record)
    assert store.list_sessions.await_count == 1
    assert memory.assert_signed_authorization.await_count == 2


@pytest.mark.asyncio
async def test_source_list_refuses_expired_or_closed_signed_flow(monkeypatch):
    memory, _ = setup(monkeypatch, active=False)
    with pytest.raises(HTTPException) as error:
        await findings.list_signed_replay_sources(
            "eng-owned", "flow-owned", operator={"role": "senior_operator"}
        )
    assert error.value.status_code == 409
    memory.assert_signed_authorization.assert_awaited_once()


@pytest.mark.asyncio
async def test_sources_with_foreign_scope_or_stale_signer_are_not_exposed(monkeypatch):
    foreign = SimpleNamespace(
        id="task-foreign", flow_id=None, engagement_id="eng-owned",
        payload={"_authorization_version": 3, "url": "https://foreign.example/",
                 "user_label": "source-a"},
        result={"workflow_id": "wf-foreign", "status": "workflow_recorded"},
    )
    setup(monkeypatch, rows=[foreign])
    record = await findings.list_signed_replay_sources(
        "eng-owned", "flow-owned", operator={"role": "senior_operator"}
    )
    assert record["sources"] == []
    assert record["identities"] == ["source-a", "target-b"]
