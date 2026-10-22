"""HTTP authorization and truthful task supervision responses."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers import supervision
from ai_osop.memory.supervision_store import SupervisionConflict, SupervisionStore


@pytest.fixture
def harness(monkeypatch):
    store = SupervisionStore(MagicMock())
    store.assert_access = AsyncMock()
    store.list_events = AsyncMock(return_value=[])
    store.list_events_after = AsyncMock(return_value=[])
    store.list_tasks = AsyncMock(return_value=[])
    store.list_mcp_dispatches = AsyncMock(return_value=[])
    store.get_mcp_dispatch = AsyncMock(
        return_value={
            "server_id": "mock-local",
            "request_id": "req-original",
            "engagement_id": "eng-1",
            "task_id": "task-1",
            "authorization_version": 1,
            "tool_name": "get_status",
            "status": "outcome_unknown",
        }
    )
    store.list_attempts = AsyncMock(return_value=[])
    store.get_control = AsyncMock(return_value=None)
    store.list_controls = AsyncMock(return_value=[])
    store.list_messages = AsyncMock(return_value=[])
    store.append_message = AsyncMock(
        return_value={
            "id": "msg-1",
            "content": "safe instruction",
            "task_id": "task-1",
            "role": "operator",
        }
    )
    store.request_control = AsyncMock(
        return_value={
            "request_id": "req-1",
            "engagement_id": "eng-1",
            "task_id": "task-1",
            "action": "cancel",
            "actor_id": "alice",
            "reason": "Stop task",
            "status": "pending",
            "receipt": None,
            "revision": 0,
        }
    )
    store.load_control = AsyncMock(
        return_value={
            "request_id": "req-1",
            "engagement_id": "eng-1",
            "task_id": "task-1",
            "action": "cancel",
            "actor_id": "alice",
            "reason": "Stop task",
            "status": "unknown",
            "receipt": {"status": "unknown"},
            "revision": 1,
        }
    )
    store.resolve_control = AsyncMock()
    orch = SimpleNamespace(
        session_memory=MagicMock(),
        supervision_store=store,
        request_task_control=AsyncMock(
            return_value={
                "status": "unknown",
                "execution_stopped": False,
            }
        ),
        reconcile_mcp_dispatch=AsyncMock(
            return_value={
                "status": "unknown",
                "persisted_status": "outcome_unknown",
                "request_id": "req-original",
            }
        ),
    )
    monkeypatch.setitem(state, "orchestrator", orch)
    monkeypatch.setattr(
        supervision,
        "assert_engagement_access",
        AsyncMock(return_value=SimpleNamespace()),
    )
    app = FastAPI()
    app.include_router(supervision.router)
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "alice",
        "role": "operator",
    }
    return TestClient(app), app, store, orch


def test_read_timeline_requires_signed_operator_role(harness):
    client, app, store, _ = harness
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "alice",
        "role": "viewer",
    }
    response = client.get("/supervision/engagements/eng-1/events")
    assert response.status_code == 403
    store.list_events.assert_not_awaited()


def test_missing_authentication_cannot_read_messages(harness):
    client, app, store, _ = harness

    async def unauthorized():
        raise HTTPException(status_code=401, detail="Missing token")

    app.dependency_overrides[verify_token] = unauthorized
    response = client.get("/supervision/engagements/eng-1/sessions/chain-1/messages")
    assert response.status_code == 401
    store.list_messages.assert_not_awaited()


def test_persisted_owner_check_prevents_cross_engagement_data_leak(harness):
    client, _, store, _ = harness
    store.assert_access.side_effect = SupervisionConflict("Operator does not own this engagement")
    response = client.get("/supervision/engagements/eng-1/events")
    assert response.status_code == 403
    store.list_events.assert_not_awaited()


def test_model_usage_requires_authorized_owner(harness, monkeypatch):
    client, _, store, _ = harness
    usage = AsyncMock(
        return_value={
            "engagement_id": "eng-1",
            "calls": 1,
            "provider_reported_cost_usd": None,
            "cost_complete": False,
        }
    )
    monkeypatch.setattr(supervision.ModelUsageLedger, "summary", usage)
    result = client.get("/supervision/engagements/eng-1/model-usage")
    assert result.status_code == 200
    assert result.json()["usage"]["cost_complete"] is False
    store.assert_access.assert_awaited_once_with("eng-1", "alice", "operator", None)
    usage.assert_awaited_once_with("eng-1")

    store.assert_access.side_effect = SupervisionConflict("Tenant ownership denied")
    result = client.get("/supervision/engagements/eng-1/model-usage")
    assert result.status_code == 403
    assert usage.await_count == 1


def test_remote_dispatch_inventory_never_bypasses_persisted_ownership(harness):
    client, _, store, _ = harness
    store.list_mcp_dispatches.return_value = [
        {
            "server_id": "mock-local",
            "request_id": "req-original",
            "task_id": "task-1",
            "tool_name": "passive_probe",
            "status": "accepted_unconfirmed",
            "authorization_version": 1,
        }
    ]
    response = client.get("/supervision/engagements/eng-1/mcp-dispatches?task_id=task-1")
    assert response.status_code == 200
    assert response.json()["dispatches"][0]["status"] == "accepted_unconfirmed"
    store.assert_access.assert_awaited_once_with("eng-1", "alice", "operator", "task-1")
    store.list_mcp_dispatches.assert_awaited_once_with("eng-1", "task-1", 100)
    store.assert_access.side_effect = SupervisionConflict("Persisted owner revoked")
    assert (
        client.get("/supervision/engagements/eng-1/mcp-dispatches?task_id=task-1").status_code
        == 403
    )
    assert store.list_mcp_dispatches.await_count == 1


def test_postgres_authorized_remote_reconciliation_does_not_claim_provider_stop(harness):
    client, _, store, orch = harness
    path = "/supervision/engagements/eng-1/tasks/task-1/mcp/reconcile"
    payload = {"server_id": "mock-local", "request_id": "req-original"}
    result = client.post(path, json=payload)
    assert result.status_code == 200
    assert result.json()["status"] == "unknown"
    assert result.json()["persisted_status"] == "outcome_unknown"
    orch.reconcile_mcp_dispatch.assert_awaited_once_with(
        "eng-1", "task-1", "mock-local", "req-original"
    )

    store.get_mcp_dispatch.return_value = None
    assert client.post(path, json=payload).status_code == 404
    assert orch.reconcile_mcp_dispatch.await_count == 1
    store.assert_access.side_effect = SupervisionConflict("Other engagement owner")
    assert client.post(path, json=payload).status_code == 403
    assert orch.reconcile_mcp_dispatch.await_count == 1


def test_cross_engagement_task_rejected_before_commands(harness):
    client, _, store, orch = harness
    store.assert_access.side_effect = SupervisionConflict("Task does not belong to engagement")
    response = client.post(
        "/supervision/engagements/eng-1/tasks/task-other/controls",
        json={"action": "cancel", "reason": "Stop task", "request_id": "req-1"},
    )
    assert response.status_code == 403
    store.request_control.assert_not_awaited()
    orch.request_task_control.assert_not_awaited()


def test_committed_command_precedes_orchestrator_and_reports_unknown(harness):
    client, _, store, orch = harness
    ordering = []

    async def persist(**kwargs):
        ordering.append("commit")
        return {
            "request_id": "req-1",
            "engagement_id": "eng-1",
            "task_id": "task-1",
            "status": "pending",
        }

    async def attempt(**kwargs):
        ordering.append("remote")
        return {"status": "unknown", "execution_stopped": False}

    store.request_control.side_effect = persist
    orch.request_task_control.side_effect = attempt
    response = client.post(
        "/supervision/engagements/eng-1/tasks/task-1/controls",
        json={"action": "stop", "reason": "Stop task", "request_id": "req-1"},
    )
    assert response.status_code == 202
    assert ordering == ["commit", "remote"]
    assert response.json()["control"]["status"] == "unknown"
    assert response.json()["execution_stopped"] is False
    orch.request_task_control.assert_awaited_once_with(
        engagement_id="eng-1",
        task_id="task-1",
        action="cancel",
        request_id="req-1",
    )


def test_missing_runtime_marks_remote_stop_unknown(harness):
    client, _, store, orch = harness
    del orch.request_task_control
    response = client.post(
        "/supervision/engagements/eng-1/tasks/task-1/controls",
        json={"action": "cancel", "reason": "Stop task", "request_id": "req-1"},
    )
    assert response.status_code == 202
    store.resolve_control.assert_awaited_once()
    assert store.resolve_control.await_args.args[:2] == ("req-1", "unknown")
    assert response.json()["execution_stopped"] is False


def test_invalid_resume_never_dispatches(harness):
    client, _, store, orch = harness
    response = client.post(
        "/supervision/engagements/eng-1/tasks/task-1/controls",
        json={"action": "override", "reason": "skip gates", "request_id": "req-x"},
    )
    assert response.status_code == 422
    store.request_control.assert_not_awaited()
    orch.request_task_control.assert_not_awaited()


def test_human_input_is_queued_with_verified_identity(harness):
    client, _, store, _ = harness
    response = client.post(
        "/supervision/engagements/eng-1/sessions/chain-1/messages",
        json={
            "task_id": "task-1",
            "content": "Check the status first",
            "request_id": "msg-request",
        },
    )
    assert response.status_code == 202
    assert response.json()["delivery_status"] == "pending"
    store.append_message.assert_awaited_once_with(
        engagement_id="eng-1",
        session_id="chain-1",
        task_id="task-1",
        role="operator",
        actor_id="alice",
        actor_role="operator",
        content="Check the status first",
        idempotency_key="msg-request",
    )


def test_task_attempts_and_messages_are_always_engagement_scoped(harness):
    client, _, store, _ = harness
    assert client.get("/supervision/engagements/eng-1/tasks/task-1/attempts").json() == {
        "attempts": []
    }
    store.assert_access.assert_awaited_with("eng-1", "alice", "operator", "task-1")
    assert client.get("/supervision/engagements/eng-1/sessions/chain-1/messages").json() == {
        "messages": []
    }
    store.list_messages.assert_awaited_with("eng-1", "chain-1", 100)


def test_timeline_cursor_uses_strictly_after_sequence(harness):
    client, _, store, _ = harness
    response = client.get("/supervision/engagements/eng-1/events?after_sequence=19&task_id=task-1")
    assert response.status_code == 200
    store.list_events_after.assert_awaited_once_with("eng-1", 19, "task-1", 100)
    store.list_events.assert_not_awaited()


def test_authenticated_persisted_task_discovery_omits_raw_payload(harness):
    client, _, store, _ = harness
    store.list_tasks.return_value = [
        {
            "task_id": "task-1",
            "task_type": "recon",
            "status": "running",
            "retry_count": 0,
            "max_retries": 3,
            "assigned_agent_id": "agent-a",
        }
    ]
    response = client.get("/supervision/engagements/eng-1/tasks")
    assert response.status_code == 200
    assert response.json()["tasks"][0]["task_id"] == "task-1"
    assert "payload" not in response.text
    store.list_tasks.assert_awaited_once_with("eng-1", 100)


def test_terminal_callback_receipts_require_authenticated_owner(harness, monkeypatch):
    from ai_osop.memory.terminal_lifecycle import TerminalLifecycleStore

    client, _, store, _ = harness
    read_callbacks = AsyncMock(
        return_value=[
            {
                "id": "cb-1",
                "engagement_id": "eng-1",
                "task_id": "task-1",
                "attempt_id": "run-1",
                "status": "unknown",
                "outcome": "succeeded",
                "receipt": {"result_code": "agent_completed"},
            }
        ]
    )
    monkeypatch.setattr(TerminalLifecycleStore, "list_callbacks", read_callbacks)
    response = client.get("/supervision/engagements/eng-1/tasks/task-1/terminal-callbacks")
    assert response.status_code == 200
    assert response.json()["callbacks"][0]["status"] == "unknown"
    assert response.json()["callbacks"][0]["outcome"] == "succeeded"
    read_callbacks.assert_awaited_once_with("eng-1", "task-1", 100)
    store.assert_access.assert_awaited_with("eng-1", "alice", "operator", "task-1")

    read_callbacks.reset_mock()
    store.assert_access.side_effect = SupervisionConflict("Operator does not own this engagement")
    denied = client.get("/supervision/engagements/eng-1/tasks/task-1/terminal-callbacks")
    assert denied.status_code == 403
    read_callbacks.assert_not_awaited()


def test_terminal_callback_receipts_reject_viewer(harness, monkeypatch):
    from ai_osop.memory.terminal_lifecycle import TerminalLifecycleStore

    client, app, store, _ = harness
    read_callbacks = AsyncMock(return_value=[])
    monkeypatch.setattr(TerminalLifecycleStore, "list_callbacks", read_callbacks)
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "viewer",
        "role": "viewer",
    }
    denied = client.get("/supervision/engagements/eng-1/tasks/task-1/terminal-callbacks")
    assert denied.status_code == 403
    read_callbacks.assert_not_awaited()
    store.assert_access.assert_not_awaited()


@pytest.mark.asyncio
async def test_sse_frames_include_resume_cursor_and_filter(monkeypatch, harness):
    _, _, store, _ = harness
    store.list_events_after.return_value = [
        {
            "id": "evt-1",
            "sequence": 41,
            "engagement_id": "eng-1",
            "task_id": "task-1",
            "kind": "agent.message.consumed",
            "actor_id": "agent-a",
            "payload": {"status": "consumed"},
            "created_at": "2026-10-14T01:00:00",
        }
    ]
    revalidate = AsyncMock(return_value=store)
    monkeypatch.setattr(supervision, "_stream_revalidate", revalidate)

    class FakeRequest:
        headers = {"authorization": "Bearer test-only"}

        async def is_disconnected(self):
            return False

    response = await supervision.stream_events(
        "eng-1",
        FakeRequest(),
        40,
        "task-1",
        {"sub": "alice", "role": "operator"},
    )
    stream = response.body_iterator
    frame = await anext(stream)
    await stream.aclose()
    assert frame.startswith("id: 41\nevent: supervision\ndata: ")
    assert '"sequence":41' in frame
    store.list_events_after.assert_awaited_once_with("eng-1", 40, "task-1", 100)
    # Admission, committed batch SELECT, then a fresh revocation check
    # immediately before emitting this individual event.
    assert revalidate.await_count == 4
