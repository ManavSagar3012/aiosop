"""Actual senior comparison API reads original PG Tasks, never sends HTTP."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.deps import state
from ai_osop.api.routers import findings
from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.core.signed_replay_comparison import persist_verified_replay_comparison
from tests.test_signed_replay_comparison import pair


class Graph:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def run(self, statement, params):
        assert "HAS_STEP" in statement and "TARGETS_ENDPOINT" in statement
        assert params == {"wid": "wf-owned", "eid": "eng-owned", "sid": "step-owned"}

        async def rows():
            yield {
                "role": "alice",
                "method": "GET",
                "url": "https://authorized.test/account",
            }

        return rows()


def setup(monkeypatch):
    a, b = pair()
    source = Task(
        id="task-original",
        type="map_workflow",
        agent_type=AgentType.WORKFLOW,
        engagement_id="eng-owned",
        status="completed",
        payload={
            "_authorization_version": 7,
            "user_label": "alice",
            "url": "https://authorized.test/original",
        },
        result={"status": "workflow_recorded", "workflow_id": "wf-owned"},
    )
    parent = Task(
        id="task-parent",
        type="replay_for_diff_auth",
        agent_type=AgentType.WORKFLOW,
        engagement_id="eng-owned",
        status="completed",
        flow_id="flow-owned",
        parent_task_id="task-original",
        approval_required=True,
        payload={
            "_authorization_version": 7,
            "_flow_revision": 3,
            "workflow_id": "wf-owned",
            "source_user_label": "alice",
            "target_user_label": "bob",
            "operator_approved": True,
            "approval_id": "apr-parent",
        },
    )
    tasks = {t.id: t for t in (source, parent, a, b)}
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock(side_effect=lambda task_id: tasks.get(task_id))
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=7))
    memory.is_task_approved = AsyncMock(return_value=True)
    memory.load_flow = AsyncMock(
        return_value=FlowRecord(
            id="flow-owned",
            engagement_id="eng-owned",
            status="running",
            revision=3,
            objective="Operator-confirmed objective",
        )
    )
    memory.load_session_state = AsyncMock(
        return_value=SessionState(
            session_id="eng-owned",
            phase="reconnaissance",
            scope=ScopeDefinition(
                engagement_id="eng-owned",
                domains=["authorized.test"],
                authorization_ref="signed-original",
            ),
        )
    )
    identities = SimpleNamespace(
        get_session_authoritative=AsyncMock(
            side_effect=lambda engagement, label: SimpleNamespace(
                engagement_id=engagement,
                user_label=label,
                is_expired=lambda **_: False,
                cookies=[{"name": "session"}],
                local_storage={},
            )
        )
    )
    orch = SimpleNamespace(
        session_memory=memory,
        session_store=identities,
        graph_memory=SimpleNamespace(_driver=SimpleNamespace(session=lambda: Graph())),
        supervision_store=SimpleNamespace(),
    )
    monkeypatch.setitem(state, "orchestrator", orch)
    monkeypatch.setattr(findings, "assert_engagement_access", AsyncMock())
    monkeypatch.setattr(
        "ai_osop.memory.graph_research_projection.verify_signed_action_event",
        AsyncMock(return_value=True),
    )
    return orch, tasks


async def query():
    return await findings.read_signed_replay_comparison(
        "eng-owned",
        "wf-owned",
        "flow-owned",
        "task-parent",
        "step-owned",
        operator={"role": "senior_operator"},
    )


@pytest.mark.asyncio
async def test_actual_senior_api_returns_redacted_candidate_never_a_finding(monkeypatch):
    orch, _ = setup(monkeypatch)
    result = await query()
    assert result["status"] == "candidate_needs_independent_review"
    assert result["findings_count"] == 0
    assert result["authorization_violation_verified"] is False
    assert result["source_authenticity_verified"] is False
    assert "alice" not in str(result) and "bob" not in str(result)
    assert "authorized.test" not in str(result)
    assert orch.session_memory.assert_signed_authorization.await_count == 2


@pytest.mark.asyncio
async def test_missing_peer_is_inconclusive_and_requires_no_remote_execution(monkeypatch):
    _, tasks = setup(monkeypatch)
    target_id = next(
        t.id for t in tasks.values() if t.type == "navigate" and t.payload["user_label"] == "bob"
    )
    del tasks[target_id]
    result = await query()
    assert result["status"] == "inconclusive"
    assert result["findings_count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("denial", ["revoked", "stale_flow", "missing_provider", "foreign_source"])
async def test_api_denies_forged_or_stale_signed_comparison(monkeypatch, denial):
    orch, tasks = setup(monkeypatch)
    if denial == "revoked":
        orch.session_memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    elif denial == "stale_flow":
        orch.session_memory.load_flow.return_value.revision = 4
    elif denial == "missing_provider":
        monkeypatch.setattr(
            "ai_osop.memory.graph_research_projection.verify_signed_action_event",
            AsyncMock(return_value=False),
        )
    elif denial == "foreign_source":
        tasks["task-original"].engagement_id = "eng-foreign"
    with pytest.raises(HTTPException) as error:
        await query()
    assert error.value.status_code in {409, 503}


@pytest.mark.asyncio
async def test_real_terminal_comparison_consumer_persists_only_redacted_pg_action(monkeypatch):
    orch, tasks = setup(monkeypatch)
    memory = orch.session_memory
    memory.record_action = AsyncMock()
    terminal = next(
        t for t in tasks.values() if t.type == "navigate" and t.payload["user_label"] == "bob"
    )
    assert await persist_verified_replay_comparison(
        memory=memory,
        supervision=orch.supervision_store,
        graph=orch.graph_memory,
        engagement_id="eng-owned",
        terminal_task_id=terminal.id,
    )
    record = memory.record_action.await_args.args[0]
    assert record.tool_name == "signed_diff_auth_compare"
    assert record.outcome == "candidate_review"
    assert record.engagement_id == "eng-owned"
    assert record.flow_id == "flow-owned"
    assert record.task_id == "task-parent"
    assert record.safe_metadata["source_task_id"] == "task-original"
    assert record.safe_metadata["comparison_sha256"]
    assert "alice" not in str(record) and "bob" not in str(record)
    assert "authorized.test" not in str(record)
    assert await persist_verified_replay_comparison(
        memory=memory,
        supervision=orch.supervision_store,
        graph=orch.graph_memory,
        engagement_id="eng-owned",
        terminal_task_id=terminal.id,
    )
    # Durable SessionMemory.record_action inserts ON CONFLICT DO NOTHING for
    # this exact deterministic comparison identity, rather than a new action.
    assert memory.record_action.await_count == 2
    assert memory.record_action.await_args.args[0].id == record.id


@pytest.mark.asyncio
async def test_terminal_comparison_waits_for_both_committed_receipts(monkeypatch):
    orch, tasks = setup(monkeypatch)
    memory = orch.session_memory
    memory.record_action = AsyncMock()
    target = next(
        t for t in tasks.values() if t.type == "navigate" and t.payload["user_label"] == "bob"
    )
    tasks.pop(target.id)
    assert (
        await persist_verified_replay_comparison(
            memory=memory,
            supervision=orch.supervision_store,
            graph=orch.graph_memory,
            engagement_id="eng-owned",
            terminal_task_id=next(t.id for t in tasks.values() if t.type == "navigate"),
        )
        is False
    )
    memory.record_action.assert_not_awaited()
    tasks[target.id] = target
    assert await persist_verified_replay_comparison(
        memory=memory,
        supervision=orch.supervision_store,
        graph=orch.graph_memory,
        engagement_id="eng-owned",
        terminal_task_id=target.id,
    )
    memory.record_action.assert_awaited_once()


@pytest.mark.asyncio
async def test_revocation_between_pair_validation_and_pg_receipt_denies_promotion(monkeypatch):
    orch, tasks = setup(monkeypatch)
    memory = orch.session_memory
    memory.record_action = AsyncMock()
    memory.assert_signed_authorization.side_effect = [
        SimpleNamespace(version=7),
        PermissionError("signed ROE revoked"),
    ]
    terminal = next(
        t for t in tasks.values() if t.type == "navigate" and t.payload["user_label"] == "bob"
    )
    with pytest.raises(PermissionError):
        await persist_verified_replay_comparison(
            memory=memory,
            supervision=orch.supervision_store,
            graph=orch.graph_memory,
            engagement_id="eng-owned",
            terminal_task_id=terminal.id,
        )
    memory.record_action.assert_not_awaited()
