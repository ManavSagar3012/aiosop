"""A senior replay request is not a second human execution approval."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.deps import state
from ai_osop.api.routers import findings
from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory


class GraphSession:
    def __init__(self, found=True):
        self.run = AsyncMock(
            return_value=SimpleNamespace(
                single=AsyncMock(return_value={"id": "wf-owned"} if found else None)
            )
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass


def setup(monkeypatch, *, found=True, source=True, target=True):
    memory = SessionMemory.__new__(SessionMemory)
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=4))
    memory.load_session_state = AsyncMock(
        return_value=SessionState(
            session_id="eng-owned",
            phase="reconnaissance",
            scope=ScopeDefinition(
                engagement_id="eng-owned",
                domains=["authorized.example"],
                authorization_ref="signed-ref",
            ),
        )
    )
    memory.load_flow = AsyncMock(
        return_value=FlowRecord(
            id="flow-owned",
            engagement_id="eng-owned",
            objective="Confirmed security research",
            status="running",
            revision=2,
        )
    )
    memory.list_flow_tasks = AsyncMock(
        return_value=[
            Task(
                type="flow_objective",
                agent_type=AgentType.RECON,
                engagement_id="eng-owned",
                flow_id="flow-owned",
                status="planned",
                payload={"title": "Authorized replay"},
            )
        ]
    )
    memory.load_task_authoritative = AsyncMock(
        return_value=Task(
            id="task-source-1",
            type="map_workflow",
            agent_type=AgentType.WORKFLOW,
            engagement_id="eng-owned",
            status="completed",
            payload={
                "_authorization_version": 4,
                "user_label": "owner-a",
                "url": "https://authorized.example/",
            },
            result={"workflow_id": "wf-owned", "status": "success"},
        )
    )

    # Point reads are authoritative: a missing proposal TaskORM cannot
    # materialize as the original source Task for an unrelated ID.
    async def load_task(identifier):
        if identifier == "task-source-1":
            return memory.load_task_authoritative.return_value
        return None

    memory.load_task_authoritative.side_effect = load_task
    graph = GraphSession(found=found)

    async def lookup(eid, label):
        allowed = source if label == "owner-a" else target
        if not allowed:
            return None
        return SimpleNamespace(
            engagement_id=eid,
            user_label=label,
            cookies=[{"name": "session"}],
            local_storage={},
            bearer_token="",
            is_expired=lambda **_: False,
        )

    orch = SimpleNamespace(
        session_memory=memory,
        session_store=SimpleNamespace(get_session_authoritative=AsyncMock(side_effect=lookup)),
        graph_memory=SimpleNamespace(_driver=SimpleNamespace(session=lambda: graph)),
        schedule_task=AsyncMock(),
    )
    monkeypatch.setitem(state, "orchestrator", orch)
    monkeypatch.setattr(findings, "assert_engagement_access", AsyncMock())
    return orch, graph


def request(**override):
    return findings.ReplayWorkflowRequest(
        **{
            "source_user_label": "owner-a",
            "target_user_label": "target-b",
            "expected_authorization_version": 4,
            "flow_id": "flow-owned",
            "source_task_id": "task-source-1",
            "expected_flow_revision": 2,
            **override,
        }
    )


@pytest.mark.asyncio
async def test_owned_signed_replay_is_only_a_new_approval_required_task(monkeypatch):
    orch, graph = setup(monkeypatch)
    result = await findings.replay_workflow(
        "eng-owned", "wf-owned", request(), operator={"role": "senior_operator"}
    )
    task = orch.schedule_task.await_args.args[0]
    assert task.type == "replay_for_diff_auth"
    assert task.id.startswith("task-") and len(task.id) == 37
    assert task.approval_required is True
    assert task.flow_id == "flow-owned"
    assert task.parent_task_id == "task-source-1"
    assert task.payload == {
        "workflow_id": "wf-owned",
        "source_user_label": "owner-a",
        "target_user_label": "target-b",
        "_authorization_version": 4,
        "_flow_revision": 2,
    }
    assert result == {
        "status": "awaiting_execution_approval",
        "task_id": task.id,
        "workflow_id": "wf-owned",
        "execution_started": False,
    }
    assert orch.session_memory.assert_signed_authorization.await_count == 2
    assert graph.run.await_args.args[1] == {"wid": "wf-owned", "eid": "eng-owned"}


@pytest.mark.asyncio
async def test_identical_replay_review_uses_same_id_and_existing_task_refuses_retry(monkeypatch):
    orch, _ = setup(monkeypatch)
    initial = await findings.replay_workflow(
        "eng-owned", "wf-owned", request(), operator={"role": "senior_operator"}
    )
    first_task = orch.schedule_task.await_args.args[0]
    # A lost HTTP response or a new UI mount must not manufacture another
    # authorization proposal for the same immutable signed review tuple.
    again = await findings.replay_workflow(
        "eng-owned", "wf-owned", request(), operator={"role": "senior_operator"}
    )
    assert again["task_id"] == initial["task_id"] == first_task.id
    assert orch.schedule_task.await_count == 2  # stubbed scheduling, not DB
    real_source = orch.session_memory.load_task_authoritative.return_value

    async def persisted(identifier):
        return real_source if identifier == real_source.id else first_task

    orch.session_memory.load_task_authoritative.side_effect = persisted
    orch.schedule_task.reset_mock()
    with pytest.raises(HTTPException) as conflict:
        await findings.replay_workflow(
            "eng-owned", "wf-owned", request(), operator={"role": "senior_operator"}
        )
    assert conflict.value.status_code == 409
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_new_human_flow_revision_changes_signed_replay_proposal_id(monkeypatch):
    orch, _ = setup(monkeypatch)
    initial = await findings.replay_workflow(
        "eng-owned", "wf-owned", request(), operator={"role": "senior_operator"}
    )
    orch.session_memory.load_flow.return_value.revision = 3
    new = await findings.replay_workflow(
        "eng-owned",
        "wf-owned",
        request(expected_flow_revision=3),
        operator={"role": "senior_operator"},
    )
    assert initial["task_id"] != new["task_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario, expected",
    [
        ("same_identity", 422),
        ("invalid_workflow", 422),
        ("missing_source", 409),
        ("missing_target", 409),
        ("cross_tenant_workflow", 404),
        ("revoked", 503),
        ("inactive", 409),
        ("schedule_conflict", 409),
        ("no_objective", 409),
        ("foreign_source", 409),
        ("paused_flow", 409),
    ],
)
async def test_unsafe_replay_proposal_never_admits_task(monkeypatch, scenario, expected):
    orch, _ = setup(
        monkeypatch,
        found=scenario != "cross_tenant_workflow",
        source=scenario != "missing_source",
        target=scenario != "missing_target",
    )
    if scenario == "revoked":
        orch.session_memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    if scenario == "inactive":
        session = await orch.session_memory.load_session_state("eng-owned")
        session.phase = "halted"
        orch.session_memory.load_session_state.return_value = session
    if scenario == "schedule_conflict":
        orch.schedule_task.side_effect = RuntimeError("SQL conflict")
    if scenario == "no_objective":
        orch.session_memory.list_flow_tasks.return_value = []
    if scenario == "foreign_source":
        orch.session_memory.load_task_authoritative.return_value.engagement_id = "eng-foreign"
    if scenario == "paused_flow":
        orch.session_memory.load_flow.return_value.status = "paused"
    candidate = request(target_user_label="owner-a") if scenario == "same_identity" else request()
    wid = "https://foreign.example/" if scenario == "invalid_workflow" else "wf-owned"
    with pytest.raises(HTTPException) as error:
        await findings.replay_workflow(
            "eng-owned", wid, candidate, operator={"role": "senior_operator"}
        )
    assert error.value.status_code == expected
    if scenario != "schedule_conflict":
        orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_roe_replaced_during_graph_read_blocks_replay(monkeypatch):
    orch, _ = setup(monkeypatch)
    orch.session_memory.assert_signed_authorization.side_effect = [
        SimpleNamespace(version=4),
        PermissionError("rotated"),
    ]
    with pytest.raises(HTTPException) as error:
        await findings.replay_workflow(
            "eng-owned",
            "wf-owned",
            request(),
            operator={"role": "senior_operator"},
        )
    assert error.value.status_code == 503
    orch.schedule_task.assert_not_awaited()
