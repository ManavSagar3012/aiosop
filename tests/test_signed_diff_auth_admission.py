"""Signed differential replay: no unapproved direct browser execution.

Models the existing PostgreSQL-first scheduler contract deterministically;
does not touch the application database, browser provider or remote target.
"""

import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory


SID = "eng-diff-1"
WID = "wf-diff-1"
FLOW = "flow-diff-1"
PARENT = "task-diff-parent-1"
SOURCE = "task-diff-source-1"
VER = 3


class AsyncRows:
    def __init__(self, rows):
        self.rows = rows

    def __aiter__(self):
        async def generate():
            for row in self.rows:
                yield dict(row)

        return generate()


class GraphSession:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def run(self, cypher, params):
        self.statements.append((cypher, params))
        return AsyncRows(self.rows)


@pytest.fixture
def admitted(monkeypatch):
    source = Task(
        id=SOURCE,
        engagement_id=SID,
        type="map_workflow",
        agent_type=AgentType.WORKFLOW,
        status="completed",
        payload={
            "_authorization_version": VER,
            "user_label": "user_a",
            "url": "https://example.test/home",
        },
        result={"status": "workflow_recorded", "workflow_id": WID},
    )
    parent = Task(
        id=PARENT,
        engagement_id=SID,
        type="replay_for_diff_auth",
        agent_type=AgentType.WORKFLOW,
        flow_id=FLOW,
        parent_task_id=SOURCE,
        status="running",
        approval_required=True,
        payload={
            "workflow_id": WID,
            "target_user_label": "user_b",
            "source_user_label": "user_a",
            "_authorization_version": VER,
            "operator_approved": True,
            "_flow_revision": 1,
            "approval_id": "apr-parent-diff-1",
        },
    )
    tasks = {parent.id: parent.model_copy(deep=True), source.id: source.model_copy(deep=True)}
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock(side_effect=lambda tid: tasks.get(tid))
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=VER))
    memory.load_flow = AsyncMock(
        return_value=FlowRecord(
            id=FLOW,
            engagement_id=SID,
            objective="Approved read-only differential replay",
            status="running",
            revision=1,
        )
    )
    memory.load_session_state = AsyncMock(
        return_value=SessionState(
            session_id=SID,
            phase="reconnaissance",
            scope=ScopeDefinition(
                engagement_id=SID,
                domains=["example.test"],
                authorization_ref="signed-roe",
            ),
        )
    )
    memory.is_task_approved = AsyncMock(return_value=True)
    rows = [
        {
            "source_role": "user_a",
            "step_id": "step-diff-1",
            "step_order": 0,
            "action_type": "GET",
            "endpoint_id": "ep-diff-1",
            "method": "GET",
            "url": "https://example.test/api/private",
        }
    ]
    graph = GraphSession(rows)

    async def schedule(task):
        if task.id not in tasks:
            raise RuntimeError("signed TaskORM must precede queue delivery")
        return task

    async def admit_pair(parent_task, children):
        assert parent_task.id == PARENT
        assert len(children) == 2
        present = [child for child in children if child.id in tasks]
        if len(present) == 1:
            raise PermissionError("partial legacy pair requires review")
        if present:
            for child in children:
                prior = tasks[child.id]
                assert prior.payload == child.payload
            return []
        tasks.update({child.id: child.model_copy(deep=True) for child in children})
        return [child.id for child in children]

    memory.admit_signed_replay_observation_pair = AsyncMock(side_effect=admit_pair)

    scheduler = SimpleNamespace(
        session_memory=memory,
        graph_memory=SimpleNamespace(
            _driver=SimpleNamespace(session=lambda: graph),
        ),
        schedule_task=AsyncMock(side_effect=schedule),
        _execute_task_durable=AsyncMock(side_effect=AssertionError("unsafe direct execution")),
    )
    userstore = SimpleNamespace(
        get_session_authoritative=AsyncMock(
            side_effect=lambda eid, label: SimpleNamespace(
                engagement_id=eid,
                user_label=label,
                is_expired=lambda: False,
            )
        )
    )
    monkeypatch.setattr(
        "ai_osop.auth.session_store.SessionStore",
        lambda *_: userstore,
    )
    return SimpleNamespace(
        parent=parent,
        source=source,
        memory=memory,
        engine=DifferentialAuthEngine(memory),
        tasks=tasks,
        graph=graph,
        rows=rows,
        scheduler=scheduler,
        users=userstore,
    )


async def _run(fx, **overrides):
    defaults = {
        "workflow_id": WID,
        "test_identities": ["user_b"],
        "engagement_id": SID,
        "orchestrator": fx.scheduler,
        "parent_task": fx.parent,
        "source_user_label": "user_a",
    }
    defaults.update(overrides)
    return await fx.engine.run_differential_test(**defaults)


@pytest.mark.asyncio
async def test_signed_replay_queues_two_separately_approved_durable_get_observations(admitted):
    fx = admitted
    result = await _run(fx)
    assert result["status"] == "pending_execution_approval"
    assert result["findings"] == [] and result["findings_count"] == 0
    assert len(result["queued_task_ids"]) == 2
    assert {fx.tasks[ident].payload["_comparison_role"] for ident in result["queued_task_ids"]} == {
        "source",
        "target",
    }
    assert {fx.tasks[ident].payload["user_label"] for ident in result["queued_task_ids"]} == {
        "user_a",
        "user_b",
    }
    for ident in result["queued_task_ids"]:
        task = fx.tasks[ident]
        assert task.approval_required is True
        assert "operator_approved" not in task.payload
        assert "approval_id" not in task.payload
        assert task.parent_task_id == PARENT
        from ai_osop.core.signed_replay_comparison import observation_subtask_id

        assert task.subtask_id == observation_subtask_id(task.id)
        assert task.dependencies == [PARENT]
        assert task.flow_id == FLOW
        assert task.max_retries == 0
        assert task.payload["method"] == "GET"
        assert task.payload["_authorization_version"] == VER
        assert task.payload["url"] == "https://example.test/api/private"
    assert fx.scheduler._execute_task_durable.await_count == 0
    assert "engagement_id:$sid" in fx.graph.statements[0][0]
    assert "TARGETS_ENDPOINT" in fx.graph.statements[0][0]
    assert fx.graph.statements[0][1] == {"wid": WID, "sid": SID}


@pytest.mark.asyncio
async def test_actual_workflow_agent_navigate_step_maps_to_read_only_get(admitted):
    # WorkflowAgent._execute_workflow_mapping writes NAVIGATE Step.action_type
    # with Endpoint.method GET. That real producer must remain usable.
    admitted.rows[0]["action_type"] = "NAVIGATE"
    result = await _run(admitted)
    assert result["status"] == "pending_execution_approval"
    assert len(result["queued_task_ids"]) == 2
    for identifier in result["queued_task_ids"]:
        child = admitted.tasks[identifier]
        assert child.payload["method"] == "GET"
        assert child.approval_required is True


@pytest.mark.asyncio
async def test_reentry_never_reschedules_a_pending_or_unknown_task(admitted):
    fx = admitted
    first = await _run(fx)
    task_id = first["queued_task_ids"][0]
    for status in ("pending", "dispatch_unknown", "completed", "failed"):
        fx.tasks[task_id].status = status
        second = await _run(fx)
        assert second["status"] == "already_admitted"
        assert second["queued_task_ids"] == []
    assert fx.scheduler.schedule_task.await_count == 2
    fx.scheduler._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alter",
    [
        "executor_missing",
        "fake_executor",
        "wrong_memory",
        "missing_parent",
        "parent_wrong_tenant",
        "parent_wrong_type",
        "unapproved_parent",
        "approval_not_verified",
        "parent_not_running",
        "wrong_policy_version",
        "revoked",
        "stale_flow",
        "foreign_flow",
        "inactive_engagement",
        "unscoped_engagement",
        "wrong_workflow",
        "wrong_user",
        "anonymous",
        "multiple_identities",
        "foreign_graph_role",
        "source_role_mismatch",
        "missing_imported_user",
        "expired_imported_user",
        "source_missing",
        "source_wrong_tenant",
        "source_wrong_flow",
        "source_not_completed",
        "source_wrong_type",
        "source_wrong_version",
        "source_wrong_workflow",
        "source_wrong_user",
        "source_out_of_scope",
        "missing_source_link",
        "source_changed_since_snapshot",
    ],
)
async def test_signed_admission_fails_closed_before_scheduling(admitted, alter):
    fx = admitted
    changes = {}
    if alter == "executor_missing":
        changes["orchestrator"] = None
    elif alter == "fake_executor":
        changes["orchestrator"] = lambda _: None
    elif alter == "wrong_memory":
        changes["orchestrator"] = SimpleNamespace(
            session_memory=AsyncMock(),
            schedule_task=AsyncMock(),
            graph_memory=fx.scheduler.graph_memory,
        )
    elif alter == "missing_parent":
        changes["parent_task"] = None
    elif alter == "parent_wrong_tenant":
        fx.parent.engagement_id = "eng-foreign"
    elif alter == "parent_wrong_type":
        fx.parent.type = "navigate"
    elif alter == "unapproved_parent":
        fx.parent.payload["operator_approved"] = False
        fx.tasks[PARENT].payload["operator_approved"] = False
    elif alter == "approval_not_verified":
        fx.memory.is_task_approved.return_value = False
    elif alter == "parent_not_running":
        fx.tasks[PARENT].status = "dispatch_unknown"
    elif alter == "wrong_policy_version":
        fx.memory.assert_signed_authorization.return_value = SimpleNamespace(version=2)
    elif alter == "revoked":
        fx.memory.assert_signed_authorization.side_effect = PermissionError()
    elif alter == "stale_flow":
        fx.memory.load_flow.return_value.status = "paused"
    elif alter == "foreign_flow":
        fx.memory.load_flow.return_value.engagement_id = "eng-other"
    elif alter == "inactive_engagement":
        fx.memory.load_session_state.return_value.phase = "halted"
    elif alter == "unscoped_engagement":
        fx.memory.load_session_state.return_value.scope.domains = []
    elif alter == "wrong_workflow":
        changes["workflow_id"] = "wf-other"
    elif alter == "wrong_user":
        changes["test_identities"] = ["user_c"]
    elif alter == "anonymous":
        changes["test_identities"] = ["anonymous"]
    elif alter == "multiple_identities":
        changes["test_identities"] = ["user_b", "user_c"]
    elif alter == "foreign_graph_role":
        fx.rows[0]["source_role"] = "user_c"
    elif alter == "source_role_mismatch":
        changes["source_user_label"] = "user_c"
    elif alter == "missing_imported_user":
        fx.users.get_session_authoritative.side_effect = lambda _eid, label: (
            None if label == "user_b" else SimpleNamespace(is_expired=lambda: False)
        )
    elif alter == "expired_imported_user":
        fx.users.get_session_authoritative.side_effect = lambda _eid, _label: (
            SimpleNamespace(is_expired=lambda: True)
        )
    elif alter == "source_missing":
        fx.tasks.pop(SOURCE)
    elif alter == "source_wrong_tenant":
        fx.tasks[SOURCE].engagement_id = "eng-other"
    elif alter == "source_wrong_flow":
        fx.tasks[SOURCE].flow_id = "flow-other"
    elif alter == "source_not_completed":
        fx.tasks[SOURCE].status = "dispatch_unknown"
    elif alter == "source_wrong_type":
        fx.tasks[SOURCE].type = "navigate"
    elif alter == "source_wrong_version":
        fx.tasks[SOURCE].payload["_authorization_version"] = VER - 1
    elif alter == "source_wrong_workflow":
        fx.tasks[SOURCE].result["workflow_id"] = "wf-other"
    elif alter == "source_wrong_user":
        fx.tasks[SOURCE].payload["user_label"] = "user_c"
    elif alter == "source_out_of_scope":
        fx.tasks[SOURCE].payload["url"] = "https://foreign.test/"
    elif alter == "missing_source_link":
        fx.parent.parent_task_id = None
    elif alter == "source_changed_since_snapshot":
        fx.tasks[PARENT].parent_task_id = "task-other"
    with pytest.raises(WorkflowException):
        await _run(fx, **changes)
    fx.scheduler.schedule_task.assert_not_awaited()
    fx.scheduler._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_completed_signed_engagement_auto_map_without_flow_is_allowed(admitted):
    fx = admitted
    assert fx.tasks[SOURCE].flow_id is None
    result = await _run(fx)
    assert result["status"] == "pending_execution_approval"
    fx.scheduler._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant",
    [
        "bad_domain",
        "scheme",
        "credentials",
        "fragment",
        "step_duplicate",
        "step_id",
        "endpoint_id",
        "step_order",
    ],
)
async def test_injected_or_foreign_step_never_schedules(admitted, variant):
    fx = admitted
    row = fx.rows[0]
    if variant == "bad_domain":
        row["url"] = "https://other.test/secret"
    elif variant == "scheme":
        row["url"] = "file:///etc/passwd"
    elif variant == "credentials":
        row["url"] = "https://user:pass@example.test/path"
    elif variant == "fragment":
        row["url"] += "#token"
    elif variant == "step_duplicate":
        fx.rows.append(copy.deepcopy(row))
    elif variant == "step_id":
        row["step_id"] = "../../step"
    elif variant == "endpoint_id":
        row["endpoint_id"] = "vuln-other"
    elif variant == "step_order":
        row["step_order"] = -2
    with pytest.raises(WorkflowException):
        await _run(fx)
    fx.scheduler.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe",
    [
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    ],
)
async def test_browser_replay_will_not_mutate_or_implicitly_change_method(admitted, unsafe):
    fx = admitted
    fx.rows[0]["method"] = unsafe
    fx.rows[0]["action_type"] = unsafe
    result = await _run(fx)
    assert result["status"] == "no_replayable_steps"
    fx.scheduler.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_admission_ambiguous_schedule_never_recursively_retries(admitted):
    fx = admitted

    async def unknown_after_persist(task):
        raise TimeoutError("unknown whether dispatch happened")

    fx.scheduler.schedule_task.side_effect = unknown_after_persist
    with pytest.raises(WorkflowException, match="UNKNOWN"):
        await _run(fx)
    assert fx.scheduler.schedule_task.await_count == 1
    # Both observations commit together, even if queue delivery fails.
    assert len(fx.tasks) == 4
    fx.scheduler._execute_task_durable.assert_not_awaited()
    follow_up = await _run(fx)
    # No automatic requeue after UNKNOWN delivery, even for pending peer.
    # A PG-driven signed queue-intent reconciler must explicitly deliver it.
    assert follow_up["status"] == "already_admitted"
    assert fx.scheduler.schedule_task.await_count == 1
    assert (await _run(fx))["status"] == "already_admitted"
    assert fx.scheduler.schedule_task.await_count == 1


@pytest.mark.asyncio
async def test_committed_pair_readback_is_authoritative_not_scheduler_return(admitted):
    fx = admitted
    fx.scheduler.schedule_task.side_effect = AsyncMock(return_value=None)
    result = await _run(fx)
    assert result["status"] == "pending_execution_approval"
    assert len(result["queued_task_ids"]) == 2
    assert fx.memory.admit_signed_replay_observation_pair.await_count == 1
    fx.scheduler._execute_task_durable.assert_not_awaited()
