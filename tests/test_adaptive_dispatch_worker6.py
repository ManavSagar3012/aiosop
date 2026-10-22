"""Deterministic PG-atomic adaptive follow-up admission; never call external agents."""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.models import ScopeDefinition
from ai_osop.memory import adaptive_dispatch as module


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class State:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.flow = SimpleNamespace(
            id="flow-adaptive", engagement_id="eng-a", status="running", revision=9,
        )
        self.approval = SimpleNamespace(
            id="apr-planner-example", task_id="task-planner-example",
            status="approved", agent_id="planner-runtime", action_type="planner_inference",
            target=self.flow.id, operator_id="human-senior", responded_at=datetime.utcnow(),
        )
        self.planner = SimpleNamespace(
            id=self.approval.task_id, status="completed", approval_required=True,
            assigned_agent_id="planner-runtime", flow_id=self.flow.id,
            payload={
                "planner_purpose": "adaptive_planning", "approval_id": self.approval.id,
                "operator_approved": True, "_authorization_version": 4,
                "planner_flow_revision": 9,
            },
            result={
                "status": "completed", "review_status": "operator_review",
                "adaptive_proposal": {
                    "action": "request_sub_recon", "parameters": {"target": "example.com"},
                },
            },
        )
        self.tasks = {}
        self.steps = {}
        self.events = []
        self.scope = ScopeDefinition(
            engagement_id="eng-a", domains=["example.com"],
            authorization_ref="signed", allowed_techniques=["recon"],
            approval_required_for=["planner_inference"],
        )
        self.engagement = SimpleNamespace(
            scope=self.scope.model_dump(mode="json"), phase="reconnaissance",
            roe={"adaptive_planning_enabled": True},
        )
        self.fail_cas = False
        self.fail_event = False

    def session(self):
        return Session(self)


class Session:
    def __init__(self, state):
        self.state = state

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        async with self.state.lock:
            snapshot = deepcopy((
                self.state.flow, self.state.planner,
                self.state.tasks, self.state.steps, self.state.events,
            ))
            try:
                yield
            except BaseException:
                (
                    self.state.flow, self.state.planner,
                    self.state.tasks, self.state.steps, self.state.events,
                ) = snapshot
                raise

    async def execute(self, statement):
        sql = str(statement)
        if "FROM approval_requests" in sql:
            return Result(self.state.approval)
        if "FROM tasks" in sql:
            return Result(self.state.planner)
        if "FROM execution_flows" in sql:
            return Result(self.state.flow)
        if sql.startswith("UPDATE execution_flows"):
            if self.state.fail_cas:
                return Result(None)
            params = statement.compile().params
            revision = params.get("revision_2")
            if revision != self.state.flow.revision:
                return Result(None)
            self.state.flow.revision += 1
            return Result(self.state.flow.revision)
        raise AssertionError(f"Unexpected SQL: {sql[:150]}")

    def add(self, orm):
        if orm.__tablename__ == "tasks":
            self.state.tasks[orm.id] = orm
        elif orm.__tablename__ == "execution_subtasks":
            self.state.steps[orm.id] = orm
        else:
            raise AssertionError(f"Unexpected ORM: {orm.__tablename__}")

    async def flush(self):
        return None


@pytest.fixture
def harness(monkeypatch):
    state = State()
    store = SimpleNamespace(
        _sessions=state.session,
        _guard=AsyncMock(return_value=(state.engagement, None)),
        approval_id=lambda _task: state.approval.id,
    )
    monkeypatch.setattr(module, "PlannerExecutionStore", lambda memory: store)

    async def signed(_db, _id, *, expected_version=None):
        if expected_version != 4:
            raise PermissionError("Signed version changed")
        return SimpleNamespace(version=4)

    monkeypatch.setattr(module, "guard_sql", AsyncMock(side_effect=signed))

    async def event(db, sid, task_id, kind, actor, payload, idempotency_key):
        if state.fail_event:
            raise OSError("Outbox unavailable")
        state.events.append((kind, actor, task_id, payload, idempotency_key))

    monkeypatch.setattr(module.SupervisionStore, "_append_event", staticmethod(event))
    return state, store


def args(**override):
    values = dict(
        request_id="apr-planner-example", engagement_id="eng-a",
        actor_id="verified-senior", actor_role="senior_operator",
        expected_authorization_version=4, expected_flow_revision=9,
        confirmed_target="example.com", confirm_execution=True,
    )
    return {**values, **override}


@pytest.mark.asyncio
async def test_atomic_signed_confirm_creates_pending_approval_gated_task_subtask_outbox(harness):
    state, _ = harness
    result = await module.confirm_adaptive_followup(object(), **args())
    assert result["status"] == "pending_dispatch_review"
    assert result["execution_started"] is False
    assert result["dispatch_required"] is True
    assert result["approval_required"] is True
    assert state.flow.revision == 10
    assert len(state.tasks) == len(state.steps) == len(state.events) == 1
    objective = next(iter(state.tasks.values()))
    step = next(iter(state.steps.values()))
    assert objective.id == result["objective_task_id"]
    assert objective.type == "flow_objective" and objective.status == "planned"
    assert objective.assigned_agent_id is None
    assert objective.payload["planned_target"] == "example.com"
    assert step.id == result["subtask_id"]
    assert step.status == "pending" and step.execution_task_id is None
    assert step.task_id == objective.id
    assert step.task_type == "full_recon" and step.approval_required is True
    assert state.planner.result["adaptive_execution_admission"]["status"] == "pending_dispatch_review"
    assert state.events[0][0] == "planner.adaptive_followup_prepared"
    assert state.events[0][1] == "verified-senior"


@pytest.mark.asyncio
async def test_duplicate_concurrent_senior_decisions_claim_exactly_once(harness):
    state, _ = harness
    results = await asyncio.gather(
        module.confirm_adaptive_followup(object(), **args()),
        module.confirm_adaptive_followup(object(), **args()),
        return_exceptions=True,
    )
    good = [r for r in results if isinstance(r, dict)]
    denied = [r for r in results if isinstance(r, module.AdaptiveDispatchDenied)]
    assert len(good) == len(denied) == 1
    assert state.flow.revision == 10
    assert len(state.tasks) == len(state.steps) == len(state.events) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("condition", [
    "junior", "no_confirmation", "old_version", "stale_flow", "paused_flow",
    "revoked", "no_recon_technique", "restricted_scan", "disabled_adaptive",
    "wrong_phase", "different_target", "outside_target", "bad_proposal",
    "not_approved", "already_claimed", "no_window",
])
async def test_invalid_policy_or_stale_user_admission_mutates_nothing(harness, condition):
    state, store = harness
    values = args()
    if condition == "junior":
        values["actor_role"] = "operator"
    elif condition == "no_confirmation":
        values["confirm_execution"] = False
    elif condition == "old_version":
        values["expected_authorization_version"] = 3
    elif condition == "stale_flow":
        values["expected_flow_revision"] = 8
    elif condition == "paused_flow":
        state.flow.status = "paused"
    elif condition == "revoked":
        module.guard_sql.side_effect = PermissionError("ROE revoked")
    elif condition == "no_recon_technique":
        state.scope.allowed_techniques = ["sqli"]
        state.engagement.scope = state.scope.model_dump(mode="json")
    elif condition == "restricted_scan":
        state.scope.restrictions = ["no_active_scanning"]
        state.engagement.scope = state.scope.model_dump(mode="json")
    elif condition == "disabled_adaptive":
        state.engagement.roe["adaptive_planning_enabled"] = False
    elif condition == "wrong_phase":
        state.engagement.phase = "exploitation"
    elif condition == "different_target":
        values["confirmed_target"] = "sub.example.com"
    elif condition == "outside_target":
        values["confirmed_target"] = "unapproved.org"
    elif condition == "bad_proposal":
        state.planner.result["adaptive_proposal"]["action"] = "exploit"
    elif condition == "not_approved":
        state.approval.status = "rejected"
    elif condition == "already_claimed":
        state.planner.result["adaptive_execution_admission"] = {"status": "prepared"}
    elif condition == "no_window":
        store._guard.side_effect = PermissionError("Testing window closed")
    original_revision = state.flow.revision
    with pytest.raises((module.AdaptiveDispatchDenied, module.AdaptiveDispatchUnavailable)):
        await module.confirm_adaptive_followup(object(), **values)
    assert state.flow.revision == original_revision
    assert not state.tasks and not state.steps and not state.events


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["cas", "outbox"])
async def test_cas_or_outbox_failure_rolls_back_entire_prepared_plan(harness, failure):
    state, _ = harness
    if failure == "cas":
        state.fail_cas = True
    else:
        state.fail_event = True
    with pytest.raises((module.AdaptiveDispatchDenied, module.AdaptiveDispatchUnavailable)):
        await module.confirm_adaptive_followup(object(), **args())
    assert state.flow.revision == 9
    assert not state.tasks and not state.steps and not state.events
    assert state.planner.result.get("adaptive_execution_admission") is None
