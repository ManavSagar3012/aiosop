"""Immutable signed adaptive target binding at the actual Flow dispatch boundary.

No database, external model, target scans, or real task scheduling is used.
"""

import asyncio
import hashlib
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from ai_osop.api.deps import verify_token
from ai_osop.api.routers import flows
from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SubtaskRecord, Task
from ai_osop.memory import adaptive_dispatch as binding
from tests.test_execution_flows_api import _create_flow_and_task, flow_client


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class Durable:
    def __init__(self):
        self.flow = SimpleNamespace(
            id="flow-adaptive", engagement_id="eng-one", status="running", revision=10,
        )
        self.request_id = "apr-planner-real"
        self.digest = hashlib.sha256(
            f"eng-one:{self.request_id}:adaptive-recon".encode()
        ).hexdigest()[:24]
        self.objective_id = f"task-adaptive-{self.digest}"
        self.step_id = f"subtask-adaptive-{self.digest}"
        self.scope = ScopeDefinition(
            engagement_id="eng-one", domains=["example.com"],
            authorization_ref="signed", allowed_techniques=["recon"],
            approval_required_for=["planner_inference"],
        )
        self.engagement = SimpleNamespace(
            phase="reconnaissance", roe={"adaptive_planning_enabled": True},
            scope=self.scope.model_dump(mode="json"),
        )
        self.parent = SimpleNamespace(
            id=self.objective_id, type="flow_objective", status="planned",
            agent_type="recon", parent_task_id=None, subtask_id=None,
            approval_required=True,
            payload={
                "adaptive_source_approval_id": self.request_id,
                "planned_target": "example.com", "_authorization_version": 4,
            },
        )
        self.step = SimpleNamespace(
            id=self.step_id, engagement_id="eng-one", flow_id=self.flow.id,
            task_id=self.objective_id, status="pending", execution_task_id=None,
            task_type="full_recon", agent_type="recon", approval_required=True,
            dependencies=[], refinement_count=0,
        )
        self.approval = SimpleNamespace(
            id=self.request_id, task_id="task-planner", status="approved",
            agent_id="planner-runtime", action_type="planner_inference",
            target=self.flow.id, operator_id="alice", responded_at=datetime.utcnow(),
        )
        self.planner = SimpleNamespace(
            id=self.approval.task_id, status="completed", type="planner_inference",
            approval_required=True, flow_id=self.flow.id,
            assigned_agent_id="planner-runtime",
            payload={
                "planner_purpose": "adaptive_planning", "approval_id": self.request_id,
                "operator_approved": True, "_authorization_version": 4,
            },
            result={
                "review_status": "operator_review",
                "adaptive_proposal": {
                    "action": "request_sub_recon", "parameters": {"target": "example.com"},
                },
                "adaptive_execution_admission": {
                    "status": "pending_dispatch_review",
                    "objective_id": self.objective_id,
                    "subtask_id": self.step_id,
                    "flow_revision": 10, "confirmed_by": "alice",
                },
            },
        )
        self.events = []
        self.reserved_tasks = {}
        self.lock = asyncio.Lock()
        self.fail_cas = False
        self.fail_event = False

    def context(self):
        return DbSession(self)

    def flow_model(self):
        return FlowRecord(
            id=self.flow.id, engagement_id="eng-one", objective="Reviewed recon",
            status=self.flow.status, revision=self.flow.revision,
        )

    def engagement_model(self):
        from ai_osop.core.models import SessionState
        return SessionState(
            session_id="eng-one", scope=self.scope, phase=self.engagement.phase,
            roe=self.engagement.roe, created_by="alice",
        )

    def subtask_model(self):
        return SubtaskRecord(
            id=self.step.id, engagement_id="eng-one", flow_id=self.flow.id,
            task_id=self.objective_id, title="Pending signed recon", task_type=self.step.task_type,
            agent_type=AgentType.RECON, approval_required=self.step.approval_required,
            status=self.step.status, dependencies=[],
        )


class DbSession:
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
                self.state.flow, self.state.step, self.state.events,
                self.state.reserved_tasks,
            ))
            try:
                yield
            except BaseException:
                (
                    self.state.flow, self.state.step,
                    self.state.events, self.state.reserved_tasks,
                ) = snapshot
                raise

    async def execute(self, statement):
        sql = str(statement)
        params = statement.compile().params
        s = self.state
        if sql.startswith("UPDATE execution_subtasks"):
            if s.step.status != "pending" or s.step.execution_task_id is not None:
                return Result(None)
            s.step.status = "dispatched"
            s.step.execution_task_id = params.get("execution_task_id")
            return Result(s.step.id)
        if sql.startswith("UPDATE execution_flows"):
            if s.fail_cas or params.get("revision_2") != s.flow.revision:
                return Result(None)
            s.flow.revision += 1
            return Result(s.flow.revision)
        if "FROM execution_flows" in sql:
            return Result(s.flow)
        if "FROM execution_subtasks" in sql:
            return Result(s.step)
        if "FROM approval_requests" in sql:
            return Result(s.approval)
        if "FROM tasks" in sql:
            task_id = next((v for k, v in params.items() if k.startswith("id_")), None)
            if task_id == s.objective_id:
                return Result(s.parent)
            if task_id == s.approval.task_id:
                return Result(s.planner)
        raise AssertionError(f"Unexpected SQL query: {sql[:180]}")

    def add(self, row):
        assert row.__tablename__ == "tasks"
        if row.id in self.state.reserved_tasks:
            raise RuntimeError("Duplicate durable execution TaskORM")
        self.state.reserved_tasks[row.id] = row

    async def flush(self):
        return None


@pytest.fixture
def durable(monkeypatch):
    s = Durable()
    store = SimpleNamespace(
        _sessions=s.context,
        _guard=AsyncMock(return_value=(s.engagement, None)),
        approval_id=lambda _: s.request_id,
    )
    monkeypatch.setattr(binding, "PlannerExecutionStore", lambda memory: store)

    async def verify(_db, _engagement, *, expected_version=None):
        if expected_version != 4:
            raise PermissionError("wrong signed version")
        return SimpleNamespace(version=4)

    monkeypatch.setattr(binding, "guard_sql", AsyncMock(side_effect=verify))

    async def event(_db, engagement_id, step_id, kind, actor, metadata, idempotency_key):
        if s.fail_event:
            raise OSError("outbox unavailable")
        s.events.append((kind, engagement_id, step_id, actor, metadata, idempotency_key))

    monkeypatch.setattr(binding.SupervisionStore, "_append_event", staticmethod(event))
    return s, store


def claim_args(s, **updates):
    task = binding.build_adaptive_execution_task(
        flow=s.flow_model(), subtask=s.subtask_model(), target="example.com",
    )
    return {
        "flow": s.flow_model(),
        "engagement": s.engagement_model(),
        "subtask": s.subtask_model(),
        "payload": {"target": "example.com"},
        "expected_revision": 10,
        "actor_id": "alice", "actor_role": "senior_operator",
        "execution_task": task,
        **updates,
    }


@pytest.mark.asyncio
async def test_signed_adaptive_claim_checks_proposal_target_and_records_atomic_event(durable):
    state, _ = durable
    accepted = await binding.claim_confirmed_adaptive_subtask(object(), **claim_args(state))
    assert accepted["status"] == "pending"
    assert accepted["execution_started"] is False
    assert state.step.status == "dispatched"
    assert state.step.execution_task_id == accepted["task_id"]
    assert len(state.reserved_tasks) == 1
    assert state.flow.revision == 11
    assert len(state.events) == 1
    assert state.events[0][0] == "planner.adaptive_dispatch_intent"
    assert state.events[0][3] == "alice"
    with pytest.raises(binding.AdaptiveDispatchDenied):
        await binding.claim_confirmed_adaptive_subtask(object(), **claim_args(state))
    assert len(state.events) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("adversarial", [
    {"target": "sub.example.com"},
    {"target": "https://example.com"},
    {"target": "EXAMPLE.COM"},
    {"target": "example.com", "url": "evil.org"},
    {"target": "example.com", "host": "sub.example.com"},
    {"target": "example.com", "targets": ["example.com", "evil.org"]},
    {"target": "example.com", "command": "nmap -A"},
    {"url": "example.com"},
    {},
])
async def test_adversarial_payload_cannot_swap_target_or_inject_arguments(durable, adversarial):
    state, _ = durable
    with pytest.raises(binding.AdaptiveDispatchDenied):
        await binding.claim_confirmed_adaptive_subtask(
            object(), **claim_args(state, payload=adversarial)
        )
    assert state.step.status == "pending"
    assert state.flow.revision == 10
    assert state.events == []
    assert state.reserved_tasks == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", [
    "junior", "wrong_actor", "no_revision", "stale_revision", "paused",
    "revoked", "different_parent_target", "different_planner_target",
    "approval_revoked", "approval_missing", "step_approval_disabled",
    "step_agent_changed", "step_type_changed", "step_dependencies_added",
    "confirmation_different_actor", "wrong_signed_version", "technique_removed",
    "planning_disabled", "wrong_namespace", "out_of_scope",
])
async def test_tampering_or_stale_signed_flow_fails_closed(durable, tamper):
    s, store = durable
    overrides = {}
    if tamper == "junior":
        overrides["actor_role"] = "operator"
    elif tamper == "wrong_actor":
        overrides["actor_id"] = "other-senior"
    elif tamper == "no_revision":
        overrides["expected_revision"] = None
    elif tamper == "stale_revision":
        overrides["expected_revision"] = 9
    elif tamper == "paused":
        s.flow.status = "paused"
    elif tamper == "revoked":
        binding.guard_sql.side_effect = PermissionError("Signer revoked")
    elif tamper == "different_parent_target":
        s.parent.payload["planned_target"] = "sub.example.com"
    elif tamper == "different_planner_target":
        s.planner.result["adaptive_proposal"]["parameters"]["target"] = "sub.example.com"
    elif tamper == "approval_revoked":
        s.approval.status = "rejected"
    elif tamper == "approval_missing":
        s.approval.operator_id = None
    elif tamper == "step_approval_disabled":
        s.step.approval_required = False
    elif tamper == "step_agent_changed":
        s.step.agent_type = "vuln_analysis"
    elif tamper == "step_type_changed":
        s.step.task_type = "exploit"
    elif tamper == "step_dependencies_added":
        s.step.dependencies = ["subtask-other"]
    elif tamper == "confirmation_different_actor":
        s.planner.result["adaptive_execution_admission"]["confirmed_by"] = "not-alice"
    elif tamper == "wrong_signed_version":
        s.parent.payload["_authorization_version"] = 5
    elif tamper == "technique_removed":
        s.scope.allowed_techniques = ["sqli"]
        s.engagement.scope = s.scope.model_dump(mode="json")
    elif tamper == "planning_disabled":
        s.engagement.roe["adaptive_planning_enabled"] = False
    elif tamper == "wrong_namespace":
        s.step.id = "subtask-adaptive-tampered"
    elif tamper == "out_of_scope":
        s.scope.exclusions = ["example.com"]
        s.engagement.scope = s.scope.model_dump(mode="json")
    with pytest.raises((binding.AdaptiveDispatchDenied, binding.AdaptiveDispatchUnavailable)):
        await binding.claim_confirmed_adaptive_subtask(object(), **claim_args(s, **overrides))
    assert s.flow.revision == 10
    assert s.step.status == "pending"
    assert s.events == []
    assert s.reserved_tasks == {}


@pytest.mark.asyncio
async def test_two_replicas_claim_once_under_concurrent_flow_revision_cas(durable):
    s, _ = durable
    results = await asyncio.gather(
        binding.claim_confirmed_adaptive_subtask(object(), **claim_args(s)),
        binding.claim_confirmed_adaptive_subtask(object(), **claim_args(s)),
        return_exceptions=True,
    )
    assert sum(isinstance(value, dict) and value.get("status") == "pending" for value in results) == 1
    assert sum(isinstance(value, binding.AdaptiveDispatchDenied) for value in results) == 1
    assert s.flow.revision == 11
    assert s.step.status == "dispatched"
    assert len(s.events) == 1
    assert len(s.reserved_tasks) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["cas", "outbox"])
async def test_failed_flow_cas_or_outbox_rolls_back_subtask_claim(durable, failure):
    s, _ = durable
    if failure == "cas":
        s.fail_cas = True
    else:
        s.fail_event = True
    with pytest.raises((binding.AdaptiveDispatchDenied, binding.AdaptiveDispatchUnavailable)):
        await binding.claim_confirmed_adaptive_subtask(object(), **claim_args(s))
    assert s.step.status == "pending"
    assert s.flow.revision == 10
    assert s.events == []
    assert s.reserved_tasks == {}


@pytest.fixture
def api_adaptive_step(flow_client, monkeypatch):
    client, app, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    digest = hashlib.sha256(b"eng-one:apr-planner-real:adaptive-recon").hexdigest()[:24]
    objective_id = f"task-adaptive-{digest}"
    subtask_id = f"subtask-adaptive-{digest}"
    sm.tasks[objective_id] = Task(
        id=objective_id, type="flow_objective", engagement_id="eng-one",
        agent_type=AgentType.RECON, flow_id=flow_id, status="planned",
        approval_required=True, payload={"planned_target": "example.com"},
    )
    sm.subtasks[subtask_id] = SubtaskRecord(
        id=subtask_id, engagement_id="eng-one", flow_id=flow_id,
        task_id=objective_id, title="Confirmed follow-up", task_type="full_recon",
        agent_type=AgentType.RECON, status="pending", approval_required=True,
    )
    app.dependency_overrides[verify_token] = lambda: {"sub": "alice", "role": "senior_operator"}
    claim = AsyncMock(return_value=True)
    monkeypatch.setattr(flows, "claim_confirmed_adaptive_subtask", claim)
    return client, app, orch, sm, flow_id, subtask_id, claim


def dispatch(client, flow_id, subtask_id, revision, payload):
    body = {"payload": payload}
    if revision is not None:
        body["expected_revision"] = revision
    return client.post(f"/flows/{flow_id}/subtasks/{subtask_id}/dispatch", json=body)


def test_adaptive_http_dispatch_uses_signed_claim_instead_of_legacy_generic_claim(api_adaptive_step):
    client, _, orch, sm, flow_id, sid, claim = api_adaptive_step
    sm.claim_subtask = AsyncMock(side_effect=AssertionError("Generic target-scope claim bypass"))
    revision = sm.flows[flow_id].revision
    # The fake signed PG claim needs to model its atomic Flow/subtask transition.
    async def signed_claim(*args, **kwargs):
        assert kwargs["payload"] == {"target": "example.com"}
        assert kwargs["actor_id"] == "alice"
        assert kwargs["actor_role"] == "senior_operator"
        assert kwargs["expected_revision"] == revision
        sm.subtasks[sid].status = "dispatched"
        sm.flows[flow_id].revision += 1
        return True
    claim.side_effect = signed_claim
    result = dispatch(client, flow_id, sid, revision, {"target": "example.com"})
    assert result.status_code == 200, result.text
    sm.claim_subtask.assert_not_awaited()
    assert claim.await_count == 1
    assert len(orch.scheduled) == 1
    assert orch.scheduled[0].payload == {"target": "example.com"}
    assert orch.scheduled[0].approval_required is True
    assert orch.scheduled[0].status == "awaiting_approval"


@pytest.mark.parametrize("wrong_actor", [
    {"sub": "alice", "role": "operator"},
    {"sub": "", "role": "senior_operator"},
])
def test_non_senior_or_missing_verified_actor_never_reaches_adaptive_claim(api_adaptive_step, wrong_actor):
    client, app, orch, sm, flow_id, sid, claim = api_adaptive_step
    app.dependency_overrides[verify_token] = lambda: wrong_actor
    result = dispatch(client, flow_id, sid, sm.flows[flow_id].revision, {"target": "example.com"})
    assert result.status_code == 403
    claim.assert_not_awaited()
    assert not orch.scheduled


def test_missing_expected_revision_cannot_claim_adaptive_subtask(api_adaptive_step):
    client, _, orch, sm, flow_id, sid, claim = api_adaptive_step
    result = dispatch(client, flow_id, sid, None, {"target": "example.com"})
    assert result.status_code == 409
    claim.assert_not_awaited()
    assert not orch.scheduled


def test_stale_revision_rejected_before_adaptive_dispatch_claim(api_adaptive_step):
    client, _, orch, sm, flow_id, sid, claim = api_adaptive_step
    result = dispatch(client, flow_id, sid, sm.flows[flow_id].revision - 1, {"target": "example.com"})
    assert result.status_code == 409
    claim.assert_not_awaited()
    assert not orch.scheduled


@pytest.mark.parametrize("reason,status", [
    (binding.AdaptiveDispatchDenied("alternate in-scope target"), 409),
    (binding.AdaptiveDispatchDenied("wrong senior confirmation"), 409),
    (binding.AdaptiveDispatchDenied("ROE revoked"), 409),
    (binding.AdaptiveDispatchUnavailable("DB unavailable"), 503),
])
def test_signed_adaptive_claim_failure_blocks_scheduler(api_adaptive_step, reason, status):
    client, _, orch, sm, flow_id, sid, claim = api_adaptive_step
    claim.side_effect = reason
    response = dispatch(client, flow_id, sid, sm.flows[flow_id].revision,
                        {"target": "sub.example.com"})
    assert response.status_code == status
    assert len(orch.scheduled) == 0
    assert sm.subtasks[sid].status == "pending"


def test_normal_manual_dispatch_stays_on_existing_generic_claim_route(flow_client):
    client, _, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(f"/flows/{flow_id}/subtasks", json={
        "task_id": task_id, "title": "Manual existing workflow",
    }).json()
    accepted = dispatch(client, flow_id, step["id"], sm.flows[flow_id].revision,
                        {"target": "https://example.com/api"})
    assert accepted.status_code == 200, accepted.text
    assert len(orch.scheduled) == 1
    assert orch.scheduled[0].approval_required is False
