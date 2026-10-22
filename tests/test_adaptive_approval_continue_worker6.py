"""Signed adaptive continuation never schedules target-side work.

All SQL/model/provider boundaries are deterministic stubs. No app DB, models,
or assessment targets are contacted.
"""

from contextlib import asynccontextmanager
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.api.deps import state
from ai_osop.api.routers import approvals
from ai_osop.core.config import AgentType
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.models import FlowRecord, ScopeDefinition, Task
from ai_osop.memory.model_usage import ModelOutcomeUncertain
from ai_osop.orchestrator import planner_resume as resume


class PaidStub(LiteLLMClient):
    def __init__(self):
        pass

    async def complete(self, *args, **kwargs):
        raise AssertionError("Live model must never be invoked by qualification tests")


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class InMemory:
    def __init__(self):
        self.engagement_id = "eng-test"
        self.flow_id = "flow-adaptive"
        self.parent = Task(
            id="task-completed", engagement_id="eng-test", type="full_recon",
            agent_type=AgentType.RECON, status="completed",
        )
        self.approval = SimpleNamespace(
            id="apr-planner-x", task_id="task-planner-x", engagement_id="eng-test",
            status="approved", action_type="planner_inference", agent_id="planner-runtime",
            target=self.flow_id, operator_id="senior", responded_at=datetime.utcnow(),
        )
        self.parked = SimpleNamespace(
            id="task-planner-x", type="planner_inference", status="awaiting_approval",
            approval_required=True, assigned_agent_id="planner-runtime",
            flow_id=self.flow_id, parent_task_id=self.parent.id,
            payload={"planner_purpose": "adaptive_planning", "_authorization_version": 4,
                     "planner_flow_revision": 8, "approval_id": self.approval.id,
                     "operator_approved": True},
            result=None,
        )
        self.flow = SimpleNamespace(
            id=self.flow_id, engagement_id="eng-test", objective="Review",
            status="running", revision=8, created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.scope = ScopeDefinition(
            engagement_id="eng-test", domains=["example.com"],
            authorization_ref="signed", approval_required_for=["planner_inference"],
        )
        self.engagement = SimpleNamespace(
            scope=self.scope.model_dump(mode="json"),
            roe={"adaptive_planning_enabled": True},
        )
        self.events = []

    def open(self):
        return Session(self)


class Session:
    def __init__(self, fixture):
        self.fixture = fixture

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        yield

    async def execute(self, statement):
        sql = str(statement)
        f = self.fixture
        if "FROM approval_requests" in sql:
            return Result(f.approval)
        if "FROM execution_flows" in sql:
            return Result(f.flow)
        if "FROM tasks" in sql:
            params = statement.compile().params
            task_id = next((v for k, v in params.items() if k.startswith("id_")), None)
            if task_id == f.parked.id:
                return Result(f.parked)
            if task_id == f.parent.id:
                return Result(SimpleNamespace(
                    id=f.parent.id, type=f.parent.type,
                    status=f.parent.status, agent_type=f.parent.agent_type.value,
                ))
        raise AssertionError(f"Unexpected SQL query {sql[:120]}")

    async def flush(self):
        return None


@pytest.fixture
def harness(monkeypatch):
    f = InMemory()
    memory = SimpleNamespace(load_task_authoritative=AsyncMock(return_value=f.parent))
    llm = PaidStub()
    controller = SimpleNamespace(
        _flow_id=lambda engagement_id: f.flow_id,
        evaluate_and_plan_next_step=AsyncMock(return_value={
            "action": "create_hypothesis", "parameters": {"statement": "Investigate passive logs"},
            "provenance": "LLM", "_planner_flow_revision": 9,
        }),
    )
    orch = SimpleNamespace(
        session_memory=memory, llm_client=llm, adaptive_planner=controller,
        schedule_task=AsyncMock(side_effect=AssertionError("Never dispatch agents")),
    )
    store = SimpleNamespace(
        _sessions=f.open,
        _guard=AsyncMock(return_value=(f.engagement, None)),
        approval_id=lambda task_id: f.approval.id,
        _append_event=AsyncMock(side_effect=lambda _db, *_args, **_kw: f.events.append(_args)),
    )
    monkeypatch.setattr(resume, "PlannerExecutionStore", lambda _memory: store)
    monkeypatch.setattr(resume, "guard_sql", AsyncMock(return_value=SimpleNamespace(version=4)))
    return f, orch, store


@pytest.mark.asyncio
async def test_approved_adaptive_continuation_returns_durable_inert_proposal(harness):
    f, orch, store = harness

    async def settled_decision(*args, **kwargs):
        f.parked.status = "completed"
        f.flow.revision = 9
        return {"action": "create_hypothesis", "parameters": {"statement": "Investigate passive logs"},
                "provenance": "LLM", "_planner_flow_revision": 9}

    orch.adaptive_planner.evaluate_and_plan_next_step.side_effect = settled_decision
    result = await resume.resume_approved_adaptive_plan(
        orch, request_id=f.approval.id, engagement_id=f.engagement_id,
        actor_id="signed-senior", actor_role="senior_operator",
        expected_authorization_version=4, expected_flow_revision=8,
    )
    assert result == {
        "status": "proposal_ready", "approval_id": f.approval.id,
        "flow_id": f.flow_id, "flow_revision": 9,
        "planner_task_id": f.parked.id, "review_required": True,
        "execution_started": False,
        "proposal": {"action": "create_hypothesis", "parameters": {"statement": "Investigate passive logs"}, "provenance": "LLM"},
    }
    assert f.parked.result["review_status"] == "operator_review"
    assert len(f.events) == 1
    orch.schedule_task.assert_not_awaited()
    # A consumed paid planner may not replay the provider or reproduce a task.
    with pytest.raises(resume.AdaptiveResumeDenied):
        await resume.resume_approved_adaptive_plan(
            orch, request_id=f.approval.id, engagement_id=f.engagement_id,
            actor_id="signed-senior", actor_role="senior_operator",
            expected_authorization_version=4, expected_flow_revision=8,
        )
    assert orch.adaptive_planner.evaluate_and_plan_next_step.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("modification", [
    "role", "revoked", "stale_flow", "not_completed", "rejected", "already_running", "wrong_version",
])
async def test_denied_adaptive_continuation_never_contacts_provider(harness, monkeypatch, modification):
    f, orch, store = harness
    args = dict(
        request_id=f.approval.id, engagement_id=f.engagement_id,
        actor_id="signed-senior", actor_role="senior_operator",
        expected_authorization_version=4, expected_flow_revision=8,
    )
    if modification == "role":
        args["actor_role"] = "operator"
    elif modification == "revoked":
        resume.guard_sql.side_effect = PermissionError("Signer revoked")
    elif modification == "stale_flow":
        f.flow.revision = 9
    elif modification == "not_completed":
        f.parent.status = "running"
    elif modification == "rejected":
        f.approval.status = "rejected"
    elif modification == "already_running":
        f.parked.status = "running"
    elif modification == "wrong_version":
        args["expected_authorization_version"] = 5
        resume.guard_sql.side_effect = PermissionError("Signer version changed")
    with pytest.raises((resume.AdaptiveResumeDenied, resume.AdaptiveResumeUnavailable)):
        await resume.resume_approved_adaptive_plan(orch, **args)
    orch.adaptive_planner.evaluate_and_plan_next_step.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_revocation_during_model_invalidates_receipt_without_dispatch(harness):
    f, orch, _ = harness
    guard_calls = 0

    async def signing(_db, _sid, *, expected_version=None):
        nonlocal guard_calls
        guard_calls += 1
        if guard_calls > 1:
            raise PermissionError("Signer revoked after provider call")
        return SimpleNamespace(version=4)

    resume.guard_sql.side_effect = signing

    async def paid_result(*args, **kwargs):
        f.parked.status = "completed"
        f.flow.revision = 9
        return {"action": "stop", "parameters": {}, "_planner_flow_revision": 9}

    orch.adaptive_planner.evaluate_and_plan_next_step.side_effect = paid_result
    with pytest.raises(resume.AdaptiveResumeDenied):
        await resume.resume_approved_adaptive_plan(
            orch, request_id=f.approval.id, engagement_id=f.engagement_id,
            actor_id="signed-senior", actor_role="senior_operator",
            expected_authorization_version=4, expected_flow_revision=8,
        )
    assert f.parked.result["review_status"] == "invalidated"
    assert f.parked.result["adaptive_proposal"] is None
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_durable_proposal_is_readable_without_model_replay(harness):
    f, orch, _ = harness
    f.parked.status = "completed"
    f.parked.payload["planner_flow_revision"] = 9
    f.parked.result = {
        "status": "completed", "review_status": "operator_review",
        "adaptive_proposal": {
            "action": "create_hypothesis",
            "parameters": {"statement": "Review passive evidence"},
            "provenance": "LLM",
        },
    }
    f.flow.revision = 9
    result = await resume.read_approved_adaptive_proposal(
        orch, request_id=f.approval.id, engagement_id=f.engagement_id,
    )
    assert result["status"] == "proposal_ready"
    assert result["approval_id"] == f.approval.id
    assert result["execution_started"] is False
    assert result["proposal"]["parameters"]["statement"] == "Review passive evidence"
    orch.adaptive_planner.evaluate_and_plan_next_step.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("staleness", ["signed_revoked", "flow_paused", "flow_revised", "no_receipt"])
async def test_stale_settled_proposal_is_not_exposed_as_reviewable(harness, staleness):
    f, orch, _ = harness
    f.parked.status = "completed"
    f.parked.payload["planner_flow_revision"] = 9
    f.parked.result = {
        "status": "completed", "review_status": "operator_review",
        "adaptive_proposal": {"action": "stop", "parameters": {}},
    }
    f.flow.revision = 9
    if staleness == "signed_revoked":
        resume.guard_sql.side_effect = PermissionError("Signer revoked")
    elif staleness == "flow_paused":
        f.flow.status = "paused"
    elif staleness == "flow_revised":
        f.flow.revision = 10
    elif staleness == "no_receipt":
        f.parked.result = None
    with pytest.raises((resume.AdaptiveResumeDenied, resume.AdaptiveResumeUnavailable)):
        await resume.read_approved_adaptive_proposal(
            orch, request_id=f.approval.id, engagement_id=f.engagement_id,
        )
    orch.adaptive_planner.evaluate_and_plan_next_step.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()


def test_proposed_recon_is_only_returned_if_inside_signed_target_scope(harness):
    f, _, _ = harness
    valid = resume._safe_proposal({
        "action": "request_sub_recon", "parameters": {"target": "example.com"}
    }, f.scope)
    assert valid == {"action": "request_sub_recon", "parameters": {"target": "example.com"}}
    unsafe = resume._safe_proposal({
        "action": "request_sub_recon", "parameters": {"target": "outside.example.net"}
    }, f.scope)
    assert unsafe["action"] == "blocked"
    assert "outside.example.net" not in str(unsafe)
