"""Isolated planner admission races and uncertain provider receipts.

This deterministic SQL adapter models a transaction lock and commits/rollbacks;
it does not claim to qualify PostgreSQL itself.
"""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.models import FlowRecord, ScopeDefinition, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.orchestrator import planner_execution as module
from ai_osop.orchestrator import engagement_controller, flow_refinement


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class State:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.flow = FlowRecord(
            id="flow-a", engagement_id="eng-a", objective="Assessment", status="running"
        )
        self.parent = Task(
            id="task-objective-a",
            engagement_id="eng-a",
            type="flow_objective",
            agent_type=AgentType.RECON,
            status="planned",
            flow_id=self.flow.id,
        )
        self.tasks = {self.parent.id: SimpleNamespace(**self.parent.model_dump())}
        self.approvals = {}
        self.events = []
        self.block_revision = False

    def open(self):
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
            snapshot = deepcopy(
                (self.state.flow, self.state.tasks, self.state.approvals, self.state.events)
            )
            try:
                yield
            except BaseException:
                self.state.flow, self.state.tasks, self.state.approvals, self.state.events = (
                    snapshot
                )
                raise

    async def execute(self, statement):
        sql = str(statement)
        params = statement.compile().params
        if "FROM supervision_controls" in sql:
            return Result(None)
        if "FROM approval_requests" in sql:
            identifier = next((v for k, v in params.items() if k.startswith("id_")), None)
            return Result(self.state.approvals.get(identifier))
        if "FROM execution_flows" in sql:
            return Result(self.state.flow)
        if "FROM tasks" in sql:
            identifier = next((v for k, v in params.items() if k.startswith("id_")), None)
            row = self.state.tasks.get(identifier)
            if row and "tasks.status = " in sql and row.status != "completed":
                row = None
            if row and not isinstance(statement.column_descriptions[0]["expr"], type):
                row = row.id
            return Result(row)
        if sql.startswith("UPDATE execution_flows"):
            expected = params.get("revision_2")
            if self.state.block_revision or expected != self.state.flow.revision:
                return Result(None)
            self.state.flow.revision += 1
            return Result(self.state.flow.revision)
        if sql.startswith("UPDATE tasks"):
            task_id = next((v for k, v in params.items() if k.startswith("id_")), None)
            row = self.state.tasks.get(task_id)
            if row is None or row.status != "running":
                return Result(None)
            row.status = next(
                v for v in params.values() if v in {"completed", "failed", "dispatch_unknown"}
            )
            return Result(row.id)
        raise AssertionError(f"Unexpected SQL statement: {sql[:120]}")

    def add(self, row):
        if row.__tablename__ == "tasks":
            self.state.tasks[row.id] = row
        elif row.__tablename__ == "approval_requests":
            self.state.approvals[row.id] = row
        elif row.__tablename__ == "supervision_events":
            self.state.events.append((row.kind, row.task_id))

    async def flush(self):
        return None


@pytest.fixture
def planner(monkeypatch):
    state = State()
    memory = SimpleNamespace(_async_session=state.open)
    store = module.PlannerExecutionStore(memory)
    store._guard = AsyncMock(
        return_value=(
            SimpleNamespace(
                scope=ScopeDefinition(
                    engagement_id="eng-a",
                    domains=["example.com"],
                    authorization_ref="signed",
                ).model_dump(mode="json"),
                roe={"adaptive_planning_enabled": True},
            ),
            None,
        )
    )

    async def guard_sql(_db, _id, *, expected_version=None):
        if expected_version is not None and expected_version != 9:
            raise PermissionError("Stale signing version")
        return SimpleNamespace(version=9)

    monkeypatch.setattr(module, "guard_sql", AsyncMock(side_effect=guard_sql))

    async def append(db, engagement_id, task_id, kind, *args, **kwargs):
        state.events.append((kind, task_id))

    store._append_event = append
    return store, state


@pytest.mark.asyncio
async def test_competing_planner_replicas_admit_exactly_one_execution(planner):
    store, state = planner
    other = module.PlannerExecutionStore(store.session_memory)
    other._guard = store._guard
    other._append_event = store._append_event
    outcomes = await asyncio.gather(
        store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation"),
        other.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation"),
        return_exceptions=True,
    )
    admitted = [item for item in outcomes if isinstance(item, module.PlannerAdmission)]
    rejected = [item for item in outcomes if isinstance(item, ModelBudgetExceeded)]
    assert len(admitted) == len(rejected) == 1
    assert admitted[0].revision == state.flow.revision == 1
    assert state.tasks[admitted[0].task_id].status == "running"
    assert state.tasks[admitted[0].task_id].payload == {
        "_authorization_version": 9,
        "planner_purpose": "flow_generation",
    }
    assert state.events == [("planner.admitted", admitted[0].task_id)]

    await store.finish(admitted[0], "dispatch_unknown")
    assert state.tasks[admitted[0].task_id].status == "dispatch_unknown"
    assert state.events[-1] == ("planner.finished", admitted[0].task_id)
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    with pytest.raises(RuntimeError, match="CAS"):
        await store.finish(admitted[0], "completed")


@pytest.mark.asyncio
async def test_stale_flow_and_missing_signer_fail_without_planner_task(planner, monkeypatch):
    store, state = planner
    state.block_revision = True
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    assert len(state.tasks) == 1 and state.flow.revision == 0 and not state.events
    state.block_revision = False
    module.guard_sql.side_effect = RuntimeError("signer unavailable")
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    assert len(state.tasks) == 1 and state.flow.revision == 0 and not state.events


@pytest.mark.asyncio
async def test_model_outcome_unknown_restores_parent_context_and_has_no_fallback(planner):
    store, state = planner
    admission = await store.admit(
        state.flow.model_copy(deep=True), state.parent, purpose="flow_generation"
    )
    RequestContext.bind(engagement_id="eng-parent", task_id="task-parent", flow_id="flow-parent")
    try:

        async def uncertain(*args, **kwargs):
            assert RequestContext.get()["task_id"] == admission.task_id
            raise RuntimeError("connection dropped after send")

        with pytest.raises(ModelOutcomeUncertain):
            await module.run_planner_completion(store, admission, uncertain)
        assert RequestContext.get()["task_id"] == "task-parent"
        assert RequestContext.get()["flow_id"] == "flow-parent"
        assert state.tasks[admission.task_id].status == "dispatch_unknown"
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
async def test_db_receipt_failure_after_provider_success_is_uncertain(planner):
    store, state = planner
    admission = await store.admit(
        state.flow.model_copy(deep=True), state.parent, purpose="flow_generation"
    )
    store.finish = AsyncMock(side_effect=OSError("database is offline"))
    completed = AsyncMock(return_value="valid LLM response")
    with pytest.raises(ModelOutcomeUncertain):
        await module.run_planner_completion(store, admission, completed)
    completed.assert_awaited_once()
    assert state.tasks[admission.task_id].status == "running"


@pytest.mark.asyncio
async def test_explicit_planner_approval_policy_parks_provider_until_human_decision(planner):
    store, state = planner
    scope = ScopeDefinition(
        engagement_id="eng-a",
        domains=["example.com"],
        authorization_ref="signed",
        approval_required_for=["planner_inference"],
    )
    store._guard.return_value = (SimpleNamespace(scope=scope.model_dump(mode="json"), roe={}), None)
    with pytest.raises(module.PlannerApprovalPending) as exc:
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    pending = exc.value
    assert pending.response() == {
        "status": "awaiting_planner_approval",
        "approval_id": pending.approval_id,
        "task_id": pending.task_id,
        "flow_revision": 1,
    }
    assert len(state.tasks) == 2 and state.flow.revision == 1
    assert state.tasks[pending.task_id].status == "awaiting_approval"
    assert state.tasks[pending.task_id].approval_required
    assert state.tasks[pending.task_id].started_at is None
    assert state.tasks[pending.task_id].payload["planner_flow_revision"] == 1
    assert state.approvals[pending.approval_id].status == "pending"
    assert state.events == [("planner.approval_requested", pending.task_id)]
    with pytest.raises(module.PlannerApprovalPending):
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    assert state.flow.revision == 1 and len(state.events) == 1


async def _park_planner(store, state):
    scope = ScopeDefinition(
        engagement_id="eng-a",
        domains=["example.com"],
        authorization_ref="signed",
        approval_required_for=["planner_inference"],
    )
    store._guard.return_value = (
        SimpleNamespace(
            scope=scope.model_dump(mode="json"),
            roe={"adaptive_planning_enabled": True},
        ),
        None,
    )
    with pytest.raises(module.PlannerApprovalPending) as raised:
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    return raised.value


def _decision_args(
    pending,
    *,
    decision="approved",
    operator_id="senior-1",
    revision=None,
    version=9,
    role="senior_operator",
):
    return dict(
        request_id=pending.approval_id,
        engagement_id="eng-a",
        task_id=pending.task_id,
        decision=decision,
        operator_id=operator_id,
        actor_role=role,
        expected_authorization_version=version,
        expected_flow_revision=pending.revision if revision is None else revision,
    )


@pytest.mark.asyncio
async def test_human_approval_never_dispatches_agent_and_resumed_task_is_fenced(planner):
    store, state = planner
    pending = await _park_planner(store, state)
    decision, changed = await store.resolve_internal_approval(**_decision_args(pending))
    assert changed and decision.status == "approved"
    assert decision.operator_id == "senior-1" and decision.responded_at
    assert state.tasks[pending.task_id].status == "awaiting_approval"
    assert state.tasks[pending.task_id].payload["approval_id"] == pending.approval_id
    assert len(state.events) == 2
    assert state.events[-1] == ("planner.approval_resolved", pending.task_id)
    # Independent replicas cannot each consume this one human decision.
    other = module.PlannerExecutionStore(store.session_memory)
    other._guard = store._guard
    other._append_event = store._append_event
    results = await asyncio.gather(
        store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation"),
        other.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation"),
        return_exceptions=True,
    )
    accepted = [r for r in results if isinstance(r, module.PlannerAdmission)]
    rejected = [r for r in results if isinstance(r, ModelBudgetExceeded)]
    assert len(accepted) == len(rejected) == 1
    assert accepted[0].revision == state.flow.revision == 2
    assert state.tasks[pending.task_id].status == "running"
    assert state.tasks[pending.task_id].payload["_authorization_version"] == 9
    assert state.events[-1] == ("planner.admitted", pending.task_id)


@pytest.mark.asyncio
async def test_internal_approval_competing_operator_decisions_are_immutable(planner):
    store, state = planner
    pending = await _park_planner(store, state)
    other = module.PlannerExecutionStore(store.session_memory)
    other._guard = store._guard
    other._append_event = store._append_event
    approvals = await asyncio.gather(
        store.resolve_internal_approval(**_decision_args(pending, decision="approved")),
        other.resolve_internal_approval(
            **_decision_args(pending, decision="rejected", operator_id="senior-2")
        ),
    )
    assert sorted(changed for _, changed in approvals) == [False, True]
    assert approvals[0][0].status == approvals[1][0].status
    assert len(state.events) == 2
    assert state.approvals[pending.approval_id].operator_id in {"senior-1", "senior-2"}
    assert state.tasks[pending.task_id].status == (
        "awaiting_approval" if approvals[0][0].status == "approved" else "failed"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override",
    [
        {"role": "operator"},
        {"version": 10},
        {"revision": 4},
        {"operator_id": ""},
    ],
)
async def test_internal_approval_denied_for_non_senior_or_stale_version(planner, override):
    store, state = planner
    pending = await _park_planner(store, state)
    args = _decision_args(pending, **override)
    with pytest.raises((PermissionError, RuntimeError)):
        await store.resolve_internal_approval(**args)
    assert state.approvals[pending.approval_id].status == "pending"
    assert state.tasks[pending.task_id].status == "awaiting_approval"
    assert len(state.events) == 1


@pytest.mark.asyncio
async def test_rejection_is_terminal_and_never_replays_planner(planner):
    store, state = planner
    pending = await _park_planner(store, state)
    result, changed = await store.resolve_internal_approval(
        **_decision_args(pending, decision="rejected")
    )
    assert changed and result.status == "rejected"
    assert state.tasks[pending.task_id].status == "failed"
    assert state.tasks[pending.task_id].result["reason"] == "operator_rejected"
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    assert state.flow.revision == 1


@pytest.mark.asyncio
async def test_closed_flow_or_revoked_signer_cannot_approve_internal_task(planner):
    store, state = planner
    pending = await _park_planner(store, state)
    state.flow.status = "paused"
    with pytest.raises(PermissionError):
        await store.resolve_internal_approval(**_decision_args(pending))
    assert state.approvals[pending.approval_id].status == "pending"
    state.flow.status = "running"
    module.guard_sql.side_effect = PermissionError("signer removed")
    with pytest.raises(PermissionError):
        await store.resolve_internal_approval(**_decision_args(pending))
    assert state.approvals[pending.approval_id].status == "pending"


@pytest.mark.asyncio
async def test_approval_event_storage_failure_rolls_back_human_decision(planner):
    store, state = planner
    pending = await _park_planner(store, state)

    async def unavailable_outbox(*args, **kwargs):
        raise OSError("event or outbox is offline")

    store._append_event = unavailable_outbox
    with pytest.raises(RuntimeError, match="unavailable"):
        await store.resolve_internal_approval(**_decision_args(pending))
    assert state.approvals[pending.approval_id].status == "pending"
    assert state.tasks[pending.task_id].status == "awaiting_approval"
    assert state.tasks[pending.task_id].payload.get("approval_id") is None
    assert state.events == [("planner.approval_requested", pending.task_id)]


@pytest.mark.asyncio
async def test_request_event_failure_rolls_back_task_and_flow(planner):
    store, state = planner
    scope = ScopeDefinition(
        engagement_id="eng-a",
        domains=["example.com"],
        authorization_ref="signed",
        approval_required_for=["planner_inference"],
    )
    store._guard.return_value = (SimpleNamespace(scope=scope.model_dump(mode="json"), roe={}), None)

    async def unavailable_outbox(*args, **kwargs):
        raise OSError("outbox unavailable")

    store._append_event = unavailable_outbox
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    assert state.flow.revision == 0
    assert list(state.tasks) == [state.parent.id]
    assert not state.approvals and not state.events


@pytest.mark.asyncio
async def test_approved_planner_lease_cannot_resume_after_flow_revision_changes(planner):
    store, state = planner
    pending = await _park_planner(store, state)
    await store.resolve_internal_approval(**_decision_args(pending))
    state.flow.revision += 1
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(state.flow.model_copy(deep=True), state.parent, purpose="flow_generation")
    assert state.tasks[pending.task_id].status == "awaiting_approval"
    assert len(state.events) == 2


@pytest.mark.asyncio
async def test_operator_flow_endpoint_returns_pending_without_proposing_steps():
    # Keep this test independent of actual SQL. It tests propagation from the
    # already persisted pending approval to the operator result contract.
    fake = SimpleNamespace(
        session_memory=AsyncMock(),
        llm_client=PaidStub(),
        _sessions={},
    )
    flow = FlowRecord(id="flow-operator", engagement_id="eng-a", objective="Authorized review")
    task = Task(
        id="task-objective",
        type="flow_objective",
        agent_type=AgentType.RECON,
        engagement_id="eng-a",
        flow_id=flow.id,
        status="planned",
    )
    fake.session_memory.list_subtasks.return_value = []
    refiner = flow_refinement.BoundedFlowRefiner(fake)
    refiner._resolve = AsyncMock(return_value=(flow, task, SimpleNamespace()))
    refiner._propose = AsyncMock(
        side_effect=module.PlannerApprovalPending("apr-planner-example", "task-planner-example", 6)
    )
    refiner._persist = AsyncMock()
    result = await refiner.generate(flow.id, task.id)
    assert result == {
        "status": "awaiting_planner_approval",
        "approval_id": "apr-planner-example",
        "task_id": "task-planner-example",
        "flow_revision": 6,
    }
    refiner._persist.assert_not_awaited()


@pytest.mark.asyncio
async def test_adaptive_planner_waits_for_human_without_consuming_iteration():
    from tests.test_adaptive_planner_runtime import make_orchestrator, completed_recon

    orch, sm, _, cached = make_orchestrator(max_iterations=2)
    sm.load_flow.return_value = FlowRecord(
        id=orch.adaptive_planner._flow_id("eng-test"),
        engagement_id="eng-test",
        objective="Scoped review",
    )
    planner = orch.adaptive_planner
    planner.evaluate_and_plan_next_step = AsyncMock(
        side_effect=module.PlannerApprovalPending("apr-planner-ex", "task-planner-ex", 8)
    )
    task = completed_recon("task-parent")
    result = await planner.on_task_completed(task)
    assert result["status"] == "awaiting_planner_approval"
    assert result["approval_id"] == "apr-planner-ex"
    assert cached["adaptive_plan:eng-test"]["iterations"] == 0
    orch.schedule_task.assert_not_awaited()


class PaidStub(LiteLLMClient):
    """A real-client type whose provider boundary is replaced by a stub."""

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = 0
        self.seen = []

    async def complete(self, *args, **kwargs):
        self.calls += 1
        self.seen.append(RequestContext.get().copy())
        if self.error:
            raise self.error
        return self.result


class AdmissionStub:
    def __init__(self, memory):
        self.admits = []
        self.finishes = []
        self.fail_finish = False

    async def admit(self, flow, parent, **kwargs):
        self.admits.append((flow, parent, kwargs))
        return module.PlannerAdmission(
            "task-planner-real",
            flow.engagement_id,
            flow.id,
            flow.revision + 1,
            kwargs.get("source_id"),
        )

    async def finish(self, admission, outcome):
        if self.fail_finish:
            raise OSError("receipt unavailable")
        self.finishes.append(outcome)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure,expected_receipt",
    [
        (None, "completed"),
        (RuntimeError("provider response lost"), "dispatch_unknown"),
        (ModelBudgetExceeded("quota denied"), "failed"),
    ],
)
async def test_real_client_flow_refiner_uses_admitted_child_and_restores_context(
    monkeypatch, failure, expected_receipt
):
    paid = PaidStub(
        result='{"steps":[{"title":"Summarize evidence",'
        '"task_type":"summarize_context","agent_type":"context_manager"}]}',
        error=failure,
    )
    store = AdmissionStub(None)
    monkeypatch.setattr(flow_refinement, "PlannerExecutionStore", lambda _: store)
    refiner = flow_refinement.BoundedFlowRefiner(
        SimpleNamespace(llm_client=paid, session_memory=None)
    )
    session = SimpleNamespace(
        session_id="eng-test",
        phase="reconnaissance",
        roe={},
        scope=ScopeDefinition(
            engagement_id="eng-test", domains=["example.com"], authorization_ref="signed"
        ),
    )
    flow = FlowRecord(id="flow-plan", engagement_id="eng-test", objective="Map authorized APIs")
    task = Task(
        id="task-objective",
        engagement_id="eng-test",
        type="flow_objective",
        flow_id=flow.id,
        status="planned",
        agent_type=AgentType.RECON,
    )
    RequestContext.bind(engagement_id="outer", task_id="task-outer")
    try:
        if failure is not None:
            with pytest.raises(
                type(failure) if isinstance(failure, ModelBudgetExceeded) else ModelOutcomeUncertain
            ):
                await refiner._propose(flow, task, session, [], None)
        else:
            steps, provenance, admitted_flow = await refiner._propose(flow, task, session, [], None)
            assert provenance == "llm" and len(steps) == 1
            assert admitted_flow.revision == flow.revision + 1
        assert store.admits[0][2]["purpose"] == "flow_generation"
        assert paid.seen[0]["task_id"] == "task-planner-real"
        assert paid.seen[0]["engagement_id"] == "eng-test"
        assert store.finishes == [expected_receipt]
        assert RequestContext.get()["task_id"] == "task-outer"
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
async def test_real_client_strategic_planning_admits_child_of_completed_task(monkeypatch):
    paid = PaidStub(result='{"action":"stop","reasoning":"Enough evidence","parameters":{}}')
    store = AdmissionStub(None)
    monkeypatch.setattr(engagement_controller, "PlannerExecutionStore", lambda _: store)
    controller = engagement_controller.GoalOrientedEngagementController(
        SimpleNamespace(llm_client=paid, session_memory=None)
    )
    controller.build_engagement_state_summary = AsyncMock(return_value={"endpoints_count": 3})
    flow = FlowRecord(
        id="flow-adaptive", engagement_id="eng-test", objective="Review discovery", revision=5
    )
    parent = Task(
        id="task-recon",
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-test",
        status="completed",
    )
    decision = await controller.evaluate_and_plan_next_step(
        "eng-test", parent_task=parent, flow=flow
    )
    assert decision["action"] == "stop" and decision["provenance"] == "LLM"
    assert decision["_planner_flow_revision"] == 6
    assert store.admits[0][2]["purpose"] == "adaptive_planning"
    assert store.admits[0][1].id == parent.id
    assert store.finishes == ["completed"]
    assert paid.seen[0]["task_id"] == "task-planner-real"


@pytest.mark.asyncio
async def test_real_client_planner_receipt_failure_never_falls_back(monkeypatch):
    paid = PaidStub(result='{"action":"stop","parameters":{}}')
    store = AdmissionStub(None)
    store.fail_finish = True
    monkeypatch.setattr(engagement_controller, "PlannerExecutionStore", lambda _: store)
    controller = engagement_controller.GoalOrientedEngagementController(
        SimpleNamespace(llm_client=paid, session_memory=None)
    )
    controller.build_engagement_state_summary = AsyncMock(return_value={})
    controller._heuristic_fallback_plan = AsyncMock()
    flow = FlowRecord(id="flow-adaptive", engagement_id="eng-test", objective="Review discovery")
    parent = Task(
        id="task-recon",
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-test",
        status="completed",
    )
    with pytest.raises(ModelOutcomeUncertain):
        await controller.evaluate_and_plan_next_step("eng-test", parent_task=parent, flow=flow)
    controller._heuristic_fallback_plan.assert_not_awaited()


@pytest.mark.asyncio
async def test_paid_planner_cancellation_during_finalization_persists_unknown(planner):
    """A cancelled post-provider callback cannot turn a billed call retryable."""
    store, state = planner
    admission = module.PlannerAdmission(
        "task-planner-" + "a" * 32,
        state.flow.engagement_id,
        state.flow.id,
        1,
        None,
    )
    state.tasks[admission.task_id] = SimpleNamespace(
        id=admission.task_id,
        status="running",
        type="planner_inference",
        engagement_id=admission.engagement_id,
    )
    provider = AsyncMock(return_value='{"steps":[]}')

    async def cancelled_finalizer(_raw):
        await asyncio.sleep(0)
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await module.run_planner_completion(
            store,
            admission,
            provider,
            ["approved"],
            finalize=cancelled_finalizer,
        )
    provider.assert_awaited_once()
    assert state.tasks[admission.task_id].status == "dispatch_unknown"
    assert state.events == [("planner.finished", admission.task_id)]


@pytest.mark.asyncio
async def test_paid_planner_cancelled_unknown_receipt_failure_retains_single_use_claim(planner):
    store, state = planner
    admission = module.PlannerAdmission(
        "task-planner-" + "b" * 32,
        state.flow.engagement_id,
        state.flow.id,
        1,
        None,
    )
    state.tasks[admission.task_id] = SimpleNamespace(
        id=admission.task_id,
        status="running",
        type="planner_inference",
        engagement_id=admission.engagement_id,
    )
    provider = AsyncMock(return_value="response")
    store.finish = AsyncMock(side_effect=OSError("unavailable database"))

    async def cancelled_finalizer(_raw):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await module.run_planner_completion(
            store,
            admission,
            provider,
            [],
            finalize=cancelled_finalizer,
        )
    provider.assert_awaited_once()
    store.finish.assert_awaited_once_with(admission, "dispatch_unknown")
    assert state.tasks[admission.task_id].status == "running"
