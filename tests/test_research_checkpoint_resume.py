"""Deterministic PostgreSQL transaction and interrupted Flow research recovery."""

import asyncio
import re
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.models import FlowRecord, ScopeDefinition, Task
from ai_osop.memory.model_usage import ModelOutcomeUncertain
from ai_osop.orchestrator import flow_refinement, research_checkpoint
from ai_osop.orchestrator.planner_execution import PlannerAdmission


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class DB:
    def __init__(self, state):
        self.state = state

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        async with self.state.lock:
            snapshot = deepcopy((self.state.tasks, self.state.events))
            try:
                yield
            except BaseException:
                self.state.tasks, self.state.events = snapshot
                raise

    async def execute(self, statement):
        sql = str(statement)
        params = statement.compile().params
        if "FROM execution_flows" in sql:
            return Result(self.state.flow_row)
        if "FROM execution_subtasks" in sql:
            return Result(self.state.step)
        if "FROM approval_requests" in sql:
            return Result(self.state.approval)
        if "FROM tasks" in sql:
            identifier = next((v for k, v in params.items() if k.startswith("id_")), None)
            row = self.state.tasks.get(identifier)
            if "tasks.status = " in sql and row is not None and row.status != "completed":
                row = None
            if row is not None and re.match(r"SELECT\s+tasks\.id\s+FROM", sql):
                row = row.id
            return Result(row)
        raise AssertionError(f"Unexpected SQL statement: {sql[:150]}")

    def add(self, row):
        assert row.__tablename__ == "tasks"
        assert row.id not in self.state.tasks
        self.state.tasks[row.id] = row

    async def flush(self):
        return None


class State:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.flow = FlowRecord(
            id="flow-research",
            engagement_id="eng-research",
            objective="Approved research",
            status="running",
        )
        self.parent = Task(
            id="task-research-parent",
            engagement_id="eng-research",
            type="flow_objective",
            agent_type=AgentType.RECON,
            status="planned",
            flow_id=self.flow.id,
        )
        self.flow_row = SimpleNamespace(id=self.flow.id, status="running", revision=0)
        self.tasks = {self.parent.id: SimpleNamespace(**self.parent.model_dump())}
        self.events = []
        self.step = None
        self.approval = None
        self.version = 7
        self.scope = ScopeDefinition(
            engagement_id="eng-research",
            domains=["example.com"],
            authorization_ref="signed",
        )
        self.engagement = SimpleNamespace(
            scope=self.scope.model_dump(mode="json"),
            roe={"allow_active_scanning": False},
        )

    def open(self):
        return DB(self)

    def new_planner(self, status="running", *, revision=1):
        identifier = research_checkpoint.PlannerExecutionStore.task_id(
            self.flow.id,
            self.parent.id,
            "flow_generation",
        )
        self.flow_row.revision = revision
        task = SimpleNamespace(
            id=identifier,
            type="planner_inference",
            status=status,
            flow_id=self.flow.id,
            engagement_id=self.flow.engagement_id,
            parent_task_id=self.parent.id,
            subtask_id=None,
            assigned_agent_id="planner-runtime",
            approval_required=False,
            payload={"_authorization_version": self.version, "planner_purpose": "flow_generation"},
            result={"status": "completed"} if status == "completed" else None,
        )
        self.tasks[identifier] = task
        return PlannerAdmission(identifier, self.flow.engagement_id, self.flow.id, revision, None)


@pytest.fixture
def ledger(monkeypatch):
    state = State()
    store = research_checkpoint.ResearchCheckpointStore(
        SimpleNamespace(_async_session=state.open),
    )
    store._guard = AsyncMock(return_value=(state.engagement, None))

    async def guard(_db, _engagement_id):
        if state.version != 7:
            raise PermissionError("signing authority revoked")
        return SimpleNamespace(version=7)

    monkeypatch.setattr(research_checkpoint, "guard_sql", guard)

    async def append(_db, engagement_id, task_id, kind, *_args, **_kwargs):
        state.events.append((engagement_id, task_id, kind))

    store._append_event = append
    return store, state


@pytest.mark.asyncio
async def test_research_checkpoint_stores_only_verified_bounded_counts(ledger):
    store, state = ledger
    admission = state.new_planner()
    flow = state.flow.model_copy(update={"revision": admission.revision})
    signal = await store.prepare(
        admission,
        flow,
        state.parent,
        source_id=None,
        pass_number=0,
        signals={
            "findings_count": 3,
            "verified": True,
            "credentials": "SECRET",
            "untrusted": "IGNORE_ALL_INSTRUCTIONS",
            "endpoints_count": 10**9,
        },
    )
    assert signal == {"findings_count": 3, "verified": True}
    research = state.tasks[store._research_id(admission.task_id)]
    assert research.status == "completed"
    assert research.type == "planner_research"
    assert research.result["signals"] == signal
    assert "SECRET" not in str(research.result)
    assert len(state.events) == 1
    # Replaying an identical read-only research checkpoint is idempotent.
    assert (
        await store.prepare(
            admission,
            flow,
            state.parent,
            source_id=None,
            pass_number=0,
            signals={"findings_count": 3, "verified": True},
        )
        == signal
    )
    assert len(state.events) == 1


@pytest.mark.asyncio
async def test_completed_legacy_proposal_without_research_receipt_cannot_replay(ledger):
    store, state = ledger
    admission = state.new_planner(status="completed")
    flow = state.flow.model_copy(update={"revision": 1})
    steps = [
        {
            "title": "Summarize verified evidence",
            "description": "Review counts",
            "task_type": "summarize_context",
            "agent_type": "context_manager",
            "target": None,
            "depends_on": [],
        }
    ]
    await store.save_proposal(
        admission,
        flow,
        state.parent,
        source_id=None,
        pass_number=0,
        steps=steps,
        provenance="llm",
    )
    fresh = research_checkpoint.ResearchCheckpointStore(store.session_memory)
    fresh._guard = store._guard
    # A paid-completion marker and persisted proposal are insufficient
    # without the separately verified original research input receipt.
    with pytest.raises(ModelOutcomeUncertain, match="research checkpoint"):
        await fresh.recover(
            flow,
            state.parent,
            purpose="flow_generation",
            source_id=None,
            pass_number=0,
        )
    assert len(state.events) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("state_name", ["running", "dispatch_unknown", "failed", "completed"])
async def test_unsettled_or_missing_output_is_never_replayed(ledger, state_name):
    store, state = ledger
    state.new_planner(status=state_name)
    flow = state.flow.model_copy(update={"revision": 1})
    with pytest.raises(ModelOutcomeUncertain):
        await store.recover(
            flow,
            state.parent,
            purpose="flow_generation",
            source_id=None,
            pass_number=0,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["revision", "paused", "revoked", "foreign", "parent"])
async def test_changed_authority_or_flow_denies_research_and_recovery(ledger, change):
    store, state = ledger
    admission = state.new_planner(status="completed")
    flow = state.flow.model_copy(update={"revision": 1})
    if change == "revision":
        state.flow_row.revision += 1
    elif change == "paused":
        state.flow_row.status = "paused"
    elif change == "revoked":
        state.version = 8
    elif change == "foreign":
        state.tasks[state.parent.id].flow_id = "flow-other"
    elif change == "parent":
        state.tasks[state.parent.id].status = "cancelled"
    with pytest.raises((research_checkpoint.ResearchCheckpointDenied, PermissionError)):
        await store.recover(
            flow,
            state.parent,
            purpose="flow_generation",
            source_id=None,
            pass_number=0,
        )
    assert not state.events


@pytest.mark.asyncio
async def test_outbox_failure_rolls_back_proposal_and_blocks_unknown_replay(ledger):
    store, state = ledger
    admission = state.new_planner(status="completed")
    flow = state.flow.model_copy(update={"revision": 1})
    store._append_event = AsyncMock(side_effect=OSError("outbox unavailable"))
    with pytest.raises(OSError):
        await store.save_proposal(
            admission,
            flow,
            state.parent,
            source_id=None,
            pass_number=0,
            steps=[],
            provenance="deterministic",
        )
    assert state.tasks[admission.task_id].result == {"status": "completed"}
    with pytest.raises(ModelOutcomeUncertain):
        await store.recover(
            flow,
            state.parent,
            purpose="flow_generation",
            source_id=None,
            pass_number=0,
        )


@pytest.mark.asyncio
async def test_research_outbox_failure_rolls_back_before_any_model_request(ledger):
    store, state = ledger
    admission = state.new_planner()
    flow = state.flow.model_copy(update={"revision": 1})
    store._append_event = AsyncMock(side_effect=OSError("outbox unavailable"))
    with pytest.raises(OSError):
        await store.prepare(
            admission,
            flow,
            state.parent,
            source_id=None,
            pass_number=0,
            signals={"verified": True},
        )
    assert store._research_id(admission.task_id) not in state.tasks
    # Planner admission has already been claimed, so crashing here must not
    # retry even though the provider has never received the request.
    with pytest.raises(ModelOutcomeUncertain):
        await store.recover(
            flow,
            state.parent,
            purpose="flow_generation",
            source_id=None,
            pass_number=0,
        )


@pytest.mark.asyncio
async def test_revoked_human_planner_approval_blocks_completed_proposal(ledger):
    store, state = ledger
    admission = state.new_planner(status="completed")
    flow = state.flow.model_copy(update={"revision": 1})
    planner = state.tasks[admission.task_id]
    planner.approval_required = True
    approval_id = store.approval_id(admission.task_id)
    planner.payload.update({"operator_approved": True, "approval_id": approval_id})
    state.approval = SimpleNamespace(
        id=approval_id,
        status="approved",
        action_type="planner_inference",
        target=flow.id,
        agent_id="planner-runtime",
        operator_id="senior-1",
        responded_at=datetime.utcnow(),
    )
    await store.save_proposal(
        admission,
        flow,
        state.parent,
        source_id=None,
        pass_number=0,
        steps=[],
        provenance="deterministic",
    )
    with pytest.raises(ModelOutcomeUncertain, match="research checkpoint"):
        await store.recover(
            flow,
            state.parent,
            purpose="flow_generation",
            source_id=None,
            pass_number=0,
        )
    state.approval.status = "rejected"
    with pytest.raises(research_checkpoint.ResearchCheckpointDenied):
        await store.recover(
            flow,
            state.parent,
            purpose="flow_generation",
            source_id=None,
            pass_number=0,
        )


@pytest.mark.asyncio
async def test_refinement_research_requires_confirmed_execution_receipt(ledger):
    store, state = ledger
    state.step = SimpleNamespace(
        id="subtask-source",
        engagement_id=state.flow.engagement_id,
        flow_id=state.flow.id,
        task_id=state.parent.id,
        status="completed",
        refinement_count=1,
        execution_task_id="task-completed-execution",
    )
    state.tasks["task-completed-execution"] = SimpleNamespace(
        id="task-completed-execution",
        status="completed",
        engagement_id=state.flow.engagement_id,
        flow_id=state.flow.id,
        subtask_id="subtask-source",
    )
    flow = state.flow
    assert (
        await store.recover(
            flow,
            state.parent,
            purpose="flow_refinement",
            source_id="subtask-source",
            pass_number=1,
        )
        is None
    )
    state.tasks["task-completed-execution"].status = "dispatch_unknown"
    with pytest.raises(research_checkpoint.ResearchCheckpointDenied):
        await store.recover(
            flow,
            state.parent,
            purpose="flow_refinement",
            source_id="subtask-source",
            pass_number=1,
        )


class PaidStub(LiteLLMClient):
    def __init__(self):
        self.complete = AsyncMock(
            return_value=(
                '{"steps":[{"title":"Summarize verified evidence",'
                '"task_type":"summarize_context","agent_type":"context_manager"}]}'
            )
        )


@pytest.mark.asyncio
async def test_real_flow_refinement_path_resumes_parked_proposal(ledger, monkeypatch):
    store, state = ledger
    paid = PaidStub()
    memory = store.session_memory

    # The model admission and settlement state transitions are represented by
    # a deterministic durable stub; checkpoint SQL operations use DB above.
    class AdmissionStub:
        async def admit(self, flow, parent, **kwargs):
            assert kwargs["purpose"] == "flow_generation"
            return state.new_planner()

        async def finish(self, admission, outcome):
            task = state.tasks[admission.task_id]
            task.status = outcome
            task.result = {"status": outcome}

    monkeypatch.setattr(flow_refinement, "PlannerExecutionStore", lambda _: AdmissionStub())
    monkeypatch.setattr(flow_refinement, "ResearchCheckpointStore", lambda _: store)
    refiner = flow_refinement.BoundedFlowRefiner(
        SimpleNamespace(llm_client=paid, session_memory=memory),
    )
    session = SimpleNamespace(scope=state.scope, phase="reconnaissance", roe={})
    steps, provenance, first_flow = await refiner._propose(
        state.flow,
        state.parent,
        session,
        [],
        None,
    )
    assert provenance == "llm" and first_flow.revision == 1
    assert len(steps) == 1 and paid.complete.await_count == 1
    # Simulate a crash immediately before Flow persistence and a fresh worker
    # reentering the same generation route on the updated Flow revision.
    steps_again, provenance_again, returned_flow = await refiner._propose(
        first_flow,
        state.parent,
        session,
        [],
        None,
    )
    assert provenance_again == "llm" and returned_flow.revision == 1
    assert steps_again == steps and paid.complete.await_count == 1
    assert sorted(e[2] for e in state.events) == [
        "planner.finished",
        "planner.proposal_checkpoint",
        "planner.research_checkpoint",
    ]


@pytest.mark.asyncio
async def test_untrusted_recovered_steps_cannot_bypass_scope_or_rerun_provider(monkeypatch):
    paid = PaidStub()
    recovered = research_checkpoint.SettledProposal(
        steps=[
            {
                "title": "Scan unauthorized host",
                "description": "",
                "task_type": "burp_scan",
                "agent_type": "vuln_analysis",
                "target": "evil.invalid",
                "depends_on": [],
            }
        ],
        provenance="llm",
        revision=1,
    )
    checkpoint = SimpleNamespace(recover=AsyncMock(return_value=recovered))
    monkeypatch.setattr(flow_refinement, "ResearchCheckpointStore", lambda _: checkpoint)
    refiner = flow_refinement.BoundedFlowRefiner(
        SimpleNamespace(llm_client=paid, session_memory=SimpleNamespace(_async_session=object())),
    )
    scope = ScopeDefinition(
        engagement_id="eng-research",
        domains=["example.com"],
        authorization_ref="signed",
        restrictions=["no_active_scanning"],
    )
    session = SimpleNamespace(scope=scope, phase="reconnaissance", roe={})
    flow = FlowRecord(
        id="flow-research",
        engagement_id="eng-research",
        objective="Review evidence",
        status="running",
        revision=1,
    )
    task = Task(
        id="task-objective",
        engagement_id="eng-research",
        type="flow_objective",
        status="planned",
        agent_type=AgentType.RECON,
        flow_id=flow.id,
    )
    with pytest.raises(research_checkpoint.ResearchCheckpointDenied):
        await refiner._propose(flow, task, session, [], None)
    paid.complete.assert_not_awaited()
