"""Operator-controlled Generator/Refiner tests with persistent fake state."""

import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, SubtaskRecord, Task
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.orchestrator.orchestrator import Orchestrator


class Memory:
    def __init__(self):
        self.flows = {}
        self.tasks = {}
        self.subtasks = {}
        self.sessions = {}
        self.writes = []
        self._commit_lock = asyncio.Lock()

    async def load_flow(self, flow_id):
        return self.flows.get(flow_id).model_copy(deep=True) if flow_id in self.flows else None

    async def store_flow(self, flow):
        self.flows[flow.id] = flow.model_copy(deep=True)
        self.writes.append(("flow", flow.id, flow.revision))

    async def load_task(self, task_id):
        return self.tasks.get(task_id).model_copy(deep=True) if task_id in self.tasks else None

    async def store_task(self, task):
        self.tasks[task.id] = task.model_copy(deep=True)
        self.writes.append(("task", task.id, task.status))

    async def load_session_state(self, session_id):
        return self.sessions.get(session_id)

    async def list_subtasks(self, flow_id, task_id=None, limit=100):
        return [
            subtask.model_copy(deep=True)
            for subtask in sorted(self.subtasks.values(), key=lambda x: x.order)
            if subtask.flow_id == flow_id and (task_id is None or subtask.task_id == task_id)
        ][:limit]

    async def store_subtask(self, subtask):
        self.subtasks[subtask.id] = subtask.model_copy(deep=True)
        self.writes.append(("subtask", subtask.id, subtask.status))

    async def commit_flow_refinement(
        self, flow, engagement, expected_subtask_ids, additions, source=None
    ):
        """Model PostgreSQL all-or-nothing planning and revision CAS."""
        async with self._commit_lock:
            current = self.flows.get(flow.id)
            current_engagement = self.sessions.get(flow.engagement_id)
            if (
                current is None
                or current.revision != flow.revision
                or current.status != flow.status
                or current.status not in {"pending", "running"}
                or current_engagement is None
                or current_engagement.phase != engagement.phase
                or current_engagement.scope != engagement.scope
                or current_engagement.roe != engagement.roe
                or {s.id for s in self.subtasks.values() if s.flow_id == flow.id}
                != set(expected_subtask_ids)
            ):
                return None
            if source is not None:
                latest = self.subtasks.get(source.id)
                if (
                    latest is None
                    or latest.status != "completed"
                    or latest.refinement_count != source.refinement_count
                ):
                    return None
            for step in additions:
                if step.id in self.subtasks:
                    raise ValueError("duplicate planned step")
            for step in additions:
                await self.store_subtask(step)
            if source is not None:
                revised = source.model_copy(
                    update={
                        "refinement_count": source.refinement_count + 1,
                        "updated_at": __import__("datetime").datetime.utcnow(),
                    }
                )
                await self.store_subtask(revised)
            committed = flow.model_copy(deep=True)
            committed.revision += 1
            if committed.status == "pending":
                committed.status = "running"
            await self.store_flow(committed)
            return committed.model_copy(deep=True)


@pytest.fixture
def harness():
    memory = Memory()
    llm = AsyncMock()
    graph = AsyncMock()
    graph.upsert_task.return_value = True
    orchestrator = Orchestrator(memory, graph, AsyncMock(), llm, coordination_bus=AsyncMock())
    session = SessionState(
        session_id="eng-test",
        scope=ScopeDefinition(
            engagement_id="eng-test",
            domains=["example.com"],
            authorization_ref="signed-roe",
        ),
        phase="reconnaissance",
    )
    memory.sessions[session.session_id] = session
    orchestrator._sessions[session.session_id] = session
    flow = FlowRecord(
        id="flow-test", engagement_id=session.session_id, objective="Map authorized website"
    )
    memory.flows[flow.id] = flow
    objective = Task(
        id="task-objective",
        type="flow_objective",
        agent_type=AgentType.RECON,
        engagement_id=session.session_id,
        flow_id=flow.id,
        status="planned",
        payload={"title": "Review authorized API"},
    )
    memory.tasks[objective.id] = objective
    orchestrator._audit_log = AsyncMock()
    orchestrator.adaptive_planner.on_task_completed = AsyncMock()
    return orchestrator, memory, llm, flow, objective


def proposed_steps(*steps):
    return json.dumps({"steps": list(steps)})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "refusal",
    [
        ModelBudgetExceeded("No authorized model quota"),
        ModelOutcomeUncertain("Provider may have billed"),
    ],
)
async def test_generator_never_deterministically_falls_back_after_model_safety_refusal(
    harness, refusal
):
    orch, memory, llm, flow, objective = harness
    llm.complete.side_effect = refusal
    with pytest.raises(type(refusal)):
        await orch.generate_flow_subtasks(flow.id, objective.id)
    assert memory.subtasks == {}
    assert memory.flows[flow.id].revision == 0


@pytest.mark.asyncio
async def test_paused_plan_prevents_background_or_manual_generation(harness):
    """Pause must also freeze the model-generated steps, not only HTTP dispatch."""
    orchestrator, memory, llm, flow, objective = harness
    memory.flows[flow.id].status = "paused"

    result = await orchestrator.generate_flow_subtasks(flow.id, objective.id)

    assert result["status"] == "blocked"
    assert memory.subtasks == {}
    llm.complete.assert_not_awaited()


def step(title, task_type, agent_type, **extra):
    return {
        "title": title,
        "description": "Operator reviews the resulting evidence.",
        "task_type": task_type,
        "agent_type": agent_type,
        **extra,
    }


def completed_subtask(harness, *, task_type="full_recon"):
    orchestrator, memory, _, flow, objective = harness
    subtask = SubtaskRecord(
        id="subtask-source",
        engagement_id=flow.engagement_id,
        flow_id=flow.id,
        task_id=objective.id,
        title="Completed scoped reconnaissance",
        task_type=task_type,
        agent_type=AgentType.RECON,
        status="dispatched",
        execution_task_id="task-executed",
    )
    memory.subtasks[subtask.id] = subtask
    task = Task(
        id="task-executed",
        type=task_type,
        agent_type=AgentType.RECON,
        engagement_id=flow.engagement_id,
        flow_id=flow.id,
        subtask_id=subtask.id,
        parent_task_id=objective.id,
        payload={"domain": "example.com"},
        status="running",
    )
    memory.tasks[task.id] = task
    orchestrator._tasks[task.id] = task
    return task, subtask


@pytest.mark.asyncio
async def test_generator_persists_validated_steps_and_dependencies_without_execution(harness):
    orch, memory, llm, flow, objective = harness
    llm.complete.return_value = proposed_steps(
        step("Summarize evidence", "summarize_context", "context_manager"),
        step(
            "Scoped recon proposal",
            "full_recon",
            "recon",
            target="https://example.com/admin",
            depends_on=[0],
        ),
    )
    orch.schedule_task = AsyncMock()

    outcome = await orch.generate_flow_subtasks(flow.id, objective.id)

    assert outcome["status"] == "proposed"
    assert outcome["provenance"] == "llm"
    assert outcome["steps_total"] == 2
    assert memory.flows[flow.id].revision == 1
    steps = await memory.list_subtasks(flow.id)
    assert [s.task_type for s in steps] == ["summarize_context", "full_recon"]
    assert [s.order for s in steps] == [0, 1]
    assert steps[1].dependencies == [steps[0].id]
    assert steps[0].approval_required is False
    assert steps[1].approval_required is True
    assert steps[1].status == "pending"
    assert "example.com/admin" in steps[1].description
    orch.schedule_task.assert_not_awaited()
    assert (await orch.generate_flow_subtasks(flow.id, objective.id))["status"] == "unchanged"
    llm.complete.assert_awaited_once()


@pytest.mark.parametrize(
    "bad_output",
    [
        "not json",
        proposed_steps(step("Launch exploit", "exploit_validation", "exploit_validation")),
        proposed_steps(step("Scan foreign host", "full_recon", "recon", target="evil.example.net")),
        proposed_steps(
            step("Circular dependency", "summarize_context", "context_manager", depends_on=[0])
        ),
        proposed_steps(step("Wrong agent", "full_recon", "reporting")),
        proposed_steps(
            step("Unexpected parameter", "generate_report", "reporting", payload={"cmd": "x"})
        ),
    ],
)
@pytest.mark.asyncio
async def test_invalid_llm_plan_uses_safe_deterministic_fallback(harness, bad_output):
    orch, memory, llm, flow, objective = harness
    llm.complete.return_value = bad_output
    outcome = await orch.flow_refiner.generate(flow.id, objective.id)
    assert outcome["provenance"] == "deterministic"
    saved = await memory.list_subtasks(flow.id)
    assert len(saved) == 1
    assert saved[0].task_type == "summarize_context"
    assert saved[0].status == "pending"


@pytest.mark.asyncio
async def test_generator_respects_active_technique_restrictions(harness):
    orch, memory, llm, flow, objective = harness
    orch._sessions[flow.engagement_id].scope.restrictions = ["no_active_scanning"]
    llm.complete.return_value = proposed_steps(step("Scan", "nuclei_scan", "vuln_analysis"))
    result = await orch.flow_refiner.generate(flow.id, objective.id)
    assert result["provenance"] == "deterministic"
    assert next(iter(memory.subtasks.values())).approval_required is False


@pytest.mark.asyncio
async def test_generator_honors_shared_roe_approval_policy(harness):
    orch, memory, llm, flow, objective = harness
    orch._sessions[flow.engagement_id].scope.approval_required_for = ["generate_report"]
    llm.complete.return_value = proposed_steps(
        step("Create review report", "generate_report", "reporting")
    )
    result = await orch.flow_refiner.generate(flow.id, objective.id)
    assert result["provenance"] == "llm"
    proposed = next(iter(memory.subtasks.values()))
    assert proposed.task_type == "generate_report"
    assert proposed.approval_required is True


@pytest.mark.parametrize("condition", ["unsigned", "halted", "outside_window", "wrong_objective"])
@pytest.mark.asyncio
async def test_generator_requires_authorized_live_flow_and_valid_objective(harness, condition):
    orch, memory, llm, flow, objective = harness
    if condition == "unsigned":
        orch._sessions[flow.engagement_id].scope.authorization_ref = None
    elif condition == "halted":
        memory.flows[flow.id].status = "halted"
    elif condition == "outside_window":
        from datetime import datetime, timedelta

        orch._sessions[flow.engagement_id].scope.testing_window_end = datetime.utcnow() - timedelta(
            minutes=10
        )
    else:
        memory.tasks[objective.id].flow_id = "flow-foreign"
    outcome = await orch.flow_refiner.generate(flow.id, objective.id)
    assert outcome["status"] == "blocked"
    assert memory.subtasks == {}
    llm.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_generator_budget_is_fifteen_steps_across_flow(harness):
    orch, memory, llm, flow, objective = harness
    for index in range(15):
        memory.subtasks[f"subtask-{index}"] = SubtaskRecord(
            id=f"subtask-{index}",
            flow_id=flow.id,
            task_id="task-another-objective",
            engagement_id=flow.engagement_id,
            title=f"Previously planned step {index}",
            order=index,
        )
    result = await orch.flow_refiner.generate(flow.id, objective.id)
    assert result["status"] == "limit_reached"
    assert len(memory.subtasks) == 15
    llm.complete.assert_not_awaited()


@pytest.mark.parametrize("change", ["revision", "halt", "scope"])
@pytest.mark.asyncio
async def test_generator_rejects_stale_llm_plan_after_operator_changes(harness, change):
    orch, memory, llm, flow, objective = harness

    async def inference(_messages, **_kwargs):
        if change == "revision":
            memory.flows[flow.id].revision += 1
        elif change == "halt":
            memory.flows[flow.id].status = "halted"
        else:
            orch._sessions[flow.engagement_id].scope.authorization_ref = None
        return proposed_steps(
            step("Scoped recon proposal", "full_recon", "recon", target="example.com")
        )

    llm.complete.side_effect = inference
    outcome = await orch.generate_flow_subtasks(flow.id, objective.id)
    assert outcome["status"] == ("conflict" if change == "revision" else "blocked")
    assert len(memory.subtasks) == 0


@pytest.mark.parametrize("completion_route", ["orchestrator", "task_scheduler"])
@pytest.mark.asyncio
async def test_confirmed_completion_runs_refiner_once_after_persistence(harness, completion_route):
    orch, memory, llm, flow, _ = harness
    task, source = completed_subtask(harness)
    llm.complete.return_value = proposed_steps(
        step("Review confirmed evidence", "summarize_context", "context_manager"),
        step("Prepare verified findings", "generate_report", "reporting", depends_on=[0]),
    )
    orch.schedule_task = AsyncMock()
    callback = (
        orch._on_task_success
        if completion_route == "orchestrator"
        else orch.task_scheduler._on_task_success
    )
    await callback(task, {"status": "success", "verified": True})
    rows = await memory.list_subtasks(flow.id)
    assert memory.tasks[task.id].status == "completed"
    assert memory.subtasks[source.id].status == "completed"
    assert memory.subtasks[source.id].refinement_count == 1
    assert memory.flows[flow.id].revision == 1
    assert len(rows) == 3
    assert rows[1].dependencies == [source.id]
    assert rows[2].dependencies == [source.id, rows[1].id]
    assert next(
        i for i, w in enumerate(memory.writes) if w == ("task", task.id, "completed")
    ) < next(i for i, w in enumerate(memory.writes) if w == ("subtask", rows[1].id, "pending"))
    orch.schedule_task.assert_not_awaited()
    # Duplicate completion notifications are idempotent.
    assert (await orch.flow_refiner.on_subtask_completed(task, {"status": "success"}))[
        "status"
    ] == "unchanged"
    assert len(await memory.list_subtasks(flow.id)) == 3


@pytest.mark.asyncio
async def test_refiner_never_runs_on_unconfirmed_or_failed_task(harness):
    orch, memory, llm, flow, _ = harness
    task, source = completed_subtask(harness)
    assert (await orch.flow_refiner.on_subtask_completed(task, {"status": "success"}))[
        "status"
    ] == "ignored"
    task.status = "completed"
    assert (await orch.flow_refiner.on_subtask_completed(task, {"status": "failed"}))[
        "status"
    ] == "ignored"
    # Status alone cannot bypass the persisted completed execution requirement.
    assert (await orch.flow_refiner.on_subtask_completed(task, {"status": "success"}))[
        "status"
    ] == "ignored"
    assert memory.subtasks[source.id].refinement_count == 0
    llm.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_three_manual_refinements_maximum_and_no_duplicate_proposals(harness):
    orch, memory, llm, flow, _ = harness
    task, source = completed_subtask(harness)
    task.status = "completed"
    memory.tasks[task.id] = task
    memory.subtasks[source.id].status = "completed"
    llm.complete.return_value = proposed_steps(
        step("Summarize findings", "summarize_context", "context_manager")
    )
    auto = await orch.flow_refiner.on_subtask_completed(task, {"status": "success"})
    assert auto["refinement_count"] == 1
    assert (await orch.flow_refiner.on_subtask_completed(task, {"status": "success"}))[
        "status"
    ] == "unchanged"
    for expected in (2, 3):
        revised = await orch.refine_flow_subtask(flow.id, source.id)
        assert revised["refinement_count"] == expected
    assert (await orch.refine_flow_subtask(flow.id, source.id))["status"] == "limit_reached"
    assert memory.flows[flow.id].revision == 3
    assert len(memory.subtasks) == 2
    assert llm.complete.await_count == 3


@pytest.mark.asyncio
async def test_refiner_is_serialized_under_concurrent_completion_events(harness):
    orch, memory, llm, flow, _ = harness
    task, source = completed_subtask(harness)
    task.status = "completed"
    memory.tasks[task.id] = task
    memory.subtasks[source.id].status = "completed"
    llm.complete.return_value = proposed_steps(
        step("Review logs", "summarize_context", "context_manager")
    )
    results = await asyncio.gather(
        orch.flow_refiner.on_subtask_completed(task, {"status": "success"}),
        orch.flow_refiner.on_subtask_completed(task, {"status": "success"}),
    )
    assert {r["status"] for r in results} == {"proposed", "unchanged"}
    assert llm.complete.await_count == 1
    assert memory.flows[flow.id].revision == 1


@pytest.mark.asyncio
async def test_independent_planner_instances_cannot_commit_same_revision(harness):
    """Two replicas have separate locks but share one atomic persistence tier."""
    orch, memory, llm, flow, objective = harness
    peer_llm = AsyncMock()
    peer = Orchestrator(
        memory,
        AsyncMock(),
        AsyncMock(),
        peer_llm,
        coordination_bus=AsyncMock(),
    )
    peer._sessions[flow.engagement_id] = orch._sessions[flow.engagement_id]
    both_inference_started = asyncio.Event()
    count = 0

    async def shared_inference(_messages, **_kwargs):
        nonlocal count
        count += 1
        if count == 2:
            both_inference_started.set()
        await asyncio.wait_for(both_inference_started.wait(), timeout=2)
        return proposed_steps(step("Review accessible evidence", "summarize_context", "context_manager"))

    llm.complete.side_effect = shared_inference
    peer_llm.complete.side_effect = shared_inference
    results = await asyncio.wait_for(
        asyncio.gather(
            orch.flow_refiner.generate(flow.id, objective.id),
            peer.flow_refiner.generate(flow.id, objective.id),
        ),
        timeout=5,
    )
    assert {item["status"] for item in results} == {"proposed", "conflict"}
    assert len(await memory.list_subtasks(flow.id)) == 1
    assert memory.flows[flow.id].revision == 1


@pytest.mark.asyncio
async def test_refiner_repeated_llm_step_preserves_dependency_reference(harness):
    orch, memory, llm, flow, _ = harness
    task, source = completed_subtask(harness)
    task.status = "completed"
    memory.tasks[task.id] = task
    memory.subtasks[source.id].status = "completed"
    existing = SubtaskRecord(
        id="subtask-existing",
        engagement_id=flow.engagement_id,
        flow_id=flow.id,
        task_id=source.task_id,
        order=1,
        title="Summarize results",
        task_type="summarize_context",
        agent_type=AgentType.CONTEXT_MANAGER,
    )
    memory.subtasks[existing.id] = existing
    llm.complete.return_value = proposed_steps(
        step("Summarize results", "summarize_context", "context_manager"),
        step("Publish summary for operator review", "generate_report", "reporting", depends_on=[0]),
    )
    result = await orch.flow_refiner.on_subtask_completed(task, {"status": "success"})
    assert result["status"] == "proposed"
    assert result["steps_total"] == 3
    added = memory.subtasks[result["added_subtask_ids"][0]]
    assert added.dependencies == [source.id, existing.id]


@pytest.mark.asyncio
async def test_refiner_uses_only_safe_outcome_counts_and_documents_confirmed_findings(
    harness,
):
    orch, memory, llm, flow, _ = harness
    task, source = completed_subtask(harness)
    task.status = "completed"
    memory.tasks[task.id] = task
    memory.subtasks[source.id].status = "completed"
    memory.subtasks[source.id].result_summary = json.dumps(
        {
            "findings_count": 3,
            "verified": True,
            "credentials": "NEVER_SEND_THIS_SECRET",
            "payload": "IGNORE_PRIOR_INSTRUCTIONS",
            "nested": {"key": "private"},
        }
    )
    llm.complete.return_value = "not JSON"
    result = await orch.flow_refiner.on_subtask_completed(task, {"status": "success"})
    assert result["provenance"] == "deterministic"
    proposed = memory.subtasks[result["added_subtask_ids"][0]]
    assert proposed.task_type == "generate_report"
    prompt = llm.complete.await_args.args[0][1]["content"]
    assert '"findings_count": 3' in prompt
    assert "NEVER_SEND_THIS_SECRET" not in prompt
    assert "IGNORE_PRIOR_INSTRUCTIONS" not in prompt


@pytest.mark.asyncio
async def test_failed_completion_never_creates_a_plan(harness):
    orch, memory, llm, flow, _ = harness
    task, _ = completed_subtask(harness)
    task.retry_count = task.max_retries
    await orch._on_task_failure(task, {"status": "failed", "error": "probe error"})
    assert memory.subtasks["subtask-source"].status == "failed"
    assert len(memory.subtasks) == 1
    assert memory.flows[flow.id].revision == 0
    llm.complete.assert_not_awaited()
