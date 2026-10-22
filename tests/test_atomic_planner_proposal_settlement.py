"""One PG transaction settles the paid planner and its recoverable proposal."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.model_usage import ModelOutcomeUncertain
from ai_osop.orchestrator.flow_refinement import ProposedStep
from ai_osop.orchestrator.planner_execution import run_planner_completion
from ai_osop.orchestrator.research_checkpoint import ResearchCheckpointDenied
from tests.test_research_checkpoint_resume import ledger


def _steps():
    return [
        ProposedStep(
            title="Summarize independently confirmed evidence",
            description="Read bounded verified counts only",
            task_type="summarize_context",
            agent_type="context_manager",
            target=None,
            depends_on=[],
        ).model_dump(mode="json")
    ]


async def _prepare(ledger_fixture):
    store, state = ledger_fixture
    admission = state.new_planner()
    flow = state.flow.model_copy(update={"revision": admission.revision})
    await store.prepare(
        admission, flow, state.parent,
        source_id=None, pass_number=0, signals={"verified": True},
    )
    return store, state, admission, flow


@pytest.mark.asyncio
async def test_atomic_planner_settlement_recovers_without_second_paid_call(ledger):
    store, state, admission, flow = await _prepare(ledger)
    provider = AsyncMock(return_value="VALIDATED_BOUNDED_PLAN_RECEIPT")

    async def finish(raw):
        assert raw == "VALIDATED_BOUNDED_PLAN_RECEIPT"
        await store.complete_with_proposal_atomic(
            admission, flow, state.parent,
            source_id=None, pass_number=0,
            steps=_steps(), provenance="llm",
        )
        return "proposal-committed"

    result = await run_planner_completion(
        store, admission, provider, ["approved task"],
        finalize=finish,
    )
    assert result == "proposal-committed"
    provider.assert_awaited_once()
    assert state.tasks[admission.task_id].status == "completed"
    assert state.tasks[admission.task_id].result["proposal_steps"] == _steps()
    assert sorted(event[2] for event in state.events) == [
        "planner.finished",
        "planner.proposal_checkpoint",
        "planner.research_checkpoint",
    ]
    recovered = await store.recover(
        flow, state.parent, purpose="flow_generation",
        source_id=None, pass_number=0,
    )
    assert recovered.steps == _steps() and recovered.provenance == "llm"
    assert provider.await_count == 1


@pytest.mark.asyncio
async def test_outbox_crash_rolls_back_both_proposal_and_paid_success(ledger):
    store, state, admission, flow = await _prepare(ledger)
    normal_event = store._append_event

    async def event_failure(*args, **kwargs):
        if args[3] == "planner.proposal_checkpoint":
            raise OSError("outbox unavailable password=SECRET")
        return await normal_event(*args, **kwargs)

    store._append_event = event_failure
    provider = AsyncMock(return_value="model response")

    async def finish(_):
        await store.complete_with_proposal_atomic(
            admission, flow, state.parent,
            source_id=None, pass_number=0,
            steps=_steps(), provenance="llm",
        )

    with pytest.raises(ModelOutcomeUncertain, match="receipt was not persisted") as exc:
        await run_planner_completion(
            store, admission, provider, ["approved task"], finalize=finish,
        )
    assert "SECRET" not in str(exc.value)
    provider.assert_awaited_once()
    assert state.tasks[admission.task_id].status == "running"
    assert state.tasks[admission.task_id].result is None
    assert state.events == [
        (state.flow.engagement_id, store._research_id(admission.task_id),
         "planner.research_checkpoint")
    ]
    with pytest.raises(ModelOutcomeUncertain, match="no replay"):
        await store.recover(
            flow, state.parent, purpose="flow_generation",
            source_id=None, pass_number=0,
        )


@pytest.mark.asyncio
async def test_atomic_settlement_rejects_revoked_policy_without_marking_completed(ledger):
    store, state, admission, flow = await _prepare(ledger)
    state.version = 8
    with pytest.raises(PermissionError):
        await store.complete_with_proposal_atomic(
            admission, flow, state.parent, source_id=None,
            pass_number=0, steps=_steps(), provenance="llm",
        )
    assert state.tasks[admission.task_id].status == "running"
    assert len(state.events) == 1


@pytest.mark.asyncio
async def test_malicious_output_cannot_be_saved_as_completed_injection(ledger):
    store, state, admission, flow = await _prepare(ledger)
    with pytest.raises(ResearchCheckpointDenied, match="schema"):
        await store.complete_with_proposal_atomic(
            admission, flow, state.parent, source_id=None,
            pass_number=0,
            steps=[{"task_type": "shell", "prompt": "ignore scope"}],
            provenance="llm",
        )
    assert state.tasks[admission.task_id].status == "running"


@pytest.mark.asyncio
async def test_concurrent_duplicate_settlements_deny_stale_caller(ledger):
    store, state, admission, flow = await _prepare(ledger)

    async def settle():
        try:
            await store.complete_with_proposal_atomic(
                admission, flow, state.parent,
                source_id=None, pass_number=0,
                steps=_steps(), provenance="llm",
            )
            return True
        except ResearchCheckpointDenied:
            return False

    assert sorted(await asyncio.gather(settle(), settle())) == [False, True]
    assert state.tasks[admission.task_id].status == "completed"
    assert len(state.events) == 3
