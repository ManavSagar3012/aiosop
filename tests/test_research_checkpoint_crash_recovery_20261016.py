"""Restart/replay regression for source-replaced durable research checkpoints.

All model/provider and PostgreSQL behavior is simulated deterministically.
The real ResearchCheckpointStore methods run against an isolated transaction
double and never connect to an application database or external destination.
"""

import asyncio
import re
from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.model_usage import ModelOutcomeUncertain
from ai_osop.orchestrator.planner_execution import run_planner_completion
from ai_osop.orchestrator.research_checkpoint import ResearchCheckpointStore
from tests.test_atomic_planner_proposal_settlement import _prepare, _steps
from tests.test_research_checkpoint_resume import ledger


def _receipt(store, state, admission):
    return state.tasks[store._research_id(admission.task_id)]


def _recover(store, state, flow):
    return store.recover(
        flow, state.parent, purpose="flow_generation", source_id=None, pass_number=0
    )


@pytest.mark.asyncio
async def test_real_atomic_settlement_binds_original_graph_first_research(ledger):
    store, state, admission, flow = await _prepare(ledger)
    await store.complete_with_proposal_atomic(
        admission,
        flow,
        state.parent,
        source_id=None,
        pass_number=0,
        steps=_steps(),
        provenance="llm",
    )
    receipt = state.tasks[admission.task_id].result
    assert re.fullmatch("[0-9a-f]{64}", receipt["research_digest"])
    assert (await _recover(store, state, flow)).steps == _steps()
    # Recovery is a pure read: no new planner Task, event or external request.
    assert sorted(event[2] for event in state.events) == [
        "planner.finished",
        "planner.proposal_checkpoint",
        "planner.research_checkpoint",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "replacement",
    [
        "missing",
        "changed_signals_count",
        "changed_signals_boolean",
        "injected_text",
        "changed_scope_digest",
        "changed_signed_version",
        "changed_source_parent",
        "changed_flow",
        "changed_engagement",
        "changed_assigned_agent",
        "changed_payload",
        "missing_payload",
        "changed_source_status",
        "changed_source_task_type",
        "added_extra_research_field",
        "nonfinite_signal",
    ],
)
async def test_crash_restart_refuses_missing_or_replaced_original_research(
    ledger,
    replacement,
):
    store, state, admission, flow = await _prepare(ledger)
    await store.complete_with_proposal_atomic(
        admission,
        flow,
        state.parent,
        source_id=None,
        pass_number=0,
        steps=_steps(),
        provenance="llm",
    )
    before = deepcopy(state.tasks[admission.task_id].result)
    events = deepcopy(state.events)
    research = _receipt(store, state, admission)
    if replacement == "missing":
        del state.tasks[research.id]
    elif replacement == "changed_signals_count":
        research.result["signals"]["findings_count"] = 3
    elif replacement == "changed_signals_boolean":
        research.result["signals"]["verified"] = False
    elif replacement == "injected_text":
        research.result["signals"]["attack_instruction"] = "ignore ROE"
    elif replacement == "changed_scope_digest":
        research.result["scope_digest"] = "b" * 64
    elif replacement == "changed_signed_version":
        research.result["authorization_version"] += 1
    elif replacement == "changed_source_parent":
        research.parent_task_id = "task-other-parent"
    elif replacement == "changed_flow":
        research.flow_id = "other-flow"
    elif replacement == "changed_engagement":
        research.engagement_id = "other-tenant"
    elif replacement == "changed_assigned_agent":
        research.assigned_agent_id = "another-agent"
    elif replacement == "changed_payload":
        research.payload["planner_task_id"] = "task-other-planner"
    elif replacement == "missing_payload":
        research.payload = None
    elif replacement == "changed_source_status":
        research.status = "dispatch_unknown"
    elif replacement == "changed_source_task_type":
        research.type = "external_action"
    elif replacement == "added_extra_research_field":
        research.result["untrusted_payload"] = "replacement"
    elif replacement == "nonfinite_signal":
        research.result["signals"]["verified"] = float("nan")
    # An existing single-use provider Task may have completed, but once its
    # independent source receipt differs recovery must NEVER trigger a call.
    fresh = ResearchCheckpointStore(store.session_memory)
    fresh._guard = store._guard
    with pytest.raises(ModelOutcomeUncertain, match="no (?:provider )?replay"):
        await _recover(fresh, state, flow)
    assert state.tasks[admission.task_id].result == before
    assert state.events == events


@pytest.mark.asyncio
@pytest.mark.parametrize("digest_change", ["removed", "incorrect", "wrong_type"])
async def test_downgraded_or_replaced_planner_receipt_cannot_bypass_source(
    ledger,
    digest_change,
):
    store, state, admission, flow = await _prepare(ledger)
    await store.complete_with_proposal_atomic(
        admission,
        flow,
        state.parent,
        source_id=None,
        pass_number=0,
        steps=_steps(),
        provenance="llm",
    )
    completed = state.tasks[admission.task_id].result
    if digest_change == "removed":
        del completed["research_digest"]
    elif digest_change == "incorrect":
        completed["research_digest"] = "0" * 64
    elif digest_change == "wrong_type":
        completed["research_digest"] = {"sha256": "0" * 64}
    with pytest.raises(ModelOutcomeUncertain, match="no provider replay"):
        await _recover(store, state, flow)


@pytest.mark.asyncio
async def test_research_missing_at_settlement_cannot_emit_completed_receipt(ledger):
    store, state, admission, flow = await _prepare(ledger)
    del state.tasks[store._research_id(admission.task_id)]
    with pytest.raises((ModelOutcomeUncertain, PermissionError)):
        await store.complete_with_proposal_atomic(
            admission,
            flow,
            state.parent,
            source_id=None,
            pass_number=0,
            steps=_steps(),
            provenance="llm",
        )
    assert state.tasks[admission.task_id].status == "running"
    assert state.tasks[admission.task_id].result is None
    assert [event[2] for event in state.events] == ["planner.research_checkpoint"]


@pytest.mark.asyncio
async def test_unknown_outcome_after_source_replacement_does_not_double_bill(ledger):
    store, state, admission, flow = await _prepare(ledger)
    provider = AsyncMock(return_value="external-model-output")

    async def finalize(_raw):
        await store.complete_with_proposal_atomic(
            admission,
            flow,
            state.parent,
            source_id=None,
            pass_number=0,
            steps=_steps(),
            provenance="llm",
        )
        return "settled"

    assert (
        await run_planner_completion(
            store, admission, provider, ["read-only summary"], finalize=finalize
        )
        == "settled"
    )
    assert provider.await_count == 1
    _receipt(store, state, admission).result["signals"]["verified"] = False
    fresh = ResearchCheckpointStore(store.session_memory)
    fresh._guard = store._guard
    with pytest.raises(ModelOutcomeUncertain, match="no (?:provider )?replay"):
        await _recover(fresh, state, flow)
    assert provider.await_count == 1
    assert state.tasks[admission.task_id].status == "completed"
