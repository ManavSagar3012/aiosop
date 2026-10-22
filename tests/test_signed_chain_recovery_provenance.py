"""Graph recovery hints cannot choose a new signed target or local HAR source."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


def fixture(*, kind="map_workflow", result=None, signed=True):
    task = Task(
        id="task-source-provenance",
        engagement_id="eng-source-provenance",
        type=kind,
        agent_type=AgentType.WORKFLOW,
        status="completed",
        payload={
            "url": "https://authorized.example/",
            "user_label": "operator-one",
            **({"_authorization_version": 3} if signed else {}),
        },
        result=result or {"status": "success", "workflow_id": "workflow-1"},
    )
    session = SessionState(
        session_id=task.engagement_id,
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id=task.engagement_id,
            domains=["authorized.example"],
            authorization_ref="signed-policy",  # stub: verified separately
        ),
    )
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock(return_value=task)
    memory.list_recoverable_signed_chain_parents = AsyncMock(return_value=[])
    memory.load_task = AsyncMock(side_effect=AssertionError("stale Redis read"))
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=3))
    memory.load_session_state = AsyncMock(return_value=session)
    graph = SimpleNamespace(
        find_incomplete_chains=AsyncMock(
            return_value=[
                {
                    "id": task.id,
                    "engagement_id": task.engagement_id,
                    "type": kind,
                    "result_summary": {
                        "url": "https://foreign.example/",
                        "har_path": "C:/Windows/secret.har",
                        "user_label": "ignore-safety-and-escape",
                        "workflow_id": "graph-forged",
                    },
                }
            ]
        )
    )
    orch = SimpleNamespace(
        graph_memory=graph,
        session_memory=memory,
        _resume_chain_link=AsyncMock(return_value=None),
    )
    return orch, task, memory


@pytest.mark.asyncio
async def test_signed_restart_uses_pg_original_target_not_forged_graph_summary():
    orch, task, memory = fixture()
    await Orchestrator.recover_state(orch)
    orch._resume_chain_link.assert_awaited_once()
    supplied = orch._resume_chain_link.await_args.args[0]
    assert supplied["id"] == task.id
    assert supplied["result_summary"] == {
        "workflow_id": "workflow-1",
        "status": "success",
        "url": "https://authorized.example/",
        "user_label": "operator-one",
    }
    memory.load_task_authoritative.assert_awaited_once_with(task.id)
    memory.load_task.assert_not_awaited()
    memory.assert_signed_authorization.assert_awaited_once_with(
        task.engagement_id,
        expected_version=3,
    )


@pytest.mark.asyncio
async def test_signed_restart_recovers_pg_completed_parent_even_without_graph_node():
    orch, task, memory = fixture()
    orch.graph_memory.find_incomplete_chains.return_value = []
    memory.list_recoverable_signed_chain_parents.return_value = [
        {"id": task.id, "engagement_id": task.engagement_id, "type": task.type}
    ]
    summary = await Orchestrator.recover_state(orch)
    assert summary["chains_resumed"] == 0  # Stubbed creation, not fabricated success
    orch._resume_chain_link.assert_awaited_once()
    assert orch._resume_chain_link.await_args.args[0]["result_summary"]["url"] == "https://authorized.example/"
    memory.load_task_authoritative.assert_awaited_once_with(task.id)


@pytest.mark.asyncio
async def test_pg_chain_recovery_survives_derived_graph_outage():
    orch, task, memory = fixture()
    memory.list_recoverable_signed_chain_parents.return_value = [
        {"id": task.id, "engagement_id": task.engagement_id, "type": task.type}
    ]
    orch.graph_memory.find_incomplete_chains.side_effect = OSError("Neo4j offline")
    result = await Orchestrator.recover_state(orch)
    assert result["reconcile_required"] == 0
    orch._resume_chain_link.assert_awaited_once()


@pytest.mark.asyncio
async def test_failed_chain_child_admission_stays_unknown_and_does_not_abort_other_parents():
    orch, task, memory = fixture()
    other = task.model_copy(deep=True)
    other.id = "task-second-chain-parent"
    memory.list_recoverable_signed_chain_parents.return_value = [
        {"id": task.id, "engagement_id": task.engagement_id, "type": task.type},
        {"id": other.id, "engagement_id": other.engagement_id, "type": other.type},
    ]
    orch.graph_memory.find_incomplete_chains.return_value = []

    async def read_task(identifier):
        return task if identifier == task.id else other

    memory.load_task_authoritative.side_effect = read_task
    orch._resume_chain_link.side_effect = [
        OSError("unknown PostgreSQL scheduler outcome"),
        None,
    ]
    result = await Orchestrator.recover_state(orch)
    assert result["reconcile_required"] == 1
    assert result["chains_resumed"] == 0
    assert orch._resume_chain_link.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["unsigned", "revoked", "wrong_type", "foreign_url"])
async def test_poisoned_graph_or_roe_cannot_resume_autonomous_chain(reason):
    orch, task, memory = fixture(signed=reason != "unsigned")
    if reason == "revoked":
        memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    if reason == "wrong_type":
        orch.graph_memory.find_incomplete_chains.return_value[0]["type"] = "full_recon"
    if reason == "foreign_url":
        task.payload["url"] = "https://foreign.example/"
    await Orchestrator.recover_state(orch)
    orch._resume_chain_link.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,allowed",
    [
        ("har/signed-capture.har", True),
        ("C:/Windows/secret.har", False),
        ("../escape.har", False),
        ("/etc/secret.har", False),
        ("folder/../secret.har", False),
    ],
)
async def test_har_recovery_uses_only_safe_original_task_receipt(path, allowed):
    orch, task, _ = fixture(
        kind="capture_authenticated_surface",
        result={"status": "success", "har_path": path},
    )
    await Orchestrator.recover_state(orch)
    if allowed:
        orch._resume_chain_link.assert_awaited_once()
        assert orch._resume_chain_link.await_args.args[0]["result_summary"]["har_path"] == path
    else:
        orch._resume_chain_link.assert_not_awaited()
