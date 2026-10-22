"""Authenticated chain restart never treats a Neo4j edge as TaskORM admission."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.exceptions import WorkflowException
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


def prepare():
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock(return_value=None)
    memory.assert_signed_authorization = AsyncMock()
    graph = SimpleNamespace(task_has_spawned=AsyncMock(return_value=False))
    orch = SimpleNamespace(
        graph_memory=graph,
        session_memory=memory,
        _engagement_is_authenticated=AsyncMock(return_value=True),
        _authenticated_user_label_is_active=AsyncMock(return_value=True),
        _persist_task_dependency=AsyncMock(),
        _audit_log=AsyncMock(),
        schedule_task=AsyncMock(),
    )
    parent = {
        "id": "task-source-parent",
        "engagement_id": "eng-parent",
        "type": "map_workflow",
        "authorization_version": 3,
        "result_summary": {
            "url": "https://authorized.example/",
            "user_label": "operator-one",
            "workflow_id": "workflow-one",
        },
    }
    return orch, parent


@pytest.mark.asyncio
async def test_signed_recovery_admits_deterministic_task_before_graph_projection():
    orch, parent = prepare()
    events = []

    async def schedule(task):
        events.append(("postgres-admit-and-dispatch", task.id))

    async def edge(_parent, child):
        events.append(("neo4j-link", child.id))

    orch.schedule_task.side_effect = schedule
    orch._persist_task_dependency.side_effect = edge
    first = await Orchestrator._resume_chain_link(orch, parent)
    assert first.parent_task_id == parent["id"]
    assert first.dependencies == [parent["id"]]
    assert first.id.startswith("task-") and len(first.id) == 37
    assert events == [
        ("postgres-admit-and-dispatch", first.id),
        ("neo4j-link", first.id),
    ]
    second, same_parent = prepare()
    assert (await Orchestrator._resume_chain_link(second, same_parent)).id == first.id


@pytest.mark.asyncio
async def test_pg_submission_failure_does_not_create_false_spawned_edge():
    orch, parent = prepare()
    orch.schedule_task.side_effect = OSError("PG commit/dispatch outcome unknown")
    with pytest.raises(OSError):
        await Orchestrator._resume_chain_link(orch, parent)
    orch._persist_task_dependency.assert_not_awaited()


@pytest.mark.asyncio
async def test_restart_repairs_only_graph_from_existing_child_without_replay():
    orch, parent = prepare()
    admitted = await Orchestrator._resume_chain_link(orch, parent)
    admitted.payload["_authorization_version"] = 3
    orch.schedule_task.reset_mock()
    orch._persist_task_dependency.reset_mock()
    orch.session_memory.load_task_authoritative.return_value = admitted
    assert await Orchestrator._resume_chain_link(orch, parent) is None
    orch.schedule_task.assert_not_awaited()
    orch._persist_task_dependency.assert_awaited_once()
    assert orch._persist_task_dependency.await_args.args[1] is admitted


@pytest.mark.asyncio
async def test_legacy_graph_only_spawned_edge_cannot_suppress_missing_pg_child():
    orch, parent = prepare()
    orch.graph_memory.task_has_spawned.return_value = True
    # Old code recorded SPAWNED before committing the child. The graph edge
    # must not suppress deterministic PG admission on this signed path.
    child = await Orchestrator._resume_chain_link(orch, parent)
    assert child is not None
    orch.schedule_task.assert_awaited_once()
    orch.graph_memory.task_has_spawned.assert_not_awaited()


@pytest.mark.asyncio
async def test_existing_pg_child_is_not_replayed_even_with_orphaned_graph_edge():
    orch, parent = prepare()
    admitted = await Orchestrator._resume_chain_link(orch, parent)
    admitted.payload["_authorization_version"] = parent["authorization_version"]
    orch.graph_memory.task_has_spawned.return_value = True
    orch.session_memory.load_task_authoritative.return_value = admitted
    orch.schedule_task.reset_mock()
    assert await Orchestrator._resume_chain_link(orch, parent) is None
    orch.schedule_task.assert_not_awaited()
    orch._persist_task_dependency.assert_awaited()


@pytest.mark.asyncio
async def test_conflicting_child_task_identity_never_resumes_or_dispatches():
    orch, parent = prepare()
    admitted = await Orchestrator._resume_chain_link(orch, parent)
    admitted.payload["_authorization_version"] = 3
    orch.schedule_task.reset_mock()
    orch._persist_task_dependency.reset_mock()
    admitted.parent_task_id = "task-foreign"
    orch.session_memory.load_task_authoritative.return_value = admitted
    with pytest.raises(WorkflowException, match="conflicts"):
        await Orchestrator._resume_chain_link(orch, parent)
    orch.schedule_task.assert_not_awaited()
    orch._persist_task_dependency.assert_not_awaited()


@pytest.mark.asyncio
async def test_same_deterministic_id_but_different_signed_target_cannot_be_graph_linked():
    orch, parent = prepare()
    admitted = await Orchestrator._resume_chain_link(orch, parent)
    orch.schedule_task.reset_mock()
    orch._persist_task_dependency.reset_mock()
    admitted.payload.update(
        {
            "_authorization_version": 3,
            "url": "https://foreign.example/",
        }
    )
    orch.session_memory.load_task_authoritative.return_value = admitted
    with pytest.raises(WorkflowException, match="conflicts"):
        await Orchestrator._resume_chain_link(orch, parent)
    orch.schedule_task.assert_not_awaited()
    orch._persist_task_dependency.assert_not_awaited()


@pytest.mark.asyncio
async def test_injected_extra_execution_payload_is_not_trusted_during_repair():
    orch, parent = prepare()
    admitted = await Orchestrator._resume_chain_link(orch, parent)
    admitted.payload.update({"_authorization_version": 3, "target_url": "https://foreign.example/"})
    orch.session_memory.load_task_authoritative.return_value = admitted
    orch.schedule_task.reset_mock()
    orch._persist_task_dependency.reset_mock()
    with pytest.raises(WorkflowException, match="conflicts"):
        await Orchestrator._resume_chain_link(orch, parent)
    orch.schedule_task.assert_not_awaited()
    orch._persist_task_dependency.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_auth_replay_requires_original_user_label_and_distinct_human_approval():
    orch, parent = prepare()
    parent["type"] = "extract_har_api_inventory"
    parent["result_summary"] = {"workflow_id": "wf-source"}
    assert await Orchestrator._resume_chain_link(orch, parent) is None
    orch.schedule_task.assert_not_awaited()

    parent["result_summary"]["target_user_label"] = "user-b"
    child = await Orchestrator._resume_chain_link(orch, parent)
    assert child.type == "replay_for_diff_auth"
    assert child.approval_required is True
    assert child.payload["target_user_label"] == "user-b"
    assert child.payload["workflow_id"] == "wf-source"
    assert "operator_approved" not in child.payload
    orch.schedule_task.assert_awaited_once()


@pytest.mark.asyncio
async def test_signer_rotation_during_child_recovery_prevents_even_graph_repair():
    orch, parent = prepare()
    orch.session_memory.assert_signed_authorization.side_effect = PermissionError(
        "signed version revoked"
    )
    with pytest.raises(PermissionError):
        await Orchestrator._resume_chain_link(orch, parent)
    orch.session_memory.load_task_authoritative.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()
