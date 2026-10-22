"""Live callback admission must be PG-backed, not in-memory or Neo4j-backed."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


def setup_callback(*, kind="map_workflow", result=None):
    original = Task(
        id="task-authoritative-callback",
        type=kind,
        agent_type=AgentType.WORKFLOW,
        engagement_id="eng-signed-callback",
        status="completed",
        payload={
            "_authorization_version": 2,
            "url": "https://authorized.example/",
            "user_label": "user-one",
            "workflow_id": "wf-signed",
        },
        result=result if result is not None else {"workflow_id": "wf-signed"},
    )
    scope = ScopeDefinition(
        engagement_id=original.engagement_id,
        domains=["authorized.example"],
        authorization_ref="signed-store-test-reference",
    )
    session = SessionState(
        session_id=original.engagement_id,
        phase="reconnaissance",
        scope=scope,
    )
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock(return_value=original)
    memory.load_session_state = AsyncMock(return_value=session)
    memory.assert_signed_authorization = AsyncMock()
    graph = SimpleNamespace(task_has_spawned=AsyncMock(return_value=True))
    orch = SimpleNamespace(
        session_memory=memory,
        graph_memory=graph,
        _resume_chain_link=AsyncMock(),
    )
    return orch, original


@pytest.mark.asyncio
async def test_callback_disregards_graph_edge_and_untrusted_result():
    orch, original = setup_callback()
    tampered = original.model_copy(deep=True)
    tampered.payload["url"] = "https://foreign.example/"
    await Orchestrator._chain_authenticated_surface(
        orch, tampered, {"workflow_id": "forged-graph-workflow"}
    )
    orch._resume_chain_link.assert_awaited_once()
    parent = orch._resume_chain_link.await_args.args[0]
    assert parent["result_summary"]["url"] == "https://authorized.example/"
    assert parent["result_summary"]["workflow_id"] == "wf-signed"
    assert parent["authorization_version"] == 2
    orch.graph_memory.task_has_spawned.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["unsigned", "not_completed", "revoked", "foreign_target", "halted"])
async def test_callback_does_not_admit_untrusted_signed_parent(failure):
    orch, original = setup_callback()
    if failure == "unsigned":
        original.payload.pop("_authorization_version")
    elif failure == "not_completed":
        original.status = "running"
    elif failure == "revoked":
        orch.session_memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    elif failure == "foreign_target":
        original.payload["url"] = "https://foreign.example/"
    elif failure == "halted":
        session = await orch.session_memory.load_session_state(original.engagement_id)
        session.phase = "halted"
    await Orchestrator._chain_authenticated_surface(orch, original, {"workflow_id": "made-up"})
    orch._resume_chain_link.assert_not_awaited()


@pytest.mark.asyncio
async def test_callback_captured_har_only_uses_safe_pg_result_and_workflow():
    orch, original = setup_callback(
        kind="capture_authenticated_surface",
        result={"har_path": "captures/signed.har"},
    )
    await Orchestrator._chain_authenticated_surface(
        orch, original, {"har_path": "C:/Windows/secret.har", "workflow_id": "forged"}
    )
    parent = orch._resume_chain_link.await_args.args[0]
    assert parent["result_summary"]["har_path"] == "captures/signed.har"
    assert parent["result_summary"]["workflow_id"] == "wf-signed"
    original.result = {"har_path": "../../unsafe.har"}
    orch._resume_chain_link.reset_mock()
    await Orchestrator._chain_authenticated_surface(orch, original, {})
    orch._resume_chain_link.assert_not_awaited()


@pytest.mark.asyncio
async def test_extract_chain_replays_only_pg_pinned_workflow_id():
    orch, original = setup_callback(kind="extract_har_api_inventory", result={})
    await Orchestrator._chain_authenticated_surface(
        orch, original, {"workflow_id": "attacker-workflow-id"}
    )
    parent = orch._resume_chain_link.await_args.args[0]
    assert parent["result_summary"]["workflow_id"] == "wf-signed"
    assert "target_user_label" not in parent["result_summary"]
