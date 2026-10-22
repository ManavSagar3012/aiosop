"""Authenticated discovery must commit its deterministic PG Task before graph dedupe."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


def harness():
    engagement_id = "eng-discovery-signed"
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_session_state = AsyncMock(
        return_value=SessionState(
            session_id=engagement_id,
            phase="reconnaissance",
            scope=ScopeDefinition(
                engagement_id=engagement_id,
                domains=["authorized.example"],
                authorization_ref="signed-test-policy",
            ),
        )
    )
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=4))
    memory.load_task_authoritative = AsyncMock(return_value=None)
    graph = SimpleNamespace(claim_auto_discovery=AsyncMock(return_value=True))
    orch = SimpleNamespace(
        session_memory=memory,
        graph_memory=graph,
        _engagement_is_authenticated=AsyncMock(return_value=True),
        _pick_auth_user_label=AsyncMock(return_value="signed-user"),
        _authenticated_user_label_is_active=AsyncMock(return_value=True),
        schedule_task=AsyncMock(),
        _audit_log=AsyncMock(),
    )
    return orch, engagement_id


@pytest.mark.asyncio
async def test_discovery_commits_pg_first_and_never_creates_graph_claim():
    orch, engagement_id = harness()
    actions = []

    async def schedule(_task):
        actions.append("pg-schedule")

    async def audit(_event):
        actions.append("audit")

    orch.schedule_task.side_effect = schedule
    orch._audit_log.side_effect = audit
    task = await Orchestrator.ensure_authenticated_discovery(
        orch, engagement_id, url_hint="https://authorized.example/login"
    )
    assert isinstance(task, Task)
    assert task.type == "map_workflow"
    assert task.agent_type == AgentType.WORKFLOW
    assert task.approval_required is True
    assert task.payload["_authorization_version"] == 4
    assert task.payload["url"] == "https://authorized.example/login"
    assert actions == ["pg-schedule", "audit"]
    orch.graph_memory.claim_auto_discovery.assert_not_awaited()


@pytest.mark.asyncio
async def test_existing_task_deduped_even_without_any_graph_projection():
    orch, engagement_id = harness()
    first = await Orchestrator.ensure_authenticated_discovery(orch, engagement_id)
    orch.session_memory.load_task_authoritative.return_value = first
    again = await Orchestrator.ensure_authenticated_discovery(orch, engagement_id)
    assert again is None
    orch.schedule_task.assert_awaited_once()
    orch.graph_memory.claim_auto_discovery.assert_not_awaited()


@pytest.mark.asyncio
async def test_pg_failure_creates_no_graph_slot_and_retries_same_identity():
    orch, engagement_id = harness()
    orch.schedule_task.side_effect = RuntimeError("PG unavailable")
    with pytest.raises(RuntimeError, match="PG unavailable"):
        await Orchestrator.ensure_authenticated_discovery(orch, engagement_id)
    orch.graph_memory.claim_auto_discovery.assert_not_awaited()
    previous_id = orch.schedule_task.await_args.args[0].id
    orch.schedule_task.side_effect = None
    child = await Orchestrator.ensure_authenticated_discovery(orch, engagement_id)
    assert child.id == previous_id


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["revoked", "scope", "halted", "invalid_label", "unauthenticated", "revoked_import", "no_pinned_user"])
async def test_auth_discovery_rejects_unsafe_admission(failure):
    orch, engagement_id = harness()
    url = "https://authorized.example/"
    if failure == "revoked":
        orch.session_memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    elif failure == "scope":
        url = "https://foreign.example/"
    elif failure == "halted":
        state = await orch.session_memory.load_session_state(engagement_id)
        state.phase = "halted"
    elif failure == "invalid_label":
        orch._pick_auth_user_label.return_value = "../../unsafe"
    elif failure == "unauthenticated":
        orch._engagement_is_authenticated.return_value = False
    elif failure == "revoked_import":
        orch._authenticated_user_label_is_active.return_value = False
    elif failure == "no_pinned_user":
        orch._pick_auth_user_label.return_value = None
        orch._authenticated_user_label_is_active.return_value = False
    assert (
        await Orchestrator.ensure_authenticated_discovery(orch, engagement_id, url_hint=url)
        is None
    )
    orch.schedule_task.assert_not_awaited()
    orch.graph_memory.claim_auto_discovery.assert_not_awaited()


@pytest.mark.asyncio
async def test_colliding_pg_discovery_identity_is_denied_without_mutation():
    orch, engagement_id = harness()
    first = await Orchestrator.ensure_authenticated_discovery(orch, engagement_id)
    first.engagement_id = "other-tenant"
    orch.session_memory.load_task_authoritative.return_value = first
    with pytest.raises(Exception, match="identity conflict"):
        await Orchestrator.ensure_authenticated_discovery(orch, engagement_id)
    orch.schedule_task.assert_awaited_once()
