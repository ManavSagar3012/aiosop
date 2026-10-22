"""Extracted entrypoints must share signed PG-first discovery admission."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.engagement_manager import EngagementManager
from ai_osop.orchestrator.task_scheduler import TaskScheduler


def signed_harness():
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock()
    memory.assert_signed_authorization = AsyncMock()
    orch = SimpleNamespace(
        session_memory=memory,
        ensure_authenticated_discovery=AsyncMock(),
        _engagement_is_authenticated=AsyncMock(return_value=True),
        _pick_auth_user_label=AsyncMock(return_value="actual-identity"),
        graph_memory=SimpleNamespace(_driver=None),
    )
    orch.engagement_manager = EngagementManager(orch)
    return orch


@pytest.mark.asyncio
async def test_imported_session_and_phase_hooks_use_one_canonical_admission():
    orch = signed_harness()
    manager = orch.engagement_manager
    await manager.ensure_authenticated_discovery(
        "eng-1", url_hint="https://authorized.example/"
    )
    orch.ensure_authenticated_discovery.assert_awaited_once_with(
        "eng-1", url_hint="https://authorized.example/"
    )
    orch.ensure_authenticated_discovery.reset_mock()
    await manager.claim_auto_discovery("eng-1", "caller-claimed-label", "session-import")
    orch.ensure_authenticated_discovery.assert_awaited_once_with("eng-1")
    orch.session_memory.load_task_authoritative.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_callback_requires_completed_original_task_and_signed_version():
    orch = signed_harness()
    source = Task(
        id="task-original", type="auth_diff", agent_type=AgentType.WORKFLOW,
        engagement_id="eng-1", status="completed",
        payload={"_authorization_version": 5},
    )
    orch.session_memory.load_task_authoritative.return_value = source
    await orch.engagement_manager.claim_auto_discovery(
        "eng-1", "forged-session-label", source.id
    )
    orch.session_memory.assert_signed_authorization.assert_awaited_once_with(
        "eng-1", expected_version=5
    )
    orch.ensure_authenticated_discovery.assert_awaited_once_with("eng-1")
    # Neither a Neo4j preclaim nor the obsolete _schedule_authenticated_discovery
    # method is reachable, and caller-supplied identity is not authority.
    assert not hasattr(orch, "_schedule_authenticated_discovery")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"status": "running"},
        {"engagement_id": "eng-other"},
        {"type": "map_workflow"},
        {"payload": {"_authorization_version": "1"}},
        {"payload": {}},
    ],
)
async def test_signed_source_is_never_inferred_from_graph_or_caller(changes):
    orch = signed_harness()
    task = Task(
        id="task-signed", type="auth_diff", status="completed",
        engagement_id="eng-1", agent_type=AgentType.WORKFLOW,
        payload={"_authorization_version": 3},
    )
    for key, value in changes.items():
        setattr(task, key, value)
    orch.session_memory.load_task_authoritative.return_value = task
    await orch.engagement_manager.claim_auto_discovery("eng-1", "A", "task-signed")
    orch.ensure_authenticated_discovery.assert_not_awaited()
    orch.session_memory.assert_signed_authorization.assert_not_awaited()


@pytest.mark.asyncio
async def test_revocation_prevents_callback_from_scheduling_any_child():
    orch = signed_harness()
    orch.session_memory.load_task_authoritative.return_value = Task(
        id="task-signed", type="auth_diff", status="completed",
        engagement_id="eng-1", agent_type=AgentType.WORKFLOW,
        payload={"_authorization_version": 3},
    )
    orch.session_memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    with pytest.raises(PermissionError):
        await orch.engagement_manager.claim_auto_discovery("eng-1", "A", "task-signed")
    orch.ensure_authenticated_discovery.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_scheduler_dispatch_ignores_stale_graph_and_agent_availability():
    orch = signed_harness()
    orch.engagement_manager.claim_auto_discovery = AsyncMock()
    scheduler = TaskScheduler(orch)
    await scheduler._chain_authenticated_surface(
        Task(id="task-1", type="auth_diff", status="completed",
             engagement_id="eng-1", agent_type=AgentType.WORKFLOW)
    )
    orch.engagement_manager.claim_auto_discovery.assert_awaited_once_with(
        "eng-1", "", "task-1"
    )
    orch._engagement_is_authenticated.assert_not_awaited()
    orch._pick_auth_user_label.assert_not_awaited()


@pytest.mark.asyncio
async def test_non_diff_source_does_not_spawn_discovery():
    orch = signed_harness()
    orch.engagement_manager.claim_auto_discovery = AsyncMock()
    await TaskScheduler(orch)._chain_authenticated_surface(
        Task(id="task-1", type="map_workflow", status="completed",
             engagement_id="eng-1", agent_type=AgentType.WORKFLOW)
    )
    orch.engagement_manager.claim_auto_discovery.assert_not_awaited()
