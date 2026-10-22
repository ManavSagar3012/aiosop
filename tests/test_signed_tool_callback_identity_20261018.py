"""Write-ahead callback admission must revalidate signed Task identity."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.orchestrator.terminal_dispatcher import TerminalCallbackDispatcher


@pytest.fixture
def dispatcher():
    store = SimpleNamespace(
        renew_callback_lease=AsyncMock(return_value=True),
        start_callback_effect=AsyncMock(return_value=True),
        confirm_callback_effect=AsyncMock(return_value=True),
    )
    return TerminalCallbackDispatcher(SimpleNamespace(terminal_store=store))


@pytest.mark.asyncio
async def test_revocation_between_wal_and_effect_never_invokes_callback(dispatcher):
    item = {"id": "cb-1", "lease_id": "lease-1", "engagement_id": "eng-a", "task_id": "task-a"}
    loader = AsyncMock(
        side_effect=[
            SimpleNamespace(id="task-a", engagement_id="eng-a"),
            PermissionError("ROE revoked"),
        ]
    )
    dispatcher._load_authorized_task = loader
    action = AsyncMock()
    with pytest.raises(PermissionError, match="revoked"):
        await dispatcher._apply_effect(item, "sync_subtask", action)
    dispatcher.store.start_callback_effect.assert_awaited_once()
    action.assert_not_awaited()
    dispatcher.store.confirm_callback_effect.assert_not_awaited()


@pytest.mark.asyncio
async def test_cross_tenant_rebound_callback_denied_after_wal(dispatcher):
    item = {"id": "cb-2", "lease_id": "lease-2", "engagement_id": "eng-a", "task_id": "task-a"}
    dispatcher._load_authorized_task = AsyncMock(
        side_effect=[
            SimpleNamespace(id="task-a", engagement_id="eng-a"),
            SimpleNamespace(id="task-a", engagement_id="eng-other"),
        ]
    )
    action = AsyncMock()
    with pytest.raises(RuntimeError, match="identity changed"):
        await dispatcher._apply_effect(item, "graph_upsert", action)
    action.assert_not_awaited()


@pytest.mark.asyncio
async def test_current_same_source_confirms_only_once(dispatcher):
    item = {"id": "cb-3", "lease_id": "lease-3", "engagement_id": "eng-a", "task_id": "task-a"}
    dispatcher._load_authorized_task = AsyncMock(
        return_value=SimpleNamespace(id="task-a", engagement_id="eng-a")
    )
    action = AsyncMock()
    await dispatcher._apply_effect(item, "sync_subtask", action)
    assert dispatcher._load_authorized_task.await_count == 2
    assert dispatcher.store.renew_callback_lease.await_count == 3
    action.assert_awaited_once()
    dispatcher.store.confirm_callback_effect.assert_awaited_once()
