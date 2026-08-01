"""AIOSOP-REAPER-INMEM-SYNC: AgentReaper must write its requeue back to _tasks.

AgentReaper requeues a Redis-reconstructed copy of a dead agent's running task.
If it does not also update the orchestrator's in-memory ``_tasks`` map, that copy
stays ``status="running"``, and RecoveryService._reap_stuck_tasks (which iterates
``_tasks``) re-reaps the same task — a double requeue / double execution. This
pins the in-memory writeback that prevents the sequential double-reap.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.reliability.agent_reaper import AgentReaper


@pytest.mark.asyncio
async def test_recover_agent_syncs_requeued_task_into_memory():
    task_dict = {
        "id": "task-abc",
        "type": "recon_scan",
        "agent_type": "recon",
        "status": "running",
        "assigned_agent_id": "agent-1",
        "engagement_id": "eng-1",
        "retry_count": 0,
        "max_retries": 3,
    }

    orch = MagicMock()
    orch._tasks = {}  # in-memory view the other reaper iterates
    orch.graph_memory = MagicMock(upsert_task=AsyncMock())
    orch.session_memory = MagicMock(
        acquire_lock=AsyncMock(return_value=True),
        release_lock=AsyncMock(return_value=True),
        find_tasks_by_agent=AsyncMock(return_value=[task_dict]),
        store_task=AsyncMock(),
        update_agent_status=AsyncMock(),
        write_audit_event=AsyncMock(),
    )
    orch.task_scheduler = MagicMock(schedule_task=AsyncMock())

    reaper = AgentReaper(orch, state_machine=MagicMock())
    await reaper._recover_agent("agent-1")

    # The requeued task must now be visible in the in-memory map as pending,
    # so RecoveryService won't see it as still-running and re-reap it.
    assert "task-abc" in orch._tasks
    assert orch._tasks["task-abc"].status == "pending"
    assert orch._tasks["task-abc"].assigned_agent_id is None


@pytest.mark.asyncio
async def test_recover_agent_tolerates_missing_tasks_map():
    # A fixture/replica whose orch has no dict _tasks must not crash the reaper.
    task_dict = {
        "id": "task-xyz",
        "type": "recon_scan",
        "agent_type": "recon",
        "status": "running",
        "assigned_agent_id": "agent-2",
        "engagement_id": "eng-1",
        "retry_count": 0,
        "max_retries": 3,
    }
    orch = MagicMock()
    orch._tasks = None  # not a dict -> writeback must be skipped, not error
    orch.graph_memory = MagicMock(upsert_task=AsyncMock())
    orch.session_memory = MagicMock(
        acquire_lock=AsyncMock(return_value=True),
        release_lock=AsyncMock(return_value=True),
        find_tasks_by_agent=AsyncMock(return_value=[task_dict]),
        store_task=AsyncMock(),
        update_agent_status=AsyncMock(),
        write_audit_event=AsyncMock(),
    )
    orch.task_scheduler = MagicMock(schedule_task=AsyncMock())

    reaper = AgentReaper(orch, state_machine=MagicMock())
    await reaper._recover_agent("agent-2")  # must not raise

    orch.task_scheduler.schedule_task.assert_awaited_once()
