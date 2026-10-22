"""One failed recovery I/O must not strand unrelated signed pending tasks."""

from unittest.mock import AsyncMock

import pytest

from tests.test_signed_recovery_gate import _harness


@pytest.mark.asyncio
async def test_one_redis_failure_does_not_abort_other_pending_recovery():
    recovery, memory = _harness()
    first = (await memory.list_all_tasks())[0]
    second = first.model_copy(update={"id": "task-recovery-second"})
    memory.list_all_tasks.return_value = [first, second]
    memory.push_task_queue.side_effect = [OSError("redis temporarily down"), None]

    result = await recovery.recover_state()
    assert result["engagements"] == 1
    assert result["tasks"] == 1
    assert result["skipped"] == 1
    assert first.status == "pending" and second.status == "pending"
    assert memory.push_task_queue.await_count == 2


@pytest.mark.asyncio
async def test_unavailable_first_flow_does_not_block_second_authorized_task():
    recovery, memory = _harness()
    first = (await memory.list_all_tasks())[0]
    first.flow_id = "flow-unavailable"
    second = first.model_copy(update={"id": "task-recovery-second", "flow_id": None})
    memory.list_all_tasks.return_value = [first, second]
    memory.load_flow = AsyncMock(side_effect=OSError("PG read timeout"))

    result = await recovery.recover_state()
    assert result["tasks"] == 1
    assert result["skipped"] == 1
    memory.push_task_queue.assert_awaited_once()
    assert memory.push_task_queue.await_args.args[0] == "tasks:eng-recovery"
