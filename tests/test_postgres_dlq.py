import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import DLQEntryORM, SessionMemory
from ai_osop.reliability.dlq import DeadLetterQueue
from tests._mocks import stub_async_session_maker, stub_db_result


@pytest.mark.asyncio
async def test_postgres_dlq_persistence():
    """Verify that DLQ calls Postgres store/retrieve methods and runs SQL statements."""
    # Setup mock session
    mock_session = AsyncMock()
    mock_session_maker = stub_async_session_maker(mock_session)

    session_mem = SessionMemory()
    session_mem._async_session = mock_session_maker
    session_mem._redis = AsyncMock()  # Mock hot-tier cache
    session_mem._redis.ping = AsyncMock()

    # Setup mock data to return on select query
    mock_orm = DLQEntryORM(
        id="dlq-123",
        task_id="task-123",
        engagement_id="eng-123",
        task_type="test_task",
        agent_type="recon",
        reason="exhausted",
        final_error="timeout",
        task_payload={"id": "task-123", "payload": {}},
        status="pending_review",
        created_at=datetime.utcnow(),
    )

    mock_result = stub_db_result(
        scalar_one_or_none=mock_orm,
        scalars=[mock_orm],
        all_rows=[("pending_review", 5), ("requeued", 2), ("discarded", 1)],
    )

    mock_session.execute.return_value = mock_result

    dlq = DeadLetterQueue(session_mem)

    # Test Enqueue
    task = Task(
        id="task-123",
        type="test_task",
        agent_type=AgentType.RECON,
        engagement_id="eng-123",
        payload={},
    )

    entry_id = await dlq.enqueue(task, reason="exhausted", final_error="timeout")
    assert entry_id.startswith("dlq-")

    mock_session.execute.assert_called_once()
    mock_session.commit.assert_called_once()
    mock_session.reset_mock()

    # Test Get Entry (warm tier fallback)
    session_mem.retrieve_hot = AsyncMock(return_value=None)

    entry = await dlq._session_memory.get_dlq_entry(entry_id)
    assert entry is not None
    assert entry.id == "dlq-123"
    assert entry.status == "pending_review"

    mock_session.execute.assert_called_once()
    mock_session.reset_mock()

    # Test List Entries
    entries = await dlq.list_entries(engagement_id="eng-123", status="pending_review")
    assert len(entries) == 1
    assert entries[0].id == "dlq-123"

    mock_session.execute.assert_called_once()
    mock_session.reset_mock()

    # Test Stats
    stats = await dlq.get_stats()
    assert stats["pending"] == 5
    assert stats["requeued"] == 2
    assert stats["discarded"] == 1

    mock_session.execute.assert_called_once()
