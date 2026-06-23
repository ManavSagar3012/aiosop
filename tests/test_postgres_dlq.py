import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.reliability.dlq import DeadLetterQueue, DLQEntry
from ai_osop.memory.session_memory import SessionMemory, DLQEntryORM


@pytest.mark.asyncio
async def test_postgres_dlq_persistence():
    """Verify that DLQ calls Postgres store/retrieve methods and runs SQL statements."""
    # 1. Setup mock session and engine
    mock_session = AsyncMock()
    mock_session_maker = MagicMock()
    mock_session_maker.return_value.__aenter__.return_value = mock_session

    session_mem = SessionMemory()
    session_mem._async_session = mock_session_maker
    session_mem._redis = AsyncMock()  # Mock hot-tier cache
    session_mem._redis.ping = AsyncMock()

    # 2. Setup mock data to return on select query (mock scalar_one_or_none)
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
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_orm
    # For list queries, return a scalar iterator
    mock_result.scalars.return_value = [mock_orm]
    # For stats query, return status-count tuples
    mock_result.all.return_value = [("pending_review", 5), ("requeued", 2), ("discarded", 1)]
    
    mock_session.execute.return_value = mock_result

    dlq = DeadLetterQueue(session_mem)

    # 3. Test Enqueue
    task = Task(
        id="task-123",
        type="test_task",
        agent_type=AgentType.RECON,
        engagement_id="eng-123",
        payload={},
    )
    
    entry_id = await dlq.enqueue(task, reason="exhausted", final_error="timeout")
    assert entry_id.startswith("dlq-")
    
    # Verify that session.execute was called to insert into Postgres
    mock_session.execute.assert_called_once()
    mock_session.commit.assert_called_once()
    mock_session.reset_mock()

    # 4. Test Get Entry (warm tier fallback)
    # Reset hot cache to simulate Redis miss and trigger Postgres select
    session_mem.retrieve_hot = AsyncMock(return_value=None)
    
    entry = await dlq._session_memory.get_dlq_entry(entry_id)
    assert entry is not None
    assert entry.id == "dlq-123"
    assert entry.status == "pending_review"
    
    mock_session.execute.assert_called_once()
    mock_session.reset_mock()

    # 5. Test List Entries
    entries = await dlq.list_entries(engagement_id="eng-123", status="pending_review")
    assert len(entries) == 1
    assert entries[0].id == "dlq-123"
    
    mock_session.execute.assert_called_once()
    mock_session.reset_mock()

    # 6. Test Stats
    stats = await dlq.get_stats()
    assert stats["pending"] == 5
    assert stats["requeued"] == 2
    assert stats["discarded"] == 1
    
    mock_session.execute.assert_called_once()
