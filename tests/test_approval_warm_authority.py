"""Approval cache is never evidence of a successful PostgreSQL decision."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.models import ApprovalRequest
from ai_osop.memory.session_memory import SessionMemory


@pytest.fixture
def warm_approval_store():
    memory = SessionMemory()
    session = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=None)
    memory._async_session = MagicMock(return_value=ctx)
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=False)
    session.begin = MagicMock(return_value=tx)
    # First SELECT: no existing approval. Second SELECT: the exact persisted
    # task being bound; approval registration must never trust a summary.
    session.execute.side_effect = [
        SimpleNamespace(scalar_one_or_none=lambda: None),
        SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(
            status="awaiting_approval", type="summarize_context",
            approval_required=True, payload={"_authorization_version": 1, "target": "none"},
        )),
    ]
    session.add = MagicMock()
    memory.store_hot = AsyncMock()
    memory.retrieve_hot = AsyncMock(side_effect=AssertionError("Redis must not authorize an approval"))
    request = ApprovalRequest(
        task_id="task-valid", engagement_id="eng-valid", agent_id="agent-1",
        action_type="summarize_context", target="none", payload_summary="safe",
        risk_assessment="low", status="pending",
    )
    return memory, session, request


@pytest.mark.asyncio
async def test_postgres_commit_failure_cannot_write_a_redis_approval(warm_approval_store):
    memory, session, request = warm_approval_store
    session.begin.return_value.__aexit__.side_effect = OSError("durable write failed")
    with pytest.raises(OSError, match="durable write failed"):
        await memory.store_approval_request(request)
    memory.store_hot.assert_not_awaited()


@pytest.mark.asyncio
async def test_redis_failure_after_postgres_commit_does_not_undo_approval(warm_approval_store):
    memory, session, request = warm_approval_store
    memory.store_hot.side_effect = ConnectionError("Redis offline")
    await memory.store_approval_request(request)
    session.begin.assert_called_once()
    session.begin.return_value.__aexit__.assert_awaited_once()
    memory.store_hot.assert_awaited_once()


@pytest.mark.asyncio
async def test_approval_lookup_ignores_potentially_stale_redis_cache(warm_approval_store):
    memory, session, request = warm_approval_store
    session.execute.side_effect = None
    session.execute.return_value = SimpleNamespace(
        scalar_one_or_none=lambda: SimpleNamespace(**request.model_dump()),
    )
    result = await memory.load_approval_request(request.id)
    assert result is not None
    assert result.status == "pending"
    memory.retrieve_hot.assert_not_awaited()


@pytest.mark.asyncio
async def test_direct_approval_grant_cannot_bypass_atomic_signed_path(warm_approval_store):
    memory, session, request = warm_approval_store
    request.status = "approved"
    request.operator_id = "self-asserted"
    with pytest.raises(PermissionError, match="atomic signed resolution"):
        await memory.store_approval_request(request)
    session.begin.assert_not_called()
    memory.store_hot.assert_not_awaited()


@pytest.mark.asyncio
async def test_postgres_read_failure_does_not_fallback_to_forged_redis_grant(warm_approval_store):
    memory, session, request = warm_approval_store
    session.execute.side_effect = OSError("Postgres unavailable")
    with pytest.raises(OSError, match="Postgres unavailable"):
        await memory.load_approval_request(request.id)
    memory.retrieve_hot.assert_not_awaited()
