"""Regression test for the retention-service Postgres cleanup bug (audit 2026-08-01).

Root cause: ``RetentionService._cleanup_postgres`` opened
``async with self.session_memory._async_session() as session`` and ran ONLY the
task-delete inside the block. The block closed there, so the subsequent
session/approval/audit-log/session-state statements executed against a CLOSED
session — silently no-op'ing (or raising) on every retention run. Only tasks
were ever cleaned.

The fix moves every statement INSIDE a single session/transaction. This test
proves all five classes are now actually deleted/archived on an in-memory DB.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ai_osop.auth.session_store import UserSessionORM
from ai_osop.memory.retention_service import RetentionService
from ai_osop.memory.session_memory import (
    ApprovalRequestORM,
    AuditLogORM,
    Base,
    SessionStateORM,
    TaskORM,
)


class _StubSessionMemory:
    """Minimal stand-in exposing only what RetentionService touches."""

    def __init__(self, session_factory):
        self._async_session = session_factory
        self._redis = None  # _audit_redis_ttl short-circuits without Redis


def _old(days_ago: int) -> datetime:
    return datetime.utcnow() - timedelta(days=days_ago)


@pytest.mark.asyncio
async def test_cleanup_postgres_deletes_all_five_classes():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Seed one expired row of each class.
    async with factory() as s:
        s.add(
            TaskORM(
                id="task-old",
                type="t",
                priority=1,
                agent_type="recon",
                payload={},
                status="completed",
                completed_at=_old(400),
                engagement_id="eng-x",
            )
        )
        s.add(
            UserSessionORM(
                pk="eng-x:u",
                engagement_id="eng-x",
                user_label="u",
                cookies={},
                captured_at=_old(400),
                expires_at=_old(400),
            )
        )
        s.add(
            ApprovalRequestORM(
                id="apr-old",
                engagement_id="eng-x",
                task_id="task-old",
                status="approved",
                responded_at=_old(400),
            )
        )
        s.add(
            AuditLogORM(
                event_id="evt-old",
                timestamp=_old(3000),  # beyond 7-year audit retention
                event_type="test",
                severity="info",
                actor_type="system",
                actor_id="t",
                archived=False,
            )
        )
        s.add(
            SessionStateORM(
                session_id="sess-old",
                last_accessed=_old(400),
                created_at=_old(400),
                updated_at=_old(400),
            )
        )
        await s.commit()

    # A fresh row that must NOT be touched (guard against over-deletion).
    async with factory() as s:
        s.add(
            TaskORM(
                id="task-fresh",
                type="t",
                priority=1,
                agent_type="recon",
                payload={},
                status="completed",
                completed_at=datetime.utcnow(),
                engagement_id="eng-x",
            )
        )
        await s.commit()

    svc = RetentionService(graph_memory=None, session_memory=_StubSessionMemory(factory))
    results = await svc._cleanup_postgres()

    # Every class must report a nonzero effect — impossible before the fix.
    assert results["tasks_deleted"] == 1, results
    assert results["sessions_deleted"] == 1, results
    assert results["approvals_deleted"] == 1, results
    assert results["audit_logs_archived"] == 1, results
    assert results["session_states_deleted"] == 1, results

    # Fresh task survives; audit row is soft-deleted (still present, archived).
    async with factory() as s:
        from sqlalchemy import select

        fresh = await s.execute(select(TaskORM).where(TaskORM.id == "task-fresh"))
        assert fresh.scalar_one_or_none() is not None

        audit = await s.execute(select(AuditLogORM).where(AuditLogORM.event_id == "evt-old"))
        row = audit.scalar_one_or_none()
        assert row is not None and row.archived is True


@pytest.mark.asyncio
async def test_cleanup_postgres_is_transactional_on_empty_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    svc = RetentionService(graph_memory=None, session_memory=_StubSessionMemory(factory))
    results = await svc._cleanup_postgres()
    # No rows -> zero deletions, and no exception from a dead session.
    assert all(v == 0 for v in results.values()), results
