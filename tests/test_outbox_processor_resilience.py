"""Resilience tests for OutboxProcessor failure branches.

Targets the corner cases the happy-path test (test_outbox_dlq.py) does not
pin: rollback semantics on mid-batch failure, monotonic ``attempt_count``
increments across ticks, the MAX_ATTEMPTS -> DLQ transition quiescing the
entry, and the unknown-entity_type branch raising/penning a DLQ row.

Uses a real in-memory SQLite database via ``sqlalchemy.ext.asyncio`` so the
actual SQL UPDATE statements execute (the mock-session test double in
test_outbox_dlq.py only asserts that *an* UPDATE statement was compiled —
it cannot tell whether the row was actually mutated).
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ai_osop.memory.outbox_processor import MAX_ATTEMPTS, OutboxProcessor
from ai_osop.memory.session_memory import Base, OutboxORM, SessionMemory


@pytest.fixture
async def sqlite_session_memory():
    """A real SessionMemory object backed by in-memory SQLite.

    Avoids the Postgres+Redis dependency in ``SessionMemory.connect()`` by
    wiring just the async session factory the outbox processor touches.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    sm = SessionMemory()
    sm._pg_engine = engine
    sm._async_session = factory
    try:
        yield sm, factory
    finally:
        await engine.dispose()


@pytest.fixture
def graph_memory_mock():
    """A GraphMemory stand-in whose upsert/add methods are individually stubable."""
    gm = MagicMock()
    gm.upsert_task = AsyncMock(return_value=None)
    gm.add_vulnerability = AsyncMock(return_value=None)
    gm.add_endpoint = AsyncMock(return_value=None)
    gm.add_asset = AsyncMock(return_value=None)
    return gm


async def _insert_outbox_row(
    factory: async_sessionmaker,
    *,
    entity_type: str = "task",
    entity_id: str = "eid-1",
    payload: Optional[dict] = None,
    attempt_count: int = 0,
    dlq: bool = False,
    processed: bool = False,
) -> int:
    """Persist an outbox row directly so we exercise the real SELECT/UPDATE path."""
    if payload is None:
        payload = {
            "id": "task-1",
            "type": "test",
            "agent_type": "recon",
            "engagement_id": "eng-1",
        }
    async with factory() as s:
        row = OutboxORM(
            entity_type=entity_type,
            entity_id=entity_id,
            action="upsert",
            payload=payload,
            processed=processed,
            attempt_count=attempt_count,
            dlq=dlq,
            created_at=datetime.utcnow(),
        )
        s.add(row)
        await s.commit()
        return row.id


async def _fetch(factory: async_sessionmaker, row_id: int) -> OutboxORM:
    async with factory() as s:
        result = await s.execute(select(OutboxORM).where(OutboxORM.id == row_id))
        return result.scalars().one()


@pytest.mark.asyncio
async def test_transient_failure_recovers_on_third_attempt(sqlite_session_memory, graph_memory_mock):
    """Fail-fail-succeed: each failure bumps attempt_count; the success marks processed.

    This pins the recovery semantic — a transient Neo4j blip must not poison
    the entry, and once the projection succeeds the row is permanently
    resolved (processed=True) rather than re-attempting.
    """
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(factory)

    proc = OutboxProcessor(sm, graph_memory_mock)

    # Tick 1: fail
    graph_memory_mock.upsert_task = AsyncMock(side_effect=RuntimeError("neo4j blip 1"))
    await proc.process_batch()
    row = await _fetch(factory, row_id)
    assert row.attempt_count == 1
    assert row.processed is False
    assert row.dlq is False
    assert "neo4j blip 1" in (row.last_error or "")

    # Tick 2: fail
    graph_memory_mock.upsert_task = AsyncMock(side_effect=RuntimeError("neo4j blip 2"))
    await proc.process_batch()
    row = await _fetch(factory, row_id)
    assert row.attempt_count == 2
    assert row.processed is False
    assert row.dlq is False
    assert "neo4j blip 2" in (row.last_error or "")

    # Tick 3: success
    graph_memory_mock.upsert_task = AsyncMock(return_value=None)
    await proc.process_batch()
    row = await _fetch(factory, row_id)
    assert row.processed is True
    assert row.dlq is False
    # attempt_count does NOT reset on success — it's a lifetime counter.
    assert row.attempt_count == 2

    # Tick 4: success is a no-op because the SELECT filters processed=False.
    graph_memory_mock.upsert_task.reset_mock()
    await proc.process_batch()
    graph_memory_mock.upsert_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_vulnerability_failure_increments_attempt_count(
    sqlite_session_memory, graph_memory_mock
):
    """The vulnerability projection path also goes through the same rollback /
    attempt-count instrumentation, not a separate code path that could regress."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(
        factory,
        entity_type="vulnerability",
        payload={
            "id": "vuln-1",
            "title": "Reflected XSS",
            "vuln_type": "xss",
            "severity": "high",
            "description": "Reflected XSS probe",
            "tool_source": "test",
            "confidence": 0.9,
            "target_url": "https://example.com/x?q=1",
            "engagement_id": "eng-1",
        },
    )
    proc = OutboxProcessor(sm, graph_memory_mock)

    graph_memory_mock.add_vulnerability = AsyncMock(side_effect=RuntimeError("neo4j down"))
    await proc.process_batch()

    row = await _fetch(factory, row_id)
    assert row.attempt_count == 1
    assert row.processed is False
    assert row.dlq is False
    assert "neo4j down" in (row.last_error or "")
    graph_memory_mock.add_vulnerability.assert_awaited_once()
    # _from_outbox flag is on the call signature so the projection can't loop.
    _, kwargs = graph_memory_mock.add_vulnerability.await_args
    assert kwargs.get("_from_outbox") is True


@pytest.mark.asyncio
async def test_unknown_entity_type_persists_error_and_attempts(
    sqlite_session_memory, graph_memory_mock
):
    """Unknown entity_type raises, the attempt_count ticks up, and the error
    message is recorded so an operator can read it out of the row itself."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(factory, entity_type="nonsense")

    proc = OutboxProcessor(sm, graph_memory_mock)
    await proc.process_batch()

    row = await _fetch(factory, row_id)
    assert row.attempt_count == 1
    assert row.processed is False
    assert row.dlq is False
    assert "unknown outbox entity_type" in (row.last_error or "")
    assert "nonsense" in (row.last_error or "")

    # None of the entity projections fired.
    graph_memory_mock.upsert_task.assert_not_awaited()
    graph_memory_mock.add_vulnerability.assert_not_awaited()
    graph_memory_mock.add_endpoint.assert_not_awaited()
    graph_memory_mock.add_asset.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_entity_type_reaches_dlq_at_max_attempts(
    sqlite_session_memory, graph_memory_mock
):
    """An unknown entity_type ticks attempt_count up like any other failure and
    is quiesced at MAX_ATTEMPTS — a misconfigured producer no longer loops forever."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(
        factory,
        entity_type="totally-bogus",
        attempt_count=MAX_ATTEMPTS - 1,  # one failure away from DLQ
    )

    proc = OutboxProcessor(sm, graph_memory_mock)
    await proc.process_batch()

    row = await _fetch(factory, row_id)
    assert row.attempt_count == MAX_ATTEMPTS
    assert row.processed is False
    assert row.dlq is True
    assert "unknown outbox entity_type" in (row.last_error or "")


@pytest.mark.asyncio
async def test_entry_at_max_attempts_not_retried_further(
    sqlite_session_memory, graph_memory_mock
):
    """A row already marked dlq=True must never be selected again. The SELECT
    filters ``dlq == False``, so a poisoned entry cannot keep hammering Neo4j.

    This guards the WHOLE LOOP invariant: not just "we set dlq=True eventually"
    but "after we set dlq=True the entry is permanently quiesced."
    """
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(
        factory,
        attempt_count=MAX_ATTEMPTS,
        dlq=True,
    )

    proc = OutboxProcessor(sm, graph_memory_mock)
    await proc.process_batch()
    await proc.process_batch()  # second tick — still no-op

    # upsert_task was NEVER called.
    graph_memory_mock.upsert_task.assert_not_awaited()
    # And the row is untouched.
    row = await _fetch(factory, row_id)
    assert row.attempt_count == MAX_ATTEMPTS
    assert row.dlq is True
    assert row.processed is False


@pytest.mark.asyncio
async def test_crossing_max_attempts_marks_dlq_and_emits_alert(
    sqlite_session_memory, graph_memory_mock, caplog
):
    """The tick that takes attempt_count from MAX_ATTEMPTS-1 to MAX_ATTEMPTS
    is the one that flips dlq=True. Subsequent ticks must not touch the row."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(factory, attempt_count=MAX_ATTEMPTS - 1)

    proc = OutboxProcessor(sm, graph_memory_mock)
    graph_memory_mock.upsert_task = AsyncMock(side_effect=RuntimeError("persistent"))

    # Tick N-1 -> N: this is the flip.
    await proc.process_batch()
    row = await _fetch(factory, row_id)
    assert row.attempt_count == MAX_ATTEMPTS
    assert row.dlq is True
    assert row.processed is False

    # Subsequent ticks must not schedule further attempts (the SELECT drops it).
    graph_memory_mock.upsert_task.reset_mock()
    await proc.process_batch()
    graph_memory_mock.upsert_task.assert_not_awaited()
    row = await _fetch(factory, row_id)
    # attempt_count does NOT creep past MAX_ATTEMPTS — the entry is quiesced.
    assert row.attempt_count == MAX_ATTEMPTS


@pytest.mark.asyncio
async def test_last_error_truncated_to_512_chars(sqlite_session_memory, graph_memory_mock):
    """OutboxORM.last_error is a String(512); a pathological exception message
    (e.g. a 10KB stack trace embedded in the error string) must be truncated
    before persistence. The processor slices ``str(e)[:512]``."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(factory)

    proc = OutboxProcessor(sm, graph_memory_mock)
    long_error = "x" * 4096
    graph_memory_mock.upsert_task = AsyncMock(side_effect=RuntimeError(long_error))

    await proc.process_batch()

    row = await _fetch(factory, row_id)
    assert row.attempt_count == 1
    assert row.last_error is not None
    assert len(row.last_error) <= 512
    assert row.last_error == "x" * 512


@pytest.mark.asyncio
async def test_multiple_rows_isolated_failures(sqlite_session_memory, graph_memory_mock):
    """When one entry in a batch fails, the others still succeed. A flaky
    projection for entry A must not poison entry B in the same tick — the
    per-row try/except scopes the failure."""
    sm, factory = sqlite_session_memory
    fail_id = await _insert_outbox_row(factory, entity_id="fail-me")
    ok_id = await _insert_outbox_row(factory, entity_id="ok-me")

    proc = OutboxProcessor(sm, graph_memory_mock)
    # First call (fail_id, processed first since insertion order == created_at
    # order) raises; second call (ok_id) succeeds.
    graph_memory_mock.upsert_task = AsyncMock(
        side_effect=[RuntimeError("first call fails"), None]
    )

    await proc.process_batch()

    a = await _fetch(factory, fail_id)
    b = await _fetch(factory, ok_id)
    assert a.attempt_count == 1
    assert a.processed is False
    assert a.dlq is False
    assert b.attempt_count == 0
    assert b.processed is True
    assert b.dlq is False


@pytest.mark.asyncio
async def test_attempt_count_of_none_treated_as_zero(sqlite_session_memory, graph_memory_mock):
    """Backward-compat: rows written by older code may have attempt_count=NULL.
    The processor uses ``(entry.attempt_count or 0) + 1`` so these rows still
    tick forward instead of crashing on a TypeError."""
    sm, factory = sqlite_session_memory
    # Insert with attempt_count=None by hand — ORM defaults column to 0 only
    # when the row goes through the standard constructor; forcing None is what
    # a legacy row would look like.
    async with factory() as s:
        row = OutboxORM(
            entity_type="task",
            entity_id="legacy-row",
            action="upsert",
            payload={
                "id": "task-legacy",
                "type": "test",
                "agent_type": "recon",
                "engagement_id": "eng-1",
            },
            processed=False,
            attempt_count=None,
            dlq=False,
            created_at=datetime.utcnow(),
        )
        s.add(row)
        await s.commit()
        row_id = row.id

    proc = OutboxProcessor(sm, graph_memory_mock)
    graph_memory_mock.upsert_task = AsyncMock(side_effect=RuntimeError("legacy error"))

    await proc.process_batch()

    row = await _fetch(factory, row_id)
    assert row.attempt_count == 1
    assert row.processed is False


@pytest.mark.asyncio
async def test_successful_task_marks_processed_with_real_update(
    sqlite_session_memory, graph_memory_mock
):
    """The happy path against a real DB: the row goes from processed=False to
    processed=True, attempt_count stays at 0, dlq stays False."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(factory)

    proc = OutboxProcessor(sm, graph_memory_mock)
    await proc.process_batch()

    row = await _fetch(factory, row_id)
    assert row.processed is True
    assert row.attempt_count == 0
    assert row.dlq is False
    assert row.last_error is None
    graph_memory_mock.upsert_task.assert_awaited_once()


@pytest.mark.asyncio
async def test_endpoint_entry_projects_with_from_outbox_flag(sqlite_session_memory, graph_memory_mock):
    """entity_type='endpoint' should dispatch to add_endpoint with
    _from_outbox=True so the projection cannot re-enqueue itself."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(
        factory,
        entity_type="endpoint",
        entity_id="ep-1",
        payload={
            "id": "ep-1",
            "url": "https://example.com/api",
            "method": "GET",
            "engagement_id": "eng-1",
        },
    )

    proc = OutboxProcessor(sm, graph_memory_mock)
    await proc.process_batch()

    graph_memory_mock.add_endpoint.assert_awaited_once()
    kwargs = graph_memory_mock.add_endpoint.await_args.kwargs
    assert kwargs.get("_from_outbox") is True

    row = await _fetch(factory, row_id)
    assert row.processed is True


@pytest.mark.asyncio
async def test_asset_entry_projects_with_from_outbox_flag(sqlite_session_memory, graph_memory_mock):
    """entity_type='asset' should dispatch to add_asset with _from_outbox=True."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(
        factory,
        entity_type="asset",
        entity_id="asset-1",
        payload={
            "id": "asset-1",
            "type": "domain",
            "value": "example.com",
            "source": "recon",
            "confidence": 0.9,
            "engagement_id": "eng-1",
        },
    )

    proc = OutboxProcessor(sm, graph_memory_mock)
    await proc.process_batch()

    graph_memory_mock.add_asset.assert_awaited_once()
    kwargs = graph_memory_mock.add_asset.await_args.kwargs
    assert kwargs.get("_from_outbox") is True

    row = await _fetch(factory, row_id)
    assert row.processed is True


@pytest.mark.asyncio
async def test_attack_path_entry_projects_via_replay(sqlite_session_memory):
    """entity_type='attack_path' uses add_attack_path_from_outbox (raw payload
    replay) because a full AttackPath cannot be reconstructed from the minimal
    outbox payload. Pin the dispatch and the processed=True write."""
    sm, factory = sqlite_session_memory
    payload = {
        "id": "path-abc",
        "node_ids": ["vuln-1", "vuln-2"],
        "confidence": 0.8,
        "edges": [{"from_id": "vuln-1", "to_id": "vuln-2", "type": "exploit_chain"}],
    }
    row_id = await _insert_outbox_row(
        factory,
        entity_type="attack_path",
        entity_id="path-abc",
        payload=payload,
    )

    gm = MagicMock()
    gm.add_attack_path_from_outbox = AsyncMock(return_value=None)
    proc = OutboxProcessor(sm, gm)

    await proc.process_batch()

    gm.add_attack_path_from_outbox.assert_awaited_once_with(payload)
    row = await _fetch(factory, row_id)
    assert row.processed is True


@pytest.mark.asyncio
async def test_run_processes_one_batch_then_stops(sqlite_session_memory, graph_memory_mock):
    """run() keeps looping until stop() flips _running False; the loop body
    must call process_batch at least once. Pin the wiring so a refactor that
    accidentally swallows this loop crashes a test instead of silently
    dropping all outbox processing."""
    sm, factory = sqlite_session_memory
    row_id = await _insert_outbox_row(factory)

    proc = OutboxProcessor(sm, graph_memory_mock, interval=0)  # tight loop; we stop early

    async def _stop_after_first_tick():
        # Wait until process_batch has had a chance to run once, then stop.
        for _ in range(50):
            row = await _fetch(factory, row_id)
            if row.processed:
                break
            await asyncio.sleep(0.05)
        await proc.stop()

    run_task = asyncio.create_task(proc.run())
    stop_task = asyncio.create_task(_stop_after_first_tick())
    await asyncio.wait_for(run_task, timeout=5.0)
    await stop_task

    row = await _fetch(factory, row_id)
    assert row.processed is True
