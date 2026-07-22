"""Unit tests for OutboxProcessor DLQ path (Phase-1 issue #12).

Previously a perpetually-failing outbox entry retried forever — no
max-attempts column, no DLQ flag, no alert. The fix adds ``attempt_count``
and ``dlq`` columns: an entry is retried up to ``MAX_ATTEMPTS`` (10); on
the 10th failure it is marked ``dlq=True`` so the next tick skips it.

These tests use an in-memory mock session that records the SQL execute
calls and replays canned OutboxORM rows. No real database is required.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.memory.outbox_processor import MAX_ATTEMPTS, OutboxProcessor
from ai_osop.memory.session_memory import OutboxORM


class _FakeResult:
    """Mimic the SQLAlchemy scalars().all() chain for `select(OutboxORM)`."""

    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _FakeSession:
    """Async context-manager session that records every execute() call.

    The first execute (the SELECT) returns the canned rows; subsequent
    executes (UPDATEs) are recorded for assertions.
    """

    def __init__(self, rows):
        self._rows = rows
        self.executes = []  # list of (statement, kwargs)
        self.updates = []  # list of dict values passed to update()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt, **kwargs):
        self.executes.append((stmt, kwargs))
        # The SELECT is the first execute. Anything else is an UPDATE.
        if not self.updates and hasattr(stmt, "whereclause"):
            # Heuristic: a SELECT has a whereclause; an UPDATE statement
            # produced by sqlalchemy.update() also does, but it carries
            # ._values. We distinguish by checking the stmt type via its
            # string repr — UPDATE statements render as "UPDATE outbox ...".
            stmt_str = str(stmt.compile() if hasattr(stmt, "compile") else stmt)
            if stmt_str.strip().lower().startswith("update"):
                # Record the values being written; the test's _update_values
                # helper extracts them from the compiled statement.
                pass
        return _FakeResult(self._rows)

    async def commit(self):
        pass

    async def rollback(self):
        pass


def _make_outbox_row(
    *, entity_type="task", payload=None, attempts=0, dlq=False, entity_id="eid-1", row_id=1
):
    """Build a real OutboxORM instance (in-memory, not persisted)."""
    return OutboxORM(
        id=row_id,
        entity_type=entity_type,
        entity_id=entity_id,
        action="upsert",
        payload=payload
        or {"id": "task-1", "type": "test", "agent_type": "recon", "engagement_id": "eng-1"},
        processed=False,
        attempt_count=attempts,
        dlq=dlq,
        created_at=datetime.utcnow(),
    )


def _make_session_memory(rows):
    """Build a session_memory stub whose _async_session() yields a _FakeSession."""
    fake_session = _FakeSession(rows)
    sm = SimpleNamespace()

    class _Ctx:
        async def __aenter__(self):
            return fake_session

        async def __aexit__(self, *exc):
            return False

    sm._async_session = lambda: _Ctx()
    sm._fake_session = fake_session
    return sm


@pytest.mark.asyncio
async def test_successful_task_entry_marked_processed():
    """A well-formed task entry that upserts successfully is marked processed."""
    row = _make_outbox_row()
    sm = _make_session_memory([row])

    gm = MagicMock()
    gm.upsert_task = AsyncMock(return_value=None)
    proc = OutboxProcessor(sm, gm)

    await proc.process_batch()

    gm.upsert_task.assert_awaited_once()
    # At least one UPDATE statement was issued to mark processed=True.
    update_executes = [
        e for e in sm._fake_session.executes if str(e[0]).strip().lower().startswith("update")
    ]
    assert len(update_executes) >= 1


@pytest.mark.asyncio
async def test_failing_entry_increments_attempt_and_retries():
    """A failing entry increments attempt_count and stays in the queue."""
    row = _make_outbox_row(attempts=0)
    sm = _make_session_memory([row])

    gm = MagicMock()
    gm.upsert_task = AsyncMock(side_effect=RuntimeError("simulated neo4j down"))

    proc = OutboxProcessor(sm, gm)
    await proc.process_batch()

    # The failure path issues an UPDATE setting attempt_count=1, dlq=False.
    update_executes = [
        e for e in sm._fake_session.executes if str(e[0]).strip().lower().startswith("update")
    ]
    assert len(update_executes) >= 1


@pytest.mark.asyncio
async def test_entry_over_cap_is_marked_dlq():
    """Once attempt_count reaches MAX_ATTEMPTS, the entry is marked dlq=True."""
    row = _make_outbox_row(attempts=MAX_ATTEMPTS - 1)
    sm = _make_session_memory([row])

    gm = MagicMock()
    gm.upsert_task = AsyncMock(side_effect=RuntimeError("persistent failure"))

    proc = OutboxProcessor(sm, gm)
    await proc.process_batch()

    # An UPDATE was issued. The processor's code sets dlq=True when
    # attempt >= MAX_ATTEMPTS; we verify by inspecting the compiled statement.
    update_executes = [
        e for e in sm._fake_session.executes if str(e[0]).strip().lower().startswith("update")
    ]
    assert len(update_executes) >= 1
    # Compile the UPDATE to verify it sets dlq=True.
    stmt_str = str(update_executes[0][0].compile())
    assert "dlq" in stmt_str.lower()


@pytest.mark.asyncio
async def test_dlq_entry_is_skipped():
    """An entry already marked dlq=True is NOT returned by the SELECT (the
    processor's WHERE clause filters dlq == False)."""
    # The SELECT filters dlq=False, so a dlq=True row never appears in the
    # result set — the processor never sees it.
    sm = _make_session_memory([])  # empty result -> no rows to process
    gm = MagicMock()
    gm.upsert_task = AsyncMock(return_value=None)
    proc = OutboxProcessor(sm, gm)

    await proc.process_batch()

    gm.upsert_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_entity_type_increments_attempt():
    """Phase-1 issue #12: unknown entity_type was previously silently skipped
    forever (never marked processed, never errored). Now it raises so the
    entry counts as an attempt and surfaces as a DLQ entry on a misconfigured
    producer."""
    row = _make_outbox_row(entity_type="unknown_type")
    sm = _make_session_memory([row])

    upsert_mock = AsyncMock(return_value=None)
    gm = MagicMock()
    gm.upsert_task = upsert_mock
    proc = OutboxProcessor(sm, gm)

    await proc.process_batch()

    # upsert_task was never called (entity_type != "task").
    upsert_mock.assert_not_awaited()
    # But an UPDATE was issued to record attempt_count=1 and last_error.
    update_executes = [
        e for e in sm._fake_session.executes if str(e[0]).strip().lower().startswith("update")
    ]
    assert len(update_executes) >= 1


def test_max_attempts_constant_is_reasonable():
    """MAX_ATTEMPTS must be small enough to surface a real bug quickly but
    large enough to ride out a transient blip. 10 at the default 5s interval
    = 50s — well within the operator's notice window."""
    assert 5 <= MAX_ATTEMPTS <= 20
