"""Security and commit boundaries for PostgreSQL-backed agent supervision."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.memory.session_memory import Base
from ai_osop.memory.supervision_store import (
    SupervisionAttemptORM,
    SupervisionControlORM,
    SupervisionEventORM,
    SupervisionMessageORM,
    SupervisionOutboxORM,
    SupervisionStore,
    SupervisionConflict,
    _identifier,
    _safe_payload,
)


ENGAGEMENT = SimpleNamespace(
    session_id="eng-1",
    created_by="alice",
    phase="reconnaissance",
    scope={
        "engagement_id": "eng-1",
        "domains": ["example.test"],
        "ips": [],
        "authorization_ref": "ROE-123",
    },
)
TASK = SimpleNamespace(
    id="task-1", engagement_id="eng-1", status="running", approval_required=False
)


class _ScalarResult:
    def __init__(self, scalar=None, rowcount=1):
        self.scalar = scalar
        self.rowcount = rowcount

    def scalar_one_or_none(self):
        return self.scalar

    def scalars(self):
        return SimpleNamespace(all=lambda: self.scalar or [])


class _Transaction:
    def __init__(self, db):
        self.db = db

    async def __aenter__(self):
        return self.db

    async def __aexit__(self, exc_type, exc_value, tb):
        if exc_type is not None:
            self.db.rolled_back += 1
            return False
        if self.db.fail_commit:
            raise OSError("PostgreSQL commit rejected")
        self.db.commits += 1
        return False


class _FakeSession:
    def __init__(self, scalars, fail_commit=False):
        self.results = iter(scalars)
        self.statements = []
        self.added = []
        self.commits = 0
        self.rolled_back = 0
        self.fail_commit = fail_commit
        self.flushed = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, tb):
        return False

    def begin(self):
        return _Transaction(self)

    async def execute(self, statement):
        self.statements.append(statement)
        response = next(self.results)
        return response if isinstance(response, _ScalarResult) else _ScalarResult(response)

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        self.flushed += 1
        for row in self.added:
            if isinstance(row, SupervisionEventORM) and row.sequence is None:
                row.sequence = self.flushed
            if hasattr(row, "created_at") and row.created_at is None:
                row.created_at = datetime.utcnow()
            if hasattr(row, "updated_at") and row.updated_at is None:
                row.updated_at = datetime.utcnow()

    async def refresh(self, row):
        return None


def _store(db):
    memory = MagicMock()
    memory._async_session = lambda: db
    return SupervisionStore(memory)


def test_supervision_schema_has_db_uniqueness_scope_and_ordering():
    assert {
        "supervision_events",
        "supervision_messages",
        "supervision_attempts",
        "supervision_controls",
        "supervision_outbox",
    } <= set(Base.metadata.tables)
    assert "uq_supervision_attempt_number" in {
        constraint.name for constraint in SupervisionAttemptORM.__table__.constraints
    }
    assert "uq_supervision_event_dedupe" in {
        constraint.name for constraint in SupervisionEventORM.__table__.constraints
    }
    assert "uq_supervision_message_dedupe" in {
        constraint.name for constraint in SupervisionMessageORM.__table__.constraints
    }
    assert SupervisionOutboxORM.__table__.columns["event_id"].unique
    assert "ix_supervision_events_timeline" in {
        item.name for item in SupervisionEventORM.__table__.indexes
    }


def test_receipt_sanitizer_does_not_persist_raw_tool_output():
    assert _safe_payload(
        {
            "status": "unknown",
            "authorization": "Bearer abcde",
            "password": "no",
            "arguments": {"secret": "no"},
            "receipts": {
                "mcp": {"status": "unknown", "raw_response": "password=bad"},
                "temporal": "requested",
            },
        }
    ) == {
        "status": "unknown",
        "receipts": {"mcp": {"status": "unknown"}, "temporal": "requested"},
    }


def test_oversized_idempotency_key_must_fail_instead_of_colliding():
    with pytest.raises(ValueError, match="identifier"):
        _identifier("same-prefix-" + "x" * 200, 128)
    assert _identifier("start:run-123", 128) == "start:run-123"


@pytest.mark.asyncio
async def test_event_outbox_is_single_transaction_and_has_no_secrets():
    db = _FakeSession([ENGAGEMENT, TASK])
    event = await _store(db).append_event(
        "eng-1",
        "task-1",
        "agent.progress",
        "worker",
        {
            "status": "running",
            "password": "do-not-store",
            "receipts": {"mcp": {"status": "accepted", "headers": "secret"}},
        },
    )
    assert event["payload"] == {
        "status": "running",
        "receipts": {"mcp": {"status": "accepted"}},
    }
    assert db.commits == 1
    assert len(db.added) == 2
    evt, outbox = db.added
    assert isinstance(evt, SupervisionEventORM)
    assert isinstance(outbox, SupervisionOutboxORM)
    assert outbox.event_id == evt.id
    assert outbox.payload["event_id"] == evt.id
    sql = str(db.statements[0].compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE" in sql


@pytest.mark.asyncio
async def test_commit_failure_does_not_claim_event_success():
    db = _FakeSession([ENGAGEMENT], fail_commit=True)
    with pytest.raises(OSError, match="commit rejected"):
        await _store(db).append_event("eng-1", kind="agent.started")
    assert db.commits == 0
    assert len(db.added) == 2


@pytest.mark.asyncio
async def test_invalid_engagement_blocks_durable_command_and_outbox():
    db = _FakeSession([None])
    with pytest.raises(SupervisionConflict, match="Engagement does not exist"):
        await _store(db).request_control("eng-1", "task-1", "cancel", "alice", "Stop now", "req-1")
    assert db.added == []
    assert db.commits == 0
    assert db.rolled_back == 1


@pytest.mark.asyncio
async def test_operator_input_rejects_unowned_engagement_before_writes():
    db = _FakeSession([ENGAGEMENT])
    with pytest.raises(SupervisionConflict, match="does not own"):
        await _store(db).append_message(
            "eng-1",
            "conversation-1",
            "task-1",
            "operator",
            "mallory",
            "retry",
            "once-1",
            actor_role="operator",
        )
    assert db.added == []


@pytest.mark.asyncio
async def test_stop_command_is_pending_with_event_and_outbox_after_commit():
    db = _FakeSession([ENGAGEMENT, TASK, None])
    result = await _store(db).request_control(
        "eng-1",
        "task-1",
        "cancel",
        "alice",
        "Stop task",
        "req-stop",
    )
    assert result["status"] == "pending"
    assert result["revision"] == 0
    assert db.commits == 1
    assert [type(row) for row in db.added] == [
        SupervisionControlORM,
        SupervisionEventORM,
        SupervisionOutboxORM,
    ]
    assert db.added[1].kind == "agent.control.requested"


@pytest.mark.asyncio
async def test_duplicate_attempt_is_not_created_or_dispatched_twice():
    running = SimpleNamespace(
        id="run-existing",
        engagement_id="eng-1",
        task_id="task-1",
        attempt=1,
        status="running",
        external_id="temporal-1",
        receipt=None,
        revision=1,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    # The mocked engagement row must provide the same ROE shape as the
    # actual persisted PostgreSQL ORM row.
    db = _FakeSession([SimpleNamespace(**{**vars(ENGAGEMENT), "roe": {}}), TASK, running])
    result = await _store(db).start_attempt("eng-1", "task-1", attempt=1)
    assert result["created"] is False
    assert result["status"] == "running"
    assert not db.added
    assert db.commits == 1


@pytest.mark.asyncio
async def test_initial_attempt_returns_created_only_after_durable_commit():
    db = _FakeSession([SimpleNamespace(**{**vars(ENGAGEMENT), "roe": {}}), TASK, None])
    result = await _store(db).start_attempt("eng-1", "task-1", 1)
    assert result["created"] is True
    assert result["status"] == "queued"
    assert len(db.added) == 3
    assert db.commits == 1


@pytest.mark.asyncio
async def test_attempt_update_uses_revision_cas_and_commits_event_atomically():
    attempt = SimpleNamespace(
        id="run-1",
        engagement_id="eng-1",
        task_id="task-1",
        attempt=1,
        status="running",
        revision=3,
        external_id="temporal-1",
        receipt=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db = _FakeSession([attempt, _ScalarResult(rowcount=1)])
    result = await _store(db).update_attempt(
        "run-1",
        expected_revision=3,
        status="unknown",
        receipt={"outcome": "remote_disconnected", "secret": "must-not-store"},
    )
    assert result is not None
    assert len(db.added) == 2
    assert isinstance(db.added[0], SupervisionEventORM)
    assert isinstance(db.added[1], SupervisionOutboxORM)
    sql = str(db.statements[1].compile(dialect=postgresql.dialect()))
    assert "UPDATE supervision_attempts" in sql
    assert "supervision_attempts.revision =" in sql
    assert db.commits == 1


@pytest.mark.asyncio
async def test_failed_attempt_revision_cas_does_not_publish_event():
    attempt = SimpleNamespace(
        id="run-1",
        engagement_id="eng-1",
        task_id="task-1",
        attempt=1,
        status="running",
        revision=3,
        external_id=None,
        receipt=None,
    )
    db = _FakeSession([attempt, _ScalarResult(rowcount=0)])
    result = await _store(db).update_attempt(
        "run-1",
        expected_revision=3,
        status="unknown",
    )
    assert result is None
    assert db.added == []
    assert db.commits == 1


@pytest.mark.asyncio
async def test_start_attempt_rejects_stale_consequential_approval():
    task = SimpleNamespace(
        id="task-1",
        engagement_id="eng-1",
        status="running",
        approval_required=True,
        payload={"operator_approved": False, "approval_id": "apr-old"},
    )
    db = _FakeSession([ENGAGEMENT, task])
    with pytest.raises(SupervisionConflict, match="no current persisted approval"):
        await _store(db).start_attempt("eng-1", "task-1", 1)
    assert db.added == []


@pytest.mark.asyncio
async def test_resume_blocks_on_unresolved_previous_remote_control():
    db = _FakeSession([ENGAGEMENT, TASK, "req-previous", None])
    with pytest.raises(SupervisionConflict, match="outcome is unknown"):
        await _store(db).request_control(
            "eng-1", "task-1", "resume", "alice", "Continue", "req-next"
        )
    assert db.added == []
    assert db.commits == 0


@pytest.mark.asyncio
async def test_stop_confirmation_requires_positive_remote_receipt():
    store = _store(_FakeSession([]))
    with pytest.raises(SupervisionConflict, match="requires a verifiable"):
        await store.resolve_control(
            "req-stop",
            "confirmed_stopped",
            {"receipts": {"temporal": {"status": "cancel_requested"}}},
        )
