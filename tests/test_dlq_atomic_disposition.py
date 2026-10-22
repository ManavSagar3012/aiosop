"""Owner/signer/entry are fenced in the same transaction as DLQ disposition."""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory import dlq_resolution
from ai_osop.memory.dlq_resolution import DLQResolutionDenied, DLQResolutionStore
from ai_osop.reliability.dlq import DeadLetterQueue
from ai_osop.core.models import Task
from ai_osop.core.config import AgentType


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class State:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.owner = "signed-senior"
        self.entry = SimpleNamespace(
            id="dlq-atomic",
            engagement_id="eng-atomic",
            task_id="task-original",
            status="pending_review",
            resolved_at=None,
            operator_notes=None,
        )
        self.events = []
        self.queries = []

    def open(self):
        return DB(self)


class DB:
    def __init__(self, state):
        self.state = state

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        async with self.state.lock:
            snapshot = deepcopy((self.state.entry, self.state.events))
            try:
                yield
            except BaseException:
                self.state.entry, self.state.events = snapshot
                raise

    async def execute(self, stmt):
        query = str(stmt)
        self.state.queries.append(query)
        if "FROM session_states" in query:
            return Result(self.state.owner)
        if "FROM dlq_entries" in query:
            return Result(self.state.entry)
        raise AssertionError(f"Unexpected SQL {query[:100]}")


@pytest.fixture
def ledger(monkeypatch):
    state = State()
    monkeypatch.setattr(
        dlq_resolution, "guard_sql", AsyncMock(return_value=SimpleNamespace(version=3))
    )

    async def event(_db, engagement_id, task_id, kind, actor_id, payload, *, idempotency_key):
        state.events.append((engagement_id, task_id, kind, actor_id, payload, idempotency_key))

    monkeypatch.setattr(
        dlq_resolution.SupervisionStore, "_append_event", AsyncMock(side_effect=event)
    )
    memory = SimpleNamespace(_async_session=state.open)
    return DLQResolutionStore(memory), state


@pytest.mark.asyncio
async def test_competing_seniors_obtain_one_discard_and_one_durable_event(ledger):
    store, state = ledger
    other = DLQResolutionStore(store._memory)
    results = await asyncio.gather(
        store.discard("eng-atomic", "dlq-atomic", "signed-senior", "reviewed false positive"),
        other.discard("eng-atomic", "dlq-atomic", "signed-senior", "reviewed false positive"),
    )
    assert sorted(results) == ["conflict", "discarded"]
    assert state.entry.status == "discarded"
    assert state.entry.operator_notes == "reviewed false positive"
    assert state.events == [
        (
            "eng-atomic",
            "task-original",
            "dlq.discarded",
            "signed-senior",
            {"entry_id": "dlq-atomic", "status": "discarded"},
            "dlq-discard:dlq-atomic",
        )
    ]
    assert any("FOR UPDATE" in query for query in state.queries)


@pytest.mark.asyncio
async def test_revoked_signer_fails_before_entry_mutation(ledger, monkeypatch):
    store, state = ledger
    monkeypatch.setattr(
        dlq_resolution,
        "guard_sql",
        AsyncMock(side_effect=PermissionError("revoked signed ROE")),
    )
    with pytest.raises(PermissionError):
        await store.discard("eng-atomic", "dlq-atomic", "signed-senior", "reviewed and rejected")
    assert state.entry.status == "pending_review"
    assert state.events == []


@pytest.mark.asyncio
async def test_outbox_failure_rolls_back_same_disposition_transaction(ledger, monkeypatch):
    store, state = ledger
    monkeypatch.setattr(
        dlq_resolution.SupervisionStore,
        "_append_event",
        AsyncMock(side_effect=OSError("event outbox unavailable")),
    )
    with pytest.raises(OSError):
        await store.discard("eng-atomic", "dlq-atomic", "signed-senior", "reviewed and rejected")
    assert state.entry.status == "pending_review"
    assert state.entry.resolved_at is None


@pytest.mark.asyncio
async def test_cross_tenant_and_untrusted_notes_fail_closed(ledger):
    store, state = ledger
    for values in (
        ("eng-atomic", "dlq-atomic", "foreign", "reviewed and rejected"),
        ("eng-atomic", "dlq-atomic", "signed-senior", "short"),
        ("eng/../../../foreign", "dlq-atomic", "signed-senior", "reviewed and rejected"),
    ):
        with pytest.raises(DLQResolutionDenied):
            await store.discard(*values)
    assert state.entry.status == "pending_review"
    assert state.events == []


@pytest.mark.asyncio
async def test_exact_oidc_subject_with_provider_delimiter_remains_supported(ledger):
    store, state = ledger
    state.owner = "auth0|signed-senior"
    assert (
        await store.discard(
            "eng-atomic",
            "dlq-atomic",
            "auth0|signed-senior",
            "Confirmed duplicate and discarded",
        )
        == "discarded"
    )
    assert state.events[0][3] == "auth0|signed-senior"


@pytest.mark.asyncio
async def test_direct_legacy_dlq_helper_cannot_replay_signed_flow_task():
    task = Task(
        id="task-signed",
        engagement_id="eng-atomic",
        type="full_recon",
        agent_type=AgentType.RECON,
        flow_id="flow-atomic",
        payload={"_authorization_version": 3},
    )
    entry = SimpleNamespace(status="pending_review", task_payload=task.model_dump())
    memory = SimpleNamespace(
        get_dlq_entry=AsyncMock(return_value=entry), store_dlq_entry=AsyncMock()
    )
    assert await DeadLetterQueue(memory).requeue("dlq-atomic") is None
    memory.store_dlq_entry.assert_not_awaited()
