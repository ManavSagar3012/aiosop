"""Live PostgreSQL interactive supervision qualification.

Run only against a disposable, separately named test database:
  OSOP_SUPERVISION_TEST_PG_URI=postgresql+asyncpg://.../supervision_qualification_...
Never runs against the application's regular PostgreSQL database.
"""

import asyncio
import os
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from ai_osop.memory.session_memory import SessionStateORM, TaskORM
from ai_osop.memory.supervision_store import SupervisionStore


def _url():
    raw = os.environ.get("OSOP_SUPERVISION_TEST_PG_URI", "")
    if not raw:
        pytest.skip("Set OSOP_SUPERVISION_TEST_PG_URI for isolated live PostgreSQL test")
    url = make_url(raw)
    if (
        not str(url.database or "").startswith("supervision_qualification_")
        or url.host not in {"127.0.0.1", "localhost"}
        or url.port in {None, 5432, 5433}
        or url.drivername != "postgresql+asyncpg"
    ):
        pytest.fail("Refusing to run qualification against non-isolated PostgreSQL")
    return raw


def _alembic(sync_connection, revision, operation):
    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["connection"] = sync_connection
    getattr(command, operation)(cfg, revision)


@pytest.fixture
async def live():
    engine = create_async_engine(_url(), pool_size=5)
    async with engine.begin() as connection:
        await connection.run_sync(_alembic, "head", "upgrade")
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    class Memory:
        _async_session = maker

    try:
        yield engine, maker, SupervisionStore(Memory())
    finally:
        await engine.dispose()


async def _seed(maker, monkeypatch, *, retry_count=0, max_retries=3):
    from ai_osop.memory.authorization_store import AuthorizationStore
    from tests.test_authorization_store import make_signed_session
    from types import SimpleNamespace

    suffix = uuid.uuid4().hex[:16]
    eid, tid = "eng-" + suffix, "task-" + suffix
    now = datetime.utcnow()
    owner_session, receipt, _, _ = make_signed_session(
        monkeypatch, session_id=eid, owner="alice",
        authorization_id="auth-supervision-" + suffix,
        domains=["example.test"], roe_override={},
    )
    owner_session.phase = "reconnaissance"
    await AuthorizationStore(SimpleNamespace(_async_session=maker)).create_authorized_session(
        owner_session, receipt, owner_session.created_by,
    )
    async with maker() as session:
        async with session.begin():
            session.add(
                TaskORM(
                    id=tid,
                    engagement_id=eid,
                    type="recon",
                    priority=5,
                    agent_type="recon",
                    payload={"_authorization_version": 1, "domain": "example.test"},
                    dependencies=[],
                    max_retries=max_retries,
                    timeout_seconds=120,
                    scope_check=True,
                    approval_required=False,
                    status="running",
                    result=None,
                    retry_count=retry_count,
                    created_at=now,
                )
            )
    return eid, tid


@pytest.mark.asyncio
async def test_live_competing_consumers_one_claim(live, monkeypatch):
    _, maker, store = live
    eid, tid = await _seed(maker, monkeypatch)
    message = await store.append_message(
        eid,
        "conversation-live",
        tid,
        "operator",
        "alice",
        "Please verify the state",
        "message-1",
        "operator",
    )
    claims = await asyncio.gather(
        store.claim_inbox(eid, tid, "worker-a", 30, 8),
        store.claim_inbox(eid, tid, "worker-b", 30, 8),
    )
    assert sum(len(chunk) for chunk in claims) == 1
    first = claims[0] or claims[1]
    winner = "worker-a" if claims[0] else "worker-b"
    loser = "worker-b" if claims[0] else "worker-a"
    assert first[0]["id"] == message["id"]
    assert first[0]["delivery_state"] == "leased"
    assert await store.ack_inbox(message["id"], loser) is None
    # Only a model-return boundary may call ACK.
    consumed = await store.ack_inbox(message["id"], winner, "consumed")
    assert consumed["delivery_state"] == "consumed"
    records = await store.list_messages(eid, "conversation-live")
    assert records[0]["delivery_state"] == "consumed"
    assert records[0]["consumed_at"] is not None
    assert await store.claim_inbox(eid, tid, "worker-c") == []


@pytest.mark.asyncio
async def test_live_expired_claim_redelivery_and_stale_ack(live, monkeypatch):
    _, maker, store = live
    eid, tid = await _seed(maker, monkeypatch)
    message = await store.append_message(
        eid,
        "conversation-crash",
        tid,
        "operator",
        "alice",
        "Continue after recovered model call",
        "crash-1",
        "operator",
    )
    assert len(await store.claim_inbox(eid, tid, "crashed-worker", 1, 1)) == 1
    await asyncio.sleep(1.15)
    recovered = await store.claim_inbox(eid, tid, "recovered-worker", 30, 1)
    assert len(recovered) == 1
    assert recovered[0]["id"] == message["id"]
    assert recovered[0]["delivery_attempts"] == 2
    assert await store.ack_inbox(message["id"], "crashed-worker") is None
    assert (await store.ack_inbox(message["id"], "recovered-worker"))[
        "delivery_state"
    ] == "consumed"


@pytest.mark.asyncio
async def test_live_pause_ack_resume_control_cas(live, monkeypatch):
    _, maker, store = live
    eid, tid = await _seed(maker, monkeypatch)
    paused = await store.request_control(eid, tid, "pause", "alice", "review", "pause-" + tid)
    assert paused["status"] == "pending"
    acked = await store.resolve_control(
        paused["request_id"],
        "acknowledged",
        {"status": "agent_checkpoint_pause", "source": "cooperative_agent_boundary"},
    )
    assert acked["status"] == "acknowledged"
    assert acked["revision"] == 1
    resumed = await store.request_control(eid, tid, "resume", "alice", "continue", "resume-" + tid)
    assert resumed["status"] == "pending"
    assert (
        await store.resolve_control(
            resumed["request_id"], "acknowledged", {"status": "agent_checkpoint_resume"}
        )
    )["revision"] == 1
    controls = await store.list_controls(eid, tid)
    assert {row["action"] for row in controls} == {"pause", "resume"}
    events = await store.list_events_after(eid, 0, tid, 100)
    assert all(events[i]["sequence"] < events[i + 1]["sequence"] for i in range(len(events) - 1))
    assert all(row["engagement_id"] == eid for row in events)


@pytest.mark.asyncio
async def test_live_execution_token_lease_prevents_race_and_replay(live, monkeypatch):
    _, maker, store = live
    eid, tid = await _seed(maker, monkeypatch)
    claims = await asyncio.gather(
        store.claim_execution_lease(eid, tid, "worker-a", 30),
        store.claim_execution_lease(eid, tid, "worker-b", 30),
    )
    assert sum(row["acquired"] for row in claims) == 1
    acquired = next(row for row in claims if row["acquired"])
    owner = acquired["owner_id"]
    token = acquired["lease_id"]
    assert not await store.check_execution_lease(eid, tid, "another-worker", token)
    assert await store.check_execution_lease(eid, tid, owner, token)
    assert await store.renew_execution_lease(eid, tid, owner, token, 30)
    assert await store.mark_execution_dispatched(eid, tid, owner, token)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    assert attempt["created"]
    assert await store.release_execution_lease(eid, tid, owner, token)
    assert (await store.claim_execution_lease(eid, tid, "late-worker", 30))["acquired"] is False


@pytest.mark.asyncio
async def test_live_retry_requires_verified_remote_closure_and_new_attempt(live, monkeypatch):
    _, maker, store = live
    eid, tid = await _seed(maker, monkeypatch)
    first = await store.claim_execution_lease(eid, tid, "first-owner")
    assert first["acquired"]
    assert await store.mark_execution_dispatched(eid, tid, "first-owner", first["lease_id"])
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    assert (
        await store.update_attempt(
            attempt["id"],
            attempt["revision"],
            "failed",
            receipt={"remote_stopped": True, "receipt_id": "provider-final-123"},
        )
    )["status"] == "failed"
    assert await store.release_execution_lease(eid, tid, "first-owner", first["lease_id"])
    async with maker() as session:
        async with session.begin():
            await session.execute(
                update(TaskORM).where(TaskORM.id == tid).values(retry_count=1, status="pending")
            )
    retry = await store.claim_execution_lease(eid, tid, "second-owner")
    assert retry["acquired"] is True
    assert retry["lease_id"] != first["lease_id"]
    assert not await store.check_execution_lease(eid, tid, "first-owner", first["lease_id"])
    assert await store.release_execution_lease(eid, tid, "second-owner", retry["lease_id"])


@pytest.mark.asyncio
async def test_live_ambiguous_failure_blocks_retry_even_after_release(live, monkeypatch):
    _, maker, store = live
    eid, tid = await _seed(maker, monkeypatch)
    initial = await store.claim_execution_lease(eid, tid, "worker-a")
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.update_attempt(
        attempt["id"],
        attempt["revision"],
        "failed",
        receipt={"result_code": "timeout"},
    )
    assert await store.release_execution_lease(eid, tid, "worker-a", initial["lease_id"])
    async with maker() as session:
        async with session.begin():
            await session.execute(
                update(TaskORM).where(TaskORM.id == tid).values(retry_count=1, status="pending")
            )
    blocked = await store.claim_execution_lease(eid, tid, "worker-b")
    assert blocked == {"acquired": False, "reason": "attempt_exists_unreconciled"}


@pytest.mark.asyncio
async def test_live_dispatched_without_attempt_poisons_lease(live, monkeypatch):
    _, maker, store = live
    eid, tid = await _seed(maker, monkeypatch)
    first = await store.claim_execution_lease(eid, tid, "owner-a")
    assert first["acquired"]
    assert await store.mark_execution_dispatched(eid, tid, "owner-a", first["lease_id"])
    # Simulate a crash between remote dispatch and attempt persistence.
    assert not await store.release_execution_lease(eid, tid, "owner-a", first["lease_id"])
    assert (await store.claim_execution_lease(eid, tid, "owner-b")) == {
        "acquired": False,
        "reason": "prior_lease_unreconciled",
    }


@pytest.mark.asyncio
async def test_live_migration_upgrade_and_downgrade_0005(live):
    engine, _, _ = live
    async with engine.begin() as connection:
        await connection.run_sync(_alembic, "0004", "downgrade")
        state = await connection.run_sync(
            lambda conn: (
                {c["name"] for c in inspect(conn).get_columns("supervision_messages")},
                inspect(conn).has_table("supervision_execution_leases"),
            )
        )
        assert "delivery_state" not in state[0]
        assert not state[1]
        await connection.run_sync(_alembic, "head", "upgrade")
        state = await connection.run_sync(
            lambda conn: (
                {c["name"] for c in inspect(conn).get_columns("supervision_messages")},
                inspect(conn).has_table("supervision_execution_leases"),
            )
        )
        assert "delivery_state" in state[0]
        assert state[1]
