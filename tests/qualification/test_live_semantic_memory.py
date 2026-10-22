"""Live isolation of signed semantic memory in disposable PostgreSQL."""

import asyncio
import os
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.session_memory import SessionMemory, TaskORM
from ai_osop.memory.vector_memory import VectorMemory
from tests.test_authorization_store import make_signed_session

EMBEDDING = [1.0] + [0.0] * 1535


def _uri():
    value = os.getenv("OSOP_SEMANTIC_TEST_PG_URI", "")
    if not value:
        pytest.skip("Disposable semantic PostgreSQL unavailable")
    parsed = make_url(value)
    if (
        parsed.drivername != "postgresql+asyncpg"
        or parsed.host not in {"127.0.0.1", "localhost"}
        or parsed.port in {None, 5432, 5433}
        or not str(parsed.database or "").startswith("semantic_qualification_")
    ):
        pytest.fail("Refusing non-disposable semantic database")
    return value


def _migration(connection, operation, revision):
    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["connection"] = connection
    getattr(command, operation)(cfg, revision)


@pytest.fixture
async def live(monkeypatch):
    monkeypatch.setenv("OSOP_MOCK_LLM", "false")
    uri = _uri()
    engine = create_async_engine(uri)
    store = None
    try:
        async with engine.begin() as connection:
            await connection.run_sync(_migration, "upgrade", "head")
        maker = async_sessionmaker(engine, expire_on_commit=False)
        memory = SessionMemory.__new__(SessionMemory)
        memory._async_session = maker
        authority = AuthorizationStore(memory)

        async def seed(eid, private=None):
            signed, verified, _, key = make_signed_session(
                monkeypatch, session_id=eid,
                authorization_id="auth-" + eid, private_key=private,
            )
            await authority.create_authorized_session(
                signed, verified, signed.created_by
            )
            tid = "task-" + eid
            async with maker() as db, db.begin():
                db.add(TaskORM(
                    id=tid, engagement_id=eid, type="summarize_context",
                    agent_type="context_manager", priority=5,
                    payload={"_authorization_version": 1},
                    dependencies=[], max_retries=0, timeout_seconds=60,
                    scope_check=True, approval_required=False,
                    status="running", result=None, retry_count=0,
                    created_at=datetime.utcnow(),
                ))
            return tid, key

        suffix = uuid.uuid4().hex[:10]
        engagement_a = "eng-sem-a-" + suffix
        engagement_b = "eng-sem-b-" + suffix
        task_a, key = await seed(engagement_a)
        task_b, _ = await seed(engagement_b, private=key)
        store = VectorMemory(uri, session_memory=memory)
        await store.connect()
        yield engine, store, authority, (engagement_a, task_a), (engagement_b, task_b)
    finally:
        if store is not None:
            await store.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_real_pgvector_engagement_isolation_and_metadata_redaction(live):
    _, store, _, left, right = live
    eid_a, task_a = left
    eid_b, task_b = right
    record_id = await store.store_payload(
        "asset_inventory", "Asset inventory with token=REDACT_EXAMPLE_VALUE",
        EMBEDDING,
        {"source": "inventory", "target": "https://private.example/resource"},
        engagement_id=eid_a, task_id=task_a, category="summary",
    )
    assert isinstance(record_id, int)
    assert await store.search_similar_payloads(
        EMBEDDING, engagement_id=eid_b, task_id=task_b, category="summary"
    ) == []
    rows = await store.search_similar_payloads(
        EMBEDDING, engagement_id=eid_a, task_id=task_a, category="summary"
    )
    assert len(rows) == 1
    assert "REDACT_EXAMPLE_VALUE" not in str(rows)
    assert "private.example" not in str(rows)
    assert rows[0]["metadata"]["source"] == "inventory"


@pytest.mark.asyncio
async def test_real_pgvector_revoked_policy_cannot_read_or_write(live):
    _, store, authority, left, _ = live
    engagement_id, task_id = left
    assert await authority.revoke(
        engagement_id, "operator-owner", 1, "Stop semantic storage"
    )
    with pytest.raises(PermissionError):
        await store.search_similar_payloads(
            EMBEDDING, engagement_id=engagement_id, task_id=task_id,
        )
    with pytest.raises(PermissionError):
        await store.store_payload(
            "inventory", "Unapproved future entry", EMBEDDING, {},
            engagement_id=engagement_id, task_id=task_id,
        )


@pytest.mark.asyncio
async def test_pgvector_write_refuses_revocation_between_preflight_and_insert(live, monkeypatch):
    engine, store, authority, left, _ = live
    engagement_id, task_id = left
    original_authorize = store._authorize

    async def revoke_after_preflight(eid, tid):
        version = await original_authorize(eid, tid)
        assert await authority.revoke(
            eid, "operator-owner", version,
            "Revoke while vector writer is awaiting its SQL transaction",
        )
        return version

    monkeypatch.setattr(store, "_authorize", revoke_after_preflight)
    with pytest.raises(PermissionError, match="authorization changed"):
        await store.store_payload(
            "inventory", "Stale signed knowledge must not commit", EMBEDDING, {},
            engagement_id=engagement_id, task_id=task_id,
        )
    async with engine.connect() as conn:
        count = (await conn.execute(text(
            "SELECT count(*) FROM supervision_semantic_knowledge WHERE engagement_id=:eid"
        ), {"eid": engagement_id})).scalar_one()
        assert count == 0


@pytest.mark.asyncio
async def test_pgvector_write_and_revoke_serialize_on_signed_session_row(live, monkeypatch):
    _, store, authority, left, _ = live
    engagement_id, task_id = left
    original_fence = store._fence_write_transaction
    locked = asyncio.Event()
    release = asyncio.Event()

    async def held_fence(connection, eid, tid, version):
        await original_fence(connection, eid, tid, version)
        locked.set()
        await release.wait()

    monkeypatch.setattr(store, "_fence_write_transaction", held_fence)
    writer = asyncio.create_task(store.store_payload(
        "inventory", "Knowledge committed before operator revocation",
        EMBEDDING, {}, engagement_id=engagement_id, task_id=task_id,
    ))
    try:
        await asyncio.wait_for(locked.wait(), timeout=5)
        revoker = asyncio.create_task(authority.revoke(
            engagement_id, "operator-owner", 1, "Revoke during signed vector write"
        ))
        await asyncio.sleep(0.2)
        assert not revoker.done(), "Revocation raced past a held signed write fence"
        release.set()
        assert isinstance(await asyncio.wait_for(writer, timeout=5), int)
        assert await asyncio.wait_for(revoker, timeout=5)
        with pytest.raises(PermissionError):
            await store.search_similar_payloads(
                EMBEDDING, engagement_id=engagement_id, task_id=task_id,
            )
    finally:
        release.set()
        if not writer.done():
            writer.cancel()
            await asyncio.gather(writer, return_exceptions=True)


@pytest.mark.asyncio
async def test_new_semantic_migration_round_trip(live):
    engine, store, _, _, _ = live
    await store.close()
    async with engine.begin() as connection:
        await connection.run_sync(_migration, "downgrade", "0010")
        assert not await connection.run_sync(
            lambda c: inspect(c).has_table("supervision_semantic_knowledge")
        )
        await connection.run_sync(_migration, "upgrade", "head")
        assert await connection.run_sync(
            lambda c: inspect(c).has_table("supervision_semantic_knowledge")
        )
