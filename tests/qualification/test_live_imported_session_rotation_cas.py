"""Real PostgreSQL regression: an in-flight browser must not revive revoked login.

Requires OSOP_SESSION_ROTATION_TEST_PG_URI targeting a disposable localhost
session_rotation_qualification_* database. Never uses an application database,
real website, browser provider, or paid model.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.auth.session_store import SessionStore, UserSessionORM
from ai_osop.memory.session_memory import Base, SessionMemory
from ai_osop.memory.schema_migrations import ensure_schema


@pytest.fixture
async def live_store(monkeypatch):
    uri = __import__("os").environ.get("OSOP_SESSION_ROTATION_TEST_PG_URI", "")
    if not uri:
        pytest.skip("Requires explicitly selected disposable session rotation PostgreSQL")
    parsed = urlsplit(uri)
    if (
        parsed.scheme != "postgresql+asyncpg"
        or parsed.hostname != "127.0.0.1"
        or not parsed.port
        or parsed.port == 5432
        or not parsed.path.strip("/").startswith("session_rotation_qualification_")
    ):
        pytest.fail("Refusing any non-isolated PostgreSQL database")
    engine = create_async_engine(uri)
    try:
        await ensure_schema(engine, uri)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        memory = SessionMemory.__new__(SessionMemory)
        memory._pg_engine = engine
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        memory._redis = SimpleNamespace(
            get=AsyncMock(return_value=None),
            setex=AsyncMock(),
            delete=AsyncMock(),
        )
        store = SessionStore(memory)
        yield store
    finally:
        await engine.dispose()


class StubSessionClient:
    def __init__(self, *, session, **_kwargs):
        self.session = session
        self.cookies_dirty = True
        self.closed = False
        self.session.cookies = [
            {"name": "sid", "value": "rotated", "domain": "example.test", "path": "/"}
        ]

    async def aclose(self):
        self.closed = True


def install_browser_stub(monkeypatch):
    import ai_osop.auth.session_client as browser_client

    monkeypatch.setattr(browser_client, "SessionClient", StubSessionClient)


async def persisted(store, engagement_id, user_label):
    async with store.sm._async_session() as db:
        return (
            await db.execute(select(UserSessionORM).where(
                UserSessionORM.pk == f"{engagement_id}:{user_label}"
            ))
        ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_live_operator_delete_mid_browser_request_does_not_resurrect(monkeypatch, live_store):
    install_browser_stub(monkeypatch)
    store = live_store
    eid = "eng-session-rotation-deleted"
    username = "user-a"
    await store.save_session(eid, username, cookies=[{"name": "sid", "value": "old"}])
    async with store.as_user(eid, username) as browser:
        assert await store.delete_session(eid, username)
    assert browser.closed
    assert await persisted(store, eid, username) is None
    assert await store.get_session_authoritative(eid, username) is None
    # No implicit save_session INSERT/UPSERT of a deleted credential.
    assert store.sm._redis.delete.await_count >= 2


@pytest.mark.asyncio
async def test_live_operator_replacement_mid_browser_request_cannot_overwrite(monkeypatch, live_store):
    install_browser_stub(monkeypatch)
    store = live_store
    eid = "eng-session-rotation-replaced"
    username = "user-a"
    original = await store.save_session(
        eid, username, cookies=[{"name": "sid", "value": "original"}]
    )
    async with store.as_user(eid, username):
        replacement = await store.save_session(
            eid, username, cookies=[{"name": "sid", "value": "replacement"}]
        )
        assert replacement.captured_at != original.captured_at
    found = await store.get_session_authoritative(eid, username)
    assert found is not None
    assert found.cookies[0]["value"] == "replacement"


@pytest.mark.asyncio
async def test_live_same_import_can_rotate_cookies_without_rewriting_identity(monkeypatch, live_store):
    install_browser_stub(monkeypatch)
    store = live_store
    eid = "eng-session-rotation-allowed"
    username = "user-a"
    original = await store.save_session(
        eid, username, cookies=[{"name": "sid", "value": "original"}]
    )
    async with store.as_user(eid, username):
        pass
    found = await store.get_session_authoritative(eid, username)
    assert found is not None
    assert found.cookies[0]["value"] == "rotated"
    assert found.captured_at == original.captured_at
    assert found.expires_at == original.expires_at
