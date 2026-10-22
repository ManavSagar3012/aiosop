"""Disposable-PostgreSQL verification that snapshots cannot overwrite signed ROE."""

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.engine import make_url

from ai_osop.core.exceptions import MemoryException
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.session_memory import SessionMemory
from tests.test_authorization_store import make_signed_session


def _url():
    value = os.getenv("OSOP_SIGNED_PERSIST_TEST_PG_URI")
    if not value:
        pytest.skip("No disposable session persistence PostgreSQL DB configured")
    parsed = make_url(value)
    if (
        parsed.drivername != "postgresql+asyncpg"
        or parsed.host not in {"localhost", "127.0.0.1"}
        or parsed.port in {None, 5432, 5433}
        or not str(parsed.database or "").startswith("session_persist_qualification_")
    ):
        pytest.fail("Refusing non-disposable PostgreSQL database")
    return value


def _upgrade(conn):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = conn
    command.upgrade(config, "head")


@pytest.mark.asyncio
async def test_signed_session_scope_cannot_be_upserted_or_reopened(monkeypatch):
    engine = create_async_engine(_url(), pool_size=4)
    try:
        async with engine.begin() as db:
            await db.run_sync(_upgrade)
        memory = SessionMemory.__new__(SessionMemory)
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        session, verified, _, _ = make_signed_session(monkeypatch)
        store = AuthorizationStore(memory)
        await store.create_authorized_session(session, verified, session.created_by)

        active = session.model_copy(deep=True)
        active.phase = "reconnaissance"
        await memory.persist_session_state(active)
        assert (await memory.load_session_state(active.session_id)).phase == "reconnaissance"
        altered = active.model_copy(deep=True)
        altered.scope.domains.append("unapproved.example")
        with pytest.raises(MemoryException, match="Cannot overwrite signed"):
            await memory.persist_session_state(altered)
        assert (await memory.load_session_state(active.session_id)).scope.domains == [
            "authorized.example"
        ]
        altered_owner = active.model_copy(deep=True)
        altered_owner.created_by = "other-operator"
        with pytest.raises(MemoryException, match="Cannot overwrite signed"):
            await memory.persist_session_state(altered_owner)
        assert (await memory.load_session_state(active.session_id)).created_by == session.created_by

        unknown = active.model_copy(deep=True)
        unknown.session_id = "eng-unverified-from-snapshot"
        unknown.scope.engagement_id = unknown.session_id
        with pytest.raises(MemoryException, match="atomic verified"):
            await memory.persist_session_state(unknown)
        assert await memory.load_session_state(unknown.session_id) is None

        assert await store.revoke(
            active.session_id, session.created_by, 1, "operator revoked policy"
        )
        with pytest.raises(MemoryException, match="active signed"):
            await memory.persist_session_state(active)
        halted = active.model_copy(deep=True)
        halted.phase = "halted"
        await memory.persist_session_state(halted)
        assert (await memory.load_session_state(active.session_id)).phase == "halted"
        with pytest.raises(MemoryException, match="active signed"):
            await memory.persist_session_state(
                active.model_copy(update={"phase": "reconnaissance"})
            )
    finally:
        await engine.dispose()
