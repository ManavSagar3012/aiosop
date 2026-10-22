"""Opt-in real Postgres signed-ROE qualification in a fresh loopback-only DB.

Requires OSOP_AUTH_QUAL_POSTGRES_URL for disposable authorization_qual DB.
No existing application Postgres service or database may be used.
"""

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.memory.authorization_store import AuthorizationDenied, AuthorizationStore, guard_sql
from tests.test_authorization_store import make_signed_session


URL = os.getenv("OSOP_AUTH_QUAL_POSTGRES_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(not URL, reason="Set disposable OSOP_AUTH_QUAL_POSTGRES_URL"),
]
PROJECT = Path(__file__).resolve().parents[2]


def _safe_url():
    if not URL:
        pytest.skip("Disposable PostgreSQL not configured")
    address = make_url(URL)
    if (
        address.drivername != "postgresql+asyncpg"
        or address.host not in ("localhost", "127.0.0.1")
        or address.database != "authorization_qual"
        or address.port in (None, 5432, 5433, 15645)
    ):
        pytest.fail("Qualification refuses non-disposable PostgreSQL URL")
    return URL


def _migration(connection, revision):
    cfg = Config(str(PROJECT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT / "migrations"))
    cfg.attributes["connection"] = connection
    if revision == "0008":
        command.downgrade(cfg, "0008")
    else:
        command.upgrade(cfg, revision)


async def _count(db, table):
    assert table in {
        "signed_authorizations", "session_states",
        "supervision_events", "supervision_outbox",
    }
    return (await db.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one()


async def test_real_postgres_authorization_lifecycle(monkeypatch):
    engine = create_async_engine(_safe_url(), pool_size=4, max_overflow=0)
    try:
        async with engine.begin() as connection:
            existing = await connection.execute(text(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name='alembic_version'"
            ))
            assert existing.scalar_one() == 0, "Test DB must be brand-new"
            await connection.run_sync(lambda sync: _migration(sync, "0009"))

        factory = async_sessionmaker(engine, expire_on_commit=False)
        store = AuthorizationStore(SimpleNamespace(_async_session=factory))
        session, verified, _, signing_key = make_signed_session(monkeypatch)
        receipt = await store.create_authorized_session(session, verified, session.created_by)
        assert receipt["status"] == "active" and receipt["version"] == 1
        binding = await store.assert_active(session.session_id, 1, verified.policy_digest)
        assert binding.authorization_id == verified.authorization_id

        async with factory() as db:
            assert await _count(db, "session_states") == 1
            assert await _count(db, "signed_authorizations") == 1
            assert await _count(db, "supervision_events") == 1
            assert await _count(db, "supervision_outbox") == 1
            event = (await db.execute(
                text("SELECT payload FROM supervision_events LIMIT 1")
            )).scalar_one()
            assert event["status"] == "active"
            assert "signature" not in event and "roe" not in event

        with pytest.raises(AuthorizationDenied, match="already exists"):
            await store.create_authorized_session(session, verified, session.created_by)
        async with factory() as db:
            assert await _count(db, "supervision_events") == 1
            assert await _count(db, "supervision_outbox") == 1

        legacy, legacy_verified, _, _ = make_signed_session(
            monkeypatch, session_id="eng-legacy", private_key=signing_key,
        )
        async with factory() as db, db.begin():
            await db.execute(text(
                "INSERT INTO session_states "
                "(session_id,scope,roe,phase,agents,created_by,created_at,updated_at) "
                "VALUES (:sid,CAST(:scope AS jsonb),CAST(:roe AS jsonb),"
                "'initialized','{}',:owner,now(),now())"
            ), {
                "sid": legacy.session_id,
                "scope": json.dumps(legacy.scope.model_dump(mode="json")),
                "roe": json.dumps(legacy.roe), "owner": legacy.created_by,
            })
        with pytest.raises(AuthorizationDenied, match="No active verified"):
            await store.assert_active(legacy.session_id)
        with pytest.raises(AuthorizationDenied, match="Legacy engagement"):
            await store.register_verified(
                legacy.session_id, legacy_verified, legacy.created_by,
            )

        assert await store.revoke(session.session_id, session.created_by, 2, "stale") is False
        with pytest.raises(AuthorizationDenied, match="owner"):
            await store.revoke(session.session_id, "cross-tenant", 1, "denied")
        assert await store.revoke(session.session_id, session.created_by, 1, "manual") is True
        assert await store.revoke(session.session_id, session.created_by, 1, "again") is False
        with pytest.raises(AuthorizationDenied, match="No active"):
            await store.assert_active(session.session_id)
        async with factory() as db:
            assert await _count(db, "supervision_events") == 2
            assert await _count(db, "supervision_outbox") == 2
            reason = (await db.execute(text(
                "SELECT revocation_reason FROM signed_authorizations "
                "WHERE session_id=:sid"
            ), {"sid": session.session_id})).scalar_one()
            assert "manual" not in reason and reason.startswith("operator_revocation:sha256:")

        rotated, verified_v2, _, _ = make_signed_session(
            monkeypatch, session_id=session.session_id, version=2,
            private_key=signing_key, authorization_id="auth-version-2",
        )
        assert (await store.register_verified(
            session.session_id, verified_v2, session.created_by
        ))["version"] == 2
        assert (await store.assert_active(session.session_id, 2)).version == 2
        with pytest.raises(AuthorizationDenied, match="version fence"):
            await store.assert_active(session.session_id, 1)
        with pytest.raises(AuthorizationDenied, match="digest fence"):
            await store.assert_active(session.session_id, expected_digest="a" * 64)

        # Removing the trusted KID denies dispatch even with unchanged PG rows.
        current_trust = os.environ["OSOP_ROE_TRUSTED_KEYS_JSON"]
        monkeypatch.setenv("OSOP_ROE_TRUSTED_KEYS_JSON", "{}")
        with pytest.raises(AuthorizationDenied):
            await store.assert_active(session.session_id)
        monkeypatch.setenv("OSOP_ROE_TRUSTED_KEYS_JSON", current_trust)

        # Mutated owner/ROE or signature must never inherit the verified flag.
        async with factory() as db, db.begin():
            await db.execute(text(
                "UPDATE session_states SET roe=CAST(:roe AS jsonb) WHERE session_id=:sid"
            ), {"sid": session.session_id, "roe": '{"tampered":true}'})
        with pytest.raises(AuthorizationDenied, match="scope or owner"):
            await store.assert_active(session.session_id)
        async with factory() as db, db.begin():
            await db.execute(text(
                "UPDATE session_states SET roe=CAST(:roe AS jsonb) WHERE session_id=:sid"
            ), {"sid": session.session_id, "roe": json.dumps(rotated.roe)})

        # Tampering with the persisted signature, independent of its stored
        # content digest, must fail the next dispatch guard.
        async with factory() as db, db.begin():
            await db.execute(text(
                "UPDATE signed_authorizations SET signature=:bad "
                "WHERE session_id=:sid AND version=2"
            ), {"sid": session.session_id, "bad": "A" * 86})
        with pytest.raises(AuthorizationDenied, match="signature"):
            await store.assert_active(session.session_id)
        async with factory() as db, db.begin():
            await db.execute(text(
                "UPDATE signed_authorizations SET signature=:good "
                "WHERE session_id=:sid AND version=2"
            ), {"sid": session.session_id, "good": verified_v2.signature})

        # Revoke must wait for a guard's session row share-lock transaction.
        guard_started = asyncio.Event()
        async with factory() as held, held.begin():
            assert (await guard_sql(held, session.session_id)).version == 2
            guard_started.set()
            async def revoke_in_parallel():
                await guard_started.wait()
                return await store.revoke(
                    session.session_id, session.created_by, 2, "operator-request",
                )
            revoking = asyncio.create_task(revoke_in_parallel())
            done, _ = await asyncio.wait({revoking}, timeout=0.25)
            assert not done, "Revoke was not fenced by guard transaction"
        assert await asyncio.wait_for(revoking, timeout=3) is True
        with pytest.raises(AuthorizationDenied):
            await store.assert_active(session.session_id)

        async with factory() as db:
            assert await _count(db, "signed_authorizations") == 2
            assert await _count(db, "supervision_outbox") == 4

        # Migration 0009 is reversible on disposable database, no auto grants.
        async with engine.begin() as connection:
            await connection.run_sync(lambda sync: _migration(sync, "0008"))
            table = (await connection.execute(text(
                "SELECT to_regclass('signed_authorizations')"
            ))).scalar_one()
            assert table is None
            await connection.run_sync(lambda sync: _migration(sync, "0009"))
        with pytest.raises(AuthorizationDenied, match="No active verified"):
            await store.assert_active(session.session_id)
    finally:
        await engine.dispose()
