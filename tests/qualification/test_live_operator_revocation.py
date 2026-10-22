"""Explicit opt-in PostgreSQL integration for cross-replica operator invalidation.

Refuses app databases and privileged ports. No real organization tokens, IdP,
security targets or app migration state are accessed.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from jose import jwt
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from ai_osop.memory.operator_revocation import (
    OperatorAuthEventORM, OperatorRevocationLedger, OperatorRevoked,
)


def _uri():
    uri = os.environ.get("OSOP_OPERATOR_REVOCATION_TEST_PG_URI", "")
    if not uri:
        pytest.skip("Explicit disposable PostgreSQL operator-revocation DB not configured")
    url = make_url(uri)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"127.0.0.1", "localhost"}
        or url.port in {None, 5432, 5433}
        or not str(url.database or "").startswith("operator_revocation_qualification_")
    ):
        pytest.fail("Refusing non-disposable operator revocation database")
    return uri


def _alembic(connection):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


@pytest.fixture
async def replicas():
    uri = _uri()
    a = create_async_engine(uri, pool_size=2)
    b = create_async_engine(uri, pool_size=2)
    async with a.begin() as connection:
        await connection.run_sync(_alembic)
    ma = sessionmaker(a, class_=AsyncSession, expire_on_commit=False)
    mb = sessionmaker(b, class_=AsyncSession, expire_on_commit=False)
    try:
        yield (
            OperatorRevocationLedger(SimpleNamespace(_async_session=ma)),
            OperatorRevocationLedger(SimpleNamespace(_async_session=mb)),
            ma,
        )
    finally:
        await a.dispose()
        await b.dispose()


def _principal(sub="operator"):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub, "role": "operator",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=20)).timestamp()),
    }
    bearer = jwt.encode(payload, "revocation-qualification-secret-only", algorithm="HS256")
    return bearer, {"sub": sub, "role": "operator", "claims": payload}


@pytest.mark.asyncio
async def test_live_two_distinct_pg_pools_enforce_logout_and_account_status(replicas):
    first, second, maker = replicas
    token, principal = _principal()
    other, _ = _principal("second-operator")
    await first.assert_active(token, principal)
    assert await first.revoke_token(token, principal)
    assert not await first.revoke_token(token, principal)
    with pytest.raises(OperatorRevoked):
        await second.assert_active(token, principal)

    await first.disable_subject(
        "second-operator", actor_id="supervisor", disabled=True,
        reason="Account credentials compromised",
    )
    with pytest.raises(OperatorRevoked):
        await second.assert_active(other, {"sub": "second-operator"})
    await second.disable_subject(
        "second-operator", actor_id="supervisor", disabled=False,
        reason="Identity verified after review",
    )
    await first.assert_active(other, {"sub": "second-operator"})
    with pytest.raises(OperatorRevoked):
        await second.assert_active(token, principal)

    async with maker() as db:
        events = (await db.execute(
            select(OperatorAuthEventORM).where(
                OperatorAuthEventORM.subject_id.in_(["operator", "second-operator"]),
            )
        )).scalars().all()
    assert sorted(e.kind for e in events) == [
        "credential_revoked", "subject_disabled", "subject_enabled",
    ]
    assert all(len(e.reason) >= 10 and "bearer" not in e.reason for e in events)


@pytest.mark.asyncio
async def test_live_audit_insert_error_rolls_back_token_revocation(replicas):
    first, second, maker = replicas
    token, principal = _principal("rollback-operator")
    # Own disposable schema only; force a transaction failure after the
    # revocation INSERT but before the audit event is committed.
    async with maker() as db:
        async with db.begin():
            await db.execute(text("""
                CREATE OR REPLACE FUNCTION reject_test_operator_event()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.actor_id = 'rollback-operator' THEN
                        RAISE EXCEPTION 'disposable qualification injection';
                    END IF;
                    RETURN NEW;
                END; $$
            """))
            await db.execute(text("""
                CREATE TRIGGER trg_test_reject_operator_event
                BEFORE INSERT ON operator_auth_events
                FOR EACH ROW EXECUTE FUNCTION reject_test_operator_event()
            """))
    try:
        with pytest.raises(Exception):
            await first.revoke_token(token, principal)
        # An outbox/audit write failure MUST NOT invalidate the bearer on
        # one replica while the mutation is uncommitted.
        await second.assert_active(token, principal)
    finally:
        async with maker() as db:
            async with db.begin():
                await db.execute(text("DROP TRIGGER IF EXISTS trg_test_reject_operator_event ON operator_auth_events"))
                await db.execute(text("DROP FUNCTION IF EXISTS reject_test_operator_event()"))
