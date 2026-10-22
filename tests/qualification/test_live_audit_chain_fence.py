"""Cross-process audit HMAC append and rollback, isolated PostgreSQL only.

Set OSOP_AUDIT_QUAL_PG_URI to a freshly created loopback test database whose
name begins audit_qualification_. Never run against an application database.
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import settings
from ai_osop.core.models import AuditEvent
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.session_memory import AuditLogORM, SessionMemory
from ai_osop.safety.scope import AuditIntegrity
from tests.test_authorization_store import make_signed_session


def _uri():
    uri = os.getenv("OSOP_AUDIT_QUAL_PG_URI")
    if not uri:
        pytest.skip("Disposable audit qualification PostgreSQL not configured")
    url = make_url(uri)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"127.0.0.1", "localhost"}
        or url.port in {None, 5432, 5433, 15645}
        or not str(url.database or "").startswith("audit_qualification_")
    ):
        pytest.fail("Refusing non-disposable audit qualification database")
    return uri


def _upgrade(connection):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


@pytest.mark.asyncio
async def test_two_signed_pg_audit_writers_form_one_verifiable_chain(monkeypatch):
    engine = create_async_engine(_uri(), pool_size=5, max_overflow=0)
    try:
        async with engine.begin() as db:
            await db.run_sync(_upgrade)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        nonce = uuid.uuid4().hex[:12]
        engagement_id = "eng-audit-" + nonce
        signed, verified, _, _ = make_signed_session(
            monkeypatch, session_id=engagement_id,
            authorization_id="auth-audit-" + nonce,
        )
        signed.phase = "reconnaissance"
        first_memory = SessionMemory()
        first_memory._async_session = maker
        await AuthorizationStore(first_memory).create_authorized_session(
            signed, verified, signed.created_by,
        )
        second_memory = SessionMemory()
        second_memory._async_session = maker
        key = "audit-production-isolated-test-key-20261014-123456"
        monkeypatch.setattr(settings, "environment", "production")
        monkeypatch.setattr(settings, "audit_hmac_key", key)

        now = datetime.utcnow()
        def create(index, *, same_id=None):
            return AuditEvent(
                event_id=same_id or f"evt-audit-{nonce}-{index}",
                timestamp=now + timedelta(seconds=index),
                event_type="audit.qualification", severity="info",
                actor_type="system", actor_id="qualification-worker",
                action={"sequence": index}, result={"status": "recorded"},
                context={}, engagement_id=engagement_id,
            )

        first, second = create(1), create(2)
        # Distinct session/connection objects; if execution scheduling puts
        # second first, the stale first timestamp is rejected, never forked.
        attempted = await asyncio.gather(
            first_memory.write_audit_event(first),
            second_memory.write_audit_event(second),
            return_exceptions=True,
        )
        assert all(result is None or isinstance(result, Exception) for result in attempted)
        assert sum(result is None for result in attempted) >= 1
        async with maker() as db:
            persisted = (await db.execute(
                select(AuditLogORM).where(AuditLogORM.engagement_id == engagement_id)
                .order_by(AuditLogORM.timestamp.asc(), AuditLogORM.event_id.asc())
            )).scalars().all()
        assert len(persisted) == sum(result is None for result in attempted)
        chain = [AuditEvent(
            event_id=row.event_id, timestamp=row.timestamp,
            event_type=row.event_type, severity=row.severity,
            actor_type=row.actor_type, actor_id=row.actor_id,
            action=row.action, result=row.result, context=row.context,
            integrity_hash=row.integrity_hash, engagement_id=row.engagement_id,
        ) for row in persisted]
        assert AuditIntegrity(key.encode()).verify_chain(chain)
        assert all(item.integrity_hash is not None for item in chain)

        # A failed UNIQUE write must not corrupt the predecessor or mutate
        # the attempted event to claim a successfully persisted signature.
        rejected = create(3, same_id=persisted[0].event_id)
        with pytest.raises(IntegrityError):
            await first_memory.write_audit_event(rejected)
        assert rejected.integrity_hash is None
        async with maker() as db:
            unchanged = (await db.execute(
                select(AuditLogORM).where(AuditLogORM.engagement_id == engagement_id)
            )).scalars().all()
        assert len(unchanged) == len(persisted)
    finally:
        await engine.dispose()
