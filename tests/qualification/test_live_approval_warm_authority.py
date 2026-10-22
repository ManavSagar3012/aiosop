"""Approval persistence qualification against a NEW disposable PostgreSQL.

Opt-in: not part of the regular unit suite. Never points at an app database,
external assessment target or remotely supplied PostgreSQL host.
"""

import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import AgentType
from ai_osop.core.models import ApprovalRequest
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.session_memory import SessionMemory, TaskORM
from tests.test_authorization_store import make_signed_session


def _qualification_url():
    uri = os.environ.get("OSOP_APPROVAL_TEST_PG_URI")
    if not uri:
        pytest.skip("Dedicated disposable approval qualification database not configured")
    url = make_url(uri)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"localhost", "127.0.0.1"}
        or url.port in {None, 5432, 5433, 15645}
        or not str(url.database or "").startswith("approval_qualification_")
    ):
        pytest.fail("Refusing to use a non-disposable approval qualification database")
    return uri


def _migrate(connection):
    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, "head")


def _downgrade_to_0011(connection):
    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["connection"] = connection
    command.downgrade(cfg, "0011")


@pytest.mark.asyncio
async def test_real_pg_decision_survives_redis_loss_and_ignores_forged_hot_grant(monkeypatch):
    engine = create_async_engine(_qualification_url(), pool_size=3)
    try:
        async with engine.begin() as db:
            await db.run_sync(_migrate)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        nonce = uuid.uuid4().hex[:12]
        session, verified, _, _ = make_signed_session(
            monkeypatch, session_id="eng-approval-" + nonce,
            authorization_id="auth-approval-" + nonce,
        )
        session.phase = "reconnaissance"
        memory = SessionMemory()
        memory._async_session = maker
        memory.store_hot = AsyncMock()
        memory.retrieve_hot = AsyncMock(side_effect=AssertionError("Hot approvals are never authoritative"))
        await AuthorizationStore(memory).create_authorized_session(
            session, verified, session.created_by,
        )

        request = ApprovalRequest(
            id="apr-live-" + nonce, engagement_id=session.session_id,
            task_id="task-live-" + nonce, agent_id="agent-live",
            action_type="summarize_context", target="unknown",
            payload_summary="No external tool execution", risk_assessment="low",
        )
        async with maker() as db, db.begin():
            db.add(TaskORM(
                id=request.task_id, engagement_id=session.session_id,
                type=request.action_type, priority=5,
                agent_type=AgentType.CONTEXT_MANAGER.value,
                payload={"_authorization_version": verified.version},
                dependencies=[], max_retries=0, timeout_seconds=60,
                scope_check=True, approval_required=True,
                status="awaiting_approval", result=None, retry_count=0,
            ))

        await memory.store_approval_request(request)
        memory.retrieve_hot = AsyncMock(return_value=request.model_copy(
            update={"status": "approved", "operator_id": "spoofed-operator"},
        ).model_dump())
        assert (await memory.load_approval_request(request.id)).status == "pending"
        memory.retrieve_hot.assert_not_awaited()

        memory.store_hot.side_effect = ConnectionError("isolated Redis unavailable")
        approved, was_new = await memory.resolve_approval_atomic(
            request.id, request.engagement_id, request.task_id,
            "approved", "signed-operator",
        )
        assert was_new and approved.status == "approved"
        # A second SessionMemory instance represents another worker/process.
        another = SessionMemory()
        another._async_session = maker
        another.retrieve_hot = AsyncMock(side_effect=AssertionError("Redis read is unsafe"))
        found = await another.load_approval_request(request.id)
        assert found is not None
        assert found.status == "approved"
        assert found.operator_id == "signed-operator"
        another.retrieve_hot.assert_not_awaited()

        # The upgrade supports the real awaiting_approval status. A downgrade
        # must refuse to truncate it, then succeed once the fixture is placed
        # in a shorter status and permit upgrade back to 0012.
        with pytest.raises(RuntimeError, match="exceed 16 characters"):
            async with engine.begin() as db:
                await db.run_sync(_downgrade_to_0011)
        async with maker() as db, db.begin():
            saved = (await db.execute(select(TaskORM).where(
                TaskORM.id == request.task_id,
            ))).scalar_one()
            assert saved.status == "awaiting_approval"
            saved.status = "pending"
        async with engine.begin() as db:
            await db.run_sync(_downgrade_to_0011)
            await db.run_sync(_migrate)
            assert (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one() == "0012"
    finally:
        await engine.dispose()
