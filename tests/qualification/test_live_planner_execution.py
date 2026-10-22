"""Real PostgreSQL planner ownership and revocation qualification.

Opt-in, disposable loopback database ONLY. Never contacts any assessment
target, external model provider, or existing application database.
"""

import asyncio
import os
import uuid
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from unittest.mock import AsyncMock

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.memory.session_memory import ExecutionFlowORM, TaskORM
from ai_osop.memory.supervision_store import SupervisionEventORM, SupervisionOutboxORM
from ai_osop.orchestrator.planner_execution import PlannerExecutionStore, run_planner_completion
from tests.test_authorization_store import make_signed_session


def _url():
    value = os.environ.get("OSOP_PLANNER_TEST_PG_URI")
    if not value:
        pytest.skip("Isolated planner qualification database not configured")
    url = make_url(value)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"localhost", "127.0.0.1"}
        or url.port in {None, 5432, 5433, 15645}
        or not str(url.database or "").startswith("planner_qualification_")
    ):
        pytest.fail("Refusing database outside planner qualification namespace")
    return value


def _migrate(connection):
    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, "head")


@pytest.fixture
async def live(monkeypatch):
    engine = create_async_engine(_url(), pool_size=6, max_overflow=0)
    try:
        async with engine.begin() as db:
            await db.run_sync(_migrate)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        nonce = uuid.uuid4().hex[:12]
        sid = "eng-planner-" + nonce
        session, verified, _, _ = make_signed_session(
            monkeypatch, session_id=sid, authorization_id="auth-planner-" + nonce
        )
        session.phase = "reconnaissance"
        memory = SimpleNamespace(_async_session=maker)
        auth = AuthorizationStore(memory)
        await auth.create_authorized_session(session, verified, session.created_by)
        flow = FlowRecord(
            id="flow-planner-" + nonce,
            engagement_id=sid,
            objective="Operator-reviewed passive assessment plan",
            status="running",
            revision=0,
        )
        parent = Task(
            id="task-root-" + nonce,
            engagement_id=sid,
            type="flow_objective",
            agent_type=AgentType.RECON,
            status="planned",
            flow_id=flow.id,
            payload={"_authorization_version": 1},
        )
        async with maker() as db, db.begin():
            db.add(ExecutionFlowORM(
                id=flow.id, engagement_id=sid, objective=flow.objective,
                status="running", revision=0,
                created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
            ))
            db.add(TaskORM(
                id=parent.id, engagement_id=sid, type=parent.type,
                priority=5, agent_type=parent.agent_type.value,
                payload=parent.payload, dependencies=[], max_retries=0,
                timeout_seconds=60, scope_check=True, approval_required=False,
                status="planned", result=None, retry_count=0,
                created_at=datetime.utcnow(), flow_id=flow.id,
            ))
        yield maker, PlannerExecutionStore(memory), auth, flow, parent
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_live_two_planner_replicas_single_signed_claim_and_one_outbox(live):
    maker, store, _, flow, parent = live
    another = PlannerExecutionStore(store.session_memory)
    outcomes = await asyncio.gather(
        store.admit(flow, parent, purpose="flow_generation"),
        another.admit(flow, parent, purpose="flow_generation"),
        return_exceptions=True,
    )
    won = [item for item in outcomes if not isinstance(item, Exception)]
    lost = [item for item in outcomes if isinstance(item, Exception)]
    assert len(won) == len(lost) == 1
    assert isinstance(lost[0], ModelBudgetExceeded)
    assert won[0].revision == 1
    async with maker() as db:
        saved_flow = (await db.execute(select(ExecutionFlowORM).where(
            ExecutionFlowORM.id == flow.id
        ))).scalar_one()
        assert saved_flow.revision == 1
        tasks = (await db.execute(select(TaskORM).where(
            TaskORM.type == "planner_inference", TaskORM.engagement_id == flow.engagement_id
        ))).scalars().all()
        assert len(tasks) == 1
        assert tasks[0].payload["_authorization_version"] == 1
        assert tasks[0].status == "running"
        event_count = (await db.execute(select(func.count()).select_from(
            SupervisionEventORM
        ).where(SupervisionEventORM.task_id == won[0].task_id))).scalar_one()
        assert event_count == 1
    await store.finish(won[0], "completed")
    async with maker() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == won[0].task_id
        ))).scalar_one()
        assert task.status == "completed"
        assert (await db.execute(select(func.count()).select_from(
            SupervisionOutboxORM
        ).where(SupervisionOutboxORM.engagement_id == flow.engagement_id))).scalar_one() == 3


@pytest.mark.asyncio
async def test_live_revoked_signer_blocks_admission_but_unknown_receipt_can_commit(live):
    maker, store, auth, flow, parent = live
    admission = await store.admit(flow, parent, purpose="flow_generation")
    assert await auth.revoke(flow.engagement_id, "operator-owner", 1, "test revocation")
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(
            flow.model_copy(update={"revision": 1}),
            parent, purpose="flow_generation",
        )
    async def ambiguous_provider():
        raise TimeoutError("Provider may already have billed")
    with pytest.raises(ModelOutcomeUncertain):
        await run_planner_completion(store, admission, ambiguous_provider)
    async with maker() as db:
        outcome = (await db.execute(select(TaskORM.status).where(
            TaskORM.id == admission.task_id
        ))).scalar_one()
    assert outcome == "dispatch_unknown"


@pytest.mark.asyncio
async def test_live_audit_transaction_failure_never_commits_planner_dispatch(live):
    maker, store, _, flow, parent = live
    async def fail_append(*args, **kwargs):
        raise RuntimeError("simulated audit outbox outage")
    store._append_event = fail_append
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(flow, parent, purpose="flow_generation")
    async with maker() as db:
        current = (await db.execute(select(ExecutionFlowORM.revision).where(
            ExecutionFlowORM.id == flow.id
        ))).scalar_one()
        task_count = (await db.execute(select(func.count()).select_from(TaskORM).where(
            TaskORM.engagement_id == flow.engagement_id,
            TaskORM.type == "planner_inference",
        ))).scalar_one()
    assert current == 0
    assert task_count == 0
