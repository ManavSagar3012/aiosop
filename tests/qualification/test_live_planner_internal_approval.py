"""Opt-in real PostgreSQL signed internal planner approval qualification.

Only runs against an explicitly configured disposable loopback database in
the `planner_qualification_*` namespace. No application DB or model API calls.
"""

import asyncio
import base64
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelUsageLedger
from ai_osop.memory.session_memory import (
    ApprovalRequestORM, ExecutionFlowORM, TaskORM,
)
from ai_osop.memory.supervision_store import SupervisionEventORM, SupervisionOutboxORM
from ai_osop.orchestrator.planner_execution import (
    PlannerApprovalPending, PlannerExecutionStore,
)
from ai_osop.safety.signed_roe import canonical_json_bytes, verify_signed_roe
from tests.test_authorization_store import make_signed_session


def _disposable_url():
    raw = os.environ.get("OSOP_PLANNER_TEST_PG_URI", "")
    if not raw:
        pytest.skip("Disposable planner PostgreSQL is not configured")
    url = make_url(raw)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"127.0.0.1", "localhost"}
        or url.port is None or url.port in {5432, 5433, 15645}
        or not str(url.database or "").startswith("planner_qualification_")
    ):
        pytest.fail("Refusing to modify a non-disposable PostgreSQL database")
    return raw


def _migrate(connection):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


@pytest.fixture
async def pg_planner(monkeypatch):
    engine = create_async_engine(_disposable_url(), pool_size=5, max_overflow=0)
    try:
        async with engine.begin() as db:
            await db.run_sync(_migrate)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        suffix = uuid.uuid4().hex[:10]
        sid = "eng-planner-approval-" + suffix
        session, _, envelope, private_key = make_signed_session(
            monkeypatch, session_id=sid, authorization_id="auth-plan-apr-" + suffix,
        )
        session.scope.approval_required_for = ["planner_inference"]
        session.phase = "reconnaissance"
        envelope["policy"]["approval_required_for"] = ["planner_inference"]
        envelope["signature"] = base64.urlsafe_b64encode(
            private_key.sign(canonical_json_bytes(envelope["policy"]))
        ).decode("ascii").rstrip("=")
        signed = verify_signed_roe(
            envelope, expected_engagement_id=sid, expected_owner=session.created_by,
            expected_scope=session.scope, expected_roe=session.roe,
            now=datetime.now(timezone.utc),
        )
        memory = SimpleNamespace(_async_session=maker)
        await AuthorizationStore(memory).create_authorized_session(
            session, signed, session.created_by,
        )
        flow = FlowRecord(
            id="flow-plan-apr-" + suffix,
            engagement_id=sid,
            objective="Passive assessment for authorized domain",
            status="running", revision=0,
        )
        objective = Task(
            id="task-plan-root-" + suffix,
            type="flow_objective", agent_type=AgentType.RECON,
            engagement_id=sid, status="planned", flow_id=flow.id,
            payload={"_authorization_version": 1},
        )
        async with maker() as db, db.begin():
            db.add(ExecutionFlowORM(**flow.model_dump()))
            db.add(TaskORM(
                id=objective.id,
                type=objective.type,
                priority=objective.priority,
                agent_type=objective.agent_type.value,
                payload=objective.payload,
                dependencies=[],
                max_retries=0,
                timeout_seconds=60,
                scope_check=True,
                approval_required=False,
                status=objective.status,
                result=None,
                retry_count=0,
                created_at=datetime.utcnow(),
                engagement_id=sid,
                flow_id=flow.id,
            ))
        yield maker, PlannerExecutionStore(memory), ModelUsageLedger(memory), flow, objective
    finally:
        await engine.dispose()


def _decision(pending, flow, *, decision="approved", role="senior_operator", version=1):
    return dict(
        request_id=pending.approval_id,
        engagement_id=flow.engagement_id,
        task_id=pending.task_id,
        decision=decision,
        operator_id="qual-senior",
        actor_role=role,
        expected_authorization_version=version,
        expected_flow_revision=pending.revision,
    )


@pytest.mark.asyncio
async def test_pg_atomic_internal_approval_then_one_paid_model_reservation(pg_planner):
    maker, store, ledger, flow, parent = pg_planner
    with pytest.raises(PlannerApprovalPending) as created:
        await store.admit(flow, parent, purpose="flow_generation")
    pending = created.value
    assert pending.revision == 1
    async with maker() as db:
        assert (await db.execute(select(TaskORM.status).where(
            TaskORM.id == pending.task_id
        ))).scalar_one() == "awaiting_approval"
        assert (await db.execute(select(ApprovalRequestORM.status).where(
            ApprovalRequestORM.id == pending.approval_id
        ))).scalar_one() == "pending"

    with pytest.raises(PlannerApprovalPending):
        await store.admit(flow.model_copy(update={"revision": 1}), parent, purpose="flow_generation")
    with pytest.raises(PermissionError):
        await store.resolve_internal_approval(**_decision(pending, flow, role="operator"))
    with pytest.raises((PermissionError, RuntimeError)):
        await store.resolve_internal_approval(**_decision(pending, flow, version=2))

    first, second = await asyncio.gather(
        store.resolve_internal_approval(**_decision(pending, flow)),
        PlannerExecutionStore(store.session_memory).resolve_internal_approval(**_decision(pending, flow)),
    )
    assert sorted((first[1], second[1])) == [False, True]
    assert first[0].status == second[0].status == "approved"
    async with maker() as db:
        assert (await db.execute(select(TaskORM.status).where(
            TaskORM.id == pending.task_id
        ))).scalar_one() == "awaiting_approval"

    fresh = flow.model_copy(update={"revision": pending.revision})
    results = await asyncio.gather(
        store.admit(fresh, parent, purpose="flow_generation"),
        PlannerExecutionStore(store.session_memory).admit(fresh, parent, purpose="flow_generation"),
        return_exceptions=True,
    )
    admissions = [r for r in results if not isinstance(r, Exception)]
    denied = [r for r in results if isinstance(r, ModelBudgetExceeded)]
    assert len(admissions) == len(denied) == 1
    admitted = admissions[0]
    assert admitted.task_id == pending.task_id and admitted.revision == 2
    # Model usage admission checks the exact signed planner task and the
    # approval row, not a fabricated/reused parent ID. No provider is called.
    call_id = await ledger.reserve(flow.engagement_id, pending.task_id, "local-qualification-model", "completion")
    assert call_id.startswith("call-")
    async with maker() as db:
        assert (await db.execute(select(func.count()).select_from(
            SupervisionEventORM
        ).where(SupervisionEventORM.task_id == pending.task_id))).scalar_one() == 3
        assert (await db.execute(select(func.count()).select_from(
            SupervisionOutboxORM
        ).where(SupervisionOutboxORM.engagement_id == flow.engagement_id))).scalar_one() == 4
    await store.finish(admitted, "completed")
    async with maker() as db:
        assert (await db.execute(select(TaskORM.status).where(
            TaskORM.id == pending.task_id
        ))).scalar_one() == "completed"


@pytest.mark.asyncio
async def test_pg_human_rejection_cannot_admit_planner(pg_planner):
    maker, store, _, flow, parent = pg_planner
    with pytest.raises(PlannerApprovalPending) as created:
        await store.admit(flow, parent, purpose="flow_generation")
    pending = created.value
    rejected, changed = await store.resolve_internal_approval(
        **_decision(pending, flow, decision="rejected")
    )
    assert changed and rejected.status == "rejected"
    with pytest.raises(ModelBudgetExceeded):
        await store.admit(flow.model_copy(update={"revision": 1}), parent, purpose="flow_generation")
    async with maker() as db:
        assert (await db.execute(select(TaskORM.status).where(
            TaskORM.id == pending.task_id
        ))).scalar_one() == "failed"
