"""Real PostgreSQL signed planner human review without paid model execution.

Opt-in: only fresh disposable local pgvector PostgreSQL. Tests create
authorized records but never contact a model provider or assessment target.
"""

import asyncio
import base64
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.api.deps import state
from ai_osop.api.routers.approvals import router as approvals_router
from ai_osop.core.config import AgentType, settings
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.model_usage import ModelBudgetExceeded
from ai_osop.memory.session_memory import (
    SessionMemory, ExecutionFlowORM, TaskORM, ApprovalRequestORM,
)
from ai_osop.memory.supervision_store import SupervisionEventORM, SupervisionOutboxORM
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.planner_execution import (
    PlannerApprovalPending, PlannerExecutionStore,
)
from ai_osop.safety.signed_roe import canonical_json_bytes, verify_signed_roe
from tests.test_authorization_store import make_signed_session


def _url():
    uri = os.getenv("OSOP_PLANNER_APPROVAL_TEST_PG_URI")
    if not uri:
        pytest.skip("Isolated planner approval PostgreSQL is not configured")
    url = make_url(uri)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"127.0.0.1", "localhost"}
        or url.port in {None, 5432, 5433, 15645}
        or not str(url.database or "").startswith("planner_approval_qualification_")
    ):
        pytest.fail("Refusing to access a non-disposable planner qualification DB")
    return uri


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
        async with engine.begin() as conn:
            await conn.run_sync(_migrate)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        nonce = uuid.uuid4().hex[:12]
        engagement_id = "eng-planner-approval-" + nonce
        session, _, envelope, private_key = make_signed_session(
            monkeypatch, session_id=engagement_id,
            authorization_id="auth-planner-approval-" + nonce,
        )
        # Issue a genuinely NEW signed policy explicitly requiring human
        # approval before model inference. No fabricated approval ref.
        session.scope.approval_required_for = ["planner_inference"]
        policy = {**envelope["policy"],
                  "approval_required_for": ["planner_inference"]}
        signed = {
            "version": envelope["version"], "policy": policy,
            "signature": base64.urlsafe_b64encode(
                private_key.sign(canonical_json_bytes(policy))
            ).decode("ascii").rstrip("="),
        }
        verified = verify_signed_roe(
            signed, expected_engagement_id=engagement_id,
            expected_owner=session.created_by,
            expected_scope=session.scope, expected_roe=session.roe,
            now=datetime.now(timezone.utc),
        )
        session.phase = "reconnaissance"
        memory = SessionMemory()
        memory._async_session = maker
        memory.store_hot = AsyncMock()
        auth = AuthorizationStore(memory)
        await auth.create_authorized_session(session, verified, session.created_by)
        flow = FlowRecord(
            id="flow-planner-approval-" + nonce,
            engagement_id=engagement_id, objective="Authorized offline planning",
            status="running", revision=0,
        )
        root = Task(
            id="task-planner-parent-" + nonce, engagement_id=engagement_id,
            type="flow_objective", agent_type=AgentType.CONTEXT_MANAGER,
            status="planned", flow_id=flow.id,
            payload={"_authorization_version": verified.version},
        )
        async with maker() as db, db.begin():
            db.add(ExecutionFlowORM(
                id=flow.id, engagement_id=engagement_id,
                objective=flow.objective, status="running", revision=0,
                created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
            ))
            db.add(TaskORM(
                id=root.id, engagement_id=engagement_id, type=root.type,
                priority=5, agent_type=root.agent_type.value,
                payload=root.payload, dependencies=[], max_retries=0,
                timeout_seconds=60, scope_check=True, approval_required=False,
                status="planned", retry_count=0, result=None,
                created_at=datetime.utcnow(), flow_id=flow.id,
            ))
        yield memory, maker, auth, flow, root
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_live_planner_review_http_ack_and_single_use_model_admission(live, monkeypatch):
    memory, maker, auth, flow, parent = live
    first_store = PlannerExecutionStore(memory)
    with pytest.raises(PlannerApprovalPending) as waiting:
        await first_store.admit(flow, parent, purpose="flow_generation")
    pending = waiting.value
    assert pending.revision == 1
    async with maker() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == pending.task_id,
        ))).scalar_one()
        assert task.status == "awaiting_approval"
        assert task.started_at is None
        assert (await db.execute(select(func.count()).select_from(
            SupervisionEventORM,
        ).where(
            SupervisionEventORM.task_id == pending.task_id,
            SupervisionEventORM.kind == "planner.approval_requested",
        ))).scalar_one() == 1

    # Authenticate a new API replica with NO local cached approval/task.
    another_memory = SessionMemory()
    another_memory._async_session = maker
    another_memory.store_hot = AsyncMock()
    replica = Orchestrator(another_memory, AsyncMock(), AsyncMock(), AsyncMock())
    assert not replica._approval_requests and not replica._tasks
    monkeypatch.setitem(state, "orchestrator", replica)
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "disposable-planner-api-key")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    token = jwt.encode({
        "sub": "verified-planner-operator", "role": "senior_operator",
        "exp": 4102444800,
    }, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    headers = {"Authorization": "Bearer " + token}
    app = FastAPI()
    app.include_router(approvals_router)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver",
    ) as client:
        listed = await client.get("/approvals/pending", headers=headers)
        assert listed.status_code == 200, listed.text
        record = next(x for x in listed.json() if x["id"] == pending.approval_id)
        assert record["flow_id"] == flow.id
        assert record["flow_revision"] == 1
        assert record["authorization_version"] == 1

        stale = await client.post(
            f"/approvals/{pending.approval_id}/resolve", headers=headers,
            json={
                "request_id": pending.approval_id, "decision": "approved",
                "expected_flow_revision": 0, "expected_authorization_version": 1,
            },
        )
        assert stale.status_code == 409
        correct = await client.post(
            f"/approvals/{pending.approval_id}/resolve", headers=headers,
            json={
                "request_id": pending.approval_id, "decision": "approved",
                "expected_flow_revision": 1, "expected_authorization_version": 1,
            },
        )
        assert correct.status_code == 200, correct.text
        assert correct.json()["status"] == "approved"
        assert correct.json()["operator_id"] == "verified-planner-operator"
    assert not replica._tasks  # No generic ContextManager agent dispatched.
    async with maker() as db:
        parked = (await db.execute(select(TaskORM).where(
            TaskORM.id == pending.task_id,
        ))).scalar_one()
        assert parked.status == "awaiting_approval"

    # Only an explicit, newly authorized planner entry can begin the model.
    updated_flow = flow.model_copy(update={"revision": 1})
    second_store = PlannerExecutionStore(memory)
    outcomes = await asyncio.gather(
        first_store.admit(updated_flow, parent, purpose="flow_generation"),
        second_store.admit(updated_flow, parent, purpose="flow_generation"),
        return_exceptions=True,
    )
    claims = [o for o in outcomes if not isinstance(o, Exception)]
    denied = [o for o in outcomes if isinstance(o, Exception)]
    assert len(claims) == len(denied) == 1
    assert isinstance(denied[0], ModelBudgetExceeded)
    await first_store.finish(claims[0], "completed")
    async with maker() as db:
        terminal = (await db.execute(select(TaskORM).where(
            TaskORM.id == pending.task_id,
        ))).scalar_one()
        assert terminal.status == "completed"
        assert (await db.execute(select(func.count()).select_from(
            SupervisionOutboxORM,
        ).where(
            SupervisionOutboxORM.engagement_id == flow.engagement_id,
        ))).scalar_one() >= 4


@pytest.mark.asyncio
async def test_live_planner_revocation_before_operator_decision_fails_closed(live):
    memory, maker, auth, flow, parent = live
    with pytest.raises(PlannerApprovalPending) as waiting:
        await PlannerExecutionStore(memory).admit(
            flow, parent, purpose="flow_generation",
        )
    pending = waiting.value
    assert await auth.revoke(
        flow.engagement_id, "operator-owner", 1,
        "operator revoked planner before approval",
    )
    with pytest.raises(PermissionError):
        await PlannerExecutionStore(memory).resolve_internal_approval(
            pending.approval_id, flow.engagement_id, pending.task_id,
            "approved", "verified-planner-operator",
            actor_role="senior_operator",
            expected_authorization_version=1,
            expected_flow_revision=1,
        )
    async with maker() as db:
        request = (await db.execute(select(ApprovalRequestORM).where(
            ApprovalRequestORM.id == pending.approval_id,
        ))).scalar_one()
        assert request.status == "pending"
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == pending.task_id,
        ))).scalar_one()
        assert task.status == "awaiting_approval"
        assert task.payload.get("operator_approved") is not True
