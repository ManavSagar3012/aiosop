"""Optional real-PostgreSQL qualification for migration and Flow atomicity.

Run only against a disposable database, for example:
OSOP_LIVE_POSTGRES_URI=postgresql+asyncpg://... pytest tests/qualification/test_live_flow_postgres.py

Never point this suite at a production database: it applies schema migrations
and writes isolated test records. The default broad suite excludes this path.
"""

import asyncio
import os
import uuid
from datetime import datetime

import pytest
import redis.asyncio as redis
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, SubtaskRecord, Task
from ai_osop.memory.schema_migrations import ensure_schema
from ai_osop.memory.session_memory import Base, SessionMemory, SessionStateORM
from ai_osop.memory.authorization_store import AuthorizationStore
from tests.test_authorization_store import make_signed_session


@pytest.fixture
async def postgres():
    uri = os.environ.get("OSOP_LIVE_POSTGRES_URI")
    if not uri:
        pytest.skip("OSOP_LIVE_POSTGRES_URI not provided; no real DB contacted")
    engine = create_async_engine(uri, pool_size=5)
    try:
        await ensure_schema(engine, uri)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        store = SessionMemory()
        store._pg_engine = engine
        store._async_session = async_sessionmaker(engine, expire_on_commit=False)
        yield store
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_live_migrations_create_execution_tables(postgres):
    async with postgres._pg_engine.connect() as connection:
        tables = await connection.run_sync(lambda sync: set(inspect(sync).get_table_names()))
    assert {"alembic_version", "execution_flows", "execution_subtasks", "tasks"} <= tables


@pytest.mark.asyncio
async def test_live_flow_status_cas_one_winner_across_connections(postgres):
    suffix = uuid.uuid4().hex[:12]
    engagement_id = f"eng-live-{suffix}"
    flow = FlowRecord(id=f"flow-live-{suffix}", engagement_id=engagement_id, objective="Local qualification")
    assert await postgres.create_flow_if_absent(flow) is True
    assert await postgres.create_flow_if_absent(flow) is False

    one, two = await asyncio.gather(
        postgres.transition_flow_status(flow.id, engagement_id, 0, ["pending"], "paused"),
        postgres.transition_flow_status(flow.id, engagement_id, 0, ["pending"], "cancelled"),
    )
    assert sum(x is not None for x in (one, two)) == 1
    saved = await postgres.load_flow(flow.id)
    assert saved.revision == 1
    assert saved.status in {"paused", "cancelled"}
    assert await postgres.create_flow_if_absent(flow) is False
    after = await postgres.load_flow(flow.id)
    assert after.status == saved.status and after.revision == 1


async def _create_engagement(postgres, suffix, monkeypatch, roe=None):
    engagement_id = f"eng-live-{suffix}"
    session, signed, _, _ = make_signed_session(
        monkeypatch,
        session_id=engagement_id,
        authorization_id="auth-live-" + suffix,
        domains=["example.test"],
        roe_override=roe or {},
    )
    session.phase = "reconnaissance"
    await AuthorizationStore(postgres).create_authorized_session(
        session, signed, session.created_by,
    )
    return session


@pytest.mark.asyncio
async def test_live_refinement_insert_error_rolls_back_entire_revision(postgres, monkeypatch):
    suffix = uuid.uuid4().hex[:12]
    session = await _create_engagement(postgres, suffix, monkeypatch)
    engagement_id = session.session_id
    flow = FlowRecord(id=f"flow-live-{suffix}", engagement_id=engagement_id, objective="Atomicity")
    assert await postgres.create_flow_if_absent(flow)

    duplicate_id = f"subtask-live-{suffix}"
    proposals = [
        SubtaskRecord(
            id=duplicate_id,
            flow_id=flow.id,
            engagement_id=engagement_id,
            task_id=f"task-live-{suffix}",
            title="First candidate",
            order=i,
        )
        for i in range(2)
    ]
    with pytest.raises(Exception) as exc:
        await postgres.commit_flow_refinement(
            flow=flow,
            engagement=session,
            expected_subtask_ids=[],
            additions=proposals,
            activate_flow=False,
        )
    assert "unique" in str(exc.value).lower() or "duplicate" in str(exc.value).lower()
    after = await postgres.load_flow(flow.id)
    assert after.revision == 0 and after.status == "pending"
    assert await postgres.list_subtasks(flow.id) == []


@pytest.mark.asyncio
async def test_live_objective_creation_racing_pause_never_leaves_orphan_task(postgres, monkeypatch):
    suffix = uuid.uuid4().hex[:12]
    session = await _create_engagement(postgres, suffix, monkeypatch)
    flow = FlowRecord(
        id=f"flow-live-{suffix}", engagement_id=session.session_id, objective="Operator objective"
    )
    assert await postgres.create_flow_if_absent(flow)
    objective = Task(
        type="flow_objective", status="planned", agent_type=AgentType.RECON,
        engagement_id=session.session_id, flow_id=flow.id,
        payload={"_authorization_version": 1},
    )
    created, paused = await asyncio.gather(
        postgres.create_flow_objective(flow, session, objective),
        postgres.transition_flow_status(
            flow.id, session.session_id, flow.revision, ["pending"], "paused"
        ),
    )
    assert (created is not None) != (paused is not None)
    tasks = await postgres.list_flow_tasks(flow.id)
    assert len(tasks) == (1 if created else 0)
    current = await postgres.load_flow(flow.id)
    assert current.revision == 1
    assert current.status == ("pending" if created else "paused")


@pytest.mark.asyncio
async def test_live_claim_subtask_racing_pause_is_atomic(postgres, monkeypatch):
    suffix = uuid.uuid4().hex[:12]
    session = await _create_engagement(postgres, suffix, monkeypatch)
    flow = FlowRecord(
        id=f"flow-live-{suffix}", engagement_id=session.session_id, objective="Dispatch race"
    )
    assert await postgres.create_flow_if_absent(flow)
    subtask = SubtaskRecord(
        id=f"subtask-live-{suffix}", engagement_id=session.session_id,
        flow_id=flow.id, task_id=f"task-live-{suffix}",
        title="In-scope recon", agent_type=AgentType.RECON,
    )
    await postgres.store_subtask(subtask)
    claimed, paused = await asyncio.gather(
        postgres.claim_subtask(
            subtask.id,
            session.session_id,
            flow=flow,
            engagement=session,
            subtask=subtask,
            payload={"target": "example.test"},
        ),
        postgres.transition_flow_status(
            flow.id, session.session_id, flow.revision, ["pending"], "paused"
        ),
    )
    assert claimed != (paused is not None)
    current = await postgres.load_flow(flow.id)
    steps = await postgres.list_subtasks(flow.id)
    assert current.revision == 1
    assert current.status == ("pending" if claimed else "paused")
    assert len(steps) == 1
    assert steps[0].status == ("dispatched" if claimed else "pending")


@pytest.mark.asyncio
async def test_live_redis_reservations_never_exceed_engagement_quota(postgres, monkeypatch):
    uri = os.environ.get("OSOP_LIVE_REDIS_URI")
    if not uri:
        pytest.skip("OSOP_LIVE_REDIS_URI not provided; no real Redis contacted")
    suffix = uuid.uuid4().hex[:12]
    engagement = await _create_engagement(
        postgres, suffix, monkeypatch,
        roe={
            "tool_call_budget_total": 2,
            "tool_call_budget_per_tool": 2,
            "tool_call_window_seconds": 60,
        },
    )
    postgres._redis = redis.from_url(uri, decode_responses=True)
    try:
        results = await asyncio.gather(*(
            postgres.consume_mcp_tool_budget(
                engagement.session_id, "recon.scan", "agent-live-qualification"
            )
            for _ in range(12)
        ))
        assert results.count(True) == 2
        assert results.count(False) == 10
        assert not await postgres.consume_mcp_tool_budget(
            engagement.session_id, "recon.scan", "agent-live-qualification"
        )
    finally:
        await postgres._redis.aclose()
        postgres._redis = None
