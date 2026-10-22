"""Real disposable PostgreSQL + Neo4j signed differential replay admission.

Opt-in with OSOP_DIFFAUTH_QUAL_PG_URI (a *new* localhost pgvector database
named diffauth_qualification_* on a nondefault port), OSOP_DIFFAUTH_QUAL_NEO_URI
(a *new* localhost Neo4j Bolt port) and OSOP_DIFFAUTH_QUAL_NEO_PASSWORD.

The completed map_workflow producer receipt and graph are synthetic fixtures:
this checks actual PG signed Flow, human approval CAS, one-shot local claim and
Neo4j graph reads, not live workflow capture, browser navigation or IDOR proof.
No Redis, target, model, scanner or application database is ever contacted.
"""

import asyncio
import hashlib
import os
import uuid
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import pytest
from alembic import command
from alembic.config import Config
from neo4j import AsyncGraphDatabase
from sqlalchemy import func, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import AgentType
from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
from ai_osop.core.signed_replay_comparison import classify_signed_observation_pair
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.signed_replay_execution import authorize_replay_step
from ai_osop.core.models import (
    ApprovalRequest,
    Endpoint,
    ExecutionActionRecord,
    FlowRecord,
    Task,
    Workflow,
    WorkflowStep,
)
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import (
    ApprovalRequestORM,
    SessionMemory,
    TaskORM,
)
from ai_osop.memory.supervision_store import SupervisionEventORM, SupervisionStore
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.task_scheduler import TaskScheduler
from tests.test_authorization_store import make_signed_session


def _only_disposable_services():
    pg_uri = os.environ.get("OSOP_DIFFAUTH_QUAL_PG_URI")
    neo_uri = os.environ.get("OSOP_DIFFAUTH_QUAL_NEO_URI")
    password = os.environ.get("OSOP_DIFFAUTH_QUAL_NEO_PASSWORD")
    if not (pg_uri and neo_uri and password):
        pytest.skip("Explicit fresh disposable PG and Neo4j service configuration required")
    pg = make_url(pg_uri)
    bolt = urlsplit(neo_uri)
    if (
        pg.drivername != "postgresql+asyncpg"
        or pg.host not in {"127.0.0.1", "localhost"}
        or pg.port in {None, 5432, 5433}
        or not (pg.database or "").startswith("diffauth_qualification_")
        or bolt.scheme != "bolt"
        or bolt.hostname not in {"127.0.0.1", "localhost"}
        or bolt.port in {None, 7687}
        or bolt.username
        or bolt.password
        or bolt.path not in {"", "/"}
        or bolt.query
        or bolt.fragment
    ):
        pytest.fail("Refusing non-disposable differential-auth services")
    return pg_uri, neo_uri, password


def _migrate(connection):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _approval(memory, task, *, identity):
    return ApprovalRequest(
        id=memory.deterministic_task_approval_id(task.engagement_id, task.id),
        task_id=task.id,
        engagement_id=task.engagement_id,
        agent_id="browser-agent-qualification",
        action_type=task.type,
        target=str(task.payload.get("url", task.payload.get("target", "unknown"))),
        payload_summary="Synthetic authorized replay; human review required",
        risk_assessment="high",
        evidence=[{"fixture": "synthetic", "reviewer": identity}],
    )


@pytest.fixture
async def live(monkeypatch):
    pg_uri, neo_uri, password = _only_disposable_services()
    engine = create_async_engine(pg_uri, pool_size=5, max_overflow=0)
    driver = AsyncGraphDatabase.driver(neo_uri, auth=("neo4j", password))
    try:
        await driver.verify_connectivity()
        async with engine.begin() as conn:
            await conn.run_sync(_migrate)

        memory = SessionMemory()
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        memory.store_hot = AsyncMock()
        memory.push_task_queue = AsyncMock()
        memory._redis = SimpleNamespace(setex=AsyncMock())
        graph = GraphMemory()
        graph._driver = driver
        unique = uuid.uuid4().hex[:12]
        sid = "eng-diffqual-" + unique
        wid = "wf-diffqual-" + unique
        flow_id = "flow-diffqual-" + unique
        source_id = "task-diffsource-" + unique
        parent_id = "task-diffparent-" + unique
        step_id = "step-diffqual-" + unique
        endpoint_id = "ep-diffqual-" + unique
        url = "https://authorized.example/api/owned-object"

        engagement, signed, _, _ = make_signed_session(
            monkeypatch,
            session_id=sid,
            authorization_id="auth-diffqual-" + unique,
            owner="signed-diffqual-owner",
        )
        engagement.phase = "reconnaissance"
        authority = AuthorizationStore(memory)
        await authority.create_authorized_session(
            engagement,
            signed,
            engagement.created_by,
        )
        assert (await memory.assert_signed_authorization(sid, expected_version=1)).version == 1

        flow = FlowRecord(
            id=flow_id,
            engagement_id=sid,
            objective="Human-authorized read-only differential replay",
        )
        assert await memory.create_flow_if_absent(flow)
        objective = Task(
            id="task-diffobjective-" + unique,
            engagement_id=sid,
            flow_id=flow.id,
            type="flow_objective",
            agent_type=AgentType.WORKFLOW,
            status="planned",
            payload={"title": flow.objective, "_authorization_version": 1},
        )
        saved_flow = await memory.create_flow_objective(flow, engagement, objective)
        assert saved_flow is not None

        # An original completed mapping is an explicit source fixture. We do
        # not imply a real browser producer ran in this qualification.
        async with memory._async_session() as db, db.begin():
            db.add(
                TaskORM(
                    id=source_id,
                    type="map_workflow",
                    priority=5,
                    agent_type=AgentType.WORKFLOW.value,
                    engagement_id=sid,
                    flow_id=flow_id,
                    payload={
                        "url": "https://authorized.example/home",
                        "user_label": "user_a",
                        "_authorization_version": 1,
                    },
                    dependencies=[],
                    max_retries=0,
                    timeout_seconds=60,
                    scope_check=True,
                    approval_required=False,
                    status="completed",
                    result={"status": "workflow_recorded", "workflow_id": wid},
                    retry_count=0,
                    created_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                )
            )
        sessions = SessionStore(memory)
        for identity in ("user_a", "user_b"):
            await sessions.save_session(
                sid,
                identity,
                bearer_token="fixture-local-" + identity,
            )
            assert await sessions.get_session_authoritative(sid, identity) is not None

        # Exercise the real graph producer writers: the guarded step writer
        # demands both an owned Workflow and an owned Endpoint before it may
        # materialize HAS_STEP and TARGETS_ENDPOINT.
        assert (
            await graph.add_endpoint(
                Endpoint(
                    id=endpoint_id,
                    engagement_id=sid,
                    url=url,
                    method="GET",
                    source="synthetic_local_qualification",
                )
            )
            == endpoint_id
        )
        assert (
            await graph.add_workflow(
                Workflow(
                    id=wid,
                    engagement_id=sid,
                    role="user_a",
                    name="Synthetic recorded GET",
                )
            )
            == wid
        )
        assert (
            await graph.add_workflow_step(
                WorkflowStep(
                    id=step_id,
                    workflow_id=wid,
                    endpoint_id=endpoint_id,
                    order=0,
                    action_type="NAVIGATE",
                    engagement_id=sid,
                )
            )
            == step_id
        )

        orch = Orchestrator.__new__(Orchestrator)
        orch.session_memory = memory
        orch.graph_memory = graph
        orch.temporal_enabled = False
        orch._tasks = {}
        orch._sessions = {sid: engagement}
        orch.coordination_bus = SimpleNamespace(publish=AsyncMock())
        orch.task_scheduler = TaskScheduler(orch)
        orch._execute_task_durable = AsyncMock(
            side_effect=AssertionError("Browser must not run in admission"),
        )
        # Original is already durable. The parent is a distinct reviewable
        # replay task, approved through the real PG human approval transaction.
        parent = Task(
            id=parent_id,
            engagement_id=sid,
            flow_id=flow_id,
            parent_task_id=source_id,
            dependencies=[source_id],
            type="replay_for_diff_auth",
            agent_type=AgentType.WORKFLOW,
            approval_required=True,
            max_retries=0,
            payload={
                "workflow_id": wid,
                "source_user_label": "user_a",
                "target_user_label": "user_b",
                "_authorization_version": 1,
                "_flow_revision": saved_flow.revision,
            },
        )
        await orch.schedule_task(parent)
        parent = await memory.load_task_authoritative(parent_id)
        parent_request = _approval(memory, parent, identity="operator-parent")
        assert await memory.park_task_for_approval_atomic(parent, parent_request)
        assert not await memory.claim_local_agent_start(
            await memory.load_task_authoritative(parent_id), "browser-agent-parent"
        )
        grant, first = await memory.resolve_approval_atomic(
            parent_request.id,
            sid,
            parent_id,
            "approved",
            "senior-parent-operator",
        )
        assert first and grant.status == "approved"
        assert await memory.is_task_approved(parent_id, sid, parent_request.id)
        parent = await memory.load_task_authoritative(parent_id)
        assert await memory.claim_local_agent_start(parent, "browser-agent-parent")
        parent = await memory.load_task_authoritative(parent_id)
        assert parent.status == "running"

        yield SimpleNamespace(
            memory=memory,
            factory=memory._async_session,
            graph=graph,
            orchestrator=orch,
            authority=authority,
            sid=sid,
            wid=wid,
            flow_id=flow_id,
            source_id=source_id,
            parent=parent,
            parent_approval=parent_request,
            step_id=step_id,
            endpoint_id=endpoint_id,
            url=url,
            engine=DifferentialAuthEngine(memory),
        )
    finally:
        await driver.close()
        await engine.dispose()


async def _admit(live):
    return await live.engine.run_differential_test(
        live.wid,
        ["user_b"],
        live.sid,
        live.orchestrator,
        parent_task=live.parent,
        source_user_label="user_a",
    )


@pytest.mark.asyncio
async def test_live_pair_admission_rolls_back_both_children_if_outbox_write_fails(
    live, monkeypatch
):
    original = SupervisionStore._append_event

    async def fail_outbox(*_args, **_kwargs):
        raise RuntimeError("synthetic outbox transaction abort")

    monkeypatch.setattr(SupervisionStore, "_append_event", staticmethod(fail_outbox))
    with pytest.raises(WorkflowException, match="UNKNOWN"):
        await _admit(live)
    async with live.factory() as db:
        count = (
            await db.execute(
                select(func.count())
                .select_from(TaskORM)
                .where(
                    TaskORM.parent_task_id == live.parent.id,
                    TaskORM.type == "navigate",
                )
            )
        ).scalar_one()
    assert count == 0, "Neither source nor target may survive an aborted pair transaction"
    # The new immutable Subtask rows must roll back with both TaskORM children,
    # not become orphan Flow records after an outbox failure.
    from ai_osop.memory.session_memory import ExecutionSubtaskORM

    async with live.factory() as db:
        subtask_count = (
            await db.execute(
                select(func.count())
                .select_from(ExecutionSubtaskORM)
                .where(
                    ExecutionSubtaskORM.engagement_id == live.sid,
                    ExecutionSubtaskORM.task_id == live.parent.id,
                    ExecutionSubtaskORM.task_type == "navigate",
                )
            )
        ).scalar_one()
    assert subtask_count == 0, "Aborted paired admission must not leave orphan subtasks"

    monkeypatch.setattr(SupervisionStore, "_append_event", staticmethod(original))
    accepted = await _admit(live)
    assert accepted["status"] == "pending_execution_approval"
    assert len(accepted["queued_task_ids"]) == 2


@pytest.mark.asyncio
async def test_live_concurrent_replicas_commit_one_indivisible_pair(live):
    results = await asyncio.gather(*(_admit(live) for _ in range(4)))
    assert sum(len(result["queued_task_ids"]) for result in results) == 2
    assert sorted(result["status"] for result in results) == [
        "already_admitted",
        "already_admitted",
        "already_admitted",
        "pending_execution_approval",
    ]
    async with live.factory() as db:
        rows = (
            (
                await db.execute(
                    select(TaskORM).where(
                        TaskORM.parent_task_id == live.parent.id,
                        TaskORM.type == "navigate",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 2
    assert {row.payload["_comparison_role"] for row in rows} == {"source", "target"}
    from ai_osop.core.signed_replay_comparison import observation_subtask_id
    from ai_osop.memory.session_memory import ExecutionSubtaskORM

    assert {row.subtask_id for row in rows} == {observation_subtask_id(row.id) for row in rows}
    async with live.factory() as db:
        substasks = (
            (
                await db.execute(
                    select(ExecutionSubtaskORM).where(
                        ExecutionSubtaskORM.execution_task_id.in_([row.id for row in rows])
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(subtasks) == 2
    assert {subtask.id for subtask in substasks} == {row.subtask_id for row in rows}
    assert all(
        subtask.task_id == live.parent.id
        and subtask.flow_id == live.flow_id
        and subtask.status == "dispatched"
        and subtask.approval_required
        for subtask in substasks
    )


@pytest.mark.asyncio
async def test_live_pair_outbox_recovers_only_pending_queue_hints(live):
    staged = await _admit(live)
    child_ids = staged["queued_task_ids"]
    by_role = {
        task.payload["_comparison_role"]: task
        for task in [await live.memory.load_task_authoritative(tid) for tid in child_ids]
    }
    assert set(by_role) == {"source", "target"}
    live.memory.push_task_queue.reset_mock()
    assert await live.orchestrator.reconcile_signed_replay_pair_intent(
        by_role["source"].id,
        by_role["target"].id,
    )
    assert live.memory.push_task_queue.await_count == 2
    async with live.factory() as db, db.begin():
        await db.execute(
            update(TaskORM)
            .where(
                TaskORM.id == by_role["source"].id,
            )
            .values(status="dispatch_unknown")
        )
    live.memory.push_task_queue.reset_mock()
    assert await live.orchestrator.reconcile_signed_replay_pair_intent(
        by_role["source"].id,
        by_role["target"].id,
    )
    assert live.memory.push_task_queue.await_count == 1
    delivered = live.memory.push_task_queue.await_args.args[1]
    assert delivered["id"] == by_role["target"].id
    assert delivered["status"] == "pending"


@pytest.mark.asyncio
async def test_live_redacted_comparison_action_rechecks_pg_pair_and_commits_one_outbox(
    live, monkeypatch
):
    """Synthetic provider testimony; tests PG transaction, NOT target authenticity."""
    staged = await _admit(live)
    ids = staged["queued_task_ids"]
    children = [await live.memory.load_task_authoritative(tid) for tid in ids]
    for child in children:
        request = _approval(live.memory, child, identity="signed-comparison-human")
        assert await live.memory.park_task_for_approval_atomic(child, request)
        decision, won = await live.memory.resolve_approval_atomic(
            request.id,
            live.sid,
            child.id,
            "approved",
            "senior-comparison-operator",
        )
        assert won and decision.status == "approved"
    approved = [await live.memory.load_task_authoritative(tid) for tid in ids]
    for child in approved:
        role = child.payload["_comparison_role"]
        synthetic = {
            "status": "success",
            "verification_status": "provider_testimony_only",
            "authorization_violation_verified": False,
            "remote_effect_verified": False,
            "source_task_id": live.source_id,
            "replay_parent_task_id": live.parent.id,
            "comparison_role": role,
            "redirected": False,
            "http_status_code": 200,
            "response_body_sha256": "a" * 64,
            "provider_evidence": {
                "provider_event_id": "evt-synthetic-" + role,
                "provider_receipt_sha256": "b" * 64,
                "source_authenticity_verified": False,
                "target_effect_verified": False,
                "finding_verified": False,
            },
        }
        async with live.factory() as db, db.begin():
            await db.execute(
                update(TaskORM)
                .where(TaskORM.id == child.id)
                .values(
                    status="completed",
                    result=synthetic,
                )
            )
    a, b = [await live.memory.load_task_authoritative(tid) for tid in ids]
    source, target = sorted(
        (a, b), key=lambda t: 0 if t.payload["_comparison_role"] == "source" else 1
    )
    decision = classify_signed_observation_pair(
        source,
        target,
        engagement_id=live.sid,
        parent_id=live.parent.id,
        flow_id=live.flow_id,
        workflow_id=live.wid,
        step_id=live.step_id,
        source_identity="user_a",
        target_identity="user_b",
        version=1,
        flow_revision=live.parent.payload["_flow_revision"],
        original_source_task_id=live.source_id,
    )
    assert decision["status"] == "candidate_needs_independent_review"
    digest = decision["comparison_sha256"]
    action = ExecutionActionRecord(
        id="action-"
        + hashlib.sha256((live.sid + ":" + live.parent.id + ":" + digest).encode()).hexdigest()[
            :48
        ],
        engagement_id=live.sid,
        flow_id=live.flow_id,
        task_id=live.parent.id,
        subtask_id=target.subtask_id,
        tool_name="signed_diff_auth_compare",
        outcome="candidate_review",
        safe_metadata={
            "comparison_sha256": digest,
            "source_task_id": live.source_id,
            "source_observation_task_id": source.id,
            "target_observation_task_id": target.id,
        },
    )
    original_append = SupervisionStore._append_event

    async def fail_event(*_args, **_kwargs):
        raise RuntimeError("synthetic same-transaction outbox failure")

    monkeypatch.setattr(SupervisionStore, "_append_event", staticmethod(fail_event))
    with pytest.raises(RuntimeError, match="same-transaction"):
        await live.memory.record_action(action)
    async with live.factory() as db:
        from ai_osop.memory.session_memory import ExecutionActionORM

        assert (
            await db.execute(
                select(func.count())
                .select_from(ExecutionActionORM)
                .where(
                    ExecutionActionORM.id == action.id,
                )
            )
        ).scalar_one() == 0

    monkeypatch.setattr(SupervisionStore, "_append_event", staticmethod(original_append))
    await live.memory.record_action(action)
    await live.memory.record_action(action)
    with pytest.raises(PermissionError, match="comparison disagrees"):
        await live.memory.record_action(action.model_copy(update={"outcome": "expected_denial"}))
    async with live.factory() as db:
        from ai_osop.memory.session_memory import ExecutionActionORM

        assert (
            await db.execute(
                select(func.count())
                .select_from(ExecutionActionORM)
                .where(
                    ExecutionActionORM.id == action.id,
                )
            )
        ).scalar_one() == 1
        assert (
            await db.execute(
                select(func.count())
                .select_from(SupervisionEventORM)
                .where(
                    SupervisionEventORM.engagement_id == live.sid,
                    SupervisionEventORM.idempotency_key == "signed-diff-comparison:" + action.id,
                )
            )
        ).scalar_one() == 1


@pytest.mark.asyncio
async def test_live_signed_replay_needs_distinct_human_grant_and_one_shot_pg_claim(live):
    result = await _admit(live)
    assert result["status"] == "pending_execution_approval"
    assert result["findings"] == [] and result["findings_count"] == 0
    assert len(result["queued_task_ids"]) == 2
    admitted = [
        await live.memory.load_task_authoritative(task_id) for task_id in result["queued_task_ids"]
    ]
    assert {task.payload["_comparison_role"] for task in admitted} == {"source", "target"}
    assert {task.payload["user_label"] for task in admitted} == {"user_a", "user_b"}
    child_id = next(task.id for task in admitted if task.payload["_comparison_role"] == "target")
    child = await live.memory.load_task_authoritative(child_id)
    assert child and child.status == "pending"
    assert child.approval_required and child.max_retries == 0
    assert child.parent_task_id == live.parent.id
    assert child.dependencies == [live.parent.id]
    assert child.flow_id == live.flow_id
    assert child.payload["url"] == live.url and child.payload["method"] == "GET"
    assert child.payload["user_label"] == "user_b"
    assert child.payload["_authorization_version"] == 1
    assert "approval_id" not in child.payload
    assert not await live.memory.claim_local_agent_start(child, "browser-agent-child")
    request = _approval(live.memory, child, identity="operator-child")
    assert request.id != live.parent_approval.id
    assert await live.memory.park_task_for_approval_atomic(child, request)
    assert not await live.memory.park_task_for_approval_atomic(child, request)
    child = await live.memory.load_task_authoritative(child_id)
    assert child.status == "awaiting_approval"
    assert not await live.memory.claim_local_agent_start(child, "browser-agent-child")
    approved, won = await live.memory.resolve_approval_atomic(
        request.id,
        live.sid,
        child_id,
        "approved",
        "senior-child-operator",
    )
    assert won and approved.status == "approved"
    assert approved.operator_id == "senior-child-operator"
    assert await live.memory.is_task_approved(child_id, live.sid, request.id)
    child = await live.memory.load_task_authoritative(child_id)
    assert child.payload["operator_approved"] is True
    assert child.payload["approval_id"] == request.id
    # A second grant is insufficient while the dependent parent is still running.
    assert not await live.memory.claim_local_agent_start(child, "browser-agent-child")
    assert await live.memory.settle_local_task_terminal_atomic(
        live.parent,
        "completed",
        {"status": "synthetic-replay-planned"},
    )
    assert await live.memory.claim_local_agent_start(child, "browser-agent-child")
    assert not await live.memory.claim_local_agent_start(child, "browser-agent-repeat")
    final = await live.memory.load_task_authoritative(child_id)
    assert final.status == "running"
    assert final.assigned_agent_id == "browser-agent-child"
    async with live.factory() as db:
        count = (
            await db.execute(
                select(func.count()).select_from(TaskORM).where(TaskORM.id == child_id)
            )
        ).scalar_one()
        approvals = (
            (
                await db.execute(
                    select(ApprovalRequestORM).where(
                        ApprovalRequestORM.task_id.in_([live.parent.id, child_id]),
                    )
                )
            )
            .scalars()
            .all()
        )
    assert count == 1 and len(approvals) == 2
    assert {entry.operator_id for entry in approvals} == {
        "senior-parent-operator",
        "senior-child-operator",
    }
    # After parent terminal state, the *parent replay* is no longer runnable;
    # the approved target child is one of two independently gated read-only
    # observations, while the original source child remains unapproved.
    with pytest.raises(WorkflowException):
        await _admit(live)
    live.orchestrator._execute_task_durable.assert_not_awaited()
    assert not await live.memory.claim_local_agent_start(final, "browser-agent-replay")
    async with live.graph._driver.session() as db:
        query = await db.run(
            "MATCH (f:DiffAuthFinding {engagement_id:$sid}) " "RETURN count(f) AS findings",
            {"sid": live.sid},
        )
        assert (await query.single())["findings"] == 0


@pytest.mark.asyncio
async def test_live_approved_child_worker_preflight_binds_original_pg_and_real_neo4j(live):
    """Execution-time gate uses real signed records and real graph, no target."""
    staged = await _admit(live)
    child_id = None
    for candidate_id in staged["queued_task_ids"]:
        candidate = await live.memory.load_task_authoritative(candidate_id)
        if candidate.payload["_comparison_role"] == "target":
            child_id = candidate_id
    assert child_id is not None
    child = await live.memory.load_task_authoritative(child_id)
    request = _approval(live.memory, child, identity="operator-step")
    assert await live.memory.park_task_for_approval_atomic(child, request)
    approved, won = await live.memory.resolve_approval_atomic(
        request.id,
        live.sid,
        child_id,
        "approved",
        "senior-step-operator",
    )
    assert won and approved.status == "approved"
    assert await live.memory.settle_local_task_terminal_atomic(
        live.parent,
        "completed",
        {"status": "synthetic-only-plan"},
    )
    assert await live.memory.claim_local_agent_start(
        await live.memory.load_task_authoritative(child_id),
        "browser-step-worker",
    )
    claimed = await live.memory.load_task_authoritative(child_id)
    ctx = SimpleNamespace(
        current_task=claimed,
        session_id=live.sid,
        session_memory=live.memory,
        graph_memory=live.graph,
    )
    verified = await authorize_replay_step(ctx, dict(claimed.payload))
    assert verified is not None and verified["url"] == live.url
    assert verified["user_label"] == "user_b"
    assert live.orchestrator._execute_task_durable.await_count == 0
    # Revocation after successful PG/Neo4j preflight fences the same Task.
    assert await live.authority.revoke(
        live.sid,
        "signed-diffqual-owner",
        reason="Signed replay preflight revoked before browser I/O",
        expected_version=1,
    )
    with pytest.raises(WorkflowException):
        await authorize_replay_step(ctx, dict(claimed.payload))


@pytest.mark.asyncio
async def test_live_graph_writer_rejects_foreign_endpoint_without_orphan_step(live):
    foreign_endpoint = "ep-foreign-" + uuid.uuid4().hex[:12]
    rejected_step = "step-cross-" + uuid.uuid4().hex[:12]
    assert (
        await live.graph.add_endpoint(
            Endpoint(
                id=foreign_endpoint,
                engagement_id="eng-other-" + uuid.uuid4().hex[:12],
                url=live.url,
                method="GET",
                source="synthetic_foreign",
            )
        )
        == foreign_endpoint
    )
    with pytest.raises(ValueError, match="outside engagement"):
        await live.graph.add_workflow_step(
            WorkflowStep(
                id=rejected_step,
                workflow_id=live.wid,
                endpoint_id=foreign_endpoint,
                engagement_id=live.sid,
                action_type="NAVIGATE",
            )
        )
    async with live.graph._driver.session() as db:
        response = await db.run(
            "MATCH (s:Step {id:$id}) RETURN count(s) AS steps",
            {"id": rejected_step},
        )
        assert (await response.single())["steps"] == 0
    live.orchestrator._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_live_duplicate_and_unknown_never_schedule_child_twice(live):
    first = await _admit(live)
    child_id = first["queued_task_ids"][0]
    second = await _admit(live)
    assert second == {
        "status": "already_admitted",
        "queued_task_ids": [],
        "findings": [],
        "findings_count": 0,
    }
    async with live.factory() as db, db.begin():
        await db.execute(
            update(TaskORM)
            .where(TaskORM.id == child_id)
            .values(
                status="dispatch_unknown",
            )
        )
    third = await _admit(live)
    assert third == second
    async with live.factory() as db:
        count = (
            await db.execute(
                select(func.count()).select_from(TaskORM).where(TaskORM.id == child_id)
            )
        ).scalar_one()
    assert count == 1
    assert not await live.memory.claim_local_agent_start(
        await live.memory.load_task_authoritative(child_id),
        "browser-agent-child",
    )
    live.orchestrator._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_live_revoked_authorization_denies_new_replay_without_findings(live):
    # The producer and approved parent remain persisted, but their old signed
    # policy is no longer authority to create a new child.
    assert await live.authority.revoke(
        live.sid,
        "signed-diffqual-owner",
        reason="Synthetic immediate revocation",
        expected_version=1,
    )
    with pytest.raises(WorkflowException, match="scope, Flow or parent approval"):
        await _admit(live)
    async with live.factory() as db:
        count = (
            await db.execute(
                select(func.count())
                .select_from(TaskORM)
                .where(TaskORM.parent_task_id == live.parent.id)
            )
        ).scalar_one()
    assert count == 0
    live.orchestrator._execute_task_durable.assert_not_awaited()
