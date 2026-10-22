"""Opt-in, disposable Temporal + signed PostgreSQL admission recovery qualification.

Never contact application Temporal, app PostgreSQL, real agents, networks under
assessment, MCP providers or LLMs. Safe execution requires explicit loopback
URLs with non-default ports and a dedicated context-free qualification database.
Workflow activities only return static strings or sleep; hard-kill is restricted
to a Python subprocess launched by this suite, never an existing worker.

Run example:
    OSOP_TEMPORAL_QUAL_ADDRESS=127.0.0.1:<ephemeral> \
    OSOP_TEMPORAL_QUAL_POSTGRES_URL=postgresql+asyncpg://.../temporal_qualification_... \
    pytest -q tests/qualification/test_live_temporal_admission_recovery.py
"""

import asyncio
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.session_memory import SessionMemory
from tests.test_authorization_store import make_signed_session


def _temporal_address() -> str:
    address = os.environ.get("OSOP_TEMPORAL_QUAL_ADDRESS", "")
    if not address:
        pytest.skip("No disposable Temporal server explicitly configured")
    host, sep, port_text = address.rpartition(":")
    if sep != ":" or host not in {"127.0.0.1", "localhost"}:
        pytest.fail("Refusing any non-loopback Temporal qualification address")
    try:
        port = int(port_text)
    except ValueError:
        pytest.fail("Invalid disposable Temporal port")
    if not 1024 <= port <= 65535 or port in {7233, 7234}:
        pytest.fail("Refusing default or application Temporal server port")
    return address


def _postgres_url() -> str:
    raw = os.environ.get("OSOP_TEMPORAL_QUAL_POSTGRES_URL", "")
    if not raw:
        pytest.skip("Disposable Temporal-admission PostgreSQL not configured")
    try:
        url = make_url(raw)
    except ValueError:
        pytest.fail("Invalid disposable PostgreSQL qualification URL")
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"127.0.0.1", "localhost"}
        or type(url.port) is not int
        or url.port in {5432, 5433}
        or not 1024 <= url.port <= 65535
        or not str(url.database or "").startswith("temporal_qualification_")
    ):
        pytest.fail("Refusing a non-disposable Temporal-admission database")
    return raw


def _migrate(conn) -> None:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = conn
    command.upgrade(config, "head")


@pytest.fixture
async def temporal():
    address = _temporal_address()
    sdk = pytest.importorskip("temporalio")
    from temporalio.client import Client

    client = await asyncio.wait_for(Client.connect(address), timeout=8)
    return SimpleNamespace(
        client=client,
        address=address,
        unique="temporal-qualification-" + uuid.uuid4().hex[:14],
        sdk=sdk,
    )


@pytest.fixture
async def signed_pg(monkeypatch):
    # The PostgreSQL fixture is intentionally independent of Temporal itself.
    # Validate name/host/port BEFORE creating an engine or applying migrations.
    engine = create_async_engine(_postgres_url(), pool_size=4, max_overflow=0)
    try:
        async with engine.begin() as db:
            await db.run_sync(_migrate)
        memory = SessionMemory()
        memory._pg_engine = engine
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        nonce = uuid.uuid4().hex[:14]
        session, verified, _, _ = make_signed_session(
            monkeypatch,
            session_id=f"eng-temporal-qualification-{nonce}",
            authorization_id=f"auth-temporal-qualification-{nonce}",
        )
        session.phase = "reconnaissance"
        await AuthorizationStore(memory).create_authorized_session(
            session,
            verified,
            session.created_by,
        )
        flow = FlowRecord(
            id=f"flow-temporal-qualification-{nonce}",
            engagement_id=session.session_id,
            objective="Synthetic local workflow admission, no assessment targets",
            status="running",
        )
        assert await memory.create_flow_if_absent(flow)
        task = Task(
            id=f"task-temporal-qualification-{nonce}",
            type="summarize_context",
            agent_type=AgentType.CONTEXT_MANAGER,
            engagement_id=session.session_id,
            flow_id=flow.id,
            status="pending",
            payload={"_authorization_version": 1},
        )
        await memory.store_task(task)
        yield SimpleNamespace(
            memory=memory,
            session=session,
            flow=flow,
            task=task,
            store=AuthorizationStore(memory),
        )
    finally:
        await engine.dispose()


def _local_worker(client, queue, *, duration: float = 0.0, counter=None):
    from temporalio import activity
    from temporalio.worker import Worker

    from ai_osop.orchestrator.temporal_worker import TaskWorkflow, _sandboxed_workflow_runner

    @activity.defn(name="execute_task_activity")
    async def safe_activity(_payload: dict) -> dict:
        if counter is not None:
            counter.append("invoked")
        if duration:
            await asyncio.sleep(duration)
        return {"status": "synthetic_complete", "remote_targets": 0}

    return Worker(
        client,
        task_queue=queue,
        workflows=[TaskWorkflow],
        activities=[safe_activity],
        workflow_runner=_sandboxed_workflow_runner(),
    )


@pytest.mark.asyncio
async def test_real_temporal_completed_start_id_is_not_replayed(temporal):
    from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler

    call_count = []
    scheduler = TemporalTaskScheduler(client=temporal.client, task_queue=temporal.unique)
    payload = {"id": "task-" + uuid.uuid4().hex[:12], "timeout_seconds": 10}
    async with _local_worker(temporal.client, temporal.unique, counter=call_count):
        first = await scheduler.start_task_workflow(payload)
        assert (
            await asyncio.wait_for(temporal.client.get_workflow_handle(first).result(), timeout=12)
        )["status"] == "synthetic_complete"
        assert await scheduler.start_task_workflow(payload) == first
    assert call_count == ["invoked"], "A replay must not dispatch the synthetic activity twice"


@pytest.mark.asyncio
async def test_real_ack_lost_after_temporal_commit_deduplicates_and_reconciles(temporal):
    from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler

    count = []
    payload = {"id": "task-" + uuid.uuid4().hex[:12], "timeout_seconds": 10}
    primary = TemporalTaskScheduler(client=temporal.client, task_queue=temporal.unique)

    async def send_then_lose_ack(*args, **kwargs):
        await temporal.client.start_workflow(*args, **kwargs)
        raise TimeoutError("synthetic ack lost AFTER server commit")

    interrupted = TemporalTaskScheduler(
        client=SimpleNamespace(start_workflow=send_then_lose_ack),
        task_queue=temporal.unique,
    )
    async with _local_worker(temporal.client, temporal.unique, counter=count):
        with pytest.raises(TimeoutError, match="ack lost"):
            await interrupted.start_task_workflow(payload)
        # No synthetic re-execution is permitted even if the first workflow
        # reached terminal state before client retry.
        workflow_id = await primary.start_task_workflow(payload)
        handle = temporal.client.get_workflow_handle(workflow_id)
        assert (await asyncio.wait_for(handle.result(), timeout=12))[
            "status"
        ] == "synthetic_complete"
        description = await handle.describe()
        assert getattr(description.status, "name", "") in {
            "COMPLETED",
            "WORKFLOW_EXECUTION_STATUS_COMPLETED",
        }
    assert count == ["invoked"]


@pytest.mark.asyncio
async def test_real_worker_hard_kill_does_not_retry_synthetic_activity(temporal, tmp_path):
    from temporalio.common import WorkflowIDReusePolicy
    from temporalio.worker import Worker

    marker = tmp_path / "synthetic_dispatch_marker.txt"
    worker_code = """
import asyncio, sys
from pathlib import Path
from temporalio.client import Client
from temporalio.worker import Worker
from temporalio import activity
from ai_osop.orchestrator.temporal_worker import TaskWorkflow, _sandboxed_workflow_runner
@activity.defn(name="execute_task_activity")
async def side_effect_free_blocking_activity(_payload):
    with Path(sys.argv[3]).open("a", encoding="utf8") as out:
        out.write("started\\n")
        out.flush()
    await asyncio.sleep(600)
    return {"status": "synthetic_complete"}
async def run():
    client = await Client.connect(sys.argv[1])
    async with Worker(client, task_queue=sys.argv[2], workflows=[TaskWorkflow],
                      activities=[side_effect_free_blocking_activity],
                      workflow_runner=_sandboxed_workflow_runner()):
        await asyncio.sleep(600)
asyncio.run(run())
"""
    worker_process = subprocess.Popen(
        [sys.executable, "-u", "-c", worker_code, temporal.address, temporal.unique, str(marker)],
        cwd=str(Path(__file__).resolve().parents[2]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # This task has a 3-second heartbeat and retry maximum_attempts=1.
        from ai_osop.orchestrator.temporal_worker import TaskWorkflow, _sandboxed_workflow_runner

        handle = await temporal.client.start_workflow(
            TaskWorkflow.run,
            {"id": "task-" + uuid.uuid4().hex[:12], "timeout_seconds": 3},
            id="ai-osop-task-hard-kill-" + uuid.uuid4().hex[:12],
            task_queue=temporal.unique,
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        )
        for _ in range(160):
            if marker.exists() and marker.read_text(encoding="utf8").count("started") == 1:
                break
            await asyncio.sleep(0.1)
        else:
            pytest.fail("Synthetic worker never started; cannot qualify hard kill")
        worker_process.kill()
        await asyncio.to_thread(worker_process.wait, 8)
        # Start a new worker. A heartbeat timeout must NOT redispatch
        # this side-effecting activity; Temporal maximum_attempts=1.
        called_after_crash = []
        async with _local_worker(temporal.client, temporal.unique, counter=called_after_crash):
            from temporalio.client import WorkflowFailureError

            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), timeout=20)
        assert marker.read_text(encoding="utf8").count("started") == 1
        assert called_after_crash == []
    finally:
        if worker_process.poll() is None:
            worker_process.kill()
            await asyncio.to_thread(worker_process.wait, 8)


@pytest.mark.asyncio
async def test_real_signed_pg_claim_unknown_does_not_admit_second_dispatch(signed_pg, temporal):
    from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler

    memory, task = signed_pg.memory, signed_pg.task
    first_claim = await memory.claim_temporal_dispatch(task)
    assert first_claim.startswith("temporal-claim-")
    durable = await memory.load_task_authoritative(task.id)
    assert durable.status == "dispatching" and durable.result["claim_id"] == first_claim
    with pytest.raises(PermissionError):
        await memory.claim_temporal_dispatch(task)

    # Simulated TCP loss AFTER real workflow acceptance. Do not infer that a
    # missing reply means an activity ran, and do not submit a second task.
    scheduler = TemporalTaskScheduler(client=temporal.client, task_queue=temporal.unique)
    synthetic = {"id": task.id, "timeout_seconds": 10}
    workflow_id = await scheduler.start_task_workflow(synthetic)
    with pytest.raises(PermissionError):
        await memory.claim_temporal_dispatch(task)
    await memory.settle_temporal_dispatch(
        task.id,
        task.engagement_id,
        first_claim,
        "dispatch_unknown",
    )
    stored = await memory.load_task_authoritative(task.id)
    assert stored.status == "dispatch_unknown"
    with pytest.raises(PermissionError):
        await memory.claim_temporal_dispatch(task)
    # Independent reconciliation can observe the remote *workflow ID*
    # without reopening the signed database claim or calling any targets.
    description = await temporal.client.get_workflow_handle(workflow_id).describe()
    assert description is not None
    # Do not convert UNKNOWN to scheduled without a new operator-reviewed CAS.
    assert (await memory.load_task_authoritative(task.id)).status == "dispatch_unknown"


@pytest.mark.asyncio
async def test_real_pg_admission_crash_before_temporal_rpc_is_quarantined(signed_pg, temporal):
    """No remote workflow does NOT justify resetting the durable one-shot claim."""
    from temporalio.service import RPCError, RPCStatusCode

    memory, task = signed_pg.memory, signed_pg.task
    claim_id = await memory.claim_temporal_dispatch(task)
    assert (await memory.load_task_authoritative(task.id)).status == "dispatching"
    workflow_id = "ai-osop-" + task.id
    try:
        await temporal.client.get_workflow_handle(workflow_id).describe()
    except RPCError as error:
        assert error.status == RPCStatusCode.NOT_FOUND
    else:
        pytest.fail("Synthetic task unexpectedly already exists on disposable Temporal")
    with pytest.raises(PermissionError):
        await memory.claim_temporal_dispatch(task)
    await memory.settle_temporal_dispatch(
        task.id,
        task.engagement_id,
        claim_id,
        "dispatch_unknown",
    )
    assert (await memory.load_task_authoritative(task.id)).status == "dispatch_unknown"
    with pytest.raises(PermissionError):
        await memory.claim_temporal_dispatch(task)


@pytest.mark.asyncio
async def test_real_pg_dispatch_claim_rejected_after_roe_revocation(signed_pg):
    assert await signed_pg.store.revoke(
        signed_pg.session.session_id,
        signed_pg.session.created_by,
        1,
        "disposable qualification test signed ROE revoked",
    )
    with pytest.raises(Exception):
        await signed_pg.memory.claim_temporal_dispatch(signed_pg.task)
    assert (await signed_pg.memory.load_task_authoritative(signed_pg.task.id)).status == "pending"
