"""Only disposable, loopback-bound Temporal/PostgreSQL joined-recovery fixtures.

This module is deliberately NOT a global conftest. An opt-in creates two new,
unique test containers from locally cached images, migrates only their fresh
database and removes only containers created here. No app DB, real agent,
assessment target, paid model or external witness is ever contacted.
"""

import asyncio
import os
import socket
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.supervision_store import SupervisionStore
from tests.test_authorization_store import make_signed_session

_POSTGRES_IMAGE = "pgvector/pgvector:pg16"
_TEMPORAL_IMAGE = "temporalio/temporal:latest"
_OPT_IN = "OSOP_DISPOSABLE_JOINED_RECOVERY"


def _migrate(conn):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = conn
    command.upgrade(config, "head")


def _port(container, exposed, forbidden):
    container.reload()
    bindings = container.attrs["NetworkSettings"]["Ports"][exposed]
    assert len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1"
    port = int(bindings[0]["HostPort"])
    assert 1024 <= port <= 65535 and port not in forbidden
    return port


@pytest.fixture(scope="module")
def disposable_recovery_services():
    if os.environ.get(_OPT_IN) != "1":
        pytest.skip(f"Set {_OPT_IN}=1 to provision fresh local Docker services")

    import docker
    import psycopg

    client = docker.from_env()
    # Never pull or attach to a preexisting application container.
    for image in (_POSTGRES_IMAGE, _TEMPORAL_IMAGE):
        client.images.get(image)
    suffix = uuid.uuid4().hex[:16]
    database = "temporal_qualification_joined_" + suffix
    pg_name = "osop-joined-recovery-pg-" + suffix
    temporal_name = "osop-joined-recovery-temporal-" + suffix
    for name in (pg_name, temporal_name):
        assert not client.containers.list(all=True, filters={"name": name})
    created = []
    try:
        pg = client.containers.run(
            _POSTGRES_IMAGE,
            detach=True,
            remove=False,
            name=pg_name,
            environment={
                "POSTGRES_USER": "postgres",
                "POSTGRES_PASSWORD": "joined-recovery-disposable",
                "POSTGRES_DB": database,
            },
            ports={"5432/tcp": ("127.0.0.1", None)},
            volumes={},
            labels={"osop.disposable.qualification": "joined-recovery"},
        )
        created.append(pg)
        pg_port = _port(pg, "5432/tcp", {5432, 5433})
        temporal = client.containers.run(
            _TEMPORAL_IMAGE,
            detach=True,
            remove=False,
            name=temporal_name,
            command=["server", "start-dev", "--ip", "0.0.0.0", "--port", "7233"],
            ports={"7233/tcp": ("127.0.0.1", None)},
            volumes={},
            labels={"osop.disposable.qualification": "joined-recovery"},
        )
        created.append(temporal)
        temporal_port = _port(temporal, "7233/tcp", {7233, 7234})
        for _ in range(70):
            try:
                with psycopg.connect(
                    host="127.0.0.1",
                    port=pg_port,
                    user="postgres",
                    password="joined-recovery-disposable",
                    dbname=database,
                    connect_timeout=1,
                ) as connection:
                    assert connection.execute("SELECT 1").fetchone() == (1,)
                break
            except psycopg.OperationalError:
                time.sleep(0.2)
        else:
            pytest.fail("Newly allocated disposable PostgreSQL failed readiness")
        for _ in range(70):
            try:
                with socket.create_connection(("127.0.0.1", temporal_port), timeout=1):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.fail("Newly allocated disposable Temporal failed readiness")
        yield SimpleNamespace(
            pg_url=(
                f"postgresql+asyncpg://postgres:joined-recovery-disposable"
                f"@127.0.0.1:{pg_port}/{database}"
            ),
            temporal_address=f"127.0.0.1:{temporal_port}",
        )
    finally:
        for container in reversed(created):
            try:
                container.remove(force=True)
            except docker.errors.NotFound:
                pass


@pytest.fixture
async def joined_signed_pg(disposable_recovery_services, monkeypatch):
    # Every test gets a new signed engagement; shared service is newly created
    # for this module and is disposed in the container fixture finally block.
    engine = create_async_engine(
        disposable_recovery_services.pg_url,
        pool_size=4,
        max_overflow=0,
        pool_pre_ping=True,
    )
    try:
        async with engine.begin() as connection:
            await connection.run_sync(_migrate)
        memory = SessionMemory()
        memory._pg_engine = engine
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        identifier = uuid.uuid4().hex[:12]
        session, verified, _, _ = make_signed_session(
            monkeypatch,
            session_id="eng-joined-" + identifier,
            authorization_id="auth-joined-" + identifier,
        )
        session.phase = "reconnaissance"
        authority = AuthorizationStore(memory)
        await authority.create_authorized_session(session, verified, session.created_by)
        flow = FlowRecord(
            id="flow-joined-" + identifier,
            engagement_id=session.session_id,
            objective="Synthetic recovery qualification; no target access",
            status="running",
        )
        assert await memory.create_flow_if_absent(flow)
        task = Task(
            id="task-joined-" + identifier,
            type="summarize_context",
            agent_type=AgentType.CONTEXT_MANAGER,
            engagement_id=session.session_id,
            flow_id=flow.id,
            status="pending",
            payload={"_authorization_version": 1},
        )
        await memory.store_task(task)
        supervision = SupervisionStore(memory)
        async with memory._async_session() as db:
            async with db.begin():
                event = await supervision._append_event(
                    db,
                    session.session_id,
                    task.id,
                    "qualification.joined_recovery",
                    session.created_by,
                    {"status": "UNKNOWN", "source": "disposable-joined-qualification"},
                )
                source_event_id = event.id
        yield SimpleNamespace(
            memory=memory,
            authority=authority,
            session=session,
            flow=flow,
            task=task,
            source_event_id=source_event_id,
            supervision=supervision,
            engine=engine,
            temporal_address=disposable_recovery_services.temporal_address,
        )
    finally:
        await engine.dispose()
