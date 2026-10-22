"""Deterministic Task resource lease transition qualification.

These tests use the actual PostgreSQL verifier with a simulated SQL session.
They do not claim a live PostgreSQL lease-race or Docker qualification.
"""

import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from ai_osop.memory.flow_resource_materialization import ResourceAdmissionDenied
from tests.test_signed_sandbox_resource_delivery_20261016 import source


@pytest.mark.asyncio
async def test_claim_recovered_only_after_fresh_dispatched_lease(source):
    binding, verifier, rows, _db = source
    lease = rows["supervision_execution_leases"]
    lease["state"] = "reserved"
    with pytest.raises(ResourceAdmissionDenied, match="lease"):
        await verifier(binding)
    lease["state"] = "dispatched"
    admitted = await verifier(binding)
    assert admitted["approved"] is True
    assert admitted["active"] is True
    lease["state"] = "released"
    with pytest.raises(ResourceAdmissionDenied, match="lease"):
        await verifier(binding)


@pytest.mark.asyncio
async def test_expired_or_invalid_claim_is_denied_even_with_running_task(source):
    binding, verifier, rows, _db = source
    lease = rows["supervision_execution_leases"]
    assert (await verifier(binding))["approved"] is True
    lease["expires_at"] = datetime.utcnow() - timedelta(microseconds=1)
    with pytest.raises(ResourceAdmissionDenied, match="lease"):
        await verifier(binding)
    lease["expires_at"] = datetime.utcnow() + timedelta(minutes=5)
    lease["owner_id"] = "invalid owner with whitespace"
    with pytest.raises(ResourceAdmissionDenied, match="lease"):
        await verifier(binding)


@pytest.mark.asyncio
async def test_lease_theft_and_revoked_human_approval_require_fresh_verification(source):
    binding, verifier, rows, _db = source
    assert (await verifier(binding))["active"] is True
    rows["supervision_execution_leases"]["lease_id"] = "stolen"
    with pytest.raises(ResourceAdmissionDenied, match="lease"):
        await verifier(binding)
    rows["supervision_execution_leases"]["lease_id"] = "lease-resource-claim"
    rows["approval_requests"]["status"] = "revoked"
    with pytest.raises(ResourceAdmissionDenied, match="Human approved"):
        await verifier(binding)


@pytest.mark.asyncio
async def test_cross_tenant_task_and_flow_mismatch_fail_closed(source):
    binding, verifier, rows, _db = source
    rows["tasks"]["engagement_id"] = "another-tenant"
    with pytest.raises(ResourceAdmissionDenied):
        await verifier(binding)
    rows["tasks"]["engagement_id"] = binding.engagement_id
    rows["execution_flows"]["revision"] += 1
    with pytest.raises(ResourceAdmissionDenied):
        await verifier(binding)


@pytest.mark.asyncio
async def test_disposable_pg16_real_verifier_lease_revocation(source, monkeypatch):
    """Real PG rows and transactions; signed ROE verification is SYNTHETIC.

    Uses one new loopback-only pgvector container, never an existing DB.
    """
    if os.getenv("OSOP_DISPOSABLE_RESOURCE_LEASE_PG") != "1":
        pytest.skip("Explicit disposable PG resource lease opt-in required")
    import docker
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine
    from types import SimpleNamespace
    from ai_osop.memory.authoritative_task_resources import PostgresApprovedTaskResourceVerifier
    import ai_osop.memory.authoritative_task_resources as verifier_module

    binding, _, rows, _ = source
    client = docker.from_env()
    client.images.get("pgvector/pgvector:pg16")
    name = "osop-disposable-resource-lease-" + uuid.uuid4().hex[:12]
    assert not client.containers.list(all=True, filters={"name": name})
    container = None
    engine = None
    try:
        container = client.containers.run(
            "pgvector/pgvector:pg16", name=name, detach=True, remove=False,
            environment={"POSTGRES_USER": "postgres", "POSTGRES_PASSWORD": "lease-local-only",
                         "POSTGRES_DB": "lease_lab"},
            ports={"5432/tcp": ("127.0.0.1", None)}, volumes={},
            labels={"osop.disposable.qualification": "resource-lease"},
        )
        container.reload()
        ports = container.attrs["NetworkSettings"]["Ports"]["5432/tcp"]
        assert ports and ports[0]["HostIp"] == "127.0.0.1"
        port = int(ports[0]["HostPort"])
        url = f"postgresql+asyncpg://postgres:lease-local-only@127.0.0.1:{port}/lease_lab"
        engine = create_async_engine(url, connect_args={"timeout": 3})
        for attempt in range(40):
            try:
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                break
            except Exception:
                await asyncio.sleep(.25)
        else:
            pytest.fail("Disposable PostgreSQL unavailable")

        project = Path(__file__).resolve().parents[2]
        def upgrade():
            cfg = Config(str(project / "alembic.ini"))
            cfg.set_main_option("script_location", str(project / "migrations"))
            cfg.set_main_option("sqlalchemy.url", url)
            command.upgrade(cfg, "0022")
        await asyncio.to_thread(upgrade)

        # Synthetic signed ROE: real PG store/locks are used, but no claim is
        # made that a locally generated test fixture is a trusted real signature.
        async def synthetic_guard(db, engagement_id, expected_version=None, expected_digest=None):
            assert engagement_id == binding.engagement_id
            assert expected_version == binding.authorization_version
            assert expected_digest == binding.authorization_sha256
            return SimpleNamespace(session_id=engagement_id, version=expected_version,
                                   policy_sha256=expected_digest,
                                   policy={"created_by": binding.owner_id})
        monkeypatch.setattr(verifier_module, "guard_sql", synthetic_guard)

        # Seed exactly the projected columns queried by the production verifier
        # into the isolated schema, bypassing unrelated parent FKs only here.
        for table in ("session_states", "execution_flows", "tasks", "approval_requests",
                      "execution_subtasks", "supervision_execution_leases"):
            record = rows[table]
            key_values = dict(record)
            if table == "session_states":
                key_values["session_id"] = binding.engagement_id
            if table == "tasks":
                key_values["id"] = binding.task_id
            if table == "execution_flows":
                key_values.update(objective="Synthetic lease qualification", created_at=datetime.utcnow(), updated_at=datetime.utcnow())
            if table == "execution_subtasks":
                key_values.update(task_id=binding.task_id, title="Synthetic reviewed resource", description="Lab only",
                                  task_type="read_flow_resource", agent_type="recon", order=1,
                                  dependencies=[], refinement_count=0, created_at=datetime.utcnow(),
                                  updated_at=datetime.utcnow())
            if table == "supervision_execution_leases":
                pass
            if table == "approval_requests" and key_values.get("responded_at") is not None:
                key_values["responded_at"] = key_values["responded_at"].replace(tzinfo=None)
            cols = ",".join('"' + key + '"' for key in key_values)
            for json_key in ("scope", "payload", "evidence", "dependencies"):
                if json_key in key_values:
                    key_values[json_key] = json.dumps(key_values[json_key])
            params = ",".join(("CAST(:" + k + " AS jsonb)") if k in ("scope", "payload", "evidence", "dependencies") else (":" + k) for k in key_values)
            async with engine.begin() as conn:
                await conn.execute(text("SET LOCAL session_replication_role = replica"))
                await conn.execute(text(f"INSERT INTO {table} ({cols}) VALUES ({params})"), key_values)

        memory = SimpleNamespace(_async_session=engine_sessionmaker(engine))
        verifier = PostgresApprovedTaskResourceVerifier(memory)
        assert (await verifier(binding))["approved"] is True
        async with engine.begin() as conn:
            await conn.execute(text("UPDATE supervision_execution_leases SET state='released' WHERE task_id=:task"),
                               {"task": binding.task_id})
        with pytest.raises(ResourceAdmissionDenied, match="lease"):
            await verifier(binding)
        # Real PostgreSQL row-lock race: a verifier entering during a pending
        # lease revocation must observe the committed non-dispatched state.
        async with engine.begin() as conn:
            await conn.execute(text("UPDATE supervision_execution_leases SET state='dispatched', expires_at=:expiry WHERE task_id=:task"),
                               {"task": binding.task_id, "expiry": datetime.utcnow()+timedelta(minutes=5)})
        async with engine.begin() as revoker:
            await revoker.execute(text("UPDATE supervision_execution_leases SET state='released' WHERE task_id=:task"),
                                  {"task": binding.task_id})
            pending = asyncio.create_task(verifier(binding))
            await asyncio.sleep(.15)
            assert not pending.done(), "Verifier must wait on PostgreSQL lease row lock"
        with pytest.raises(ResourceAdmissionDenied, match="lease"):
            await asyncio.wait_for(pending, timeout=3)
        async with engine.begin() as conn:
            await conn.execute(text("UPDATE supervision_execution_leases SET state='dispatched', expires_at=:expiry WHERE task_id=:task"),
                               {"task": binding.task_id, "expiry": datetime.utcnow()-timedelta(seconds=1)})
        with pytest.raises(ResourceAdmissionDenied, match="lease"):
            await verifier(binding)
    finally:
        if engine is not None:
            await engine.dispose()
        if container is not None:
            try:
                container.remove(force=True)
            except docker.errors.NotFound:
                pass


def engine_sessionmaker(engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    return async_sessionmaker(engine, expire_on_commit=False)
