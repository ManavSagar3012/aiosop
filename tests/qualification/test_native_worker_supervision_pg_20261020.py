"""Opt-in disposable PostgreSQL 0033 signed supervisor CAS qualification.

Uses a unique locally cached pgvector container on loopback. The original
Task/ROE reviewer admission is replaced with a synthetic guard; original
0027/0029/0033 SQL, immutable events and supervisor Ed25519 stay real.
No Go command, provider, network target, real DB or external effect executes.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore, MCPActionDenied
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPExecutionGrantStore,
    _native_manifest_sha256,
)
from ai_osop.memory.native_mcp_worker_supervision import (
    DOMAIN,
    NativeMCPWorkerSupervisionStore,
    _canonical,
)
from ai_osop.memory.session_memory import SessionMemory

ENG, FLOW, TASK, STEP = (
    "eng-supervisor-0033",
    "flow-supervisor-0033",
    "task-supervisor-0033",
    "subtask-supervisor-0033",
)
OWNER, AUTH = "owner-supervisor-0033", "auth-supervisor-0033"
BINDING = {
    "engagement_id": ENG,
    "flow_id": FLOW,
    "revision": 3,
    "version": 1,
    "authorization_id": AUTH,
    "authorization_sha256": "a" * 64,
}
SERVICE_SECRET = "only-disposable-native-service-secret"
SUPERVISOR_SECRET = "only-disposable-observer-secret"
SERVER, WORKER, CONTAINER = "recon-mcp", "worker-disposable-0033", "c" * 64


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _observation(
    key: Ed25519PrivateKey,
    token: dict,
    state: str,
    *,
    epoch: int = 0,
    prior: int = 0,
    container: str | None = None,
    now: int,
    **extra: str | None,
) -> dict:
    claims = {
        "version": 1,
        "grant_id": token["claims"]["grant_id"],
        "request_id": token["claims"]["request_id"],
        "server_id": SERVER,
        "worker_id": WORKER,
        "container_id": container,
        "epoch": epoch,
        "expected_revision": prior,
        "state": state,
        "observed_at": now,
        "evidence_sha256": hashlib.sha256((state + str(prior)).encode()).hexdigest(),
        "resource_sha256": None,
        "folder_staging_sha256": None,
        "readback_sha256": None,
    }
    claims.update(extra)
    return {
        "claims": claims,
        "kid": "supervisorTestKey",
        "signature": _b64(key.sign(DOMAIN + _canonical(claims))),
    }


async def _seed_source(db, action: str, request: str) -> None:
    values = {
        "action_id": action,
        "engagement_id": ENG,
        "flow_id": FLOW,
        "task_id": TASK,
        "subtask_id": STEP,
        "owner_id": OWNER,
        "flow_revision": 3,
        "authorization_id": AUTH,
        "authorization_version": 1,
        "authorization_sha256": "a" * 64,
        "approval_id": "apr-supervisor-0033",
        "lease_id": "lease-supervisor-0033",
        "lease_owner_id": "worker-disposable-0033",
        "server_id": SERVER,
        "tool_name": "authority_status",
        "side_effect_class": "READ_ONLY",
        "declaration_sha256": _native_manifest_sha256(SERVER),
        "parameters_sha256": hashlib.sha256(b"{}").hexdigest(),
        "intent_sha256": "d" * 64,
        "request_id": request,
        "reservation_token_sha256": "e" * 64,
        "status": "unknown",
        "revision": 3,
        "cancel_requested": False,
    }
    await db.execute(
        text(
            "INSERT INTO flow_mcp_action_dispatches ("
            + ",".join(values)
            + ",safe_parameters) VALUES ("
            + ",".join(":" + name for name in values)
            + ",CAST('{}' AS JSON))"
        ),
        values,
    )
    await db.execute(
        text(
            "INSERT INTO flow_mcp_action_dispatch_events (id,action_id,engagement_id,flow_id,task_id,revision,kind,status,intent_sha256) VALUES (:id,:action,:eng,:flow,:task,3,'dispatch_attempted','unknown',:intent)"
        ),
        {
            "id": "evt-" + uuid.uuid4().hex,
            "action": action,
            "eng": ENG,
            "flow": FLOW,
            "task": TASK,
            "intent": "d" * 64,
        },
    )


@pytest.mark.asyncio
async def test_native_0033_real_postgres_supervisor_cas_and_immutable_events(monkeypatch):
    if os.getenv("OSOP_DISPOSABLE_NATIVE_WORKER_0033_PG") != "1":
        pytest.skip("Dedicated disposable PG worker supervisor qualification requires opt-in")
    import docker
    from alembic import command
    from alembic.config import Config

    docker_client = docker.from_env()
    docker_client.images.get("pgvector/pgvector:pg16")  # local cache; never pull
    container_name = "osop-native-worker-0033-" + uuid.uuid4().hex[:12]
    assert not docker_client.containers.list(all=True, filters={"name": container_name})
    owned = None
    engine = None
    try:
        owned = docker_client.containers.run(
            "pgvector/pgvector:pg16",
            name=container_name,
            detach=True,
            remove=False,
            environment={
                "POSTGRES_USER": "postgres",
                "POSTGRES_PASSWORD": "native-worker-0033-local",
                "POSTGRES_DB": "native_worker_0033",
            },
            ports={"5432/tcp": ("127.0.0.1", None)},
            volumes={},
            labels={"osop.disposable.qualification": "native-supervisor-0033"},
        )
        owned.reload()
        binding = owned.attrs["NetworkSettings"]["Ports"]["5432/tcp"]
        assert len(binding) == 1 and binding[0]["HostIp"] == "127.0.0.1"
        port = int(binding[0]["HostPort"])
        assert 1024 <= port <= 65535 and port not in (5432, 5433)
        url = f"postgresql+asyncpg://postgres:native-worker-0033-local@127.0.0.1:{port}/native_worker_0033"
        engine = create_async_engine(url, pool_size=5, max_overflow=0)
        for _ in range(60):
            try:
                async with engine.connect() as db:
                    assert (await db.execute(text("SELECT 1"))).scalar_one() == 1
                break
            except Exception:
                await asyncio.sleep(0.25)
        else:
            pytest.fail("Disposable PG did not start")

        project = Path(__file__).resolve().parents[2]

        def upgrade() -> None:
            config = Config(str(project / "alembic.ini"))
            config.set_main_option("script_location", str(project / "migrations"))
            config.set_main_option("sqlalchemy.url", url)
            command.upgrade(config, "0033")

        await asyncio.to_thread(upgrade)
        memory = SessionMemory()
        memory._pg_engine = engine
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        actions = FlowMCPActionStore(memory, MCPRegistry())
        issuer = NativeMCPExecutionGrantStore(actions)
        store = NativeMCPWorkerSupervisionStore(actions)
        current = {"approved": True}

        async def source(self, db, binding, actor, action_id):
            if not current["approved"]:
                raise MCPActionDenied(409, "Synthetic approval revoked")
            original = await self._original(db, action_id)
            self.actions._same(original, binding, actor)
            return original

        monkeypatch.setattr(NativeMCPExecutionGrantStore, "_source", source)
        grant_key = Ed25519PrivateKey.generate()
        grant_seed = grant_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        grant_public = grant_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID", "grantTestKey")
        monkeypatch.setenv(
            "OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON",
            json.dumps({"grantTestKey": base64.b64encode(grant_seed).decode()}),
        )
        monkeypatch.setenv(
            "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
            json.dumps({"grantTestKey": _b64(grant_public)}),
        )
        monkeypatch.setenv(
            "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON", json.dumps({SERVER: SERVICE_SECRET})
        )
        observer_key = Ed25519PrivateKey.generate()
        observer_public = observer_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        monkeypatch.setenv(
            "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON",
            json.dumps(
                {
                    "external-supervisor": {
                        "kid": "supervisorTestKey",
                        "public_key": _b64(observer_public),
                        "secret_sha256": hashlib.sha256(SUPERVISOR_SECRET.encode()).hexdigest(),
                    }
                }
            ),
        )
        monkeypatch.delenv("OSOP_NATIVE_STAGE_RECEIPT_TRUST_JSON", raising=False)
        action = "action-" + "b" * 32
        request = "req-" + "d" * 48
        async with engine.begin() as db:
            await db.execute(
                text("INSERT INTO session_states (session_id) VALUES (:id)"), {"id": ENG}
            )
            await db.execute(
                text(
                    "INSERT INTO execution_flows (id,engagement_id,objective,status,revision,created_at,updated_at) VALUES (:id,:eng,'Isolated synthetic 0033','running',3,now(),now())"
                ),
                {"id": FLOW, "eng": ENG},
            )
            await db.execute(
                text("INSERT INTO tasks (id,engagement_id,flow_id) VALUES (:id,:eng,:flow)"),
                {"id": TASK, "eng": ENG, "flow": FLOW},
            )
            await db.execute(
                text(
                    "INSERT INTO execution_subtasks (id,engagement_id,flow_id,task_id,title,description,task_type,agent_type,approval_required,\"order\",dependencies,status,refinement_count,created_at,updated_at) VALUES (:id,:eng,:flow,:task,'Synthetic','No execution','synthetic','synthetic',true,1,CAST('[]' AS JSON),'dispatched',0,now(),now())"
                ),
                {"id": STEP, "eng": ENG, "flow": FLOW, "task": TASK},
            )
            await _seed_source(db, action, request)

        grant = await issuer.issue(BINDING, OWNER, action, request)
        token = grant["token"]
        kwargs = {"supervisor_id": "external-supervisor", "supervisor_secret": SUPERVISOR_SECRET}
        now = token["claims"]["issued_at"]
        prepared = await store.record(
            token, _observation(observer_key, token, "provisioned", now=now), **kwargs
        )
        epoch = prepared["epoch"]
        assert epoch > 0 and prepared["revision"] == 1
        with pytest.raises(MCPActionDenied):
            await store.record(
                token,
                _observation(
                    observer_key,
                    token,
                    "running",
                    epoch=epoch,
                    prior=1,
                    container=CONTAINER,
                    now=now,
                ),
                **kwargs,
            )
        await issuer.redeem(token, server_id=SERVER, server_secret=SERVICE_SECRET)
        obs = _observation(
            observer_key, token, "running", epoch=epoch, prior=1, container=CONTAINER, now=now
        )
        results = await asyncio.gather(
            store.record(token, obs, **kwargs),
            store.record(token, obs, **kwargs),
            return_exceptions=True,
        )
        assert sum(isinstance(item, dict) for item in results) == 1
        assert sum(isinstance(item, MCPActionDenied) for item in results) == 1
        assert next(item for item in results if isinstance(item, dict))["revision"] == 2
        current["approved"] = False
        # Later revocation prevents all active new declarations, while the
        # external supervisor still observes terminating and final cleanup.
        assert (
            await store.record(
                token,
                _observation(
                    observer_key,
                    token,
                    "unknown",
                    epoch=epoch,
                    prior=2,
                    container=CONTAINER,
                    now=now,
                ),
                **kwargs,
            )
        )["state"] == "unknown"

        # Synthetic current signed operator authority is the only mocked
        # prerequisite for this owner-controlled metadata intent. The real
        # PostgreSQL insert, uniqueness and immutable trigger remain live.
        async def authorized_operator(db, binding, actor, *, dispatch):
            if actor != OWNER or not dispatch or binding != BINDING:
                raise MCPActionDenied(403, "Foreign or unsigned recovery owner")
            return {"scope": {}}

        monkeypatch.setattr(actions, "_authority", authorized_operator)
        recovery_args = {
            "binding": BINDING,
            "actor_id": OWNER,
            "grant_id": grant["grant_id"],
            "expected_revision": 3,
            "explicit_human_confirmation": True,
        }
        response = await store.request_recovery(**recovery_args)
        assert response == {
            "grant_id": grant["grant_id"],
            "supervisor_revision": 3,
            "recovery_intent_recorded": True,
            "worker_execution_replayed": False,
            "independent_target_effect_verified": False,
        }
        with pytest.raises(MCPActionDenied):
            await store.request_recovery(**recovery_args)
        assert (
            await store.record(
                token,
                _observation(
                    observer_key,
                    token,
                    "reaped",
                    epoch=epoch,
                    prior=3,
                    container=CONTAINER,
                    now=now,
                ),
                **kwargs,
            )
        )["state"] == "reaped"
        with pytest.raises(MCPActionDenied):
            await store.record(
                token,
                _observation(
                    observer_key,
                    token,
                    "running",
                    epoch=epoch,
                    prior=4,
                    container=CONTAINER,
                    now=now,
                ),
                **kwargs,
            )
        async with engine.connect() as db:
            assert (
                await db.execute(
                    text(
                        "SELECT state,revision,epoch FROM native_mcp_worker_supervisions WHERE grant_id=:grant"
                    ),
                    {"grant": grant["grant_id"]},
                )
            ).one() == ("reaped", 4, epoch)
            assert (
                await db.execute(
                    text(
                        "SELECT count(*) FROM native_mcp_worker_supervision_events WHERE grant_id=:grant"
                    ),
                    {"grant": grant["grant_id"]},
                )
            ).scalar_one() == 4
            assert (
                await db.execute(
                    text(
                        "SELECT count(*) FROM native_mcp_worker_recovery_intents WHERE grant_id=:grant"
                    ),
                    {"grant": grant["grant_id"]},
                )
            ).scalar_one() == 1
            assert (
                await db.execute(
                    text("SELECT status FROM flow_mcp_action_dispatches WHERE action_id=:action"),
                    {"action": action},
                )
            ).scalar_one() == "unknown"
            with pytest.raises(Exception):
                await db.execute(
                    text("DELETE FROM native_mcp_worker_supervision_events WHERE grant_id=:grant"),
                    {"grant": grant["grant_id"]},
                )
            await db.rollback()
            with pytest.raises(Exception):
                await db.execute(
                    text("DELETE FROM native_mcp_worker_recovery_intents WHERE grant_id=:grant"),
                    {"grant": grant["grant_id"]},
                )
            await db.rollback()
    finally:
        if engine is not None:
            await engine.dispose()
        if owned is not None:
            owned.remove(force=True, v=True)
