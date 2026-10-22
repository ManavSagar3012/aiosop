"""Opt-in actual PostgreSQL 0029 grant lifecycle plus mounted FastAPI transport.

This test provisions ONLY a newly owned loopback PostgreSQL Docker container.
It seeds the original 0027 UNKNOWN Action and replaces ONLY its upstream
Flow/Task/ROE admission with an explicit synthetic guard. Real 0029 SQL,
Ed25519, FastAPI, transaction, locking and trigger code are not mocked.
It does NOT qualify genuine Task approval, external Go, or target execution.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.api.routers import native_mcp_redemption as api
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    MCPActionDenied,
)
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPExecutionGrantStore,
    _native_manifest_sha256,
)
from ai_osop.memory.session_memory import SessionMemory


ENG = "eng-disposable-native"
FLOW = "flow-disposable-native"
TASK = "task-disposable-native"
STEP = "subtask-disposable-native"
OWNER = "owner-disposable-native"
AUTH = "auth-disposable-native"
SHA = "a" * 64
SERVICE_SECRET = "separate-disposable-native-service-secret"
BINDING = {
    "engagement_id": ENG,
    "flow_id": FLOW,
    "revision": 3,
    "version": 1,
    "authorization_id": AUTH,
    "authorization_sha256": SHA,
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


async def _seed_0027(db, action: str, request: str) -> None:
    """Synthetic original committed UNKNOWN record; never dispatch a tool."""
    params = {
        "action_id": action,
        "engagement_id": ENG,
        "flow_id": FLOW,
        "task_id": TASK,
        "subtask_id": STEP,
        "owner_id": OWNER,
        "flow_revision": 3,
        "authorization_id": AUTH,
        "authorization_version": 1,
        "authorization_sha256": SHA,
        "approval_id": "apr-disposable-native",
        "lease_id": "lease-disposable-native",
        "lease_owner_id": "worker-disposable-native",
        "server_id": "recon-mcp",
        "tool_name": "authority_status",
        "side_effect_class": "READ_ONLY",
        "declaration_sha256": _native_manifest_sha256("recon-mcp"),
        "parameters_sha256": hashlib.sha256(b"{}").hexdigest(),
        "intent_sha256": "d" * 64,
        "request_id": request,
        "reservation_token_sha256": "0" * 64,
        "status": "unknown",
        "revision": 3,
        "cancel_requested": False,
    }
    names = list(params)
    await db.execute(
        text(
            "INSERT INTO flow_mcp_action_dispatches ("
            + ",".join(names)
            + ",safe_parameters) VALUES ("
            + ",".join(":" + name for name in names)
            + ",CAST('{}' AS JSON))"
        ),
        params,
    )
    await db.execute(
        text(
            "INSERT INTO flow_mcp_action_dispatch_events "
            "(id,action_id,engagement_id,flow_id,task_id,revision,"
            "kind,status,intent_sha256) VALUES "
            "(:id,:action,:eng,:flow,:task,3,'dispatch_attempted','unknown',:intent)"
        ),
        {
            "id": "evt-" + uuid.uuid4().hex,
            "action": action,
            "eng": ENG,
            "flow": FLOW,
            "task": TASK,
            "intent": params["intent_sha256"],
        },
    )


@pytest.mark.asyncio
async def test_disposable_0029_real_pg_one_use_fastapi_and_rollback(monkeypatch):
    if os.getenv("OSOP_DISPOSABLE_NATIVE_MCP_0029_PG") != "1":
        pytest.skip("Explicit own disposable PostgreSQL 0029 opt-in required")

    import docker
    from alembic import command
    from alembic.config import Config
    from ai_osop.api.main import app

    docker_client = docker.from_env()
    docker_client.images.get("pgvector/pgvector:pg16")  # Cached only. No pull.
    suffix = uuid.uuid4().hex[:12]
    container_name = "osop-native-0029-disposable-" + suffix
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
                "POSTGRES_PASSWORD": "native-0029-disposable-only",
                "POSTGRES_DB": "native_0029_disposable",
            },
            ports={"5432/tcp": ("127.0.0.1", None)},
            volumes={},
            labels={"osop.disposable.qualification": "native-0029"},
        )
        owned.reload()
        binding = owned.attrs["NetworkSettings"]["Ports"]["5432/tcp"]
        assert len(binding) == 1 and binding[0]["HostIp"] == "127.0.0.1"
        port = int(binding[0]["HostPort"])
        assert 1024 <= port <= 65535 and port not in (5432, 5433)
        url = (
            "postgresql+asyncpg://postgres:native-0029-disposable-only"
            f"@127.0.0.1:{port}/native_0029_disposable"
        )
        engine = create_async_engine(url, pool_size=5, max_overflow=0)
        for _ in range(60):
            try:
                async with engine.connect() as conn:
                    assert (await conn.execute(text("SELECT 1"))).scalar_one() == 1
                break
            except Exception:
                await asyncio.sleep(0.25)
        else:
            pytest.fail("Own isolated native 0029 PostgreSQL did not initialize")

        project = Path(__file__).resolve().parents[2]

        def upgrade() -> None:
            config = Config(str(project / "alembic.ini"))
            config.set_main_option("script_location", str(project / "migrations"))
            config.set_main_option("sqlalchemy.url", url)
            command.upgrade(config, "0029")

        await asyncio.to_thread(upgrade)

        memory = SessionMemory()
        memory._pg_engine = engine
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        actions = FlowMCPActionStore(memory, MCPRegistry())
        store = NativeMCPExecutionGrantStore(actions)

        # The ONLY simulated part is current signed Task/ROE/lease approval.
        # We still execute original committed 0027 status/event SQL and same
        # tenant/Flow/actor assertions, and all real 0029 storage functions.
        current = {"approved": True}

        async def synthetic_source(self, db, binding, actor, action_id):
            if not current["approved"]:
                raise MCPActionDenied(409, "Synthetic Task/ROE revoked")
            original = await self._original(db, action_id)
            self.actions._same(original, binding, actor)
            return original

        monkeypatch.setattr(NativeMCPExecutionGrantStore, "_source", synthetic_source)
        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        kid = "native-test-issuer"
        monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID", kid)
        monkeypatch.setenv(
            "OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON",
            json.dumps({kid: base64.b64encode(seed).decode("ascii")}),
        )
        monkeypatch.setenv(
            "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
            json.dumps({kid: _b64url(public)}),
        )
        monkeypatch.setenv(
            "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
            json.dumps({"recon-mcp": SERVICE_SECRET}),
        )
        monkeypatch.setitem(
            api.state,
            "orchestrator",
            SimpleNamespace(session_memory=memory, mcp_registry=actions.registry),
        )
        a, b = "action-" + "b" * 32, "action-" + "c" * 32
        ra, rb = "req-" + "d" * 48, "req-" + "e" * 48
        async with engine.begin() as db:
            await db.execute(
                text("INSERT INTO session_states (session_id) VALUES (:id)"),
                {"id": ENG},
            )
            await db.execute(
                text(
                    "INSERT INTO execution_flows (id,engagement_id,objective,status,"
                    "revision,created_at,updated_at) VALUES "
                    "(:id,:eng,'Synthetic local metadata','running',3,now(),now())"
                ),
                {"id": FLOW, "eng": ENG},
            )
            await db.execute(
                text("INSERT INTO tasks (id,engagement_id,flow_id) VALUES (:id,:eng,:flow)"),
                {"id": TASK, "eng": ENG, "flow": FLOW},
            )
            await db.execute(
                text(
                    "INSERT INTO execution_subtasks (id,engagement_id,flow_id,task_id,"
                    "title,description,task_type,agent_type,approval_required,"
                    '"order",dependencies,status,refinement_count,created_at,updated_at) '
                    "VALUES (:id,:eng,:flow,:task,'Synthetic','No execution',"
                    "'synthetic','synthetic',true,1,CAST('[]' AS JSON),'dispatched',0,"
                    "now(),now())"
                ),
                {"id": STEP, "eng": ENG, "flow": FLOW, "task": TASK},
            )
            await _seed_0027(db, a, ra)
            await _seed_0027(db, b, rb)

        first = await store.issue(BINDING, OWNER, a, ra)
        second = await store.issue(BINDING, OWNER, b, rb)
        headers = {
            "Authorization": "Bearer " + SERVICE_SECRET,
            "X-OSOP-Native-Server-ID": "recon-mcp",
        }
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            # Two actual independent async PostgreSQL sessions race same
            # signed grant. Exactly ONE may receive a durable HTTP200.
            competing = await asyncio.gather(
                client.post("/native-grants/redeem", json=first["token"], headers=headers),
                client.post("/native-grants/redeem", json=first["token"], headers=headers),
            )
            assert sorted(response.status_code for response in competing) == [200, 409]
            cert = next(response.json() for response in competing if response.status_code == 200)
            assert set(cert) == {"grant_id", "request_id", "claim_sha256", "durably_redeemed"}
            assert cert["grant_id"] == first["grant_id"]
            assert cert["request_id"] == ra
            assert cert["durably_redeemed"] is True
            replay = await client.post(
                "/native-grants/redeem", json=first["token"], headers=headers
            )
            assert replay.status_code == 409

            # Fail after real SQL UPDATE but before real event INSERT; actual
            # PostgreSQL transaction must rollback all changes.
            original_event = NativeMCPExecutionGrantStore._event

            async def fail_redeemed_event(db, row, kind):
                if kind == "redeemed":
                    raise RuntimeError("Synthetic crash after update before event")
                return await original_event(db, row, kind)

            monkeypatch.setattr(
                NativeMCPExecutionGrantStore, "_event", staticmethod(fail_redeemed_event)
            )
            crash = await client.post(
                "/native-grants/redeem", json=second["token"], headers=headers
            )
            assert crash.status_code == 409
            async with engine.connect() as db:
                unchanged = (
                    await db.execute(
                        text(
                            "SELECT status,revision FROM native_mcp_execution_grants "
                            "WHERE grant_id=:id"
                        ),
                        {"id": second["grant_id"]},
                    )
                ).one()
                assert tuple(unchanged) == ("issued", 1)
            monkeypatch.setattr(
                NativeMCPExecutionGrantStore, "_event", staticmethod(original_event)
            )
            current["approved"] = False
            refused = await client.post(
                "/native-grants/redeem", json=second["token"], headers=headers
            )
            assert refused.status_code == 409
            current["approved"] = True  # Only synthetic test source toggles.
            recovered = await client.post(
                "/native-grants/redeem", json=second["token"], headers=headers
            )
            assert recovered.status_code == 200

        async with engine.connect() as db:
            assert (
                await db.execute(
                    text(
                        "SELECT count(*) FROM native_mcp_execution_grants "
                        "WHERE status='redeemed' AND revision=2"
                    )
                )
            ).scalar_one() == 2
            assert (
                await db.execute(
                    text(
                        "SELECT count(*) FROM native_mcp_execution_grant_events "
                        "WHERE kind='redeemed'"
                    )
                )
            ).scalar_one() == 2
            assert (
                await db.execute(
                    text("SELECT status FROM flow_mcp_action_dispatches WHERE action_id=:id"),
                    {"id": a},
                )
            ).scalar_one() == "unknown"
            with pytest.raises(Exception):
                await db.execute(
                    text("DELETE FROM native_mcp_execution_grant_events WHERE grant_id=:id"),
                    {"id": first["grant_id"]},
                )
            await db.rollback()
    finally:
        if engine is not None:
            await engine.dispose()
        if owned is not None:
            # Remove ONLY the uniquely named container this test created.
            owned.remove(force=True, v=True)
