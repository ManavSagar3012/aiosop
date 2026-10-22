"""Opt-in PostgreSQL 16 qualification of the real signed 0027 -> 0029 stores.

This test creates and deletes ONLY its own random, loopback-bound PG container.
The ephemeral aiohttp catalog exercises *actual* MCPRegistry HTTP initialization,
but is deliberately NOT a native Go MCP provider or an execution endpoint.
No target, tool handler, application DB, paid provider or scanner is contacted.

Enable only by explicitly setting OSOP_DISPOSABLE_NATIVE_0029_PG=1. A locally
cached pgvector/pgvector:pg16 image is mandatory; no image pulls are performed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.native_mcp_grant_signing import verify_grant
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore, MCPActionDenied
from ai_osop.memory.native_mcp_execution_grants import (
    _NATIVE_BUILTIN,
    NativeMCPExecutionGrantStore,
    _native_manifest_sha256,
)
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.safety.approval_binding import pinned_evidence
from tests.test_authorization_store import make_signed_session

_OPT_IN = "OSOP_DISPOSABLE_NATIVE_0029_PG"
_IMAGE = "pgvector/pgvector:pg16"
_SERVER = "recon-mcp"
_OWNER = "operator-native-qualification"
_REVIEWER = "operator-independent-reviewer"
_SECRET = "independent-native-service-qualification-secret"
_KID = "qual-native-0029"
_PARAMETERS_SHA = hashlib.sha256(b"{}").hexdigest()


def _migrate(connection: Any) -> None:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    # The original signed 0027/0029 tests remain valid when subsequent
    # additive source-delivery migrations are installed. The disposable
    # qualification must follow the CURRENT production Alembic head.
    command.upgrade(config, "head")


@pytest.fixture(scope="module")
async def disposable_native_pg():
    if os.environ.get(_OPT_IN) != "1":
        pytest.skip(f"Set {_OPT_IN}=1 to create a new isolated PostgreSQL container")

    import docker

    client = docker.from_env()
    client.images.get(_IMAGE)  # No pull; fail if locally cached image is absent.
    suffix = uuid.uuid4().hex[:16]
    name = "osop-disposable-native-0029-" + suffix
    database = "native_0029_" + suffix
    assert not client.containers.list(all=True, filters={"name": name})
    owned = None
    engine = None
    try:
        owned = client.containers.run(
            _IMAGE,
            detach=True,
            remove=False,
            name=name,
            environment={
                "POSTGRES_USER": "postgres",
                "POSTGRES_PASSWORD": "native-disposable-only",
                "POSTGRES_DB": database,
            },
            ports={"5432/tcp": ("127.0.0.1", None)},
            volumes={},
            labels={"osop.disposable.qualification": "native-0029"},
        )
        owned.reload()
        ports = owned.attrs["NetworkSettings"]["Ports"]["5432/tcp"]
        assert len(ports) == 1 and ports[0]["HostIp"] == "127.0.0.1"
        port = int(ports[0]["HostPort"])
        assert 1024 <= port <= 65535 and port not in {5432, 5433}
        dsn = "postgresql+asyncpg://postgres:native-disposable-only" f"@127.0.0.1:{port}/{database}"
        engine = create_async_engine(dsn, pool_size=8, max_overflow=0)
        for attempt in range(70):
            try:
                async with engine.connect() as conn:
                    assert (await conn.execute(text("SELECT 1"))).scalar_one() == 1
                break
            except Exception:
                if attempt == 69:
                    pytest.fail("Newly allocated loopback PostgreSQL is unavailable")
                await asyncio.sleep(0.2)
        async with engine.begin() as conn:
            await conn.run_sync(_migrate)
        async with engine.connect() as conn:
            version = (
                await conn.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one()
            # The disposable test must migrate the full CURRENT original
            # working-tree chain, including immutable Browser 0034,
            # SourceMap 0035, and current supervision schema 0040.
            migration_config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
            migration_config.set_main_option(
                "script_location", str(Path(__file__).resolve().parents[2] / "migrations")
            )
            assert version == ScriptDirectory.from_config(migration_config).get_current_head()
            for table, trigger in (
                ("flow_mcp_action_dispatch_events", "trg_flow_mcp_action_events_immutable"),
                ("native_mcp_execution_grant_events", "trg_native_mcp_grant_events_immutable"),
                ("native_mcp_resource_offers", "trg_native_resource_offer_immutable"),
                ("native_mcp_stage_receipts", "trg_native_worker_stage_receipt_immutable"),
                (
                    "native_mcp_worker_supervision_events",
                    "trg_native_worker_supervision_events_immutable",
                ),
                (
                    "native_browser_source_preflights",
                    "trg_native_browser_source_immutable",
                ),
                (
                    "native_sourcemap_source_preflights",
                    "trg_native_sourcemap_source_immutable",
                ),
            ):
                present = (
                    await conn.execute(
                        text(
                            "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(:tbl) "
                            "AND tgname=:trigger AND NOT tgisinternal)"
                        ),
                        {"tbl": table, "trigger": trigger},
                    )
                ).scalar_one()
                assert present is True
        yield engine
    finally:
        if engine is not None:
            await engine.dispose()
        if owned is not None:
            owned.remove(force=True, v=True)  # Strictly our uniquely named container.


@pytest.fixture(scope="module")
async def initialized_catalog():
    """Real HTTP negotiated catalog, NOT Go /mcp/execute or target execution."""

    async def health(_request: web.Request) -> web.Response:
        return web.json_response({"status": "ready", "server_id": _SERVER})

    async def initialize(_request: web.Request) -> web.Response:
        return web.json_response(
            {
                "server_id": _SERVER,
                "version": "1.0.0",
                "status": "ready",
                "capabilities": ["tools"],
                "tools": [{**_NATIVE_BUILTIN, "version": "1.0.0", "required_permissions": []}],
            }
        )

    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_post("/mcp/initialize", initialize)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    assert site._server is not None
    sockets = site._server.sockets
    assert sockets and sockets[0].getsockname()[0] == "127.0.0.1"
    port = sockets[0].getsockname()[1]
    registry = MCPRegistry()
    try:
        await registry.register_server(_SERVER, "127.0.0.1", port)
        response = await registry.initialize_server(
            _SERVER, scope={}, credentials={}, session_id="native-qualification-catalog"
        )
        assert response.status == "ready"
        assert len(response.tools) == 1
        assert response.tools[0].name == "authority_status"
        assert registry._servers[_SERVER]._initialized is True
        assert registry._servers[_SERVER].get_circuit_state() == "closed"
        assert FlowMCPActionStore.declaration_sha256(
            response.tools[0], _SERVER
        ) == _native_manifest_sha256(_SERVER)
        yield registry
    finally:
        for conn in registry._servers.values():
            await conn.close()
        await runner.cleanup()


@dataclass
class QualifiedCase:
    engine: Any
    binding: dict[str, Any]
    original: FlowMCPActionStore
    grants: NativeMCPExecutionGrantStore
    action_id: str
    request_id: str
    task_id: str
    approval_id: str
    lease_id: str


@pytest.fixture
def signing_material(monkeypatch: Any) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID", _KID)
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON",
        json.dumps({_KID: base64.b64encode(private).decode("ascii")}),
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
        json.dumps({_KID: base64.urlsafe_b64encode(public).decode("ascii").rstrip("=")}),
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
        json.dumps({_SERVER: _SECRET}),
    )
    return key


async def _case(
    engine: Any,
    catalog: MCPRegistry,
    monkeypatch: Any,
    key: Ed25519PrivateKey,
    *,
    approved_target: str = "https://authorized.example/",
    dispatch: bool = True,
) -> QualifiedCase:
    suffix = uuid.uuid4().hex[:12]
    engagement = "eng-native-" + suffix
    flow_id = "flow-native-" + suffix
    task_id = "task-native-" + suffix
    parent_task_id = "task-native-parent-" + suffix
    subtask_id = "subtask-native-" + suffix
    action_id = "action-" + uuid.uuid4().hex
    approval_id = "apr-native-" + suffix
    lease_id = "lease-native-" + suffix
    session, verified, _envelope, _signer = make_signed_session(
        monkeypatch,
        session_id=engagement,
        private_key=key,
        owner=_OWNER,
        authorization_id="auth-native-" + suffix,
    )
    session.phase = "reconnaissance"
    memory = SessionMemory()
    memory._pg_engine = engine
    memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
    recorded = await AuthorizationStore(memory).create_authorized_session(session, verified, _OWNER)
    binding = {
        "engagement_id": engagement,
        "flow_id": flow_id,
        "revision": 0,
        "version": recorded["version"],
        "authorization_id": recorded["authorization_id"],
        "authorization_sha256": recorded["policy_sha256"],
    }
    payload = {
        "mcp_flow_revision": 0,
        "_authorization_version": 1,
        "mcp_action_id": action_id,
        "mcp_server_id": _SERVER,
        "mcp_tool_name": "authority_status",
        "mcp_declaration_sha256": _native_manifest_sha256(_SERVER),
        "mcp_parameters_sha256": _PARAMETERS_SHA,
        "mcp_side_effect_class": "READ_ONLY",
        "operator_approved": True,
        "approval_id": approval_id,
        "target": approved_target,
    }
    now = datetime.utcnow()
    async with engine.begin() as db:
        await db.execute(
            text(
                "INSERT INTO execution_flows (id,engagement_id,objective,status,revision,created_at,updated_at) "
                "VALUES (:fid,:eng,'Disposable inert MCP grant only','running',0,:ts,:ts)"
            ),
            {"fid": flow_id, "eng": engagement, "ts": now},
        )
        await db.execute(
            text(
                "INSERT INTO tasks "
                "(id,type,priority,agent_type,payload,dependencies,max_retries,"
                "timeout_seconds,scope_check,approval_required,status,retry_count,"
                "created_at,started_at,engagement_id,assigned_agent_id,flow_id) "
                "VALUES (:parent,'native_plan',5,'workflow',CAST('{}' AS jsonb),"
                "CAST('[]' AS jsonb),0,300,true,false,'running',0,:ts,:ts,:eng,"
                "'worker-native-qualification',:fid)"
            ),
            {"parent": parent_task_id, "ts": now, "eng": engagement, "fid": flow_id},
        )
        await db.execute(
            text(
                "INSERT INTO execution_subtasks "
                "(id,engagement_id,flow_id,task_id,title,description,task_type,agent_type,"
                'approval_required,"order",dependencies,status,refinement_count,execution_task_id,created_at,updated_at) '
                "VALUES (:sid,:eng,:fid,:task,'Native authority check','Inert local qualification',"
                "'native_authority','recon',true,1,CAST('[]' AS jsonb),'running',0,:child,:ts,:ts)"
            ),
            {
                "sid": subtask_id,
                "eng": engagement,
                "fid": flow_id,
                "task": parent_task_id,
                "child": task_id,
                "ts": now,
            },
        )
        await db.execute(
            text(
                "INSERT INTO tasks "
                "(id,type,priority,agent_type,payload,dependencies,max_retries,timeout_seconds,"
                "scope_check,approval_required,status,retry_count,created_at,started_at,"
                "engagement_id,assigned_agent_id,flow_id,subtask_id,parent_task_id) "
                "VALUES (:task,'native_authority',5,'recon',CAST(:payload AS jsonb),"
                "CAST('[]' AS jsonb),0,300,true,true,'running',0,:ts,:ts,:eng,"
                "'worker-native-qualification',:fid,:sid,:parent)"
            ),
            {
                "task": task_id,
                "parent": parent_task_id,
                "payload": json.dumps(payload),
                "ts": now,
                "eng": engagement,
                "fid": flow_id,
                "sid": subtask_id,
            },
        )
        await db.execute(
            text(
                "INSERT INTO approval_requests "
                "(id,task_id,action_type,target,status,operator_id,responded_at,evidence,engagement_id) "
                "VALUES (:approval,:task,'native_authority',:target,'approved',:reviewer,:ts,"
                "CAST(:evidence AS jsonb),:eng)"
            ),
            {
                "approval": approval_id,
                "task": task_id,
                "target": approved_target,
                "reviewer": _REVIEWER,
                "ts": now,
                "eng": engagement,
                "evidence": json.dumps(pinned_evidence([], payload)),
            },
        )
        for principal in (_OWNER, _REVIEWER):
            await db.execute(
                text(
                    "INSERT INTO operator_subject_controls (actor_id,disabled,updated_at,updated_by) "
                    "VALUES (:actor,false,:ts,:reviewer) "
                    "ON CONFLICT (actor_id) DO NOTHING"
                ),
                {"actor": principal, "ts": now, "reviewer": _OWNER},
            )
        await db.execute(
            text(
                "INSERT INTO supervision_execution_leases "
                "(task_id,engagement_id,lease_id,owner_id,state,expires_at) "
                "VALUES (:task,:eng,:lease,'worker-native-qualification','dispatched',:expiry)"
            ),
            {
                "task": task_id,
                "eng": engagement,
                "lease": lease_id,
                "expiry": now + timedelta(minutes=3),
            },
        )

    action = FlowMCPActionStore(memory, catalog)
    if dispatch:
        prepared = await action.prepare(
            binding,
            _OWNER,
            task_id,
            subtask_id,
            _SERVER,
            "authority_status",
            {},
            _PARAMETERS_SHA,
            _native_manifest_sha256(_SERVER),
        )
        assert prepared["status"] == "prepared"
        reserved = await action.reserve(binding, _OWNER, action_id)
        assert reserved["status"] == "reserved"
        assert reserved["admitted_for_dispatch"] is True
        attempted = await action.mark_dispatched(
            binding, _OWNER, action_id, prepared["request_id"], reserved["reservation_token"]
        )
        assert attempted["status"] == "unknown"
        assert attempted["dispatch_attempt_committed"] is True
    else:
        prepared = await action.prepare(
            binding,
            _OWNER,
            task_id,
            subtask_id,
            _SERVER,
            "authority_status",
            {},
            _PARAMETERS_SHA,
            _native_manifest_sha256(_SERVER),
        )
    return QualifiedCase(
        engine=engine,
        binding=binding,
        original=action,
        grants=NativeMCPExecutionGrantStore(action),
        action_id=action_id,
        request_id=prepared["request_id"],
        task_id=task_id,
        approval_id=approval_id,
        lease_id=lease_id,
    )


async def _read_case(case: QualifiedCase, grant_id: str | None = None) -> tuple[Any, Any, Any]:
    async with case.engine.connect() as db:
        action = (
            (
                await db.execute(
                    text(
                        "SELECT status,revision,cancel_requested,reservation_token_sha256 "
                        "FROM flow_mcp_action_dispatches WHERE action_id=:action"
                    ),
                    {"action": case.action_id},
                )
            )
            .mappings()
            .one()
        )
        event = (
            (
                await db.execute(
                    text(
                        "SELECT kind,status,revision FROM flow_mcp_action_dispatch_events "
                        "WHERE action_id=:action ORDER BY revision"
                    ),
                    {"action": case.action_id},
                )
            )
            .mappings()
            .all()
        )
        if grant_id is None:
            return action, event, []
        grants = (
            (
                await db.execute(
                    text(
                        "SELECT status,revision FROM native_mcp_execution_grants WHERE grant_id=:grant"
                    ),
                    {"grant": grant_id},
                )
            )
            .mappings()
            .one()
        )
        grant_events = (
            (
                await db.execute(
                    text(
                        "SELECT kind,status,revision FROM native_mcp_execution_grant_events "
                        "WHERE grant_id=:grant ORDER BY revision"
                    ),
                    {"grant": grant_id},
                )
            )
            .mappings()
            .all()
        )
        return action, event, (grants, grant_events)


def _read_events(records: Any) -> list[tuple[str, str, int]]:
    return [(r["kind"], r["status"], r["revision"]) for r in records]


@pytest.mark.asyncio(scope="module")
async def test_real_signed_0027_unknown_then_0029_issue_redeem_and_replay(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    action, actions, _ = await _read_case(case)
    assert dict(action) == {
        "status": "unknown",
        "revision": 3,
        "cancel_requested": False,
        "reservation_token_sha256": "0" * 64,
    }
    assert _read_events(actions) == [
        ("prepared", "prepared", 1),
        ("reserved", "reserved", 2),
        ("dispatch_attempted", "unknown", 3),
    ]
    issued = await case.grants.issue(case.binding, _OWNER, case.action_id, case.request_id)
    assert issued["status"] == "issued" and issued["revision"] == 1
    assert (
        verify_grant(
            issued["token"],
            public_keys=json.loads(os.environ["OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON"]),
        )
        == issued["token"]["claims"]
    )
    with pytest.raises(MCPActionDenied):
        await case.grants.issue(case.binding, _OWNER, case.action_id, case.request_id)
    action, actions, (grant, records) = await _read_case(case, issued["grant_id"])
    assert grant["status"] == "issued" and grant["revision"] == 1
    assert _read_events(records) == [("issued", "issued", 1)]
    # Independent production store instance; no in-process fake nonce ledger.
    fresh = NativeMCPExecutionGrantStore(
        FlowMCPActionStore(case.original.memory, initialized_catalog)
    )
    accepted = await fresh.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET)
    assert set(accepted) == {"grant_id", "request_id", "claim_sha256", "durably_redeemed"}
    assert accepted["durably_redeemed"] is True
    assert accepted["grant_id"] == issued["grant_id"]
    assert accepted["request_id"] == case.request_id
    assert (
        accepted["claim_sha256"]
        == hashlib.sha256(
            json.dumps(
                issued["token"]["claims"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
        ).hexdigest()
    )
    with pytest.raises(MCPActionDenied):
        await fresh.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET)
    action, actions, (grant, records) = await _read_case(case, issued["grant_id"])
    assert action["status"] == "unknown" and action["revision"] == 3
    assert grant["status"] == "redeemed" and grant["revision"] == 2
    assert _read_events(records) == [("issued", "issued", 1), ("redeemed", "redeemed", 2)]
    assert _read_events(actions)[-1] == ("dispatch_attempted", "unknown", 3)


@pytest.mark.asyncio(scope="module")
async def test_pg_two_independent_redemptions_one_winner(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    issued = await case.grants.issue(
        case.binding, _OWNER, case.action_id, case.request_id, ttl_seconds=60
    )
    results = await asyncio.wait_for(
        asyncio.gather(
            case.grants.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET),
            case.grants.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET),
            return_exceptions=True,
        ),
        timeout=15,
    )
    assert (
        sum(isinstance(value, dict) and value.get("durably_redeemed") is True for value in results)
        == 1
    )
    assert sum(isinstance(value, MCPActionDenied) for value in results) == 1
    _, _, (grant, events) = await _read_case(case, issued["grant_id"])
    assert grant["revision"] == 2 and grant["status"] == "redeemed"
    assert _read_events(events) == [("issued", "issued", 1), ("redeemed", "redeemed", 2)]


@pytest.mark.asyncio(scope="module")
@pytest.mark.parametrize(
    "change",
    ["approval_revoked", "reviewer_disabled", "lease_released", "lease_expired", "scope_changed"],
)
async def test_pg_rechecks_approval_lease_and_signed_scope_after_issue(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
    change: str,
) -> None:
    case = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    issued = await case.grants.issue(case.binding, _OWNER, case.action_id, case.request_id)
    async with disposable_native_pg.begin() as db:
        if change == "approval_revoked":
            await db.execute(
                text("UPDATE approval_requests SET status='revoked' WHERE id=:approval"),
                {"approval": case.approval_id},
            )
        elif change == "reviewer_disabled":
            await db.execute(
                text("UPDATE operator_subject_controls SET disabled=true WHERE actor_id=:reviewer"),
                {"reviewer": _REVIEWER},
            )
        elif change in ("lease_released", "lease_expired"):
            if change == "lease_released":
                await db.execute(
                    text(
                        "UPDATE supervision_execution_leases SET state='released' WHERE task_id=:task"
                    ),
                    {"task": case.task_id},
                )
            else:
                await db.execute(
                    text(
                        "UPDATE supervision_execution_leases SET expires_at=:expiry WHERE task_id=:task"
                    ),
                    {"task": case.task_id, "expiry": datetime.utcnow() - timedelta(seconds=1)},
                )
        else:
            await db.execute(
                text("UPDATE session_states SET scope=CAST(:scope AS jsonb) WHERE session_id=:eng"),
                {
                    "scope": json.dumps(
                        {
                            "engagement_id": case.binding["engagement_id"],
                            "domains": ["tampered.invalid"],
                        }
                    ),
                    "eng": case.binding["engagement_id"],
                },
            )
    with pytest.raises(MCPActionDenied):
        await case.grants.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET)
    _, _, (grant, events) = await _read_case(case, issued["grant_id"])
    assert grant["status"] == "issued" and grant["revision"] == 1
    assert _read_events(events) == [("issued", "issued", 1)]
    if change == "reviewer_disabled":
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text(
                    "UPDATE operator_subject_controls SET disabled=false WHERE actor_id=:reviewer"
                ),
                {"reviewer": _REVIEWER},
            )


@pytest.mark.asyncio(scope="module")
async def test_pg_revoked_grant_and_wrong_native_principal_cannot_redeem(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    issued = await case.grants.issue(case.binding, _OWNER, case.action_id, case.request_id)
    with pytest.raises(MCPActionDenied):
        await case.grants.redeem(
            issued["token"], server_id=_SERVER, server_secret="wrong-service-secret-proof"
        )
    with pytest.raises(MCPActionDenied):
        await case.grants.issue(
            {**case.binding, "engagement_id": "eng-unowned"},
            _OWNER,
            case.action_id,
            case.request_id,
        )
    closed = await case.grants.revoke(case.binding, _OWNER, issued["grant_id"])
    assert closed["status"] == "revoked" and closed["changed"] is True
    with pytest.raises(MCPActionDenied):
        await case.grants.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET)
    _, _, (grant, events) = await _read_case(case, issued["grant_id"])
    assert grant["status"] == "revoked" and grant["revision"] == 2
    assert _read_events(events) == [("issued", "issued", 1), ("revoked", "revoked", 2)]


@pytest.mark.asyncio(scope="module")
async def test_pg_denies_unapproved_resource_and_denies_grant_before_0027_unknown(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    before = await _case(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material, dispatch=False
    )
    with pytest.raises(MCPActionDenied):
        await before.grants.issue(before.binding, _OWNER, before.action_id, before.request_id)
    action, events, _ = await _read_case(before)
    assert action["status"] == "prepared" and _read_events(events) == [("prepared", "prepared", 1)]
    after = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    with pytest.raises(MCPActionDenied):
        await after.grants.issue(
            after.binding, _OWNER, after.action_id, after.request_id, resource_sha256="a" * 64
        )
    async with disposable_native_pg.connect() as db:
        assert (
            await db.execute(
                text("SELECT count(*) FROM native_mcp_execution_grants WHERE action_id=:action"),
                {"action": after.action_id},
            )
        ).scalar_one() == 0
    action, events, _ = await _read_case(after)
    assert action["status"] == "unknown"
    assert _read_events(events)[-1] == ("dispatch_attempted", "unknown", 3)


@pytest.mark.asyncio(scope="module")
async def test_pg_immutable_grant_event_trigger_rejects_update_and_delete(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    issued = await case.grants.issue(case.binding, _OWNER, case.action_id, case.request_id)
    for operation in (
        "UPDATE native_mcp_execution_grant_events SET kind='unknown' WHERE grant_id=:grant",
        "DELETE FROM native_mcp_execution_grant_events WHERE grant_id=:grant",
    ):
        async with disposable_native_pg.connect() as db:
            with pytest.raises(Exception):
                await db.execute(text(operation), {"grant": issued["grant_id"]})
            await db.rollback()
    _, _, (grant, events) = await _read_case(case, issued["grant_id"])
    assert grant["status"] == "issued"
    assert _read_events(events) == [("issued", "issued", 1)]


@pytest.mark.asyncio(scope="module")
async def test_pg_post_update_pre_event_failure_rolls_back_redemption_atomically(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    """A real PG INSERT fault after successful CAS must rollback both writes."""
    case = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    issued = await case.grants.issue(case.binding, _OWNER, case.action_id, case.request_id)
    try:
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text(
                    """
                CREATE FUNCTION native_qual_0029_fail_redeem_event() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.kind = 'redeemed' THEN
                        RAISE EXCEPTION 'Disposable qualification post-CAS failure';
                    END IF;
                    RETURN NEW;
                END;
                $$
            """
                )
            )
            await db.execute(
                text(
                    """
                CREATE TRIGGER trg_native_qual_0029_fail_redeem_event
                BEFORE INSERT ON native_mcp_execution_grant_events
                FOR EACH ROW EXECUTE FUNCTION native_qual_0029_fail_redeem_event()
            """
                )
            )
        with pytest.raises(MCPActionDenied):
            await case.grants.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET)
        _, _, (grant, events) = await _read_case(case, issued["grant_id"])
        assert grant["status"] == "issued" and grant["revision"] == 1
        assert _read_events(events) == [("issued", "issued", 1)]
    finally:
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text(
                    "DROP TRIGGER IF EXISTS trg_native_qual_0029_fail_redeem_event "
                    "ON native_mcp_execution_grant_events"
                )
            )
            await db.execute(text("DROP FUNCTION IF EXISTS native_qual_0029_fail_redeem_event()"))
    # A rollback cannot poison the one-shot capability before any PG commit.
    receipt = await case.grants.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET)
    assert receipt["durably_redeemed"] is True
    _, _, (grant, events) = await _read_case(case, issued["grant_id"])
    assert grant["status"] == "redeemed" and grant["revision"] == 2
    assert _read_events(events) == [("issued", "issued", 1), ("redeemed", "redeemed", 2)]


@pytest.mark.asyncio(scope="module")
async def test_pg_crash_gap_0027_committed_unknown_never_reopens_reservation(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    """No target call: emulate restart after committed 0027 and before 0029."""
    case = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    # The initial request has committed UNKNOWN. No grant has been issued.
    async with disposable_native_pg.connect() as db:
        assert (
            await db.execute(
                text("SELECT count(*) FROM native_mcp_execution_grants WHERE action_id=:action"),
                {"action": case.action_id},
            )
        ).scalar_one() == 0
    restarted = FlowMCPActionStore(case.original.memory, initialized_catalog)
    repeat = await restarted.reserve(case.binding, _OWNER, case.action_id)
    assert repeat["status"] == "unknown"
    assert repeat["admitted_for_dispatch"] is False
    with pytest.raises(MCPActionDenied):
        await restarted.mark_dispatched(
            case.binding, _OWNER, case.action_id, case.request_id, "res-" + "a" * 64
        )
    action, events, _ = await _read_case(case)
    assert action["status"] == "unknown" and action["revision"] == 3
    assert _read_events(events)[-1] == ("dispatch_attempted", "unknown", 3)


@pytest.mark.asyncio(scope="module")
async def test_pg_cancel_original_unknown_fences_future_grant_redemption(
    disposable_native_pg: Any,
    initialized_catalog: MCPRegistry,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case = await _case(disposable_native_pg, initialized_catalog, monkeypatch, signing_material)
    issued = await case.grants.issue(case.binding, _OWNER, case.action_id, case.request_id)
    closed = await case.original.cancel(case.binding, _OWNER, case.action_id)
    assert closed["status"] == "unknown" and closed["cancel_requested"] is True
    with pytest.raises(MCPActionDenied):
        await case.grants.redeem(issued["token"], server_id=_SERVER, server_secret=_SECRET)
    original, events, (grant, grant_events) = await _read_case(case, issued["grant_id"])
    assert original["status"] == "unknown" and original["cancel_requested"] is True
    assert _read_events(events)[-1][0] == "cancel_requested_unknown"
    assert grant["status"] == "issued"  # Future redemption denied; no false completion.
    assert _read_events(grant_events) == [("issued", "issued", 1)]
