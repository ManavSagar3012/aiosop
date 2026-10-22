"""Opt-in 0035 SourceMap source authority over isolated REAL PostgreSQL.

Uses the existing disposable pgvector/pg16 fixture (CURRENT Alembic 0035),
original signed ROE/0027 Flow Task Action, immutable 0013 BYTEA and 0015 senior
review, and the actual mounted central FastAPI endpoint and Ed25519 verifier.
The native server's declaration and proof verifier are exercised in process;
this does NOT prove native tool execution, TLS transport, or real target access.
With OSOP_DISPOSABLE_NATIVE_0029_PG unset, no container/DB is contacted.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import stat
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from ai_osop.api.routers import native_sourcemap_source_authority as source_api
from ai_osop.api.routers import native_sourcemap_status_authority as status_api
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry, MCPToolDefinition
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.flow_resource_exports import make_manifest
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.safety.approval_binding import pinned_evidence
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    disposable_native_pg,
)
from tests.test_authorization_store import make_signed_session


OWNER = "operator-sourcemap-original-owner"
APPROVER = "operator-sourcemap-independent-approval"
SENIOR = "operator-sourcemap-independent-senior"
ISSUER_KID = "sourcemap-real-pg-issuer"
RECEIPT_KID = "sourcemap-real-pg-native-receipt"
SERVICE_TOKEN = "independent-central-sourcemap-real-pg-service"
NATIVE_TOKEN = "separate-native-sourcemap-real-pg-principal"
TOOL = "inspect_local_original_sourcemap"
SERVER = "source-map-mcp"
PATH = "/native-sourcemap/source-preflight"
ORIGINAL = (
    b'{"version":3,"file":"bundle.js","sources":["src/inert.js"],'
    b'"names":[],"mappings":"AAAA","sourcesContent":["const offline=1;"]}'
)
SHA = hashlib.sha256(ORIGINAL).hexdigest()


def _native_module() -> Any:
    filename = Path(__file__).resolve().parents[2] / "mcp-servers/python/source_map_mcp.py"
    spec = importlib.util.spec_from_file_location("_sourcemap_real_pg_20261020", filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _configure_independent_signers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Ed25519PrivateKey, bytes]:
    central = Ed25519PrivateKey.generate()
    central_private = central.private_bytes_raw()
    central_public = central.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    native = Ed25519PrivateKey.generate()
    native_private = native.private_bytes_raw()
    native_public = native.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert central_public != native_public

    # Native issuer/public-root settings are independent from the signed ROE.
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_SIGNING_KID", ISSUER_KID)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_SIGNING_PRIVATE_KEY_B64",
        base64.b64encode(central_private).decode("ascii"),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({ISSUER_KID: base64.b64encode(central_public).decode("ascii")}),
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", NATIVE_TOKEN)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_URL",
        "https://sourcemap.authority.invalid" + PATH,
    )
    root = tmp_path / "independent-central-certificates"
    root.mkdir(mode=0o700)
    ca = root / "central-root.pem"
    ca.write_text(
        "-----BEGIN CERTIFICATE-----\n" + "A" * 128 + "\n-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_CA_BUNDLE", str(ca))
    original_mount = tmp_path / "originals"
    original_mount.mkdir(mode=0o700)
    one_shot = tmp_path / "one-shot"
    one_shot.mkdir(mode=0o700)
    monkeypatch.setenv("OSOP_SOURCEMAP_ORIGINAL_READONLY_ROOT", str(original_mount))
    monkeypatch.setenv("OSOP_SOURCEMAP_ONE_SHOT_ROOT", str(one_shot))
    native_identity = tmp_path / "native-identity"
    native_identity.mkdir(mode=0o700)
    key_file = native_identity / "native-ed25519.key"
    key_file.write_bytes(native_private)
    key_file.chmod(0o600 if os.name == "posix" else stat.S_IREAD)
    monkeypatch.setenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KID", RECEIPT_KID)
    monkeypatch.setenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({SERVER: {RECEIPT_KID: base64.b64encode(native_public).decode("ascii")}}),
    )
    return central, central_public


async def _declared_native_registry(native: Any) -> MCPRegistry:
    # Real native ASGI declaration, typed by the central MCP protocol, without
    # claiming to have negotiated an actual native network transport.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=native.app), base_url="http://native.local"
    ) as client:
        response = await client.post("/mcp/initialize")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "ready", response.text
    definitions = response.json()["tools"]
    assert len(definitions) == 1
    definition = MCPToolDefinition.model_validate(definitions[0])
    assert definition.name == TOOL
    assert definition.requires_approval is True
    assert definition.scope_check is True
    registry = MCPRegistry()
    connection = MCPConnection(server_id=SERVER, host="127.0.0.1", port=8096)
    connection._initialized = True
    connection._tools = {TOOL: definition}
    registry._servers[SERVER] = connection
    return registry


async def _signed_original_case(
    engine: Any, monkeypatch: pytest.MonkeyPatch, registry: MCPRegistry
) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:12]
    engagement = "eng-source-" + suffix
    flow = "flow-source-" + suffix
    parent = "task-source-parent-" + suffix
    task = "task-source-" + suffix
    subtask = "subtask-source-" + suffix
    action = "action-" + uuid.uuid4().hex
    approval = "apr-source-" + suffix
    lease = "lease-source-" + suffix
    artifact = "artifact-" + uuid.uuid4().hex
    session, verified, _, _ = make_signed_session(
        monkeypatch,
        session_id=engagement,
        private_key=Ed25519PrivateKey.generate(),
        owner=OWNER,
        authorization_id="auth-source-" + suffix,
        roe_override={"allow_read_only": True, "allow_source_map_inspection": True},
    )
    session.phase = "reconnaissance"
    memory = SessionMemory()
    memory._pg_engine = engine
    memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
    recorded = await AuthorizationStore(memory).create_authorized_session(session, verified, OWNER)
    binding = {
        "engagement_id": engagement,
        "flow_id": flow,
        "revision": 0,
        "version": recorded["version"],
        "authorization_id": recorded["authorization_id"],
        "authorization_sha256": recorded["policy_sha256"],
    }
    metadata = {
        "id": artifact,
        "flow_id": flow,
        "name": "original-sourcemap.json",
        "size_bytes": len(ORIGINAL),
        "sha256": SHA,
        "flow_revision": binding["revision"],
        "authorization_version": binding["version"],
    }
    manifest = make_manifest(flow, binding["revision"], binding["version"], [(metadata, ORIGINAL)])
    params = {"artifact_sha256": SHA}
    parameters_sha = FlowMCPActionStore.parameters_sha256(params)
    declaration_sha = FlowMCPActionStore.declaration_sha256(
        registry._servers[SERVER]._tools[TOOL], SERVER
    )
    payload = {
        "mcp_flow_revision": binding["revision"],
        "_authorization_version": binding["version"],
        "mcp_action_id": action,
        "mcp_server_id": SERVER,
        "mcp_tool_name": TOOL,
        "mcp_declaration_sha256": declaration_sha,
        "mcp_parameters_sha256": parameters_sha,
        "mcp_side_effect_class": "READ_ONLY",
        "operator_approved": True,
        "approval_id": approval,
        "resource_artifact_id": artifact,
        "resource_artifact_sha256": SHA,
        "resource_authorization_sha256": binding["authorization_sha256"],
        "resource_command_sha256": parameters_sha,
        "resource_manifest_sha256": manifest["manifest_sha256"],
    }
    now = datetime.utcnow()
    async with engine.begin() as db:
        await db.execute(
            text(
                "INSERT INTO execution_flows (id,engagement_id,objective,status,revision,created_at,updated_at) "
                "VALUES (:flow,:eng,'Offline original SourceMap qualification','running',0,:now,:now)"
            ),
            {"flow": flow, "eng": engagement, "now": now},
        )
        await db.execute(
            text(
                "INSERT INTO flow_artifacts "
                "(id,flow_id,engagement_id,owner_id,name,size_bytes,sha256,"
                "authorization_version,authorization_sha256,flow_revision,content) "
                "VALUES (:art,:flow,:eng,:owner,:name,:size,:sha,:version,:auth,0,:body)"
            ),
            {
                "art": artifact,
                "flow": flow,
                "eng": engagement,
                "owner": OWNER,
                "name": metadata["name"],
                "size": len(ORIGINAL),
                "sha": SHA,
                "version": binding["version"],
                "auth": binding["authorization_sha256"],
                "body": ORIGINAL,
            },
        )
        for reviewer in (OWNER, APPROVER, SENIOR):
            await db.execute(
                text(
                    "INSERT INTO operator_subject_controls (actor_id,disabled,updated_at,updated_by) "
                    "VALUES (:actor,false,:now,:owner) ON CONFLICT (actor_id) DO NOTHING"
                ),
                {"actor": reviewer, "now": now, "owner": OWNER},
            )
        await db.execute(
            text(
                "INSERT INTO flow_artifact_reviews (id,artifact_id,flow_id,engagement_id,"
                "uploader_sub,reviewer_sub,reviewer_role,decision,reason,artifact_sha256,"
                "flow_revision,authorization_id,authorization_version,authorization_sha256) "
                "VALUES (:id,:art,:flow,:eng,:owner,:senior,'senior_operator','approve',"
                "'Reviewed exact offline original SourceMap bytes',:sha,0,:auth_id,:version,:auth)"
            ),
            {
                "id": "review-" + uuid.uuid4().hex,
                "art": artifact,
                "flow": flow,
                "eng": engagement,
                "owner": OWNER,
                "senior": SENIOR,
                "sha": SHA,
                "auth_id": binding["authorization_id"],
                "version": binding["version"],
                "auth": binding["authorization_sha256"],
            },
        )
        await db.execute(
            text(
                "INSERT INTO tasks (id,type,priority,agent_type,payload,dependencies,max_retries,"
                "timeout_seconds,scope_check,approval_required,status,retry_count,created_at,"
                "started_at,engagement_id,assigned_agent_id,flow_id) "
                "VALUES (:id,'source_plan',5,'workflow',CAST('{}' AS jsonb),"
                "CAST('[]' AS jsonb),0,300,true,false,'running',0,:now,:now,:eng,"
                "'worker-source-qualification',:flow)"
            ),
            {"id": parent, "now": now, "eng": engagement, "flow": flow},
        )
        await db.execute(
            text(
                "INSERT INTO execution_subtasks (id,engagement_id,flow_id,task_id,title,"
                'description,task_type,agent_type,approval_required,"order",dependencies,'
                "status,refinement_count,execution_task_id,created_at,updated_at) "
                "VALUES (:step,:eng,:flow,:parent,'Original SourceMap inspection',"
                "'No network/target use','source_original','recon',true,1,CAST('[]' AS jsonb),"
                "'running',0,:child,:now,:now)"
            ),
            {
                "step": subtask,
                "eng": engagement,
                "flow": flow,
                "parent": parent,
                "child": task,
                "now": now,
            },
        )
        await db.execute(
            text(
                "INSERT INTO tasks (id,type,priority,agent_type,payload,dependencies,"
                "max_retries,timeout_seconds,scope_check,approval_required,status,retry_count,"
                "created_at,started_at,engagement_id,assigned_agent_id,flow_id,subtask_id,parent_task_id) "
                "VALUES (:id,'source_original',5,'recon',CAST(:payload AS jsonb),"
                "CAST('[]' AS jsonb),0,300,true,true,'running',0,:now,:now,:eng,"
                "'worker-source-qualification',:flow,:step,:parent)"
            ),
            {
                "id": task,
                "payload": json.dumps(payload),
                "now": now,
                "eng": engagement,
                "flow": flow,
                "step": subtask,
                "parent": parent,
            },
        )
        await db.execute(
            text(
                "INSERT INTO approval_requests (id,task_id,action_type,target,status,operator_id,"
                "responded_at,evidence,engagement_id) VALUES (:id,:task,'source_original',"
                "'unknown','approved',:approver,:now,CAST(:evidence AS jsonb),:eng)"
            ),
            {
                "id": approval,
                "task": task,
                "approver": APPROVER,
                "now": now,
                "evidence": json.dumps(pinned_evidence([], payload)),
                "eng": engagement,
            },
        )
        await db.execute(
            text(
                "INSERT INTO supervision_execution_leases "
                "(task_id,engagement_id,lease_id,owner_id,state,expires_at) "
                "VALUES (:task,:eng,:lease,'worker-source-qualification','dispatched',:expiry)"
            ),
            {"task": task, "eng": engagement, "lease": lease, "expiry": now + timedelta(minutes=3)},
        )
    original = FlowMCPActionStore(memory, registry)
    prepared = await original.prepare(
        binding, OWNER, task, subtask, SERVER, TOOL, params, parameters_sha, declaration_sha
    )
    assert prepared["status"] == "prepared"
    reserved = await original.reserve(binding, OWNER, action)
    assert reserved["status"] == "reserved" and reserved["admitted_for_dispatch"] is True
    attempted = await original.mark_dispatched(
        binding, OWNER, action, prepared["request_id"], reserved["reservation_token"]
    )
    assert attempted["status"] == "unknown"
    assert attempted["dispatch_attempt_committed"] is True
    return {
        "memory": memory,
        "registry": registry,
        "binding": binding,
        "task": task,
        "action": action,
        "approval": approval,
        "lease": lease,
        "artifact": artifact,
        "request_id": prepared["request_id"],
        "manifest_sha256": manifest["manifest_sha256"],
        "parameters_sha256": parameters_sha,
        "payload": payload,
    }


def _request(case: dict[str, Any]) -> dict[str, str]:
    return {
        "request_id": case["request_id"],
        "engagement_id": case["binding"]["engagement_id"],
        "task_id": case["task"],
        "server_id": SERVER,
        "tool_name": TOOL,
        "artifact_sha256": SHA,
    }


async def _receipt_rows(engine: Any, case: dict[str, Any]) -> list[dict[str, Any]]:
    async with engine.connect() as db:
        rows = (
            (
                await db.execute(
                    text(
                        "SELECT * FROM native_sourcemap_source_preflights "
                        "WHERE action_id=:action OR request_id=:request"
                    ),
                    {"action": case["action"], "request": case["request_id"]},
                )
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


@pytest.mark.asyncio
async def test_offline_native_declaration_matches_source_admission_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise native's real initialization without PostgreSQL or Docker."""
    _, issuer_root = _configure_independent_signers(monkeypatch, tmp_path)
    native = _native_module()
    registry = await _declared_native_registry(native)
    declaration = registry._servers[SERVER]._tools[TOOL]
    assert declaration.side_effect_class.value == "READ_ONLY"
    assert [(field.name, field.type, field.required) for field in declaration.parameters] == [
        ("artifact_sha256", "string", True)
    ]
    assert len(issuer_root) == 32
    assert native._SOURCE_DOMAIN == b"ai-osop/sourcemap-original-preflight/v1\x00"


@pytest.mark.asyncio(scope="module")
async def test_signed_0035_original_postgres_one_use_replay_revocation_and_immutability(
    disposable_native_pg: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer, public = _configure_independent_signers(monkeypatch, tmp_path)
    native = _native_module()
    registry = await _declared_native_registry(native)
    case = await _signed_original_case(disposable_native_pg, monkeypatch, registry)
    monkeypatch.setitem(
        source_api.state,
        "orchestrator",
        SimpleNamespace(session_memory=case["memory"], mcp_registry=case["registry"]),
    )
    app = FastAPI()
    app.include_router(source_api.router)
    app.include_router(status_api.router)
    assert sum(route.path == PATH for route in app.routes) == 1
    body = _request(case)
    headers = {"Authorization": "Bearer " + SERVICE_TOKEN}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://central-source.local"
    ) as client:
        assert (await client.post(PATH, json=body)).status_code == 401
        assert (
            await client.post(PATH, json=body, headers={"Authorization": "Bearer " + NATIVE_TOKEN})
        ).status_code == 403
        assert (
            await client.post(PATH, json={**body, "task_id": "task-foreign"}, headers=headers)
        ).status_code == 409
        assert (
            await client.post(PATH, json={**body, "artifact_sha256": "e" * 64}, headers=headers)
        ).status_code == 409

        # Same real DB and same immutable original: revoke independent senior.
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text("UPDATE operator_subject_controls SET disabled=true WHERE actor_id=:actor"),
                {"actor": SENIOR},
            )
        assert (await client.post(PATH, json=body, headers=headers)).status_code == 409
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text("UPDATE operator_subject_controls SET disabled=false WHERE actor_id=:actor"),
                {"actor": SENIOR},
            )
            await db.execute(
                text(
                    "UPDATE supervision_execution_leases SET state='cancelled' WHERE task_id=:task"
                ),
                {"task": case["task"]},
            )
        assert (await client.post(PATH, json=body, headers=headers)).status_code == 409
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text(
                    "UPDATE supervision_execution_leases SET state='dispatched' WHERE task_id=:task"
                ),
                {"task": case["task"]},
            )

        # Re-pin the approval to a CHANGED Task manifest. Human evidence can
        # match this new payload, but the original BYTEA manifest still rejects it.
        altered = {**case["payload"], "resource_manifest_sha256": "d" * 64}
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text("UPDATE tasks SET payload=CAST(:value AS jsonb) WHERE id=:task"),
                {"value": json.dumps(altered), "task": case["task"]},
            )
            await db.execute(
                text("UPDATE approval_requests SET evidence=CAST(:value AS jsonb) WHERE id=:id"),
                {"value": json.dumps(pinned_evidence([], altered)), "id": case["approval"]},
            )
        assert (await client.post(PATH, json=body, headers=headers)).status_code == 409
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text("UPDATE tasks SET payload=CAST(:value AS jsonb) WHERE id=:task"),
                {"value": json.dumps(case["payload"]), "task": case["task"]},
            )
            await db.execute(
                text("UPDATE approval_requests SET evidence=CAST(:value AS jsonb) WHERE id=:id"),
                {"value": json.dumps(pinned_evidence([], case["payload"])), "id": case["approval"]},
            )
        assert await _receipt_rows(disposable_native_pg, case) == []
        accepted = await client.post(PATH, json=body, headers=headers)
        assert accepted.status_code == 200, accepted.text
        assert accepted.headers["cache-control"] == "no-store"
        assert ORIGINAL not in accepted.content
        assert b"sourcesContent" not in accepted.content
        token = accepted.json()
        assert set(token) == {"claims", "kid", "signature"}
        assert token["kid"] == ISSUER_KID
        claims = token["claims"]
        assert claims["request_id"] == case["request_id"]
        assert claims["action_id"] == case["action"]
        assert claims["artifact_sha256"] == SHA
        assert claims["manifest_sha256"] == case["manifest_sha256"]
        assert claims["authorization_sha256"] == case["binding"]["authorization_sha256"]
        assert claims["authorization_version"] == case["binding"]["version"]
        assert claims["expires_at"] - claims["issued_at"] == 10
        assert claims["preflight_id"].startswith("nsp-")
        signature = base64.urlsafe_b64decode(token["signature"] + "==")
        signer.public_key().verify(
            signature,
            b"ai-osop/sourcemap-original-preflight/v1\x00"
            + json.dumps(
                claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            ).encode("ascii"),
        )
        assert native._source_proof(token, body, {ISSUER_KID: public}) == claims
        replay = await client.post(PATH, json=body, headers=headers)
        assert replay.status_code == 409
        # The original 0035 preflight remains one-use, but a separate signed,
        # non-consuming STATUS permission can be issued to inspect an already
        # fsynced native journal. Real PG must revalidate original 0027 UNKNOWN,
        # reviewer/lease, approved Task, original byte SHA and committed 0035.
        status_path = "/native-sourcemap/status-preflight"
        status_service = "distinct-current-status-service-real-pg"
        monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", status_service)
        status_headers = {"Authorization": "Bearer " + status_service}
        denied = await client.post(status_path, json=body, headers=headers)
        assert denied.status_code == 403
        permitted = await client.post(status_path, json=body, headers=status_headers)
        assert permitted.status_code == 200, permitted.text
        status_token = permitted.json()
        status_claims = status_token["claims"]
        assert status_claims["preflight_id"] == claims["preflight_id"]
        assert status_claims["action_id"] == case["action"]
        assert status_claims["request_id"] == case["request_id"]
        assert status_claims["artifact_sha256"] == SHA
        assert status_claims["expires_at"] - status_claims["issued_at"] == 5
        signer.public_key().verify(
            base64.urlsafe_b64decode(status_token["signature"] + "=="),
            b"ai-osop/sourcemap-original-status/v1\x00"
            + json.dumps(
                status_claims,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii"),
        )
        assert len(await _receipt_rows(disposable_native_pg, case)) == 1
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text("UPDATE operator_subject_controls SET disabled=true WHERE actor_id=:actor"),
                {"actor": SENIOR},
            )
        assert (
            await client.post(status_path, json=body, headers=status_headers)
        ).status_code == 409
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text("UPDATE operator_subject_controls SET disabled=false WHERE actor_id=:actor"),
                {"actor": SENIOR},
            )

    saved = await _receipt_rows(disposable_native_pg, case)
    assert len(saved) == 1
    row = saved[0]
    assert row["preflight_id"] == claims["preflight_id"]
    assert row["action_id"] == case["action"]
    assert row["request_id"] == case["request_id"]
    assert (
        row["claims_sha256"]
        == hashlib.sha256(
            json.dumps(
                claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            ).encode("ascii")
        ).hexdigest()
    )
    assert row["signature_sha256"] == hashlib.sha256(signature).hexdigest()
    assert row["kid"] == ISSUER_KID
    async with disposable_native_pg.connect() as db:
        original = (
            (
                await db.execute(
                    text(
                        "SELECT status,cancel_requested,receipt_sha256 FROM flow_mcp_action_dispatches "
                        "WHERE action_id=:action"
                    ),
                    {"action": case["action"]},
                )
            )
            .mappings()
            .one()
        )
        assert original["status"] == "unknown"
        assert original["cancel_requested"] is False
        assert original["receipt_sha256"] is None
        attempts = (
            await db.execute(
                text(
                    "SELECT COUNT(*) FROM flow_mcp_action_dispatch_events "
                    "WHERE action_id=:action AND kind='dispatch_attempted' AND status='unknown'"
                ),
                {"action": case["action"]},
            )
        ).scalar_one()
        assert attempts == 1
        indexes = (
            (
                await db.execute(
                    text(
                        "SELECT indexdef FROM pg_indexes "
                        "WHERE tablename='native_sourcemap_source_preflights'"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert any("UNIQUE" in definition and "(action_id)" in definition for definition in indexes)
        assert any(
            "UNIQUE" in definition and "(request_id)" in definition for definition in indexes
        )
        trigger = (
            await db.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE "
                    "tgrelid=to_regclass('native_sourcemap_source_preflights') "
                    "AND tgname='trg_native_sourcemap_source_immutable' AND NOT tgisinternal)"
                )
            )
        ).scalar_one()
        assert trigger is True

    # The immutable DDL is enforced by real PostgreSQL, including on DELETE.
    for sql in (
        "UPDATE native_sourcemap_source_preflights SET kid=kid WHERE preflight_id=:id",
        "DELETE FROM native_sourcemap_source_preflights WHERE preflight_id=:id",
    ):
        with pytest.raises(DBAPIError):
            async with disposable_native_pg.begin() as db:
                await db.execute(text(sql), {"id": claims["preflight_id"]})
    assert len(await _receipt_rows(disposable_native_pg, case)) == 1
