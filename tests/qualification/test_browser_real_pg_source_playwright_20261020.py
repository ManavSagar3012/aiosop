"""Opt-in joined real PostgreSQL 0034 -> FastAPI -> native Browser -> Chromium.

Real components: owned disposable pgvector/pg16 migrated to 0034, signed ROE
and original 0027 Action UNKNOWN, independent reviewer and lease, mounted
FastAPI router, PostgreSQL one-shot commit, real Ed25519 issuer verification,
actual local headless Chromium navigation to an owned 127.0.0.1 listener.

Simulated boundary: TLS transport between Browser and FastAPI uses an in-process
ASGI bridge, with independently pinned issuer key and TLS CA *configuration*.
It is NOT a real HTTPS/TLS handshake or a production release qualification.
No application DB, outbound site, remote provider or external test target.
Set OSOP_DISPOSABLE_NATIVE_0029_PG=1; fixture uses cached Docker image only.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

from ai_osop.api.routers import native_browser_source_authority as source_api
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry, MCPToolDefinition
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.safety.approval_binding import pinned_evidence
from ai_osop.safety.signed_roe import canonical_json_bytes, verify_signed_roe
from tests.qualification.native_browser_local_helper_20261020 import (
    ENGAGEMENT,
    LABEL,
    TASK,
    native_browser_local,
    real_chromium_executable,
)
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    disposable_native_pg,
)
from tests.test_authorization_store import make_signed_session


OWNER = "operator-browser-source-owner"
REVIEWER = "operator-browser-independent-reviewer"
SERVICE = "independent-browser-central-real-pg-qualification-service"
ISSUER_KID = "browser-pg-issuer-20261020"
REAL_HTTP = httpx.AsyncClient


def _source_request(
    case: dict[str, Any], *, task_id: str = TASK, mode: str = "none"
) -> dict[str, str]:
    return {
        "request_id": case["request_id"],
        "engagement_id": ENGAGEMENT,
        "task_id": task_id,
        "server_id": "browser-mcp",
        "tool_name": "execute",
        "action": "navigate",
        "user_label": LABEL,
        "evidence_mode": mode,
        "url_sha256": hashlib.sha256(case["url"].encode("utf-8")).hexdigest(),
        "origin": case["origin"],
    }


async def _native_declaration(native: Any) -> MCPRegistry:
    """Take the ACTUAL native initialize declaration; registry transport stub.

    This setup does not claim an actual MCPRegistry TCP initialization. It is
    necessary because this qualification's native endpoint is ASGI in-process.
    The central store nevertheless validates exact negotiated declaration SHA.
    """
    async with native.client() as client:
        discovery = await client.post(
            "/mcp/initialize",
            json={"session_id": ENGAGEMENT},
            headers=native.headers(),
        )
    assert discovery.status_code == 200, discovery.text
    declaration = MCPToolDefinition.model_validate(discovery.json()["tools"][0])
    assert declaration.name == "execute"
    registry = MCPRegistry()
    connection = MCPConnection(server_id="browser-mcp", host="127.0.0.1", port=8091)
    connection._initialized = True
    connection._tools = {"execute": declaration}
    registry._servers["browser-mcp"] = connection
    return registry


async def _signed_case(
    engine: Any,
    monkeypatch: pytest.MonkeyPatch,
    native: Any,
) -> dict[str, Any]:
    """Persist real independently signed ROE, Task, reviewer, lease and 0027."""
    registry = await _native_declaration(native)
    suffix = uuid.uuid4().hex[:12]
    flow_id = "flow-browser-" + suffix
    parent_id = "task-browser-parent-" + suffix
    subtask = "subtask-browser-" + suffix
    action_id = "action-" + uuid.uuid4().hex
    approval_id = "apr-browser-" + suffix
    lease_id = "lease-browser-" + suffix
    target = native.base_url + "/"
    key = Ed25519PrivateKey.generate()
    session, _verified, envelope, _ = make_signed_session(
        monkeypatch,
        session_id=ENGAGEMENT,
        private_key=key,
        owner=OWNER,
        authorization_id="auth-browser-" + suffix,
        domains=["authorized.example"],
        roe_override={"allow_active_scanning": True},
    )
    # Explicitly sign the one owned loopback address; mutate policy BEFORE
    # Ed25519 re-verification, never trust a caller's later scope claim.
    session.scope.ips = ["127.0.0.1/32"]
    session.scope.allowed_techniques = ["execute"]
    policy = dict(envelope["policy"])
    policy["ips"] = ["127.0.0.1/32"]
    policy["allowed_techniques"] = ["execute"]
    signed_envelope = {
        "version": 1,
        "policy": policy,
        "signature": base64.urlsafe_b64encode(key.sign(canonical_json_bytes(policy)))
        .decode("ascii")
        .rstrip("="),
    }
    verified = verify_signed_roe(
        signed_envelope,
        expected_engagement_id=ENGAGEMENT,
        expected_owner=OWNER,
        expected_scope=session.scope,
        expected_roe=session.roe,
        now=datetime.now(timezone.utc),
    )
    session.phase = "reconnaissance"
    memory = SessionMemory()
    memory._pg_engine = engine
    memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
    recorded = await AuthorizationStore(memory).create_authorized_session(
        session,
        verified,
        OWNER,
    )
    binding = {
        "engagement_id": ENGAGEMENT,
        "flow_id": flow_id,
        "revision": 0,
        "version": recorded["version"],
        "authorization_id": recorded["authorization_id"],
        "authorization_sha256": recorded["policy_sha256"],
    }
    params = {"url": target, "action": "navigate", "user_label": LABEL}
    parameters_sha = FlowMCPActionStore.parameters_sha256(params)
    declaration_sha = FlowMCPActionStore.declaration_sha256(
        registry._servers["browser-mcp"]._tools["execute"], "browser-mcp"
    )
    payload = {
        "mcp_flow_revision": 0,
        "_authorization_version": recorded["version"],
        "mcp_action_id": action_id,
        "mcp_server_id": "browser-mcp",
        "mcp_tool_name": "execute",
        "mcp_declaration_sha256": declaration_sha,
        "mcp_parameters_sha256": parameters_sha,
        "mcp_side_effect_class": "RECON_ACTIVE",
        "operator_approved": True,
        "approval_id": approval_id,
        "url": target,
    }
    now = datetime.utcnow()
    async with engine.begin() as db:
        await db.execute(
            text(
                "INSERT INTO execution_flows (id,engagement_id,objective,status,revision,created_at,updated_at)"
                " VALUES (:f,:e,'Only owned offline Browser source qualification','running',0,:ts,:ts)"
            ),
            {"f": flow_id, "e": ENGAGEMENT, "ts": now},
        )
        await db.execute(
            text(
                "INSERT INTO tasks (id,type,priority,agent_type,payload,dependencies,max_retries,"
                "timeout_seconds,scope_check,approval_required,status,retry_count,"
                "created_at,started_at,engagement_id,assigned_agent_id,flow_id) "
                "VALUES (:id,'browser_plan',5,'workflow',CAST('{}' AS jsonb),"
                "CAST('[]' AS jsonb),0,300,true,false,'running',0,:ts,:ts,:eng,"
                "'worker-local-browser',:flow)"
            ),
            {"id": parent_id, "ts": now, "eng": ENGAGEMENT, "flow": flow_id},
        )
        await db.execute(
            text(
                "INSERT INTO execution_subtasks (id,engagement_id,flow_id,task_id,title,description,"
                'task_type,agent_type,approval_required,"order",dependencies,status,'
                "refinement_count,execution_task_id,created_at,updated_at) "
                "VALUES (:sid,:eng,:flow,:parent,'Owned local navigation',"
                "'No external target','browser_navigation','recon',true,1,"
                "CAST('[]' AS jsonb),'running',0,:child,:ts,:ts)"
            ),
            {
                "sid": subtask,
                "eng": ENGAGEMENT,
                "flow": flow_id,
                "parent": parent_id,
                "child": TASK,
                "ts": now,
            },
        )
        await db.execute(
            text(
                "INSERT INTO tasks (id,type,priority,agent_type,payload,dependencies,"
                "max_retries,timeout_seconds,scope_check,approval_required,status,"
                "retry_count,created_at,started_at,engagement_id,assigned_agent_id,"
                "flow_id,subtask_id,parent_task_id) "
                "VALUES (:id,'browser_navigation',5,'recon',CAST(:payload AS jsonb),"
                "CAST('[]' AS jsonb),0,300,true,true,'running',0,:ts,:ts,:eng,"
                "'worker-local-browser',:flow,:sid,:parent)"
            ),
            {
                "id": TASK,
                "payload": json.dumps(payload),
                "ts": now,
                "eng": ENGAGEMENT,
                "flow": flow_id,
                "sid": subtask,
                "parent": parent_id,
            },
        )
        await db.execute(
            text(
                "INSERT INTO approval_requests "
                "(id,task_id,action_type,target,status,operator_id,responded_at,evidence,engagement_id) "
                "VALUES (:id,:task,'browser_navigation',:url,'approved',:reviewer,:ts,"
                "CAST(:evidence AS jsonb),:eng)"
            ),
            {
                "id": approval_id,
                "task": TASK,
                "url": target,
                "reviewer": REVIEWER,
                "ts": now,
                "evidence": json.dumps(pinned_evidence([], payload)),
                "eng": ENGAGEMENT,
            },
        )
        for principal in (OWNER, REVIEWER):
            await db.execute(
                text(
                    "INSERT INTO operator_subject_controls (actor_id,disabled,updated_at,updated_by)"
                    " VALUES (:actor,false,:ts,:owner) ON CONFLICT (actor_id) DO NOTHING"
                ),
                {"actor": principal, "ts": now, "owner": OWNER},
            )
        await db.execute(
            text(
                "INSERT INTO supervision_execution_leases "
                "(task_id,engagement_id,lease_id,owner_id,state,expires_at) "
                "VALUES (:task,:eng,:lease,'worker-local-browser','dispatched',:exp)"
            ),
            {"task": TASK, "eng": ENGAGEMENT, "lease": lease_id, "exp": now + timedelta(minutes=3)},
        )
    original = FlowMCPActionStore(memory, registry)
    prepared = await original.prepare(
        binding,
        OWNER,
        TASK,
        subtask,
        "browser-mcp",
        "execute",
        params,
        parameters_sha,
        declaration_sha,
    )
    assert prepared["status"] == "prepared"
    reserved = await original.reserve(binding, OWNER, action_id)
    assert reserved["status"] == "reserved" and reserved["admitted_for_dispatch"] is True
    dispatched = await original.mark_dispatched(
        binding, OWNER, action_id, prepared["request_id"], reserved["reservation_token"]
    )
    assert dispatched["status"] == "unknown"
    return {
        "original": original,
        "memory": memory,
        "registry": registry,
        "action_id": action_id,
        "request_id": prepared["request_id"],
        "approval_id": approval_id,
        "lease_id": lease_id,
        "url": target,
        "origin": native.base_url,
    }


def _source_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, bytes]:
    """Separate central Ed25519 issuer, native trusted public root and CA pin."""
    signer = Ed25519PrivateKey.generate()
    private = signer.private_bytes_raw()
    public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_SIGNING_KID", ISSUER_KID)
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_SIGNING_PRIVATE_KEY_B64",
        base64.b64encode(private).decode(),
    )
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({ISSUER_KID: base64.b64encode(public).decode()}),
    )
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", SERVICE)
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_URL",
        "https://source.authority.invalid/native-browser/source-preflight",
    )
    ca = tmp_path / "independent-root.pem"
    ca.write_text(
        "-----BEGIN CERTIFICATE-----\n" + "A" * 128 + "\n-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_CA_BUNDLE", str(ca))
    return {ISSUER_KID: public}


def _mount_central(case: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """Real router and PostgreSQL store; only its HTTPS network hop is bridged."""
    monkeypatch.setitem(
        source_api.state,
        "orchestrator",
        SimpleNamespace(
            session_memory=case["memory"],
            mcp_registry=case["registry"],
        ),
    )
    app = FastAPI()
    app.include_router(source_api.router)
    assert sum(r.path == "/native-browser/source-preflight" for r in app.routes) == 1
    return app


def _asgi_tls_bridge(
    native: Any,
    central: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MockTransport/ASGI bridge only: real API/PG/signature; NO TLS handshake."""
    original = REAL_HTTP

    def bridge(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert kwargs["verify"] == os.environ["OSOP_BROWSER_SOURCE_CA_BUNDLE"]
        return original(
            *args,
            transport=httpx.ASGITransport(app=central),
            base_url="https://source.authority.invalid",
            verify=False,  # TLS bypass is ONLY within in-memory ASGI test transport.
            timeout=kwargs["timeout"],
            trust_env=False,
            follow_redirects=False,
        )

    monkeypatch.setattr(native.native.httpx, "AsyncClient", bridge)


@pytest.mark.asyncio(scope="module")
async def test_real_pg_0034_fastapi_ed25519_native_playwright_one_shot(
    disposable_native_pg: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, status = await real_chromium_executable()
    if executable is None:
        pytest.skip(status)
    async with native_browser_local(tmp_path, monkeypatch) as native:
        roots = _source_keys(tmp_path, monkeypatch)
        case = await _signed_case(disposable_native_pg, monkeypatch, native)
        central = _mount_central(case, monkeypatch)
        body = _source_request(case)
        # NEGATIVE: wrong signed Task, distinct reviewer disabled, revoked lease.
        async with REAL_HTTP(
            transport=httpx.ASGITransport(app=central),
            base_url="https://source.authority.invalid",
        ) as client:
            headers = {"Authorization": "Bearer " + SERVICE}
            wrong = await client.post(
                "/native-browser/source-preflight",
                json=_source_request(case, task_id="task-wrong-tenant"),
                headers=headers,
            )
            assert wrong.status_code == 409
            async with disposable_native_pg.begin() as db:
                await db.execute(
                    text("UPDATE operator_subject_controls SET disabled=true WHERE actor_id=:id"),
                    {"id": REVIEWER},
                )
            denied = await client.post(
                "/native-browser/source-preflight",
                json=body,
                headers=headers,
            )
            assert denied.status_code == 409
            async with disposable_native_pg.begin() as db:
                await db.execute(
                    text("UPDATE operator_subject_controls SET disabled=false WHERE actor_id=:id"),
                    {"id": REVIEWER},
                )
                await db.execute(
                    text(
                        "UPDATE supervision_execution_leases SET state='cancelled' "
                        "WHERE task_id=:task"
                    ),
                    {"task": TASK},
                )
            denied = await client.post(
                "/native-browser/source-preflight",
                json=body,
                headers=headers,
            )
            assert denied.status_code == 409
            async with disposable_native_pg.begin() as db:
                await db.execute(
                    text(
                        "UPDATE supervision_execution_leases SET state='dispatched' "
                        "WHERE task_id=:task"
                    ),
                    {"task": TASK},
                )
        _asgi_tls_bridge(native, central, monkeypatch)
        async with REAL_HTTP(
            transport=httpx.ASGITransport(app=native.native.app),
            base_url="http://browser-owned-local.invalid",
            timeout=20.0,
        ) as client:
            request = {
                "tool_name": "execute",
                "request_id": case["request_id"],
                "execution_binding": {
                    "request_id": case["request_id"],
                    "engagement_id": ENGAGEMENT,
                    "task_id": TASK,
                    "server_id": "browser-mcp",
                },
                "parameters": {
                    "url": case["url"],
                    "action": "navigate",
                    "user_label": LABEL,
                },
            }
            first = await client.post(
                "/mcp/execute",
                json=request,
                headers=native.headers(),
            )
            assert first.status_code == 200, first.text
            assert first.json()["status"] == "success", first.text
            assert first.json()["result"]["status_code"] == 200
            assert native.page_hits == ["/"]
            replay = await client.post(
                "/mcp/execute",
                json=request,
                headers=native.headers(),
            )
            assert replay.json()["status"] == "duplicate_request"
            assert native.page_hits == ["/"]
        async with disposable_native_pg.connect() as db:
            saved = (
                (
                    await db.execute(
                        text(
                            "SELECT request_id,action_id,user_label,evidence_mode,kid "
                            "FROM native_browser_source_preflights WHERE action_id=:action"
                        ),
                        {"action": case["action_id"]},
                    )
                )
                .mappings()
                .all()
            )
            assert len(saved) == 1
            assert saved[0]["request_id"] == case["request_id"]
            assert saved[0]["user_label"] == LABEL
            assert saved[0]["evidence_mode"] == "none"
            assert saved[0]["kid"] in roots
            action = (
                await db.execute(
                    text("SELECT status FROM flow_mcp_action_dispatches WHERE action_id=:action"),
                    {"action": case["action_id"]},
                )
            ).scalar_one()
            assert action == "unknown"  # No consequential automatic replay.
        # Native journal replay denial was checked above. The INDEPENDENT
        # central PostgreSQL one-shot also rejects replay on another caller.
        async with REAL_HTTP(
            transport=httpx.ASGITransport(app=central),
            base_url="https://source.authority.invalid",
        ) as client:
            repeated = await client.post(
                "/native-browser/source-preflight",
                json=body,
                headers={"Authorization": "Bearer " + SERVICE},
            )
            assert repeated.status_code == 409
        assert native.blocked == []
        # Chromium may ask for time services even when background networking
        # is disabled. Those attempts terminate at the OWNED loopback deny
        # proxy; recording an intercepted request is evidence of isolation.
        assert all("clients2.google.com/time" in req for req in native.proxy_attempts)
