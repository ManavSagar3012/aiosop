"""Opt-in REAL PostgreSQL 0034 -> signed FastAPI -> offline Chromium capture.

The approved original 0027 Action includes all FOUR Browser source parameters,
including evidence_mode=screenshot_dom_har.  The 0034 preflight transaction,
signed reviewer/ROE/Task/lease checks and immutable rows use the disposable
real PostgreSQL fixture.  The Browser handler uses real Playwright Chromium
against an owned 127.0.0.1 HTML page and persists original PNG, DOM and HAR.

The native-to-central HTTPS hop is an in-process HTTPX ASGI transport bridge.
This tests the production central HTTP handler and Ed25519 verification, NOT
an actual TLS handshake.  No app DB, remote target, download or paid service.
Opt in with OSOP_DISPOSABLE_NATIVE_0029_PG=1 and a cached PG Docker image.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
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
from tests.qualification.test_browser_full_evidence_source_contract_20261020 import (
    _verify_coupled_evidence,
)
from tests.qualification.test_browser_real_pg_source_playwright_20261020 import (
    OWNER,
    REVIEWER,
    REAL_HTTP,
    SERVICE,
    _asgi_tls_bridge,
    _mount_central,
    _native_declaration,
    _source_keys,
    _source_request,
)
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    disposable_native_pg,
)
from tests.test_authorization_store import make_signed_session


_MODE = "screenshot_dom_har"
_CENTRAL_PATH = "/native-browser/source-preflight"


async def _original_approved_capture(
    engine: Any, monkeypatch: pytest.MonkeyPatch, native: Any
) -> dict[str, Any]:
    """Create an original signed four-field action, never rewrite an old one."""
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
    recorded = await AuthorizationStore(memory).create_authorized_session(session, verified, OWNER)
    binding = {
        "engagement_id": ENGAGEMENT,
        "flow_id": flow_id,
        "revision": 0,
        "version": recorded["version"],
        "authorization_id": recorded["authorization_id"],
        "authorization_sha256": recorded["policy_sha256"],
    }
    params = {
        "url": target,
        "action": "navigate",
        "user_label": LABEL,
        "evidence_mode": _MODE,
    }
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
                "INSERT INTO execution_flows "
                "(id,engagement_id,objective,status,revision,created_at,updated_at) "
                "VALUES (:f,:e,'Owned signed offline Browser full capture','running',0,:ts,:ts)"
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
                "INSERT INTO execution_subtasks (id,engagement_id,flow_id,task_id,title,"
                'description,task_type,agent_type,approval_required,"order",dependencies,'
                "status,refinement_count,execution_task_id,created_at,updated_at) "
                "VALUES (:sid,:eng,:flow,:parent,'Owned complete capture',"
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
                "(id,task_id,action_type,target,status,operator_id,responded_at,"
                "evidence,engagement_id) "
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
                    "INSERT INTO operator_subject_controls "
                    "(actor_id,disabled,updated_at,updated_by) "
                    "VALUES (:actor,false,:ts,:owner) ON CONFLICT (actor_id) DO NOTHING"
                ),
                {"actor": principal, "ts": now, "owner": OWNER},
            )
        await db.execute(
            text(
                "INSERT INTO supervision_execution_leases "
                "(task_id,engagement_id,lease_id,owner_id,state,expires_at) "
                "VALUES (:task,:eng,:lease,'worker-local-browser','dispatched',:exp)"
            ),
            {
                "task": TASK,
                "eng": ENGAGEMENT,
                "lease": lease_id,
                "exp": now + timedelta(minutes=3),
            },
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
    assert reserved["status"] == "reserved"
    assert reserved["admitted_for_dispatch"] is True
    dispatched = await original.mark_dispatched(
        binding, OWNER, action_id, prepared["request_id"], reserved["reservation_token"]
    )
    assert dispatched["status"] == "unknown"
    return {
        "memory": memory,
        "registry": registry,
        "action_id": action_id,
        "request_id": prepared["request_id"],
        "url": target,
        "origin": native.base_url,
        "parameters": params,
        "parameters_sha": parameters_sha,
        "authorization_sha256": recorded["policy_sha256"],
    }


@pytest.mark.asyncio(scope="module")
async def test_real_pg_0034_signed_source_full_capture_chromium_one_shot(
    disposable_native_pg: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full original capture joins real PG source and native Browser evidence."""
    executable, reason = await real_chromium_executable()
    if executable is None:
        pytest.skip(reason)
    async with native_browser_local(tmp_path, monkeypatch) as native:
        roots = _source_keys(tmp_path, monkeypatch)
        case = await _original_approved_capture(disposable_native_pg, monkeypatch, native)
        central = _mount_central(case, monkeypatch)
        request = _source_request(case, mode=_MODE)
        headers = {"Authorization": "Bearer " + SERVICE}
        async with REAL_HTTP(
            transport=httpx.ASGITransport(app=central),
            base_url="https://source.authority.invalid",
            trust_env=False,
        ) as client:
            for altered in (
                {**request, "evidence_mode": "none"},
                {**request, "task_id": "task-unreviewed"},
                {**request, "url_sha256": "f" * 64},
            ):
                response = await client.post(_CENTRAL_PATH, json=altered, headers=headers)
                assert response.status_code == 409, response.text

            async with disposable_native_pg.begin() as db:
                await db.execute(
                    text(
                        "UPDATE operator_subject_controls SET disabled=true "
                        "WHERE actor_id=:reviewer"
                    ),
                    {"reviewer": REVIEWER},
                )
            rejected = await client.post(_CENTRAL_PATH, json=request, headers=headers)
            assert rejected.status_code == 409, rejected.text
            async with disposable_native_pg.begin() as db:
                await db.execute(
                    text(
                        "UPDATE operator_subject_controls SET disabled=false "
                        "WHERE actor_id=:reviewer"
                    ),
                    {"reviewer": REVIEWER},
                )
                await db.execute(
                    text(
                        "UPDATE supervision_execution_leases SET state='cancelled' "
                        "WHERE task_id=:task"
                    ),
                    {"task": TASK},
                )
            rejected = await client.post(_CENTRAL_PATH, json=request, headers=headers)
            assert rejected.status_code == 409, rejected.text
            async with disposable_native_pg.begin() as db:
                await db.execute(
                    text(
                        "UPDATE supervision_execution_leases SET state='dispatched' "
                        "WHERE task_id=:task"
                    ),
                    {"task": TASK},
                )
        assert native.page_hits == []
        _asgi_tls_bridge(native, central, monkeypatch)
        payload = {
            "tool_name": "execute",
            "request_id": case["request_id"],
            "execution_binding": {
                "request_id": case["request_id"],
                "engagement_id": ENGAGEMENT,
                "task_id": TASK,
                "server_id": "browser-mcp",
            },
            "parameters": case["parameters"],
        }
        async with REAL_HTTP(
            transport=httpx.ASGITransport(app=native.native.app),
            base_url="http://browser-owned-local.invalid",
            timeout=30.0,
        ) as client:
            first = await client.post("/mcp/execute", json=payload, headers=native.headers())
            assert first.status_code == 200, first.text
            completed = first.json()
            assert completed["status"] == "success", completed
            assert provider_receipt_is_signed(
                completed["provider_receipt"],
                "browser-mcp",
                case["request_id"],
                ENGAGEMENT,
                TASK,
            )
            result = completed["result"]
            _verify_coupled_evidence(native, result, case["request_id"])
            assert "LOCAL_ONLY_BROWSER_PROOF" not in first.text
            assert "data:image/" not in first.text
            assert native.page_hits == ["/"]
            assert native.native.RequestJournal(payload["execution_binding"]).read() == "succeeded"
            witness = result["evidence_attestation"]["claims"]
            assert witness["action_id"] == case["action_id"]
            assert witness["authorization_sha256"] == case["authorization_sha256"]
            assert all(
                result["evidence"][kind]["container_image_sha256"] == "a" * 64
                for kind in ("screenshot", "dom", "har")
            )
            replay = await client.post("/mcp/execute", json=payload, headers=native.headers())
            assert replay.status_code == 200
            assert replay.json()["status"] == "duplicate_request"
            assert native.page_hits == ["/"]

        async with disposable_native_pg.connect() as db:
            saved = (
                (
                    await db.execute(
                        text(
                            "SELECT request_id,action_id,user_label,evidence_mode,kid,"
                            "preflight_id,authorization_sha256 FROM native_browser_source_preflights "
                            "WHERE action_id=:action"
                        ),
                        {"action": case["action_id"]},
                    )
                )
                .mappings()
                .all()
            )
            assert len(saved) == 1
            assert saved[0]["request_id"] == case["request_id"]
            assert saved[0]["action_id"] == case["action_id"]
            assert saved[0]["user_label"] == LABEL
            assert saved[0]["evidence_mode"] == _MODE
            assert saved[0]["kid"] in roots
            assert witness["source_preflight_id"] == saved[0]["preflight_id"]
            assert witness["authorization_sha256"] == saved[0]["authorization_sha256"]
            original = (
                (
                    await db.execute(
                        text(
                            "SELECT status,safe_parameters,parameters_sha256 "
                            "FROM flow_mcp_action_dispatches WHERE action_id=:action"
                        ),
                        {"action": case["action_id"]},
                    )
                )
                .mappings()
                .one()
            )
            assert original["status"] == "unknown"
            assert original["safe_parameters"] == case["parameters"]
            assert original["parameters_sha256"] == case["parameters_sha"]

        async with REAL_HTTP(
            transport=httpx.ASGITransport(app=central),
            base_url="https://source.authority.invalid",
            trust_env=False,
        ) as client:
            replay = await client.post(_CENTRAL_PATH, json=request, headers=headers)
            assert replay.status_code == 409, replay.text
        assert native.blocked == []
        # Chromium background network attempts, if any, hit the owned deny proxy.
        assert all("clients2.google.com/time" in url for url in native.proxy_attempts)
