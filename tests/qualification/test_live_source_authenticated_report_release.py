"""Live, DISPOSABLE PostgreSQL + Neo4j source-bound report release qualification.

Opt in ONLY with explicit loopback services owned by the tester:
  OSOP_REPORT_RELEASE_TEST_PG_URI=postgresql+asyncpg://...@127.0.0.1:15792/report_source_qualification_w10
  OSOP_REPORT_RELEASE_TEST_NEO4J_URI=bolt://127.0.0.1:17792
  OSOP_REPORT_RELEASE_TEST_NEO4J_PASSWORD=...
These strict guards are inherited from the existing live report fixture. No
application DB, real security target, paid model or remote MCP server is used.
Provider is a local Ed25519 signature generator for an inert status assertion,
NOT actual target-side exploitation or independently authenticated finding.
"""

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, update

from ai_osop.core.config import AgentType
from ai_osop.api.routers import report_attestations as report_api
from ai_osop.core.models import FlowRecord
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.session_memory import ExecutionFlowORM, TaskORM
from ai_osop.memory.supervision_store import SupervisionEventORM, SupervisionStore
from ai_osop.orchestrator.context_compaction import task_assignment_sha256
from ai_osop.reporting.attestation import hash_evidence_snapshot, verify_report_files
from ai_osop.reporting.attested_storage import (
    AttestedStorageUnavailable,
    load_attested_bundle,
)
from tests.qualification.test_live_signed_report_release_pipeline import (
    _generate_and_finalize,
    live_services,
)


def _receipt(live, task_id, server_id, request_id, private, kid):
    claims = {
        "request_id": request_id,
        "engagement_id": live.sid,
        "task_id": task_id,
        "server_id": server_id,
        "status": "succeeded",
        "verified": True,
        "stopped": False,
        "issued_at": int(time.time()),
    }
    canonical = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    signature = base64.urlsafe_b64encode(private.sign(canonical)).decode().rstrip("=")
    return {**claims, "attestation": {"kid": kid, "signature": signature}}


@pytest.fixture
async def authenticated_source(live_services, monkeypatch):
    """Real signed ROE, PostgreSQL task/Flow/supervision, Neo4j finding.

    All mutations are to explicitly disposable service URLs. The user-owned
    application DB and remotely reachable targets are never contacted.
    """
    live = live_services
    nonce = uuid.uuid4().hex[:10]
    flow_id = "flow-source-" + nonce
    source_id = "task-source-" + nonce
    server_id = "local-status-provider"
    request_id = "req-report-" + nonce
    kid = "local-test-signer"
    flow = FlowRecord(
        id=flow_id,
        engagement_id=live.sid,
        objective="Inert local signed source",
        status="running",
        revision=2,
    )
    evidence_hash = hash_evidence_snapshot(live.evidence)
    started = datetime.utcnow()
    async with live.memory._async_session() as db, db.begin():
        db.add(
            ExecutionFlowORM(
                id=flow.id,
                engagement_id=live.sid,
                objective=flow.objective,
                status=flow.status,
                revision=flow.revision,
                created_at=flow.created_at,
                updated_at=flow.updated_at,
            )
        )
        db.add(
            TaskORM(
                id=source_id,
                engagement_id=live.sid,
                type="recon",
                priority=5,
                agent_type=AgentType.RECON.value,
                status="running",
                payload={"_authorization_version": 1, "purpose": "fixture_only"},
                dependencies=[],
                max_retries=0,
                timeout_seconds=60,
                scope_check=True,
                approval_required=False,
                result=None,
                retry_count=0,
                created_at=started,
                started_at=started,
                assigned_agent_id="isolated-fixture-worker",
                flow_id=flow_id,
            )
        )

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({server_id: {kid: base64.b64encode(public).decode()}}),
    )
    store = SupervisionStore(live.memory)
    args = (live.sid, source_id, server_id, request_id)
    assert await store.claim_mcp_dispatch(*args, "passive_probe")
    receipt = _receipt(live, source_id, server_id, request_id, private, kid)
    assert await store.record_mcp_dispatch_event(
        *args,
        "reconciliation_result",
        "confirmed_finished",
        attested_receipt=receipt,
    )
    dispatch = await store.get_mcp_dispatch(*args)
    assert dispatch["status"] == "confirmed_finished"
    async with live.memory._async_session() as db:
        saved_events = (
            (
                await db.execute(
                    select(SupervisionEventORM).where(
                        SupervisionEventORM.engagement_id == live.sid,
                        SupervisionEventORM.task_id == source_id,
                        SupervisionEventORM.kind == "agent.mcp.reconciliation_result",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(saved_events) == 1
    event = saved_events[0]
    receipt_hash = hashlib.sha256(
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode(),
    ).hexdigest()
    assert event.payload["provider_receipt_sha256"] == receipt_hash
    assert event.payload["provider_receipt_status"] == "succeeded"
    assert await live.memory.verify_signed_graph_action(
        live.sid,
        source_id,
        event.id,
        receipt_hash,
        1,
    )

    # Transition only the previously claimed fixture Task to a completed
    # persisted source record. The signed receipt does not certify target-side
    # vulnerability authenticity, and we never assert otherwise.
    async with live.memory._async_session() as db, db.begin():
        await db.execute(
            update(TaskORM)
            .where(
                TaskORM.id == source_id,
                TaskORM.engagement_id == live.sid,
            )
            .values(
                status="completed",
                completed_at=datetime.utcnow(),
                result={"status": "success", "evidence_sha256": evidence_hash},
            )
        )
    original = await live.memory.load_task_authoritative(source_id)
    assert original.status == "completed"
    signed_policy = await live.memory.assert_signed_authorization(
        live.sid,
        expected_version=1,
    )
    binding = {
        "source_task_id": source_id,
        "source_task_sha256": task_assignment_sha256(original),
        "flow_id": flow_id,
        "flow_revision": flow.revision,
        "authorization_version": 1,
        "authorization_sha256": signed_policy.policy_sha256,
        "source_event_id": event.id,
        "provider_receipt_sha256": receipt_hash,
    }
    async with live.graph._driver.session() as db:
        await (
            await db.run(
                "MATCH (v:Vulnerability {engagement_id:$sid, id:$fid}) "
                "SET v += $binding RETURN v.id AS id",
                sid=live.sid,
                fid=live.fid,
                binding=binding,
            )
        ).consume()
    yield type(
        "LiveSource",
        (),
        {
            "live": live,
            "binding": binding,
            "source_id": source_id,
            "flow_id": flow_id,
            "server_id": server_id,
            "request_id": request_id,
            "receipt": receipt,
            "event_id": event.id,
            "store": store,
        },
    )()


async def _request(
    authenticated, method, path, *, subject=None, role="senior_operator", payload=None
):
    live = authenticated.live
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=live.app),
        base_url="http://testserver",
    ) as client:
        return await client.request(
            method,
            path,
            headers=live.header(subject or live.owner, role),
            json=payload,
        )


async def _prepare(authenticated):
    live = authenticated.live
    produced = await _generate_and_finalize(live)
    report = json.loads(
        Path(produced["report_paths"]["json"]).read_text(encoding="utf-8"),
    )
    assert report["findings"][0]["source_binding"] == authenticated.binding
    assert report["findings"][0]["source_authenticity_verified"] is False
    assert (
        verify_report_files(
            produced["report_paths"],
            evidence_by_finding={live.fid: live.evidence},
            trusted_public_keys={"report-qual-kid": live.public},
        )["source_authenticity_verified"]
        is False
    )
    path = f"/engagements/{live.sid}/attestations/{produced['report_id']}/release"
    body = {
        "expected_authorization_version": 1,
        "expected_attestation_sha256": produced["artifact_sha256"]["attestation"],
        "reason": "Reviewed exact signed evidence snapshot with bounded original provider source.",
        "approval_statement": "I approve releasing this exact signed report snapshot",
    }
    return produced, path, body


async def _prove_signed_source_without_release_lock(authenticated, produced):
    """Actual PG event/dispatch + Neo4j + source Task/Flow verification.

    This independently qualifies the source predicate, not the whole final
    release transaction, which currently has a PostgreSQL lock inversion.
    """
    fx = authenticated
    loaded = load_attested_bundle(fx.live.sid, produced["report_id"])
    sources = {}
    observed = await report_api._graph_evidence(
        fx.live.graph,
        fx.live.sid,
        loaded,
        source_records=sources,
    )
    assert set(observed) == {fx.live.fid}
    signed = await fx.live.memory.assert_signed_authorization(
        fx.live.sid,
        expected_version=1,
    )
    await report_api._verify_signed_finding_sources(
        SimpleNamespace(session_memory=fx.live.memory),
        fx.live.sid,
        loaded,
        sources,
        signed,
    )
    return loaded


@pytest.mark.asyncio
async def test_live_postgres_neo4j_signed_source_proof_is_real_but_not_target_proof(
    authenticated_source,
):
    fx = authenticated_source
    produced, path, _ = await _prepare(fx)
    await _prove_signed_source_without_release_lock(fx, produced)
    # Read-only signed report verification is live and separately guarded:
    # its verification bit intentionally remains false for source authenticity.
    report_response = await _request(fx, "GET", path.removesuffix("/release"))
    assert report_response.status_code == 200, report_response.text
    verified = report_response.json()["verification"]
    assert verified["source_authenticity_verified"] is False
    assert verified["exploit_success_verified"] is False


@pytest.mark.asyncio
async def test_live_signed_source_pg_neo4j_senior_post_get_and_unknown_target_effect(
    authenticated_source,
):
    fx = authenticated_source
    produced, path, body = await _prepare(fx)
    await _prove_signed_source_without_release_lock(fx, produced)
    status_before = await _request(fx, "GET", path)
    assert status_before.status_code == 200, status_before.text
    assert status_before.json()["status"] == "awaiting_human_release"
    assert status_before.json()["external_effect_verified"] is False
    foreign = await _request(fx, "POST", path, subject="other-senior", payload=body)
    assert foreign.status_code == 403
    ordinary = await _request(fx, "POST", path, role="operator", payload=body)
    assert ordinary.status_code == 403
    approved = await _request(fx, "POST", path, payload=body)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "human_release_approved"
    assert approved.json()["operator_approval_recorded"] is True
    assert approved.json()["external_effect_verified"] is False
    assert approved.json()["report_completeness_certified"] is False
    repeated = await _request(fx, "POST", path, payload=body)
    assert repeated.status_code == 200
    assert repeated.json()["release_event_id"] == approved.json()["release_event_id"]
    status = await _request(fx, "GET", path)
    assert status.status_code == 200, status.text
    assert status.json()["operator_approval_recorded"] is True
    assert status.json()["external_effect_verified"] is False
    signed_read = await _request(
        fx,
        "GET",
        path.removesuffix("/release"),
        role="operator",
    )
    assert signed_read.status_code == 200, signed_read.text
    assert signed_read.json()["verification"]["source_authenticity_verified"] is False
    assert signed_read.json()["verification"]["exploit_success_verified"] is False
    assert signed_read.json()["operator_approval_verified"] is False
    artifact = await _request(
        fx,
        "GET",
        path.replace("/release", "/artifacts/json"),
    )
    assert artifact.status_code == 200, artifact.text
    assert artifact.content == Path(produced["report_paths"]["json"]).read_bytes()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "graph_event",
        "graph_receipt",
        "graph_tenant",
        "flow_paused",
        "task_unknown",
        "task_evidence_changed",
        "enrolled_signer_revoked",
        "signed_roe_revoked",
    ],
)
async def test_live_source_revocation_and_mutation_invalidates_release(
    authenticated_source,
    monkeypatch,
    mutation,
):
    fx = authenticated_source
    live = fx.live
    produced, path, body = await _prepare(fx)
    await _prove_signed_source_without_release_lock(fx, produced)
    if mutation.startswith("graph_"):
        change = {
            "graph_event": ("source_event_id", "evt-forged"),
            "graph_receipt": ("provider_receipt_sha256", "f" * 64),
            "graph_tenant": ("source_task_id", "task-foreign-tenant"),
        }[mutation]
        async with live.graph._driver.session() as db:
            await (
                await db.run(
                    f"MATCH (v:Vulnerability {{engagement_id:$sid, id:$fid}}) "
                    f"SET v.{change[0]}=$changed",
                    sid=live.sid,
                    fid=live.fid,
                    changed=change[1],
                )
            ).consume()
    elif mutation == "flow_paused":
        async with live.memory._async_session() as db, db.begin():
            await db.execute(
                update(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == fx.flow_id,
                )
                .values(status="paused")
            )
    elif mutation in {"task_unknown", "task_evidence_changed"}:
        async with live.memory._async_session() as db, db.begin():
            values = (
                {"status": "dispatch_unknown"}
                if mutation == "task_unknown"
                else {"result": {"status": "success", "evidence_sha256": "0" * 64}}
            )
            await db.execute(
                update(TaskORM)
                .where(
                    TaskORM.id == fx.source_id,
                )
                .values(**values)
            )
    elif mutation == "enrolled_signer_revoked":
        monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "{}")
    elif mutation == "signed_roe_revoked":
        assert await AuthorizationStore(live.memory).revoke(
            live.sid,
            live.owner,
            1,
            "Disposable qualification signed policy revoked",
        )
    if mutation == "signed_roe_revoked":
        from ai_osop.memory.authorization_store import AuthorizationDenied

        with pytest.raises(AuthorizationDenied):
            await live.memory.assert_signed_authorization(live.sid, expected_version=1)
        lookup = await _request(fx, "GET", path)
        assert lookup.status_code == 403, lookup.text
    else:
        with pytest.raises(AttestedStorageUnavailable, match="manual draft only"):
            await _prove_signed_source_without_release_lock(fx, produced)
