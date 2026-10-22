"""Disposable-only, real PostgreSQL + Neo4j signed-report release qualification.

Runs the actual ReportingAgent producer, the real TerminalLifecycleStore
transactional TaskORM receipt and an authenticated FastAPI v2 read endpoint.
The synthetic graph is a *fixture*, not a tested target or exploit result.

Opt in explicitly, using ONLY newly created disposable localhost services::

  OSOP_REPORT_RELEASE_TEST_PG_URI=postgresql+asyncpg://report_qual:...@127.0.0.1:15696/report_release_qualification_worker7
  OSOP_REPORT_RELEASE_TEST_NEO4J_URI=bolt://127.0.0.1:17696
  OSOP_REPORT_RELEASE_TEST_NEO4J_PASSWORD=report_qual_only
  python -m pytest tests/qualification/test_live_signed_report_release_pipeline.py -q --no-cov

No calls to application database, real targets, an IdP or a remote model.
This covers an already-admitted synthetic running Task, not the complete
task-dispatch/human-interaction workflow or a final operator sign-off.
"""

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from jose import jwt
from neo4j import AsyncGraphDatabase
from sqlalchemy import select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.api.deps import state
from ai_osop.api.routers.report_attestations import router as attestation_router
from ai_osop.core.config import AgentType, settings
from ai_osop.core.models import Task
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import ApprovalRequestORM, SessionMemory, TaskORM
from ai_osop.memory.supervision_store import SupervisionConflict
from ai_osop.memory.terminal_lifecycle import TerminalLifecycleStore
from ai_osop.reporting.attestation import verify_report_files
from ai_osop.safety.approval_binding import pinned_evidence
from tests.test_authorization_store import make_signed_session


def _disposable_pg_url():
    raw = os.environ.get("OSOP_REPORT_RELEASE_TEST_PG_URI", "")
    if not raw:
        pytest.skip("No explicitly configured disposable report-release PostgreSQL")
    parsed = make_url(raw)
    if (
        parsed.drivername != "postgresql+asyncpg"
        or parsed.host not in {"127.0.0.1", "localhost"}
        or parsed.port in {None, 5432, 5433}
        or not (parsed.database or "").startswith("report_release_qualification_")
    ):
        pytest.fail("Refusing non-disposable PostgreSQL URL")
    return raw


def _disposable_neo4j():
    raw = os.environ.get("OSOP_REPORT_RELEASE_TEST_NEO4J_URI", "")
    if not raw:
        pytest.skip("No explicitly configured disposable report-release Neo4j")
    from urllib.parse import urlsplit
    value = urlsplit(raw)
    if (
        value.scheme != "bolt" or value.hostname not in {"127.0.0.1", "localhost"}
        or value.port in {None, 7687} or value.username or value.password
        or value.path not in {"", "/"} or value.query or value.fragment
    ):
        pytest.fail("Refusing non-disposable Neo4j URL")
    password = os.environ.get("OSOP_REPORT_RELEASE_TEST_NEO4J_PASSWORD")
    if not password:
        pytest.fail("Explicit disposable Neo4j credential required")
    return raw, password


def _migration(connection):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


@pytest.fixture
async def live_services(monkeypatch, tmp_path):
    """Exclusive synthetic owner/graph prefix inside separate disposable stores."""
    uri = _disposable_pg_url()
    neo_uri, neo_password = _disposable_neo4j()
    engine = create_async_engine(uri, pool_size=5)
    graph = GraphMemory()
    graph._driver = AsyncGraphDatabase.driver(neo_uri, auth=("neo4j", neo_password))
    try:
        await graph._driver.verify_connectivity()
        async with engine.begin() as db:
            await db.run_sync(_migration)
        memory = SessionMemory.__new__(SessionMemory)
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        suffix = uuid.uuid4().hex[:12]
        sid = "eng-reportqual-" + suffix
        tid = "task-reportqual-" + suffix
        fid = "vuln-reportqual-" + suffix
        owner = "report-owner-" + suffix
        session, signed, _, _ = make_signed_session(
            monkeypatch, session_id=sid, owner=owner,
            authorization_id="auth-reportqual-" + suffix,
        )
        session.phase = "reporting"
        await AuthorizationStore(memory).create_authorized_session(session, signed, owner)

        evidence = [{
            "type": "http", "event_id": "evt-synthetic-qual", "raw": "FAKE-SECRET-IN-RESTRICTED-EVIDENCE",
        }]
        # Real Neo4j graph node (not GraphMemory mocked data), never contacted
        # network targets. Every ID is unique and subsequently deleted.
        async with graph._driver.session() as db:
            await (await db.run(
                "CREATE (v:Vulnerability {id: $fid, engagement_id: $sid, "
                "validated: true, title: 'Synthetic recorded finding', "
                "severity: 'LOW', vuln_type: 'synthetic', "
                "evidence: $evidence}) RETURN v.id AS id",
                fid=fid, sid=sid, evidence=json.dumps(evidence),
            )).consume()

        signer = Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
        )
        pem = signer.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        signer_file = tmp_path / "report_private.pem"
        signer_file.write_bytes(pem)
        monkeypatch.setenv("OSOP_REPORT_SIGNING_KEY_FILE", str(signer_file))
        monkeypatch.setenv(
            "OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON",
            json.dumps({"report-qual-kid": base64.b64encode(public).decode()}),
        )
        monkeypatch.setenv("OSOP_ATTESTED_REPORT_ROOT", str((tmp_path / "reports").resolve()))
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(settings, "environment", "production")
        monkeypatch.setattr(settings, "jwt_secret", "synthetic-local-qualification-secret")
        monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
        monkeypatch.setattr(settings, "jwt_issuer", None)
        monkeypatch.setattr(settings, "jwt_audience", None)

        payload = {
            "version": "v1", "require_attestation": True,
            "signer_key_id": "report-qual-kid", "_authorization_version": 1,
            "approval_id": "apr-reportqual-" + suffix, "operator_approved": True,
        }
        task = Task(
            id=tid, engagement_id=sid, type="generate_report", priority=5,
            agent_type=AgentType.REPORTING, status="running", payload=payload,
            approval_required=True, assigned_agent_id="qualification-report-agent",
            started_at=datetime.utcnow(),
        )
        # The fixture deliberately starts at the already-authorized, claimed
        # Task boundary. TerminalLifecycleStore must then independently check
        # the persisted payload-bound approval and current signed ROE.
        async with memory._async_session() as db:
            async with db.begin():
                db.add(TaskORM(
                    id=tid, engagement_id=sid, type=task.type,
                    agent_type=task.agent_type.value, status=task.status,
                    priority=task.priority, payload=payload,
                    dependencies=[], max_retries=0, timeout_seconds=300,
                    scope_check=True, approval_required=True,
                    result=None, retry_count=0,
                    created_at=task.created_at, started_at=task.started_at,
                    assigned_agent_id=task.assigned_agent_id,
                ))
                db.add(ApprovalRequestORM(
                    id=payload["approval_id"], engagement_id=sid, task_id=tid,
                    status="approved", agent_id=task.assigned_agent_id,
                    action_type="generate_report", target="authorized.example",
                    payload_summary="Synthetic approved reporting task",
                    risk_assessment="No target-side operations", evidence=pinned_evidence([], payload),
                    operator_id=owner, requested_at=datetime.utcnow(),
                    responded_at=datetime.utcnow(),
                ))
        ctx = SimpleNamespace(
            current_task=task, session_id=sid, agent_id=task.assigned_agent_id,
            session_memory=memory, graph_memory=graph,
        )
        agent = ReportingAgent(ctx)
        await agent._setup_resources()
        app = FastAPI()
        app.include_router(attestation_router)
        monkeypatch.setitem(state, "orchestrator", SimpleNamespace(
            session_memory=memory, graph_memory=graph,
        ))

        def _header(subject=owner, role="operator"):
            bearer = jwt.encode({
                "sub": subject, "role": role,
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            }, settings.jwt_secret, algorithm="HS256")
            return {"Authorization": "Bearer " + bearer}

        yield SimpleNamespace(
            engine=engine, memory=memory, graph=graph,
            sid=sid, tid=tid, fid=fid, owner=owner, signed=signed,
            task=task, agent=agent, ctx=ctx, evidence=evidence,
            lifecycle=TerminalLifecycleStore(memory),
            app=app, header=_header, public=public,
        )
    finally:
        # This fixture may remove only its own synthetic graph node. The
        # disposable database/container lifecycle is managed separately.
        if "sid" in locals():
            try:
                async with graph._driver.session() as db:
                    await (await db.run(
                        "MATCH (v:Vulnerability {engagement_id:$sid}) WHERE v.id=$fid DETACH DELETE v",
                        sid=sid, fid=fid,
                    )).consume()
            except Exception:
                pass
        await graph._driver.close()
        await engine.dispose()


async def _generate_and_finalize(live):
    produced = await live.agent._generate_report(live.task.payload)
    assert produced["signature_status"] == "ed25519_signed"
    assert set(produced["artifact_sha256"]) == {
        "md", "html", "graph.html", "json", "attestation", "manifest",
    }
    assert verify_report_files(
        produced["report_paths"],
        evidence_by_finding={live.fid: live.evidence},
        trusted_public_keys={"report-qual-kid": live.public},
    )["status"] == "signature_and_snapshot_verified"
    assert json.loads(Path(produced["report_paths"]["attestation"]).read_bytes())[
        "attestation"
    ]["schema"] == "ai-osop-report-attestation-v2"

    attempt = await live.lifecycle.start_attempt(
        live.sid, live.tid, 1, status="running",
    )
    committed = await live.lifecycle.commit_terminal(
        live.sid, live.tid, attempt["id"], 0, "succeeded",
        continuation=produced,
    )
    assert committed is not None and committed["created"]
    async with live.memory._async_session() as db:
        saved = (await db.execute(select(TaskORM).where(TaskORM.id == live.tid))).scalar_one()
        assert saved.status == "completed" and saved.completed_at is not None
        assert saved.result == {
            "status": "success", "signature_status": "ed25519_signed",
            "report_id": produced["report_id"], "requires_approval": True,
            "artifact_sha256": produced["artifact_sha256"],
        }
        assert "report_paths" not in str(saved.result)
        assert "FAKE-SECRET-IN-RESTRICTED-EVIDENCE" not in str(saved.result)
    return produced


async def _get(live, report_id, *, subject=None, role="operator"):
    # TestClient spawns a separate event loop that cannot safely reuse real
    # asyncpg/Neo4j drivers already created on the pytest event loop.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=live.app), base_url="http://testserver",
    ) as client:
        return await client.get(
            f"/engagements/{live.sid}/attestations/{report_id}",
            headers=live.header(live.owner if subject is None else subject, role),
        )


@pytest.mark.asyncio
async def test_live_producer_to_terminal_receipt_to_owner_authenticated_v2_read(live_services):
    live = live_services
    produced = await _generate_and_finalize(live)
    response = await _get(live, produced["report_id"])
    assert response.status_code == 200, response.text
    verified = response.json()
    assert verified["release_status"] == "signed_report_task_snapshot_verified"
    assert verified["signed_attestation"]["attestation"]["engagement_id"] == live.sid
    assert verified["verification"]["evidence_records_checked"] == 1
    assert verified["operator_approval_verified"] is False
    assert verified["engagement_completion_verified"] is False
    assert verified["verification"]["exploit_success_verified"] is False
    assert "FAKE-SECRET-IN-RESTRICTED-EVIDENCE" not in response.text
    assert "report_paths" not in response.text
    assert (await live.lifecycle.list_callbacks(live.sid, live.tid))

    denied = await _get(live, produced["report_id"], subject="unrelated-operator")
    assert denied.status_code == 403
    senior = await _get(live, produced["report_id"], subject="unrelated-senior", role="senior_operator")
    assert senior.status_code == 200


@pytest.mark.asyncio
async def test_live_signed_report_senior_cannot_release_unattributed_graph_finding(live_services):
    """Real PG+Neo4j signed *draft* is insufficient for senior release.

    The synthetic Vulnerability node lacks independently verified signed MCP
    provider/source lineage. An approver's explicit intent does not invent
    those missing facts. This fixture must never demonstrate a successful
    release until it includes a real source-attested chain.
    """
    live = live_services
    produced = await _generate_and_finalize(live)
    rid = produced["report_id"]
    path = f"/engagements/{live.sid}/attestations/{rid}/release"
    payload = {
        "expected_authorization_version": 1,
        "expected_attestation_sha256": produced["artifact_sha256"]["attestation"],
        "reason": "Synthetic report digests and signed ownership checked before final release.",
        "approval_statement": "I approve releasing this exact signed report snapshot",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=live.app),
        base_url="http://testserver",
    ) as client:
        before = await client.get(path, headers=live.header(live.owner, "senior_operator"))
        # Release status itself requires current independent source proof;
        # legacy synthetic graph evidence has no such proof and yields 503.
        assert before.status_code == 503, before.text

        impostor = await client.post(
            path, headers=live.header("foreign-senior", "senior_operator"),
            json=payload,
        )
        assert impostor.status_code == 403
        ordinary = await client.post(
            path, headers=live.header(live.owner, "operator"), json=payload,
        )
        assert ordinary.status_code == 403

        first = await client.post(
            path, headers=live.header(live.owner, "senior_operator"),
            json=payload,
        )
        assert first.status_code == 503, first.text
        assert "FAKE-SECRET-IN-RESTRICTED-EVIDENCE" not in first.text

        repeated = await client.post(
            path, headers=live.header(live.owner, "senior_operator"),
            json=payload,
        )
        assert repeated.status_code == 503, repeated.text
        ordinary_read = await client.get(
            path, headers=live.header(live.owner, "operator"),
        )
        assert ordinary_read.status_code == 403
        recovered = await client.get(
            path, headers=live.header(live.owner, "senior_operator"),
        )
        assert recovered.status_code == 503, recovered.text


@pytest.mark.asyncio
async def test_live_evidence_mutation_invalidates_verified_v2_release(live_services):
    live = live_services
    produced = await _generate_and_finalize(live)
    assert (await _get(live, produced["report_id"])).status_code == 200
    async with live.graph._driver.session() as db:
        await (await db.run(
            "MATCH (v:Vulnerability {engagement_id:$sid, id:$fid}) "
            "SET v.evidence=$changed",
            sid=live.sid, fid=live.fid,
            changed=json.dumps([{"type": "http", "raw": "changed-after-signature"}]),
        )).consume()
    rejected = await _get(live, produced["report_id"])
    assert rejected.status_code == 503
    assert "changed-after-signature" not in rejected.text


@pytest.mark.asyncio
async def test_live_validated_flag_revocation_blocks_original_evidence(live_services):
    live = live_services
    produced = await _generate_and_finalize(live)
    assert (await _get(live, produced["report_id"])).status_code == 200
    async with live.graph._driver.session() as db:
        await (await db.run(
            "MATCH (v:Vulnerability {engagement_id:$sid, id:$fid}) SET v.validated=false",
            sid=live.sid, fid=live.fid,
        )).consume()
    assert (await _get(live, produced["report_id"])).status_code == 503


@pytest.mark.asyncio
async def test_live_completed_task_artifact_receipt_mismatch_denies_v2(live_services):
    live = live_services
    produced = await _generate_and_finalize(live)
    assert (await _get(live, produced["report_id"])).status_code == 200
    altered_hashes = dict(produced["artifact_sha256"])
    altered_hashes["manifest"] = "0" * 64
    async with live.memory._async_session() as db:
        async with db.begin():
            await db.execute(update(TaskORM).where(TaskORM.id == live.tid).values(
                result={
                    "status": "success", "signature_status": "ed25519_signed",
                    "report_id": produced["report_id"], "requires_approval": True,
                    "artifact_sha256": altered_hashes,
                },
            ))
    assert (await _get(live, produced["report_id"])).status_code == 503


@pytest.mark.asyncio
async def test_live_task_terminal_receipt_or_signed_roe_revocation_blocks_release(live_services):
    live = live_services
    produced = await _generate_and_finalize(live)
    assert (await _get(live, produced["report_id"])).status_code == 200
    async with live.memory._async_session() as db:
        async with db.begin():
            await db.execute(update(TaskORM).where(TaskORM.id == live.tid).values(
                status="dispatch_unknown", result={"reason": "remote_outcome_unverified"},
            ))
    assert (await _get(live, produced["report_id"])).status_code == 503
    async with live.memory._async_session() as db:
        async with db.begin():
            await db.execute(update(TaskORM).where(TaskORM.id == live.tid).values(
                status="completed", result={
                    "status": "success", "signature_status": "ed25519_signed",
                    "report_id": produced["report_id"], "requires_approval": True,
                    "artifact_sha256": produced["artifact_sha256"],
                },
            ))
    assert await AuthorizationStore(live.memory).revoke(
        live.sid, live.owner, 1, "Isolated report qualification revoked",
    )
    assert (await _get(live, produced["report_id"])).status_code == 403


@pytest.mark.asyncio
async def test_live_terminal_rejects_missing_signed_receipt_without_completion(live_services):
    live = live_services
    attempt = await live.lifecycle.start_attempt(live.sid, live.tid, 1, status="running")
    with pytest.raises(SupervisionConflict, match="artifact receipts"):
        await live.lifecycle.commit_terminal(
            live.sid, live.tid, attempt["id"], 0, "succeeded",
            continuation={"status": "success", "signature_status": "ed25519_signed"},
        )
    async with live.memory._async_session() as db:
        row = (await db.execute(select(TaskORM).where(TaskORM.id == live.tid))).scalar_one()
        assert row.status == "running" and row.result is None
