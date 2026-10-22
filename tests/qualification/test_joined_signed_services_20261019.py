"""One-process, one-engagement LIVE joined PostgreSQL/Redis/Neo4j/Temporal check.

OPT IN (PowerShell):
    $env:OSOP_DISPOSABLE_JOINED_RECOVERY='1'
    $env:OSOP_DISPOSABLE_REDIS_GRAPH_20261018='1'
    python -m pytest -q -o addopts= tests/qualification/test_joined_signed_services_20261019.py

Both imported Docker fixtures allocate unique containers with random loopback
ports, use only cached images, and remove only their own containers. No live
assessment target, application database, model, or independently operated
witness is used. Graph candidates and synthetic workflow results are NEVER
an independent verified target effect or approval to release a report.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from redis.exceptions import RedisError

from ai_osop.core.models import EvidenceArtifact
from ai_osop.memory.authorization_store import AuthorizationDenied
from ai_osop.memory.graph_research_context import GraphResearchDenied
from ai_osop.memory.supervision_store import SupervisionConflict
from ai_osop.memory.session_memory import (
    MemoryException,
    evidence_artifact_leaf_sha256,
)
from ai_osop.orchestrator.recovery_service import RecoveryService
from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler
from tests.qualification.joined_recovery_fixture_20261018 import (
    disposable_recovery_services,
    joined_signed_pg,
)
from tests.qualification.joined_redis_graph_fixture_20261018 import (
    disposable_redis_graph_services,
    joined_redis_graph,
)
from tests.qualification.test_joined_signed_recovery_faults_20261018 import (
    _assert_real_0022_unknown,
)
from tests.qualification.test_live_temporal_admission_recovery import _local_worker


def _graph_receipt(pg: SimpleNamespace, correlation: str, signed_digest: str) -> dict:
    """An inert *candidate* tied to our PG engagement; synthetic MCP metadata."""
    return {
        "id": "action-" + correlation,
        "engagement_id": pg.session.session_id,
        "flow_id": pg.flow.id,
        "source_task_id": pg.task.id,
        "source_event_id": pg.source_event_id,
        "flow_revision": 0,
        "authorization_version": 1,
        "authorization_sha256": signed_digest,
        "source_task_sha256": hashlib.sha256(pg.task.id.encode()).hexdigest(),
        "receipt_sha256": hashlib.sha256((correlation + "receipt").encode()).hexdigest(),
        "provider_receipt_sha256": hashlib.sha256((correlation + "provider").encode()).hexdigest(),
        "provider_signer_key_sha256": hashlib.sha256((correlation + "key").encode()).hexdigest(),
        "provider_server_id": "local-synthetic-no-provider",
        "provider_signing_kid": "no-real-signer",
        "tool_kind": "http",
        "outcome": "succeeded",
    }


@pytest.mark.asyncio
@pytest.mark.timeout(180)
async def test_live_four_service_same_signed_engagement_unknown_survives_faults(
    joined_signed_pg: SimpleNamespace,
    joined_redis_graph: SimpleNamespace,
) -> None:
    """All actual I/O below shares one signed Flow/Task/correlation in this test."""
    from temporalio.client import Client

    pg = joined_signed_pg
    rg = joined_redis_graph
    memory = pg.memory  # Production SessionMemory, real disposable PostgreSQL.
    memory._redis = rg.memory._redis  # Same instance now reaches real isolated Redis.
    graph = rg.graph  # Production GraphMemory, real isolated Neo4j.
    suffix = uuid.uuid4().hex[:12]
    queue_name = "tasks:" + pg.session.session_id
    lock_key = "lock:joined:" + pg.session.session_id

    # The fixtures must have actually migrated the brand-new database through
    # 0024 and attached the two other fresh services before any assertions.
    async with memory._async_session() as db:
        version = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
        trigger = (
            await db.execute(
                text(
                    "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE "
                    "tgrelid=to_regclass('evidence_artifacts') "
                    "AND tgname='trg_evidence_artifacts_immutable' AND NOT tgisinternal)"
                )
            )
        ).scalar_one()
    assert version == "0024" and trigger is True
    signed = await memory.assert_signed_authorization(pg.session.session_id, expected_version=1)
    assert signed.version == 1
    assert await memory.acquire_lock(lock_key, "worker-joined-owner", ttl_seconds=45)
    assert not await memory.acquire_lock(lock_key, "worker-joined-other", ttl_seconds=45)

    # Graph projection is physically stored, scoped, and deduplicated, but the
    # actual PG event is NOT an MCP signature. Do not invent such proof.
    receipt = _graph_receipt(pg, suffix, signed.policy_sha256)
    assert await graph.project_signed_tool_action(receipt)
    assert await graph.project_signed_tool_action(receipt)
    candidates = await graph.read_signed_research_candidates(
        pg.session.session_id, pg.flow.id, 1, signed.policy_sha256
    )
    assert [candidate["id"] for candidate in candidates] == [receipt["id"]]
    assert (
        await graph.read_signed_research_candidates(
            "eng-foreign-" + suffix, pg.flow.id, 1, signed.policy_sha256
        )
        == []
    )
    with pytest.raises(GraphResearchDenied, match="independent success proof"):
        await memory.verify_signed_graph_action(
            pg.session.session_id,
            pg.task.id,
            pg.source_event_id,
            receipt["provider_receipt_sha256"],
            1,
        )

    # Pending Task cannot forge a sourced evidence artifact, even with a
    # correctly shaped redacted recipe. The committed PG ledger stays empty.
    source_url = "https://authorized.example/resource"
    raw_digest = hashlib.sha256(b"local synthetic digest only").hexdigest()
    artifact_id = (
        "ev-"
        + hashlib.sha256(
            b"ai-osop-joined-duplicate-artifact-v1\x00"
            + "|".join(
                (
                    pg.session.session_id,
                    "finding-" + suffix,
                    pg.task.id,
                    pg.source_event_id,
                    raw_digest,
                )
            ).encode()
        ).hexdigest()[:32]
    )
    artifact = EvidenceArtifact(
        id=artifact_id,
        engagement_id=pg.session.session_id,
        finding_id="finding-" + suffix,
        source_tool="local-test",
        target_url=source_url,
        request_headers_sha256=raw_digest,
        request_body_sha256=raw_digest,
        response_status=200,
        response_headers_sha256=raw_digest,
        response_body_sha256=raw_digest,
        merkle_leaf_hash=raw_digest,
        replay_recipe={
            "schema": "ai-osop.redacted-evidence-reference.v1",
            "replayable": False,
            "finding_verified": False,
            "target_effect_verified": False,
            "source_task_id": pg.task.id,
            "method": "GET",
            "url": source_url,
            "original_url_sha256": hashlib.sha256(source_url.encode()).hexdigest(),
            "request_body_sha256": raw_digest,
            "request_header_names": [],
        },
    )
    artifact.merkle_leaf_hash = evidence_artifact_leaf_sha256(artifact)
    with pytest.raises(MemoryException, match="current signed Task"):
        await memory.record_evidence_artifact(artifact, source_task_id=pg.task.id)

    # Demonstrate the actual 0024 PRIMARY KEY/immutability behavior for two
    # deliveries of exactly the same deterministic artifact ID. Both test-only
    # SQL attempts are inside a manually ROLLED BACK transaction; neither
    # bypasses production source admission or leaves fabricated evidence.
    direct_insert = text(
        "INSERT INTO evidence_artifacts (id,engagement_id,finding_id,source_tool,"
        "target_url,request_headers_sha256,request_body_sha256,response_status,"
        "response_headers_sha256,response_body_sha256,merkle_leaf_hash,replay_recipe) "
        "VALUES (:id,:eng,:finding,:tool,:url,:headers,:body,:status,:rheaders,"
        ":rbody,:leaf,CAST('{}' AS JSON))"
    )
    inserted = {
        "id": artifact.id,
        "eng": pg.session.session_id,
        "finding": artifact.finding_id,
        "tool": artifact.source_tool,
        "url": artifact.target_url,
        "headers": artifact.request_headers_sha256,
        "body": artifact.request_body_sha256,
        "status": artifact.response_status,
        "rheaders": artifact.response_headers_sha256,
        "rbody": artifact.response_body_sha256,
        "leaf": artifact.merkle_leaf_hash,
    }
    async with pg.engine.connect() as conn:
        disposable_transaction = await conn.begin()
        try:
            await conn.execute(direct_insert, inserted)
            with pytest.raises(IntegrityError):
                async with conn.begin_nested():
                    await conn.execute(direct_insert, inserted)
            with pytest.raises(DBAPIError):
                async with conn.begin_nested():
                    await conn.execute(
                        text(
                            "UPDATE evidence_artifacts SET source_tool='tampered' " "WHERE id=:id"
                        ),
                        {"id": artifact.id},
                    )
            assert (
                await conn.execute(
                    text("SELECT count(*) FROM evidence_artifacts WHERE id=:id"),
                    {"id": artifact.id},
                )
            ).scalar_one() == 1
        finally:
            await disposable_transaction.rollback()
    async with memory._async_session() as db:
        assert (
            await db.execute(
                text("SELECT count(*) FROM evidence_artifacts WHERE engagement_id=:eng"),
                {"eng": pg.session.session_id},
            )
        ).scalar_one() == 0

    # Real Temporal server/worker accepts one harmless local workflow. Simulate
    # losing its acknowledgement AFTER acceptance and persist uncertainty in PG.
    client = await asyncio.wait_for(Client.connect(pg.temporal_address), timeout=12)
    claim = await memory.claim_temporal_dispatch(pg.task)
    assert claim.startswith("temporal-claim-")
    task_queue = "joined-all-" + suffix
    invocations: list[str] = []

    async def accepted_ack_lost(*args, **kwargs):
        await client.start_workflow(*args, **kwargs)
        raise TimeoutError("injected ack loss after accepted Temporal start")

    interrupted = TemporalTaskScheduler(
        client=SimpleNamespace(start_workflow=accepted_ack_lost), task_queue=task_queue
    )
    normal = TemporalTaskScheduler(client=client, task_queue=task_queue)
    payload = {"id": pg.task.id, "timeout_seconds": 10}
    async with _local_worker(client, task_queue, counter=invocations):
        with pytest.raises(TimeoutError, match="ack loss"):
            await interrupted.start_task_workflow(payload)
        assert await normal.start_task_workflow(payload) == "ai-osop-" + pg.task.id
        result = await asyncio.wait_for(
            client.get_workflow_handle("ai-osop-" + pg.task.id).result(), timeout=20
        )
        assert result == {"status": "synthetic_complete", "remote_targets": 0}
    assert invocations == ["invoked"]
    await memory.settle_temporal_dispatch(
        pg.task.id, pg.session.session_id, claim, "dispatch_unknown"
    )
    assert (await memory.load_task_authoritative(pg.task.id)).status == "dispatch_unknown"
    with pytest.raises(PermissionError):
        await memory.claim_temporal_dispatch(pg.task)

    # Read recovery directly from signed PG while live Redis/Neo4j exist. No
    # queue admission can occur for an UNKNOWN task even after a worker restart.
    orch = SimpleNamespace(session_memory=memory, graph_memory=graph, _sessions={}, _tasks={})
    replay = await RecoveryService(orch).recover_state()
    assert replay["unresolved"] == 1 and replay["tasks"] == 0
    assert await memory.pop_task_queue(queue_name) is None

    # Physical Redis outage is scoped to our newly created container only.
    # Redis reconnect remains pinned to its random loopback port; durable PG
    # UNKNOWN and the graph candidate cannot bypass one-shot signed admission.
    rg.services.redis_container.stop(timeout=2)
    with pytest.raises(RedisError):
        await asyncio.wait_for(memory.push_task_queue(queue_name, pg.task.model_dump()), timeout=5)
    after_redis_loss = await RecoveryService(orch).recover_state()
    assert after_redis_loss["unresolved"] == 1 and after_redis_loss["tasks"] == 0
    assert (await memory.load_task_authoritative(pg.task.id)).status == "dispatch_unknown"
    await _assert_real_0022_unknown(pg)

    assert await pg.authority.revoke(
        pg.session.session_id,
        pg.session.created_by,
        1,
        "Fresh isolated qualification signed ROE revocation",
    )
    with pytest.raises(AuthorizationDenied):
        await memory.assert_signed_authorization(pg.session.session_id, expected_version=1)
    with pytest.raises(SupervisionConflict, match="not active"):
        await memory.claim_temporal_dispatch(pg.task)
    # 0022 witness table stayed empty throughout the joined run; no signed
    # observation, review, verified target effect, or release was manufactured.
    async with memory._async_session() as db:
        assert (
            await db.execute(
                text(
                    "SELECT count(*) FROM independent_target_effect_verifications "
                    "WHERE engagement_id=:eng"
                ),
                {"eng": pg.session.session_id},
            )
        ).scalar_one() == 0
        assert (
            await db.execute(
                text("SELECT count(*) FROM evidence_artifacts WHERE engagement_id=:eng"),
                {"eng": pg.session.session_id},
            )
        ).scalar_one() == 0
