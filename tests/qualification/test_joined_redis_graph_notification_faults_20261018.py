"""Redis/Neo4j research and signed recovery fault qualification.

Default mode: deterministic injected faults exercising production methods.
OSOP_DISPOSABLE_REDIS_GRAPH_20261018=1 adds real fresh Redis 7/Neo4j 5
containers on random loopback-only ports. Signed ROE/notification SQL authority
is injected, NOT a live PostgreSQL/Temporal or external effect verifier.
"""

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.outbox_delivery_dedupe import OutboxConsumerUnavailable
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.coordination_bus import CoordinationEvent
from ai_osop.orchestrator.recovery_service import RecoveryService
from ai_osop.orchestrator.terminal_dispatcher import TerminalCallbackDispatcher
from tests.qualification.joined_redis_graph_fixture_20261018 import (
    disposable_redis_graph_services,
    joined_redis_graph,
)
from tests.test_outbox_cross_replica_idempotency import (
    _claims,
    _completed,
    _event,
    _expire_claim,
)
from tests.test_outbox_readback_identity_20261018 import _IdentityStore, _consumer
from tests.qualification.test_joined_signed_recovery_faults_20261018 import (
    _NoPromotion,
    _independent_unknown,
)
from tests.test_authorization_store import make_signed_session
from tests.test_restart_current_flow_authority_20261019 import (
    _recovery as _locked_pg_recovery,
)


def _recovery(memory, *, suffix, status="pending", revoked=False):
    """Production RecoveryService with injected authoritative PG list/check."""
    eid = "eng-rg-" + suffix
    task = Task(
        id="task-rg-" + suffix,
        type="summarize_context",
        agent_type=AgentType.CONTEXT_MANAGER,
        engagement_id=eid,
        status=status,
        payload={"_authorization_version": 1},
    )
    scope = ScopeDefinition(
        engagement_id=eid,
        domains=["invalid.example.test"],
        authorization_ref="synthetic-only-NOT-a-signed-authority",
    )
    session = SessionState(session_id=eid, scope=scope, phase="reconnaissance")
    memory.list_all_sessions = AsyncMock(return_value=[session])
    memory.list_all_tasks = AsyncMock(return_value=[task])

    async def signed_check(engagement_id, *, expected_version):
        assert engagement_id == eid and expected_version == 1
        if revoked:
            raise PermissionError("injected signed PG policy revoked")
        return SimpleNamespace(version=1)

    memory.assert_signed_authorization = AsyncMock(side_effect=signed_check)
    orchestrator = SimpleNamespace(session_memory=memory, _sessions={}, _tasks={})
    return RecoveryService(orchestrator), task


@pytest.mark.asyncio
async def test_injected_graph_partition_denies_signed_research_without_partial_context():
    """INJECTED failure, not a real Neo4j network partition."""
    graph = GraphMemory()
    with pytest.raises(RuntimeError, match="unavailable"):
        await graph.read_signed_research_candidates(
            "eng-rg-unit",
            "flow-rg-unit",
            1,
            "a" * 64,
        )
    # Missing graph authority is neither a verified effect nor an instruction
    # to automatically repeat an ambiguous external call.
    with pytest.raises(ValueError, match="Malformed"):
        await graph.project_signed_tool_action({"id": "action-rg-unit"})


@pytest.mark.asyncio
async def test_injected_terminal_graph_failure_is_unknown_not_automatically_replayed():
    """INJECTED possible-commit error in production TerminalCallbackDispatcher."""
    item = {
        "id": "cb-rg-injected",
        "engagement_id": "eng-rg-injected",
        "task_id": "task-rg-injected",
        "lease_id": "lease-rg-injected",
    }
    store = SimpleNamespace(
        claim_callbacks=AsyncMock(side_effect=[[item], []]),
        renew_callback_lease=AsyncMock(return_value=True),
        finish_callback=AsyncMock(return_value=True),
    )
    dispatcher = TerminalCallbackDispatcher(SimpleNamespace(terminal_store=store))
    dispatch = AsyncMock(side_effect=OSError("graph write ACK lost after uncertain commit"))
    dispatcher._project_with_owner_monitor = dispatch
    assert await dispatcher.flush_once() == 0
    store.finish_callback.assert_awaited_once_with(item["id"], item["lease_id"], status="unknown")
    assert await dispatcher.flush_once() == 0
    dispatch.assert_awaited_once_with(item)


@pytest.mark.asyncio
async def test_injected_duplicate_notification_receipt_and_lost_ack_stays_unknown():
    """INJECTED SQL source/claim ledger; real production consumer logic."""
    store = _IdentityStore()
    side_effect = AsyncMock()

    async def callback_then_lose_ack(event):
        await side_effect(event)
        _expire_claim(store)

    with pytest.raises(OutboxConsumerUnavailable, match="expired"):
        await _consumer(store).consume(_event(), callback_then_lose_ack)
    assert not _completed(store) and len(_claims(store)) == 1
    # No automatic redelivery occurs; the explicit operator/test retry is
    # at-least-once and subject to a fresh lease + durable receipt.
    side_effect.assert_awaited_once()
    assert await _consumer(store).consume(_event(), side_effect)
    assert await _consumer(store).consume(_event(), side_effect) is False
    assert len(_completed(store)) == 1 and side_effect.await_count == 2


@pytest.mark.asyncio
async def test_injected_recovery_does_not_enqueue_revoked_or_unknown_tasks():
    """INJECTED signed PG read; Redis queue is an audited no-op."""
    for status, revoked in (("pending", True), ("dispatch_unknown", False)):
        memory = SessionMemory()
        memory.push_task_queue = AsyncMock()
        service, task = _recovery(
            memory, suffix=uuid.uuid4().hex[:10], status=status, revoked=revoked
        )
        observed = await service.recover_state()
        assert observed["tasks"] == 0
        assert observed["unresolved" if status == "dispatch_unknown" else "skipped"] == 1
        memory.push_task_queue.assert_not_awaited()
        assert service._orch._tasks[task.id].id == task.id


@pytest.mark.asyncio
async def test_missing_pg_admission_fails_closed_before_any_redis_partition():
    """INJECTED missing PG transaction; no Redis partition has been exercised.

    The synthetic ROE precheck alone cannot publish a recovery hint. Production
    now demands another current signed/Task/Flow check inside the PG row locks;
    this fixture has no SQL session and must stop before Redis is contacted.
    """
    memory = SessionMemory()
    outage = AsyncMock(side_effect=ConnectionError("injected Redis partition"))
    memory._ensure_redis = AsyncMock(return_value=SimpleNamespace(zadd=outage))
    service, task = _recovery(memory, suffix=uuid.uuid4().hex[:10])
    assert memory._async_session is None
    result = await service.recover_state()
    assert result["engagements"] == 1 and result["tasks"] == 0 and result["skipped"] == 1
    memory.assert_signed_authorization.assert_awaited_once_with(
        task.engagement_id, expected_version=1
    )
    memory._ensure_redis.assert_not_awaited()
    outage.assert_not_awaited()
    assert service._orch._tasks[task.id].status == "pending"
    # This test proves pre-Redis fail-closed behavior, NOT Redis fault handling.


@pytest.mark.asyncio
async def test_injected_redis_partition_after_signed_pg_row_lock_surrogate(
    monkeypatch,
):
    """INJECTED locked-SQL surrogate + REAL production zadd path, failing Redis.

    A locally signed and cryptographically verified ROE supplies the admitted
    engagement snapshot. The deterministic SQL fixture checks current Task and
    Flow identity under the same simulated transaction, but is NOT a real PG
    or live Redis partition qualification. The injected zadd must be reached.
    """
    service, memory, task, sql = _locked_pg_recovery(monkeypatch, flow=True)
    signed_session, verified, _, _ = make_signed_session(
        monkeypatch,
        session_id=task.engagement_id,
        authorization_id="auth-redis-recovery-" + uuid.uuid4().hex[:12],
        version=task.payload["_authorization_version"],
    )
    signed_session.phase = "reconnaissance"
    memory.list_all_sessions = AsyncMock(return_value=[signed_session])
    memory.assert_signed_authorization = AsyncMock(return_value=verified)
    assert verified.engagement_id == task.engagement_id
    assert verified.scope["domains"] == signed_session.scope.domains
    assert verified.version == task.payload["_authorization_version"]

    # Execute the actual SessionMemory.push_task_queue implementation. Unlike
    # the old assertion this hits _ensure_redis and its zadd exactly once.
    outage = AsyncMock(side_effect=ConnectionError("injected Redis partition at zadd"))
    memory._ensure_redis = AsyncMock(return_value=SimpleNamespace(zadd=outage))
    memory.push_task_queue = SessionMemory.push_task_queue.__get__(memory, SessionMemory)
    result = await service.recover_state()

    assert result["engagements"] == 1 and result["tasks"] == 0 and result["skipped"] == 1
    assert sql.reads == ["task", "flow"]
    assert sql.active is False
    memory.assert_signed_authorization.assert_awaited_once_with(
        task.engagement_id, expected_version=verified.version
    )
    memory._ensure_redis.assert_awaited_once()
    outage.assert_awaited_once()
    assert outage.await_args.args[0] == "queue:tasks:" + task.engagement_id
    assert service._orch._tasks[task.id].status == "pending"
    # The Redis ACK is uncertain, and this single recovery invocation did not
    # create an execution grant, retry a consequential task, or rewrite PG.


@pytest.mark.asyncio
async def test_injected_cross_tenant_outbox_and_missing_witness_remain_unknown():
    """INJECTED signed event ledger + absent independent owner-of-record."""
    store = _IdentityStore()
    notify = AsyncMock()
    original = _event()
    forged = CoordinationEvent(
        topic=original.topic,
        source=original.source,
        payload={**original.payload, "engagement_id": "eng-other-research-tenant"},
    )
    with pytest.raises(OutboxConsumerUnavailable, match="committed source"):
        await _consumer(store).consume(forged, notify)
    notify.assert_not_awaited()
    assert not _claims(store) and not _completed(store)
    await _independent_unknown(
        _NoPromotion(),
        "eng-rg-no-witness",
        "flow-rg-no-witness",
        "finding-rg-no-witness",
    )


def _graph_proof(suffix):
    return {
        "id": "action-rg-" + suffix,
        "engagement_id": "eng-rg-" + suffix,
        "flow_id": "flow-rg-" + suffix,
        "source_task_id": "task-rg-" + suffix,
        "source_event_id": "evt-rg-" + suffix,
        "flow_revision": 1,
        "authorization_version": 1,
        "authorization_sha256": "a" * 64,
        "source_task_sha256": "b" * 64,
        "receipt_sha256": "c" * 64,
        "provider_receipt_sha256": "d" * 64,
        "provider_signer_key_sha256": "e" * 64,
        "provider_server_id": "synthetic-local-only",
        "provider_signing_kid": "test-not-a-real-signature",
        "tool_kind": "http",
        "outcome": "succeeded",
    }


@pytest.mark.asyncio
@pytest.mark.timeout(150)
async def test_live_redis_lease_and_signed_revocation_gate(joined_redis_graph):
    """REAL disposable Redis, injected PG revocation; no app task dispatched."""
    ctx = joined_redis_graph
    suffix = uuid.uuid4().hex[:10]
    key = "lock:rg-" + suffix
    assert await ctx.memory.acquire_lock(key, "worker-one", ttl_seconds=20)
    assert not await ctx.memory.acquire_lock(key, "worker-two", ttl_seconds=20)
    assert not await ctx.memory.release_lock(key, "worker-two")
    assert await ctx.memory.release_lock(key, "worker-one")

    service, task = _recovery(ctx.memory, suffix=suffix, revoked=True)
    summary = await service.recover_state()
    assert summary["tasks"] == 0 and summary["skipped"] == 1
    assert await ctx.memory.pop_task_queue("tasks:" + task.engagement_id) is None
    # Signed Task status UNKNOWN remains terminally ambiguous even with an
    # otherwise live Redis delivery queue.
    service2, task2 = _recovery(ctx.memory, suffix="unknown-" + suffix, status="dispatch_unknown")
    summary = await service2.recover_state()
    assert summary["unresolved"] == 1 and summary["tasks"] == 0
    assert await ctx.memory.pop_task_queue("tasks:" + task2.engagement_id) is None


@pytest.mark.asyncio
@pytest.mark.timeout(150)
async def test_live_neo4j_projection_dedupe_and_tenant_bound_research(joined_redis_graph):
    """REAL Neo4j; injected signed provider receipt is only a graph candidate."""
    graph = joined_redis_graph.graph
    suffix = uuid.uuid4().hex[:12]
    proof = _graph_proof(suffix)
    assert await graph.project_signed_tool_action(proof)
    assert await graph.project_signed_tool_action(proof)
    candidate = await graph.read_signed_research_candidates(
        proof["engagement_id"], proof["flow_id"], 1, proof["authorization_sha256"]
    )
    assert len(candidate) == 1 and candidate[0]["id"] == proof["id"]
    assert (
        await graph.read_signed_research_candidates(
            "eng-foreign-" + suffix,
            proof["flow_id"],
            1,
            proof["authorization_sha256"],
        )
        == []
    )
    assert not await graph.project_signed_tool_action(
        {**proof, "engagement_id": "eng-foreign-" + suffix}
    )
    # This is merely a synthetic index, not cryptographically corroborated
    # provider/owner evidence and NEVER independent target verification.


@pytest.mark.asyncio
@pytest.mark.timeout(150)
async def test_live_owned_redis_and_neo4j_shutdown_fail_closed_no_replay(joined_redis_graph):
    """REAL stop of only newly created service containers; never app services."""
    ctx = joined_redis_graph
    suffix = uuid.uuid4().hex[:12]
    task = Task(
        id="task-rg-" + suffix,
        type="summarize_context",
        agent_type=AgentType.CONTEXT_MANAGER,
        engagement_id="eng-rg-" + suffix,
        status="running",
    )
    assert await ctx.graph.upsert_task(task)
    ctx.services.redis_container.stop(timeout=2)
    ctx.services.neo_container.stop(timeout=2)
    # SessionMemory._ensure_redis is pinned to the disposable URL by fixture;
    # reconnect must NOT silently switch to application credentials/ports.
    with pytest.raises(Exception):
        await asyncio.wait_for(
            ctx.memory.push_task_queue("tasks:" + task.engagement_id, task.model_dump()),
            timeout=5,
        )
    with pytest.raises(RuntimeError, match="unavailable"):
        await asyncio.wait_for(
            ctx.graph.read_signed_research_candidates(
                task.engagement_id, "flow-rg-" + suffix, 1, "a" * 64
            ),
            timeout=7,
        )
    # A separate persisted provider/target receipt was never supplied. A
    # failed graph projection or Redis queue write cannot authorize replay.
