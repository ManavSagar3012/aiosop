"""Best-effort tenant fanout and signed feedback safety; no provider or app DB."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.payload_agent import PayloadMutationAgent
from ai_osop.core.config import AgentType, VulnClass
from ai_osop.core.models import FlowRecord, Payload, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.orchestrator.coordination_bus import AgentCoordinationBus


async def _subscribe(bus, *, tenant=None, topic="feedback.payload_validated"):
    iterator = bus.subscribe(topic, engagement_id=tenant)
    pending = asyncio.create_task(anext(iterator))
    await asyncio.sleep(0)
    return iterator, pending


@pytest.mark.asyncio
async def test_scoped_subscribers_receive_only_explicit_matching_engagement():
    bus = AgentCoordinationBus(max_queue_size=3)
    tenant_a, wait_a = await _subscribe(bus, tenant="eng-a")
    tenant_b, wait_b = await _subscribe(bus, tenant="eng-b")
    legacy, wait_global = await _subscribe(bus)
    try:
        await bus.publish("feedback.payload_validated", {"n": 0}, "publisher")
        await bus.publish(
            "feedback.payload_validated",
            {"n": 1, "engagement_id": "eng-a"},
            "publisher",
            engagement_id="eng-a",
        )
        assert (await asyncio.wait_for(wait_a, 0.25)).payload["n"] == 1
        assert not wait_b.done()
        assert (await asyncio.wait_for(wait_global, 0.25)).payload["n"] == 0
        await bus.publish(
            "feedback.payload_validated", {"n": 2, "engagement_id": "eng-b"}, "publisher"
        )
        assert (await asyncio.wait_for(wait_b, 0.25)).payload["n"] == 2
        assert bus.subscriber_count("feedback.payload_validated") == 3
        assert list(bus._subscribers["feedback.payload_validated"][0]._queue) == []
    finally:
        await tenant_a.aclose()
        await tenant_b.aclose()
        await legacy.aclose()
    assert bus.subscriber_count("feedback.payload_validated") == 0
    assert not bus._subscriber_engagements


@pytest.mark.asyncio
@pytest.mark.parametrize("event_tenant", [None, "", "eng-other", 42, True, []])
async def test_scoped_queue_never_stores_missing_or_foreign_event(event_tenant):
    bus = AgentCoordinationBus(max_queue_size=1, subscriber_send_timeout=0.02)
    subscriber, pending = await _subscribe(bus, tenant="eng-owner")
    try:
        await bus.publish(
            "feedback.payload_validated",
            {"engagement_id": event_tenant, "content": "other-tenant-secret"},
            "publisher",
        )
        assert not pending.done()
        assert bus._subscribers["feedback.payload_validated"][0].qsize() == 0
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        await subscriber.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        {},
        {"engagement_id": "eng-other"},
        {"engagement_id": None},
        {"engagement_id": True},
    ],
)
async def test_scoped_publisher_rejects_mismatch_before_any_delivery(invalid):
    bus = AgentCoordinationBus()
    subscriber, pending = await _subscribe(bus, tenant="eng-owner")
    try:
        with pytest.raises(ValueError, match="does not match"):
            await bus.publish(
                "feedback.payload_validated",
                invalid,
                "publisher",
                engagement_id="eng-owner",
            )
        assert not pending.done()
        assert bus._subscribers["feedback.payload_validated"][0].empty()
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        await subscriber.aclose()


@pytest.mark.parametrize("invalid", ["", "eng/other", 123, True, "x" * 65])
@pytest.mark.asyncio
async def test_invalid_subscription_scope_never_registers_queue(invalid):
    bus = AgentCoordinationBus()
    iterator = bus.subscribe("feedback.payload_validated", engagement_id=invalid)
    with pytest.raises(ValueError, match="engagement_id"):
        await anext(iterator)
    assert bus.subscriber_count("feedback.payload_validated") == 0


def _feedback_case():
    RequestContext.clear()
    tenant = "eng-owner"
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "payload-agent"
    ctx.agent_type = AgentType.PAYLOAD_MUTATION
    ctx.session_id = tenant
    ctx.status = "running"
    ctx.llm_client = SimpleNamespace(get_embedding=AsyncMock(return_value=[0.5] * 1536))
    ctx.vector_memory = SimpleNamespace(store_payload=AsyncMock())
    ctx.mcp_registry = AsyncMock()
    ctx.coordination_bus = AgentCoordinationBus()
    payload = Payload(
        content="inert sample for feedback",
        content_hash="digest",
        vuln_type=VulnClass.XSS,
        engagement_id=tenant,
    )
    current = Task(
        id="task-tenant-feedback",
        type="process_feedback",
        agent_type=AgentType.PAYLOAD_MUTATION,
        engagement_id=tenant,
        status="running",
        payload={
            "_authorization_version": 3,
            "engagement_id": tenant,
            "payload": payload.model_dump(),
            "result": {"status": "succeeded", "waf_blocked": False},
        },
    )
    ctx.current_task = current
    ctx.session_memory = SimpleNamespace(
        load_task_authoritative=AsyncMock(return_value=current.model_copy(deep=True)),
        assert_signed_authorization=AsyncMock(return_value=SimpleNamespace(version=3)),
    )
    agent = PayloadMutationAgent(ctx)
    agent.engine = SimpleNamespace(
        fitness_evaluator=SimpleNamespace(evaluate=MagicMock(return_value=0.9)),
    )
    feedback = {
        "engagement_id": tenant,
        "payload": payload.model_dump(),
        "result": {"status": "succeeded", "waf_blocked": False},
    }
    return SimpleNamespace(agent=agent, ctx=ctx, task=current, feedback=feedback)


@pytest.mark.asyncio
async def test_verified_active_feedback_requires_durable_task_then_signed_roe_before_embeddings():
    case = _feedback_case()
    order = []

    async def read_task(_task_id):
        order.append("postgres-task")
        return case.task.model_copy(deep=True)

    async def signed(_sid, expected_version):
        assert expected_version == 3
        order.append("signed-roe")
        return SimpleNamespace(version=3)

    async def embed(_text):
        assert order[-2:] == ["postgres-task", "signed-roe"]
        order.append("embedding")
        return [0.5] * 1536

    async def store_payload(**kwargs):
        assert order[-3:] == ["embedding", "postgres-task", "signed-roe"]
        assert kwargs["engagement_id"] == case.ctx.session_id
        assert kwargs["task_id"] == case.task.id
        order.append("vector-store")

    case.ctx.session_memory.load_task_authoritative.side_effect = read_task
    case.ctx.session_memory.assert_signed_authorization.side_effect = signed
    case.ctx.llm_client.get_embedding.side_effect = embed
    case.ctx.vector_memory.store_payload.side_effect = store_payload
    try:
        result = await case.agent._process_feedback(case.feedback)
        assert result["status"] == "success"
        assert result["stored_semantically"] is True
        assert order == [
            "postgres-task",
            "signed-roe",
            "postgres-task",
            "signed-roe",
            "embedding",
            "postgres-task",
            "signed-roe",
            "vector-store",
        ]
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_tenant",
        "wrong_tenant",
        "bad_tenant_type",
        "nested_other_tenant",
        "nested_tenant_missing",
        "result_other_tenant",
        "inactive_task",
        "cancelled_task",
        "other_agent_role",
        "other_task_type",
        "foreign_active_task",
        "context_inactive",
        "missing_signed_version",
        "missing_payload",
        "wrong_result_shape",
        "durable_other_tenant",
        "durable_completed",
        "durable_payload_mismatch",
        "signed_version_stale",
        "pg_down",
        "missing_authority",
        "switched_task",
        "request_context_foreign",
        "feedback_body_mismatch",
        "paused_flow",
        "unapproved_sensitive_task",
    ],
)
async def test_unverified_feedback_cannot_evaluate_fitness_or_spend_semantic_budget(mutation):
    case = _feedback_case()
    if mutation == "missing_tenant":
        case.feedback.pop("engagement_id")
    elif mutation == "wrong_tenant":
        case.feedback["engagement_id"] = "eng-victim"
    elif mutation == "bad_tenant_type":
        case.feedback["engagement_id"] = ["eng-owner"]
    elif mutation == "nested_other_tenant":
        case.feedback["payload"]["engagement_id"] = "eng-victim"
    elif mutation == "nested_tenant_missing":
        case.feedback["payload"].pop("engagement_id")
    elif mutation == "result_other_tenant":
        case.feedback["result"]["engagement_id"] = "eng-victim"
    elif mutation == "feedback_body_mismatch":
        case.feedback["result"]["status"] = "forged"
    elif mutation == "inactive_task":
        case.task.status = "completed"
    elif mutation == "cancelled_task":
        case.task.status = "cancelled"
    elif mutation == "other_agent_role":
        case.task.agent_type = AgentType.RECON
    elif mutation == "other_task_type":
        case.task.type = "generate_payloads"
    elif mutation == "foreign_active_task":
        case.task.engagement_id = "eng-victim"
    elif mutation == "context_inactive":
        case.ctx.status = "idle"
    elif mutation == "missing_signed_version":
        case.task.payload.pop("_authorization_version")
    elif mutation == "missing_payload":
        case.feedback["payload"] = None
    elif mutation == "wrong_result_shape":
        case.feedback["result"] = "success"
    elif mutation == "durable_other_tenant":
        case.ctx.session_memory.load_task_authoritative.return_value.engagement_id = "eng-victim"
    elif mutation == "durable_completed":
        case.ctx.session_memory.load_task_authoritative.return_value.status = "completed"
    elif mutation == "durable_payload_mismatch":
        case.ctx.session_memory.load_task_authoritative.return_value.payload["extra"] = "tamper"
    elif mutation == "signed_version_stale":
        case.ctx.session_memory.assert_signed_authorization.return_value.version = 4
    elif mutation == "pg_down":
        case.ctx.session_memory.load_task_authoritative.side_effect = OSError("postgres outage")
    elif mutation == "missing_authority":
        case.ctx.session_memory = SimpleNamespace()
    elif mutation == "switched_task":

        async def switch_task(_id):
            case.ctx.current_task = None
            return case.task

        case.ctx.session_memory.load_task_authoritative.side_effect = switch_task
    elif mutation == "request_context_foreign":
        RequestContext.bind(engagement_id="eng-victim", task_id=case.task.id)
    elif mutation == "paused_flow":
        case.task.flow_id = "flow-paused"
        case.ctx.session_memory.load_task_authoritative.return_value = case.task.model_copy(
            deep=True
        )
        case.ctx.session_memory.load_flow = AsyncMock(
            return_value=FlowRecord(
                id="flow-paused",
                engagement_id=case.ctx.session_id,
                objective="signed run",
                status="paused",
            )
        )
    elif mutation == "unapproved_sensitive_task":
        case.task.approval_required = True
        case.task.payload["approval_id"] = "apr-proposed"
        case.ctx.session_memory.load_task_authoritative.return_value = case.task.model_copy(
            deep=True
        )
        case.ctx.session_memory.is_task_approved = AsyncMock(return_value=False)
    try:
        response = await case.agent._process_feedback(case.feedback)
        assert response == {"status": "ignored", "reason": "feedback_scope_or_task_unverified"}
        case.agent.engine.fitness_evaluator.evaluate.assert_not_called()
        case.ctx.llm_client.get_embedding.assert_not_awaited()
        case.ctx.vector_memory.store_payload.assert_not_awaited()
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
async def test_authorization_revoked_after_embedding_blocks_semantic_write():
    case = _feedback_case()
    case.ctx.session_memory.assert_signed_authorization.side_effect = [
        SimpleNamespace(version=3),
        SimpleNamespace(version=3),
        PermissionError("signed authorization revoked"),
    ]
    try:
        result = await case.agent._process_feedback(case.feedback)
        assert result["status"] == "ignored"
        case.ctx.llm_client.get_embedding.assert_awaited_once()
        case.ctx.vector_memory.store_payload.assert_not_awaited()
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
async def test_approved_active_flow_feedback_is_accepted_without_bus_as_approval():
    case = _feedback_case()
    case.task.approval_required = True
    case.task.flow_id = "flow-current"
    case.task.payload["approval_id"] = "apr-human-approved"
    case.ctx.session_memory.load_task_authoritative.return_value = case.task.model_copy(deep=True)
    case.ctx.session_memory.load_flow = AsyncMock(
        return_value=FlowRecord(
            id="flow-current",
            engagement_id=case.ctx.session_id,
            objective="signed run",
            status="running",
        )
    )
    case.ctx.session_memory.is_task_approved = AsyncMock(return_value=True)
    try:
        result = await case.agent._process_feedback(case.feedback)
        assert result["status"] == "success"
        assert result["stored_semantically"] is True
        case.ctx.session_memory.is_task_approved.assert_awaited()
        case.ctx.vector_memory.store_payload.assert_awaited_once()
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
async def test_payload_listener_lifecycle_cancels_and_unsubscribes_on_shutdown():
    case = _feedback_case()
    case.ctx.session_memory.get_agent_state = AsyncMock(return_value={})
    case.ctx.session_memory.store_agent_state = AsyncMock()
    # Start exactly the production BaseAgent worker/heartbeat/listener tasks.
    case.agent._setup_resources = AsyncMock()
    case.agent._process_feedback = AsyncMock()
    await case.agent.initialize()
    bus = case.ctx.coordination_bus
    topic = "feedback.payload_validated"
    try:
        for _ in range(10):
            if bus.subscriber_count(topic) == 1:
                break
            await asyncio.sleep(0)
        assert bus.subscriber_count(topic) == 1
        assert len(case.agent._bg_tasks) == 3
        await bus.publish(topic, {"engagement_id": "eng-other"}, "foreign")
        await asyncio.sleep(0)
        case.agent._process_feedback.assert_not_awaited()
    finally:
        await asyncio.wait_for(case.agent.shutdown(), timeout=2)
        RequestContext.clear()
    assert bus.subscriber_count(topic) == 0
    assert not bus._subscriber_engagements
    assert case.agent._bg_tasks == []
