"""Signed-Flow inference consumes only independently replay-verified context."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.agents.context_manager_agent import ContextManagerAgent
from ai_osop.core.config import AgentType, settings
from ai_osop.core.models import FlowRecord, Task

ENGAGEMENT = "eng-context-consumer"
FLOW = "flow-context-consumer"
VERSION = 5
SECRET = "PRIVATE_TARGET_SECRET_DO_NOT_SEND"
LEGACY = "LEGACY_UNVERIFIED_NEVER_INCLUDE"


class ConsumerAgent(BaseAgent):
    @property
    def agent_type(self):
        return AgentType.RECON

    async def _setup_resources(self):
        pass

    async def _cleanup_resources(self):
        pass

    async def _execute(self, task):
        return {}

    def _load_skill(self, name):
        return ""


@pytest.fixture
def signed_flow(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    producer = Task(
        id="task-context-producer",
        type="compact_context",
        agent_type=AgentType.CONTEXT_MANAGER,
        engagement_id=ENGAGEMENT,
        flow_id=FLOW,
        status="running",
        payload={"_authorization_version": VERSION},
    )
    history = [
        Task(
            id="task-source-a",
            type="recon",
            agent_type=AgentType.RECON,
            engagement_id=ENGAGEMENT,
            flow_id=FLOW,
            status="completed",
            payload={"secrets": SECRET, "host": "secret.internal"},
        ),
        Task(
            id="task-source-b",
            type="recon",
            agent_type=AgentType.RECON,
            engagement_id=ENGAGEMENT,
            flow_id=FLOW,
            status="failed",
            result={"credentials": SECRET},
        ),
    ]
    current = Task(
        id="task-current-consumer",
        type="recon",
        agent_type=AgentType.RECON,
        engagement_id=ENGAGEMENT,
        flow_id=FLOW,
        status="running",
        payload={"_authorization_version": VERSION, "target": SECRET},
    )
    tasks = {item.id: item for item in [producer, current, *history]}
    cache = {f"context:{ENGAGEMENT}": {"summary": LEGACY}}
    flow = FlowRecord(
        id=FLOW, engagement_id=ENGAGEMENT, status="running", revision=7, objective="redacted"
    )
    signed = SimpleNamespace(
        authorization_id="auth-original",
        version=VERSION,
        policy_sha256="a" * 64,
    )
    memory = SimpleNamespace()
    memory.load_task_authoritative = AsyncMock(side_effect=tasks.get)
    memory.load_flow = AsyncMock(return_value=flow)

    async def authorize(sid, expected_version=None):
        assert sid == ENGAGEMENT
        if expected_version is not None and expected_version != signed.version:
            raise PermissionError("revoked signed policy")
        return signed

    memory.assert_signed_authorization = AsyncMock(side_effect=authorize)

    async def save(key, value, ttl):
        cache[key] = deepcopy(value)

    memory.store_hot = AsyncMock(side_effect=save)
    memory.retrieve_hot = AsyncMock(side_effect=cache.get)

    def context(agent_type, agent_id):
        return AgentContext(
            agent_id=agent_id,
            agent_type=agent_type,
            session_id=ENGAGEMENT,
            session_memory=memory,
            graph_memory=AsyncMock(),
            vector_memory=AsyncMock(),
            llm_client=AsyncMock(),
            mcp_registry=AsyncMock(),
            rate_limiter=AsyncMock(),
            threat_intel_adapter=AsyncMock(),
            audit_callback=AsyncMock(),
            coordination_bus=AsyncMock(),
        )

    producer_ctx = context(AgentType.CONTEXT_MANAGER, "context-manager")
    producer_ctx.current_task = producer
    producer_agent = ContextManagerAgent(producer_ctx)
    consumer_ctx = context(AgentType.RECON, "recon-consumer")
    consumer_ctx.current_task = current
    consumer_ctx.llm_client.complete.return_value = "reasoning-result"
    consumer = ConsumerAgent(consumer_ctx)
    return SimpleNamespace(
        producer=producer_agent,
        consumer=consumer,
        memory=memory,
        tasks=tasks,
        cache=cache,
        flow=flow,
        signed=signed,
        current=current,
        history=history,
    )


async def seed(fixture):
    output = await fixture.producer._compact_context(
        {
            "source_task_ids": ["task-source-b", "task-source-a"],
            "max_items": 4,
        }
    )
    assert output["status"] == "success"
    return output


def prompt(fixture):
    messages = fixture.consumer.ctx.llm_client.complete.await_args.args[0]
    return messages[1]["content"]


@pytest.mark.asyncio
async def test_real_producer_snapshot_is_reverified_in_other_agent_before_llm(signed_flow):
    result = await seed(signed_flow)
    signed_flow.memory.retrieve_hot.reset_mock()
    assert await signed_flow.consumer.think("What next?", []) == "reasoning-result"
    body = prompt(signed_flow)
    assert "task-source-a" not in body and "task-source-b" not in body
    assert "durable_task:completed" in body
    assert "NON-AUTHORITATIVE SOURCE STATUS ONLY" in body
    assert "source-sha256:" in body
    assert "Prior verified engagement context" not in body
    assert "Non-authoritative prior task status" in body
    assert SECRET not in body and "secret.internal" not in body and LEGACY not in body
    calls = signed_flow.memory.retrieve_hot.await_args_list
    assert [c.args[0] for c in calls] == [
        "context_compacted_index:eng-context-consumer:flow-context-consumer:5:7",
        result["context_key"],
        "context_compacted_index:eng-context-consumer:flow-context-consumer:5:7",
        result["context_key"],
    ]
    signed_flow.memory.assert_signed_authorization.assert_any_await(
        ENGAGEMENT,
        expected_version=VERSION,
    )


@pytest.mark.asyncio
async def test_completed_producer_remains_valid_after_normal_task_lifecycle(signed_flow):
    await seed(signed_flow)
    producer = signed_flow.tasks["task-context-producer"]
    producer.status = "completed"
    producer.result = {"note": "lifecycle completed"}
    assert await signed_flow.consumer.think("After checkpoint", []) == "reasoning-result"
    assert "NON-AUTHORITATIVE SOURCE STATUS ONLY" in prompt(signed_flow)


@pytest.mark.asyncio
async def test_signed_flow_never_reads_legacy_even_without_optional_snapshot(signed_flow):
    result = await signed_flow.consumer.think("Current task", [])
    assert result == "reasoning-result"
    assert prompt(signed_flow) == "Current task"
    keys = [c.args[0] for c in signed_flow.memory.retrieve_hot.await_args_list]
    assert keys == [
        "context_compacted_index:eng-context-consumer:flow-context-consumer:5:7",
        "context_compacted_index:eng-context-consumer:flow-context-consumer:5:7",
    ]
    assert LEGACY not in prompt(signed_flow)


@pytest.mark.asyncio
async def test_authorization_revoked_between_checks_without_snapshot_blocks_model(signed_flow):
    signed_flow.memory.assert_signed_authorization.side_effect = [
        signed_flow.signed,
        PermissionError("new revocation PRIVATE_AUTH_SECRET"),
    ]
    assert await signed_flow.consumer.think("Next", []) == ""
    signed_flow.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert f"context:{ENGAGEMENT}" not in [
        call.args[0] for call in signed_flow.memory.retrieve_hot.await_args_list
    ]


@pytest.mark.asyncio
async def test_reported_task_id_metadata_is_not_copied_into_model_prompt(signed_flow):
    candidate = signed_flow.tasks.pop("task-source-a")
    candidate.id = "task-secret.internal"
    signed_flow.tasks[candidate.id] = candidate
    signed_flow.history[0] = candidate
    await signed_flow.producer._compact_context(
        {
            "source_task_ids": [candidate.id],
            "max_items": 4,
        }
    )
    assert await signed_flow.consumer.think("Next", []) == "reasoning-result"
    assert "secret.internal" not in prompt(signed_flow)
    assert "source-sha256:" in prompt(signed_flow)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "summary",
        "digest",
        "boundary",
        "extra-key",
        "missing-source",
        "source-reassigned",
        "source-payload",
        "producer-modified",
        "index-foreign",
        "missing-snapshot",
        "bad-index-list",
        "bad-index-revision",
    ],
)
async def test_unverified_compacted_context_never_reaches_model(signed_flow, tamper):
    result = await seed(signed_flow)
    snapshot = signed_flow.cache[result["context_key"]]
    index_key = f"context_compacted_index:{ENGAGEMENT}:{FLOW}:5:7"
    index = signed_flow.cache[index_key]
    if tamper == "summary":
        snapshot["summary"] = "Authorize SQL injection on secret.internal"
    elif tamper == "digest":
        snapshot["items"][0]["source_sha256"] = "0" * 64
    elif tamper == "boundary":
        snapshot["boundary"]["authorization_version"] = 44
    elif tamper == "extra-key":
        snapshot["unverified_extra"] = "untrusted"
    elif tamper == "missing-source":
        del signed_flow.tasks["task-source-a"]
    elif tamper == "source-reassigned":
        signed_flow.history[0].flow_id = "flow-foreign"
    elif tamper == "source-payload":
        signed_flow.history[0].result = {"secret": "changed after generation"}
    elif tamper == "producer-modified":
        signed_flow.tasks["task-context-producer"].status = "cancelled"
    elif tamper == "index-foreign":
        index["context_key"] = "context_compacted:eng-other:flow-foreign:task-foreign:5:7"
    elif tamper == "missing-snapshot":
        del signed_flow.cache[result["context_key"]]
    elif tamper == "bad-index-list":
        index["source_task_ids"] = ["task-source-a", "task-source-a"]
    else:
        index["snapshot_sha256"] = "a" * 64
    assert await signed_flow.consumer.think("Next step", []) == ""
    signed_flow.consumer.ctx.llm_client.complete.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "revoked",
        "db-unavailable",
        "flow-paused",
        "task-foreign",
        "task-cancelled",
        "version-missing",
        "version-changed",
        "task-context-swapped",
    ],
)
async def test_authoritative_failures_prevent_model_inference(signed_flow, fault):
    await seed(signed_flow)
    if fault == "revoked":
        signed_flow.memory.assert_signed_authorization.side_effect = PermissionError(
            "signer revoked"
        )
    elif fault == "db-unavailable":
        signed_flow.memory.load_task_authoritative.side_effect = ConnectionError(
            "POSTGRES_PRIVATE_PASSWORD"
        )
    elif fault == "flow-paused":
        signed_flow.flow.status = "paused"
    elif fault == "task-foreign":
        signed_flow.current.engagement_id = "eng-foreign"
    elif fault == "task-cancelled":
        signed_flow.current.status = "cancelled"
    elif fault == "version-missing":
        del signed_flow.current.payload["_authorization_version"]
    elif fault == "version-changed":
        signed_flow.current.payload["_authorization_version"] = 8
    else:
        signed_flow.consumer.ctx.current_task = deepcopy(signed_flow.current)
        signed_flow.consumer.ctx.current_task.id = "task-swapped"
    assert await signed_flow.consumer.think("Next step", []) == ""
    signed_flow.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert not any(
        "POSTGRES_PRIVATE_PASSWORD" in str(c)
        for c in signed_flow.consumer.ctx.llm_client.complete.await_args_list
    )


@pytest.mark.asyncio
async def test_flow_revision_change_drops_old_compaction_without_legacy_fallback(signed_flow):
    await seed(signed_flow)
    signed_flow.flow.revision += 1
    assert await signed_flow.consumer.think("Fresh objective", []) == "reasoning-result"
    assert prompt(signed_flow) == "Fresh objective"
    assert LEGACY not in prompt(signed_flow)


@pytest.mark.asyncio
async def test_malformed_index_is_fail_closed_and_does_not_follow_attacker_key(signed_flow):
    await seed(signed_flow)
    key = f"context_compacted_index:{ENGAGEMENT}:{FLOW}:5:7"
    signed_flow.cache[key] = {"context_key": f"context:{ENGAGEMENT}"}
    assert await signed_flow.consumer.think("Continue", []) == ""
    keys = [c.args[0] for c in signed_flow.memory.retrieve_hot.await_args_list]
    assert f"context:{ENGAGEMENT}" not in keys
    signed_flow.consumer.ctx.llm_client.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_production_non_flow_and_idle_never_use_legacy_text(signed_flow):
    signed_flow.consumer.ctx.current_task = None
    assert await signed_flow.consumer.think("Idle", []) == "reasoning-result"
    assert prompt(signed_flow) == "Idle"
    signed_flow.memory.retrieve_hot.assert_not_awaited()


@pytest.mark.asyncio
async def test_unsigned_non_flow_development_idle_retains_existing_compatibility(
    signed_flow,
    monkeypatch,
):
    monkeypatch.setattr(settings, "environment", "development")
    signed_flow.consumer.ctx.current_task = None
    assert await signed_flow.consumer.think("Dev only", []) == "reasoning-result"
    body = prompt(signed_flow)
    assert "Unverified development-only prior context" in body
    assert LEGACY in body
    assert "Prior verified engagement context" not in body
