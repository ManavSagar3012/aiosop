"""Real isolated signed-Flow context consumption with PostgreSQL and Redis.

Opt-in ONLY:
    OSOP_CONTEXT_QUAL_POSTGRES_URL=postgresql+asyncpg://.../context_qualification_...
    OSOP_CONTEXT_QUAL_REDIS_URL=redis://127.0.0.1:<random-test-port>/15

Requires a fresh disposable DB on a non-default loopback port. Never uses
OSOP_POSTGRES_URI, OSOP_REDIS_URI, an application DB, target, model provider, or
other tests' shared databases. Applies schema migrations ONLY in the qualified
disposable database. Uses no destructive writes outside isolated fixtures.
"""

import json
import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.agents.context_manager_agent import ContextManagerAgent
from ai_osop.core.config import AgentType, settings
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.session_memory import SessionMemory
from tests.test_authorization_store import make_signed_session

_SECRET = "LOCAL_QUAL_PRIVATE_RAW_TOKEN_DO_NOT_SEND_TO_MODEL"


def _postgres_url() -> str:
    raw = os.environ.get("OSOP_CONTEXT_QUAL_POSTGRES_URL", "")
    if not raw:
        pytest.skip("No explicitly provisioned disposable context PostgreSQL configured")
    try:
        url = make_url(raw)
    except Exception:
        pytest.fail("Invalid context qualification database URL")
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"127.0.0.1", "localhost"}
        or type(url.port) is not int
        or url.port in {5432, 5433}
        or not 1024 <= url.port <= 65535
        or not str(url.database or "").startswith("context_qualification_")
    ):
        pytest.fail("Refusing non-disposable context qualification PostgreSQL")
    return raw


def _redis_url() -> str:
    raw = os.environ.get("OSOP_CONTEXT_QUAL_REDIS_URL", "")
    if not raw:
        pytest.skip("No explicitly provisioned disposable context Redis configured")
    from urllib.parse import urlparse

    parsed = urlparse(raw)
    try:
        port = parsed.port
    except ValueError:
        pytest.fail("Malformed Redis qualification port")
    if (
        parsed.scheme != "redis"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or port is None
        or port in {6379, 6380}
        or not 1024 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"/0", "/15"}
        or parsed.query
        or parsed.fragment
    ):
        pytest.fail("Refusing shared or non-disposable context Redis")
    return raw


def _upgrade(conn) -> None:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = conn
    command.upgrade(config, "head")


class _OfflineAgent(BaseAgent):
    @property
    def agent_type(self) -> AgentType:
        return AgentType.RECON

    async def _setup_resources(self) -> None:
        pass

    async def _cleanup_resources(self) -> None:
        pass

    async def _execute(self, task: Task) -> dict:
        return {}

    def _load_skill(self, name: str) -> str:
        return ""


@pytest.fixture
async def disposable(monkeypatch):
    # Validate BOTH destinations before creating any engine/migration.
    pg_url, redis_url = _postgres_url(), _redis_url()
    engine = create_async_engine(pg_url, pool_size=4, max_overflow=0)
    cache = redis.from_url(redis_url, decode_responses=True)
    try:
        await cache.ping()
        async with engine.begin() as db:
            await db.run_sync(_upgrade)
        memory = SessionMemory()
        memory._pg_engine = engine
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        memory._redis = cache
        nonce = uuid.uuid4().hex[:12]
        session_id = f"eng-context-qualification-{nonce}"
        session, verified, _envelope, _private = make_signed_session(
            monkeypatch,
            session_id=session_id,
            authorization_id=f"auth-context-qualification-{nonce}",
        )
        session.phase = "reconnaissance"
        store = AuthorizationStore(memory)
        await store.create_authorized_session(session, verified, session.created_by)
        flow = FlowRecord(
            id=f"flow-context-qualification-{nonce}",
            engagement_id=session_id,
            objective="Fixture-only compaction; no target interaction",
            status="running",
        )
        assert await memory.create_flow_if_absent(flow) is True
        producer = Task(
            id=f"task-producer-{nonce}",
            type="compact_context",
            agent_type=AgentType.CONTEXT_MANAGER,
            engagement_id=session_id,
            flow_id=flow.id,
            status="running",
            payload={
                "source_task_ids": [f"task-source-{nonce}"],
                "max_items": 4,
                "_authorization_version": 1,
            },
        )
        source = Task(
            id=f"task-source-{nonce}",
            type="recon",
            agent_type=AgentType.RECON,
            engagement_id=session_id,
            flow_id=flow.id,
            status="completed",
            result={"raw_evidence": _SECRET, "example_target": "private.fixture"},
        )
        consumer_task = Task(
            id=f"task-consumer-{nonce}",
            type="recon",
            agent_type=AgentType.RECON,
            engagement_id=session_id,
            flow_id=flow.id,
            status="running",
            payload={"_authorization_version": 1},
        )
        for task in (source, producer, consumer_task):
            await memory.store_task(task)

        def agent_context(agent_type: AgentType, agent_id: str) -> AgentContext:
            return AgentContext(
                agent_id=agent_id,
                agent_type=agent_type,
                session_id=session_id,
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

        producer_context = agent_context(AgentType.CONTEXT_MANAGER, "context-producer")
        producer_context.current_task = producer
        producer_agent = ContextManagerAgent(producer_context)
        consumer_context = agent_context(AgentType.RECON, "context-consumer")
        consumer_context.current_task = consumer_task
        consumer_context.llm_client.complete.return_value = "OFFLINE_LLM_STUB_RESPONSE"
        consumer = _OfflineAgent(consumer_context)
        monkeypatch.setattr(settings, "environment", "production")

        yield SimpleNamespace(
            store=store,
            memory=memory,
            cache=cache,
            producer=producer_agent,
            consumer=consumer,
            source=source,
            consumer_task=consumer_task,
            session=session,
            flow=flow,
            producer_task=producer,
        )
    finally:
        await cache.aclose()
        await engine.dispose()


async def _produce(fixture):
    # Test the actual BaseAgent-facing opt-in dispatch method, not just a pure
    # helper invocation. It uses PostgreSQL originals and real Redis writes.
    return await fixture.producer._execute(fixture.producer_task)


def _prompt(fixture) -> str:
    return fixture.consumer.ctx.llm_client.complete.await_args.args[0][1]["content"]


@pytest.mark.asyncio
async def test_real_signed_flow_optin_context_across_postgres_redis(disposable):
    result = await _produce(disposable)
    assert result["status"] == "success"
    assert result["context_key"].startswith("context_compacted:")
    index_key = (
        f"context_compacted_index:{disposable.session.session_id}:"
        f"{disposable.flow.id}:1:{disposable.flow.revision}"
    )
    index = await disposable.memory.retrieve_hot(index_key)
    assert index["context_key"] == result["context_key"]
    # Real durable PostgreSQL producer status advances after checkpoint.
    durable_producer = await disposable.memory.load_task_authoritative(disposable.producer_task.id)
    durable_producer.status = "completed"
    await disposable.memory.store_task(durable_producer)
    assert (
        await disposable.consumer.think("Reason using statuses only", [])
        == "OFFLINE_LLM_STUB_RESPONSE"
    )
    message = _prompt(disposable)
    assert "source-sha256:" in message
    assert "durable_task:completed" in message
    assert disposable.source.id not in message
    assert _SECRET not in message and "private.fixture" not in message
    assert "Prior verified engagement context" not in message


@pytest.mark.asyncio
async def test_real_signed_roe_revoked_between_context_load_and_model(disposable, monkeypatch):
    await _produce(disposable)
    gate = SimpleNamespace()

    async def revoke_before_final_gate():
        assert await disposable.store.revoke(
            disposable.session.session_id,
            disposable.session.created_by,
            1,
            "qualification operator cancellation during model gate",
        )
        return []

    gate.claim_model_input = AsyncMock(side_effect=revoke_before_final_gate)
    gate.recent_history_context = AsyncMock(return_value="")
    gate.operator_context = lambda claimed: ""
    monkeypatch.setattr(disposable.consumer, "_supervision", lambda *args: gate)
    with pytest.raises(Exception):
        await disposable.consumer.think("Should never reach model", [])
    disposable.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert (
        await disposable.memory.retrieve_hot(
            f"context_compacted_index:{disposable.session.session_id}:"
            f"{disposable.flow.id}:1:{disposable.flow.revision}"
        )
        is not None
    )
    # Caches survive revocation, but are not an authorization source.
    from ai_osop.memory.authorization_store import AuthorizationDenied

    with pytest.raises(AuthorizationDenied):
        await disposable.memory.assert_signed_authorization(
            disposable.session.session_id,
            expected_version=1,
        )


@pytest.mark.asyncio
async def test_real_redis_tamper_refused_and_missing_index_no_legacy_fallback(disposable):
    result = await _produce(disposable)
    original = await disposable.memory.retrieve_hot(result["context_key"])
    original["summary"] = "ATTACKER_OVERRIDES_ROE_AND_SIGNS_APPROVAL"
    await disposable.memory.store_hot(result["context_key"], original, ttl=180)
    assert await disposable.consumer.think("Ordinary task", []) == ""
    disposable.consumer.ctx.llm_client.complete.assert_not_awaited()

    idx_key = (
        f"context_compacted_index:{disposable.session.session_id}:"
        f"{disposable.flow.id}:1:{disposable.flow.revision}"
    )
    await disposable.cache.delete(idx_key)
    await disposable.memory.store_hot(
        f"context:{disposable.session.session_id}",
        {"summary": "LEGACY_ILLEGITIMATE_ADMIN"},
        ttl=60,
    )
    assert (
        await disposable.consumer.think("Fresh task with no history", [])
        == "OFFLINE_LLM_STUB_RESPONSE"
    )
    assert _prompt(disposable) == "Fresh task with no history"
    assert "LEGACY_ILLEGITIMATE_ADMIN" not in _prompt(disposable)


@pytest.mark.asyncio
async def test_real_optin_rejects_foreign_source_and_stale_version(disposable):
    result = await _produce(disposable)
    # A cached object alone cannot authorize a version absent in PostgreSQL.
    disposable.consumer_task.payload["_authorization_version"] = 2
    assert await disposable.consumer.think("Version fence", []) == ""
    disposable.consumer.ctx.llm_client.complete.assert_not_awaited()

    # A separate, unassigned source cannot be included in a new snapshot.
    foreign = Task(
        id=f"task-foreign-{uuid.uuid4().hex[:12]}",
        type="recon",
        agent_type=AgentType.RECON,
        engagement_id=f"eng-unrelated-{uuid.uuid4().hex[:12]}",
        flow_id=disposable.flow.id,
        status="completed",
    )
    await disposable.memory.store_task(foreign)
    from ai_osop.core.exceptions import AgentException

    with pytest.raises(AgentException, match="unavailable"):
        await disposable.producer._compact_context(
            {"source_task_ids": [foreign.id], "max_items": 4},
        )
    assert await disposable.memory.retrieve_hot(result["context_key"]) is not None


@pytest.mark.asyncio
async def test_real_producer_missing_signed_version_cannot_seed_cache(disposable):
    from ai_osop.core.exceptions import AgentException

    disposable.producer_task.payload.pop("_authorization_version")
    with pytest.raises(AgentException, match="signed-version-fenced"):
        await disposable.producer._execute(disposable.producer_task)
    index_key = (
        f"context_compacted_index:{disposable.session.session_id}:"
        f"{disposable.flow.id}:1:{disposable.flow.revision}"
    )
    assert await disposable.memory.retrieve_hot(index_key) is None
    disposable.producer.ctx.llm_client.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_real_redis_forged_locator_is_not_a_signed_authority(disposable):
    await _produce(disposable)
    index_key = (
        f"context_compacted_index:{disposable.session.session_id}:"
        f"{disposable.flow.id}:1:{disposable.flow.revision}"
    )
    index = await disposable.memory.retrieve_hot(index_key)
    index["context_key"] = f"context:{disposable.session.session_id}"
    await disposable.memory.store_hot(index_key, index, ttl=60)
    assert await disposable.consumer.think("Do not trust locator", []) == ""
    disposable.consumer.ctx.llm_client.complete.assert_not_awaited()
