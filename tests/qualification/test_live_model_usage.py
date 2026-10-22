"""Provider usage qualification, only against a disposable loopback database."""

import asyncio
import base64
import os
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import (
    ModelBudgetExceeded,
    ModelOutcomeUncertain,
    ModelUsageLedger,
    ModelUsageORM,
)
from ai_osop.memory.session_memory import SessionStateORM, TaskORM
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.supervision_store import SupervisionEventORM
from ai_osop.safety.signed_roe import canonical_json_bytes, verify_signed_roe
from tests.test_authorization_store import make_signed_session


def _uri():
    value = os.getenv("OSOP_MODEL_USAGE_TEST_PG_URI", "")
    if not value:
        pytest.skip("Dedicated model usage PostgreSQL qualification DB unavailable")
    url = make_url(value)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"127.0.0.1", "localhost"}
        or url.port in {None, 5432, 5433}
        or not str(url.database or "").startswith("model_usage_qualification_")
    ):
        pytest.fail("Refusing non-disposable PostgreSQL database")
    return value


def _alembic(connection, revision, method):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    getattr(command, method)(config, revision)


@pytest.fixture
async def live():
    engine = create_async_engine(_uri(), pool_size=5)
    async with engine.begin() as connection:
        await connection.run_sync(_alembic, "head", "upgrade")
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    class Memory:
        _async_session = maker

    try:
        yield engine, maker, ModelUsageLedger(Memory())
    finally:
        await engine.dispose()


async def _seed(maker, roe, monkeypatch):
    suffix = uuid.uuid4().hex[:16]
    engagement_id, task_id = "eng-" + suffix, "task-" + suffix
    now = datetime.utcnow()
    # Build and verify a real, per-test Ed25519-signed policy that covers
    # this *exact* spending cap and precharge ceiling. This is not an
    # unsigned row masquerading as a production admission.
    session, _, envelope, key = make_signed_session(
        monkeypatch,
        session_id=engagement_id,
        authorization_id="auth-model-usage-" + suffix,
        owner="test-operator",
    )
    session.roe = dict(roe)
    envelope["policy"]["roe"] = dict(roe)
    envelope["signature"] = (
        base64.urlsafe_b64encode(key.sign(canonical_json_bytes(envelope["policy"])))
        .decode("ascii")
        .rstrip("=")
    )
    verified = verify_signed_roe(
        envelope,
        expected_engagement_id=engagement_id,
        expected_owner="test-operator",
        expected_scope=session.scope,
        expected_roe=session.roe,
        now=datetime.now(timezone.utc),
    )
    session.phase = "reconnaissance"
    await AuthorizationStore(SimpleNamespace(_async_session=maker)).create_authorized_session(
        session,
        verified,
        "test-operator",
    )
    async with maker() as db:
        async with db.begin():
            db.add(
                TaskORM(
                    id=task_id,
                    engagement_id=engagement_id,
                    type="recon",
                    priority=5,
                    agent_type="recon",
                    payload={"_authorization_version": 1},
                    dependencies=[],
                    max_retries=1,
                    timeout_seconds=120,
                    scope_check=True,
                    approval_required=False,
                    status="running",
                    result=None,
                    retry_count=0,
                    created_at=now,
                )
            )
    return engagement_id, task_id


@pytest.mark.asyncio
async def test_live_competing_model_admission_is_atomic_and_billed_fields_exact(live, monkeypatch):
    _, maker, store = live
    engagement, task = await _seed(maker, {"llm_call_budget_total": 1}, monkeypatch)
    results = await asyncio.gather(
        store.reserve(engagement, task, "openai/gpt-test", "completion"),
        store.reserve(engagement, task, "openai/gpt-test", "completion"),
        return_exceptions=True,
    )
    admitted = [item for item in results if isinstance(item, str)]
    assert len(admitted) == 1
    assert isinstance(
        next(item for item in results if not isinstance(item, str)), ModelBudgetExceeded
    )
    response = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=120,
            completion_tokens=21,
            billed_cost_usd=0.00123,
        )
    )
    assert await store.settle(admitted[0], engagement, response, delivered=True)
    assert not await store.settle(admitted[0], engagement, response, delivered=True)
    async with maker() as db:
        row = (
            await db.execute(select(ModelUsageORM).where(ModelUsageORM.call_id == admitted[0]))
        ).scalar_one()
        assert row.status == "settled" and row.input_tokens == 120 and row.output_tokens == 21
        assert row.billed_cost_usd == Decimal("0.00123000")
    assert any(
        item["kind"] == "llm.provider_usage" for item in await store.list_events_after(engagement)
    )


@pytest.mark.asyncio
async def test_live_unsettled_provider_reservation_blocks_count_only_admission(live, monkeypatch):
    _, maker, store = live
    engagement, task = await _seed(maker, {"llm_call_budget_total": 4}, monkeypatch)
    first = await store.reserve(engagement, task, "openai/gpt-test", "completion")
    # Simulate worker process death between provider dispatch and its
    # settlement. Even though the count budget has available capacity,
    # provider execution and billing are unknown; no replacement dispatch.
    with pytest.raises(ModelBudgetExceeded, match="unreconciled"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")
    async with maker() as db:
        rows = (
            (
                await db.execute(
                    select(ModelUsageORM).where(ModelUsageORM.engagement_id == engagement)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1 and rows[0].call_id == first and rows[0].status == "reserved"


@pytest.mark.asyncio
async def test_live_unreconciled_cost_fails_closed_and_halt_denies_dispatch(live, monkeypatch):
    _, maker, store = live
    engagement, task = await _seed(
        maker,
        {
            "llm_cost_budget_usd": 0.01,
            "llm_precharge_max_call_usd": 0.005,
        },
        monkeypatch,
    )
    first = await store.reserve(engagement, task, "openai/gpt-test", "completion")
    assert await store.settle(first, engagement, None, delivered=False)
    with pytest.raises(ModelBudgetExceeded, match="unreconciled"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(SessionStateORM)
                .where(SessionStateORM.session_id == engagement)
                .values(phase="halted")
            )
    with pytest.raises(ModelBudgetExceeded, match="not authorized"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")


@pytest.mark.asyncio
async def test_live_provider_response_settles_and_transport_unknown_forbids_fallback(
    live, monkeypatch
):
    _, maker, store = live
    engagement, task = await _seed(maker, {"llm_call_budget_total": 2}, monkeypatch)
    client = LiteLLMClient(usage_store=store)
    response = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=7, completion_tokens=3, billed_cost_usd=0.003),
        choices=[SimpleNamespace(message=SimpleNamespace(content="approved summary"))],
    )
    provider = AsyncMock(return_value=response)
    monkeypatch.setattr("ai_osop.core.llm_client.litellm.acompletion", provider)
    RequestContext.bind(engagement_id=engagement, task_id=task)
    try:
        assert (
            await client.complete(
                [{"role": "user", "content": "Summarize evidence"}], model="openai/gpt-test"
            )
            == "approved summary"
        )
        provider.side_effect = TimeoutError("ambiguous transport")
        with pytest.raises(ModelOutcomeUncertain, match="may have executed"):
            await client.complete(
                [{"role": "user", "content": "Summarize evidence"}], model="openai/gpt-test"
            )
        assert provider.await_count == 2  # No third fallback invocation.
    finally:
        RequestContext.clear()
    async with maker() as db:
        rows = (
            (
                await db.execute(
                    select(ModelUsageORM).where(ModelUsageORM.engagement_id == engagement)
                )
            )
            .scalars()
            .all()
        )
        assert sorted(row.status for row in rows) == ["settled", "unknown"]


@pytest.mark.asyncio
async def test_live_model_usage_migration_rolls_back_and_restores(live):
    engine, _, _ = live
    async with engine.begin() as connection:
        await connection.run_sync(_alembic, "0006", "downgrade")
        tables = await connection.run_sync(lambda db: inspect(db).get_table_names())
        assert "supervision_model_usage" not in tables
        await connection.run_sync(_alembic, "head", "upgrade")
        tables = await connection.run_sync(lambda db: inspect(db).get_table_names())
        assert "supervision_model_usage" in tables


@pytest.mark.asyncio
async def test_live_operator_pause_cancel_and_task_terminal_block_provider_admission(
    live, monkeypatch
):
    _, maker, store = live
    engagement, task = await _seed(maker, {"llm_call_budget_total": 9}, monkeypatch)
    first = await store.request_control(
        engagement,
        task,
        "pause",
        "test-operator",
        "review",
        "pause-" + task,
        actor_role="operator",
    )
    assert first["status"] == "pending"
    with pytest.raises(ModelBudgetExceeded, match="Operator control"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")
    await store.resolve_control(
        first["request_id"],
        "acknowledged",
        {"status": "agent_checkpoint_pause", "execution_stopped": False},
    )
    await store.request_control(
        engagement,
        task,
        "resume",
        "test-operator",
        "continue",
        "resume-" + task,
        actor_role="operator",
    )
    assert await store.reserve(engagement, task, "openai/gpt-test", "completion")
    async with maker() as db:
        async with db.begin():
            await db.execute(update(TaskORM).where(TaskORM.id == task).values(status="cancelled"))
    with pytest.raises(ModelBudgetExceeded, match="Task is not executing"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")


@pytest.mark.asyncio
async def test_live_signed_precharge_parallel_admission_and_settlement_refund(live, monkeypatch):
    """Real PostgreSQL engagement row locks serialize multiple connections.

    Only the explicitly configured throwaway loopback DB is touched; calls
    never reach a provider, and the signed worst case is NOT a provider cap.
    """
    _, maker, store = live
    engagement, task = await _seed(
        maker,
        {
            "llm_cost_budget_usd": 1.0,
            "llm_precharge_max_call_usd": 0.4,
            "llm_call_budget_total": 10,
        },
        monkeypatch,
    )
    attempts = await asyncio.gather(
        *(store.reserve(engagement, task, "openai/gpt-test", "completion") for _ in range(7)),
        return_exceptions=True,
    )
    admitted = [result for result in attempts if isinstance(result, str)]
    assert len(admitted) == 2
    assert all(
        isinstance(result, ModelBudgetExceeded)
        for result in attempts
        if not isinstance(result, str)
    )
    async with maker() as db:
        pending = (
            (
                await db.execute(
                    select(ModelUsageORM).where(ModelUsageORM.engagement_id == engagement)
                )
            )
            .scalars()
            .all()
        )
        held = (
            (
                await db.execute(
                    select(SupervisionEventORM).where(
                        SupervisionEventORM.engagement_id == engagement,
                        SupervisionEventORM.kind == "llm.precharge_reserved",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(pending) == len(held) == 2
        assert sum(Decimal(evt.payload["amount"]) for evt in held) == Decimal("0.80000000")
        assert all(evt.payload["version"] == 1 for evt in held)
    provider_result = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=10,
            completion_tokens=2,
            billed_cost_usd=0.1,
        )
    )
    assert await store.settle(admitted[0], engagement, provider_result, delivered=True)
    assert not await store.settle(admitted[0], engagement, provider_result, delivered=True)
    assert await store.reserve(engagement, task, "openai/gpt-test", "completion")
    with pytest.raises(ModelBudgetExceeded, match="precharge"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")
    assert await store.settle(admitted[1], engagement, provider_result, delivered=True)
    assert await store.reserve(engagement, task, "openai/gpt-test", "completion")
    with pytest.raises(ModelBudgetExceeded, match="precharge|quota exhausted"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")
    summary = await store.summary(engagement)
    assert summary["outstanding_precharge_usd"] == "0.80000000"
    assert summary["provider_native_cost_ceiling_verified"] is False
    assert summary["cost_complete"] is False


@pytest.mark.asyncio
async def test_live_signed_invoice_credit_vs_admission_is_serialized(live, monkeypatch):
    """A real PG commit of operator credit must precede using its capacity."""
    _, maker, store = live
    engagement, task = await _seed(
        maker,
        {
            "llm_cost_budget_usd": 1.0,
            "llm_precharge_max_call_usd": 0.4,
            "llm_call_budget_total": 10,
        },
        monkeypatch,
    )
    call = await store.reserve(engagement, task, "openai/gpt-test", "completion")
    response = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=10,
            completion_tokens=5,
            billed_cost_usd=0.8,
        )
    )
    assert await store.settle(call, engagement, response, delivered=True)
    with pytest.raises(ModelBudgetExceeded, match="precharge"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")

    adjustment = dict(
        engagement_id=engagement,
        call_id=call,
        adjustment_id="adj-" + uuid.uuid4().hex,
        expected_task_id=task,
        expected_model="openai/gpt-test",
        expected_operation="completion",
        expected_authorization_version=1,
        provider="openai",
        invoice_reference="invoice-test-1",
        invoice_line_id="line-" + uuid.uuid4().hex,
        invoice_sha256="a" * 64,
        cost_delta_usd="-0.30000000",
        actor_id="test-operator",
        actor_role="senior_operator",
    )
    combined = await asyncio.gather(
        store.adjust_provider_invoice(**adjustment),
        store.reserve(engagement, task, "openai/gpt-test", "completion"),
        return_exceptions=True,
    )
    assert combined[0] is True
    assert isinstance(combined[1], (str, ModelBudgetExceeded))
    summary = await store.summary(engagement)
    assert summary["provider_reported_cost_usd"] == "0.80000000"
    assert (
        summary["invoice_adjusted_cost_usd"] is None
        or summary["invoice_adjusted_cost_usd"] == "0.50000000"
    )
    assert summary["invoice_adjustment_total_usd"] == "-0.30000000"
    # If reserve won the lock first it was denied; retry only after the
    # durable human credit event has committed (never optimistically).
    if isinstance(combined[1], ModelBudgetExceeded):
        assert await store.reserve(engagement, task, "openai/gpt-test", "completion")
    with pytest.raises(ModelBudgetExceeded, match="precharge"):
        await store.reserve(engagement, task, "openai/gpt-test", "completion")
    async with maker() as db:
        rows = (
            (
                await db.execute(
                    select(ModelUsageORM).where(ModelUsageORM.engagement_id == engagement)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        assert next(row for row in rows if row.call_id == call).billed_cost_usd == Decimal(
            "0.80000000"
        )
        events = (
            (
                await db.execute(
                    select(SupervisionEventORM).where(
                        SupervisionEventORM.engagement_id == engagement,
                        SupervisionEventORM.kind == "llm.invoice_adjustment",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(events) == 1 and events[0].payload["status"] == "operator_attested"
