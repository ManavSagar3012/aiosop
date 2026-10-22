"""Deterministic PG-row-lock model of model pre-charge and settlement.

No provider endpoint, app DB, pricing API or network calls are made.
The transaction lock emulates the row lock acquired by SupervisionStore._guard.
"""

import asyncio
import copy
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import (
    ModelBudgetExceeded,
    ModelOutcomeUncertain,
    ModelUsageLedger,
)
from ai_osop.memory.supervision_store import SupervisionConflict


class _Result:
    def __init__(self, value):
        self.value = value

    def scalars(self):
        return SimpleNamespace(all=lambda: self.value)

    def scalar_one_or_none(self):
        return self.value

    def one(self):
        return self.value


class _Pool:
    def __init__(self, *, cost=1, ceiling=0.4, count=12):
        self.lock = asyncio.Lock()
        self.rows = []
        self.events = []
        self.roe = {
            "llm_cost_budget_usd": cost,
            "llm_precharge_max_call_usd": ceiling,
            "llm_call_budget_total": count,
        }
        self.inject_failure = None
        self.statements = []

    def __call__(self):
        return _Session(self)


class _Session:
    def __init__(self, pool):
        self.pool = pool

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def begin(self):
        return self

    async def execute(self, query):
        sql = str(query)
        self.pool.statements.append(sql)
        if "FROM session_states" in sql:
            # Every settlement acquires the same durable session-row lock.
            assert "FOR UPDATE" in sql
            return _Result("eng-1")
        if "FROM supervision_controls" in sql:
            return _Result(None)
        if "FROM supervision_events" in sql:
            return _Result(list(self.pool.events))
        if "FROM supervision_model_usage" in sql:
            if "count(" in sql:
                rows = self.pool.rows
                return _Result(
                    (
                        len(rows),
                        sum(row.status == "settled" for row in rows),
                        sum(row.status != "settled" for row in rows),
                        sum(row.billed_cost_usd is None for row in rows),
                        sum((row.billed_cost_usd or Decimal(0) for row in rows), Decimal(0)),
                        sum((row.input_tokens or 0 for row in rows)) or None,
                        sum((row.output_tokens or 0 for row in rows)) or None,
                    )
                )
            if "FOR UPDATE" in sql:
                parameters = query.compile().params
                lookup = next(
                    (value for name, value in parameters.items() if name.startswith("call_id_")),
                    None,
                )
                return _Result(next((row for row in self.pool.rows if row.call_id == lookup), None))
            return _Result(list(self.pool.rows))
        raise AssertionError(sql)

    def add(self, row):
        # Simulated unit-of-work flushed inside the held engagement transaction.
        self.pool.rows.append(row)

    async def flush(self):
        return None


class _TransactionalSession(_Session):
    async def __aenter__(self):
        await self.pool.lock.acquire()
        self.snapshot = copy.deepcopy((self.pool.rows, self.pool.events))
        return self

    async def __aexit__(self, exc_type, *_):
        if exc_type is not None:
            self.pool.rows, self.pool.events = self.snapshot
        self.pool.lock.release()
        return False


def _pool_fixture(*, cost=1, ceiling=0.4, count=12, signed_version=5):
    pool = _Pool(cost=cost, ceiling=ceiling, count=count)

    # Each fake session's begin() returns a transaction with a shared row
    # lock; separate connections never share in-memory per-worker locks.
    class _Connection(_Session):
        def begin(self):
            return _TransactionalSession(self.pool)

    ledger = ModelUsageLedger(SimpleNamespace(_async_session=lambda: _Connection(pool)))
    task = SimpleNamespace(
        status="running",
        flow_id=None,
        approval_required=False,
        type="planner_inference",
        payload={"_authorization_version": signed_version},
    )
    engagement = SimpleNamespace(
        scope={"engagement_id": "eng-1", "domains": ["example.test"]},
        roe=pool.roe,
    )

    async def _guard(db, engagement_id, task_id, **kwargs):
        assert pool.lock.locked()  # Represents _guard's SELECT .. FOR UPDATE
        assert engagement_id == "eng-1"
        assert task_id == "task-1"
        assert kwargs.get("require_window") is True
        return engagement, task

    async def _append(db, engagement_id, task_id, kind, actor, payload, idempotency_key):
        if pool.inject_failure == kind:
            raise ConnectionError("Simulated PostgreSQL outbox failure")
        pool.events.append(
            SimpleNamespace(
                engagement_id=engagement_id,
                task_id=task_id,
                kind=kind,
                actor_id=actor,
                payload=copy.deepcopy(payload),
                idempotency_key=idempotency_key,
            )
        )
        return True

    ledger._guard = AsyncMock(side_effect=_guard)
    ledger._append_event = AsyncMock(side_effect=_append)
    return pool, ledger, task


def _response(cost=None):
    return SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=10,
            completion_tokens=3,
            billed_cost_usd=cost,
        ),
        choices=[SimpleNamespace(message=SimpleNamespace(content="synthetic"))],
    )


async def _reserve(ledger):
    return await ledger.reserve("eng-1", "task-1", "openai/test", "completion")


async def _settle(ledger, call_id, cost=None, delivered=True):
    return await ledger.settle(
        call_id,
        "eng-1",
        _response(cost),
        delivered=delivered,
    )


def _events(pool, kind):
    return [event for event in pool.events if event.kind == kind]


def _invoice_kwargs(call, *, line="line-001", amount="0.20000000"):
    return dict(
        engagement_id="eng-1",
        call_id=call,
        expected_task_id="task-1",
        expected_model="openai/test",
        expected_operation="completion",
        expected_authorization_version=5,
        provider="openai",
        invoice_reference="invoice-001",
        invoice_line_id=line,
        invoice_sha256="a" * 64,
        billed_cost_usd=amount,
        actor_id="senior-1",
        actor_role="senior_operator",
    )


def _adjust_kwargs(call, *, adjustment_id="adj-001", line="adjust-line-001", delta="-0.50000000"):
    args = _invoice_kwargs(call, line=line)
    args.pop("billed_cost_usd")
    args.update(adjustment_id=adjustment_id, cost_delta_usd=delta)
    return args


@pytest.mark.asyncio
async def test_precharge_requires_positive_explicit_signed_worst_case():
    for missing in (None, 0, -1, True, float("inf"), "0.4"):
        pool, ledger, _ = _pool_fixture()
        if missing is None:
            pool.roe.pop("llm_precharge_max_call_usd")
        else:
            pool.roe["llm_precharge_max_call_usd"] = missing
        with pytest.raises(ModelBudgetExceeded):
            await _reserve(ledger)
        assert pool.rows == [] and pool.events == []


@pytest.mark.asyncio
async def test_bound_at_budget_margin_does_not_admit_optimistic_call():
    pool, ledger, _ = _pool_fixture(cost=0.3, ceiling=0.31)
    with pytest.raises(ModelBudgetExceeded, match="precharge"):
        await _reserve(ledger)
    assert not pool.rows


@pytest.mark.asyncio
async def test_signed_hold_is_in_same_transaction_as_usage_row():
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.250000001)
    call = await _reserve(ledger)
    assert pool.rows[0].call_id == call
    assert pool.rows[0].billed_cost_usd is None
    event = _events(pool, "llm.precharge_reserved")[0]
    assert event.payload == {
        "status": "reserved",
        "call_id": call,
        "amount": "0.25000001",
        "version": 5,
        "source": "signed_operator_worst_case",
    }
    assert event.idempotency_key == "model-precharge:" + call
    assert pool.rows[0].status == "reserved"
    assert pool.statements  # Fake SQL runs inside the row-lock transaction.


@pytest.mark.asyncio
async def test_competing_parallel_precharges_never_overadmit_budget():
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.4)
    results = await asyncio.gather(
        *(_reserve(ledger) for _ in range(8)),
        return_exceptions=True,
    )
    ids = [result for result in results if isinstance(result, str)]
    assert len(ids) == 2
    assert all(
        isinstance(result, ModelBudgetExceeded) for result in results if not isinstance(result, str)
    )
    assert len({row.call_id for row in pool.rows}) == len(ids)
    assert sum(
        Decimal(event.payload["amount"]) for event in _events(pool, "llm.precharge_reserved")
    ) == Decimal("0.80000000")
    assert pool.lock.locked() is False


@pytest.mark.asyncio
async def test_successful_settlement_refunds_unused_held_capacity():
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.4)
    first, second = await asyncio.gather(_reserve(ledger), _reserve(ledger))
    with pytest.raises(ModelBudgetExceeded):
        await _reserve(ledger)
    assert await _settle(ledger, first, 0.1)
    release = _events(pool, "llm.precharge_settled")[0]
    assert release.payload["reserved_usd"] == "0.40000000"
    assert release.payload["released_usd"] == "0.30000000"
    assert release.payload["excess_usd"] == "0"
    assert release.payload["provider_native_cap_verified"] is False
    assert pool.rows[0].billed_cost_usd == Decimal("0.10000000")
    third = await _reserve(ledger)
    assert third not in {first, second}
    summary = await ledger.summary("eng-1")
    assert summary["outstanding_precharge_usd"] == "0.80000000"
    assert summary["cost_complete"] is False
    assert summary["provider_native_cost_ceiling_verified"] is False


@pytest.mark.asyncio
async def test_unknown_cost_keeps_held_capacity_and_disables_retry():
    pool, ledger, _ = _pool_fixture()
    first = await _reserve(ledger)
    assert await _settle(ledger, first, delivered=False)
    assert pool.rows[0].status == "unknown"
    assert pool.rows[0].billed_cost_usd is None
    assert not _events(pool, "llm.precharge_settled")
    with pytest.raises(ModelBudgetExceeded, match="unreconciled"):
        await _reserve(ledger)
    summary = await ledger.summary("eng-1")
    assert summary["outstanding_precharge_usd"] == "0.40000000"
    assert summary["cost_complete"] is False


@pytest.mark.asyncio
async def test_known_success_with_no_billed_cost_does_not_claim_refund():
    pool, ledger, _ = _pool_fixture()
    call = await _reserve(ledger)
    assert await _settle(ledger, call, cost=None, delivered=True)
    assert pool.rows[0].status == "settled"
    assert pool.rows[0].billed_cost_usd is None
    assert not _events(pool, "llm.precharge_settled")
    with pytest.raises(ModelBudgetExceeded, match="unreconciled receipt"):
        await _reserve(ledger)
    summary = await ledger.summary("eng-1")
    assert summary["outstanding_precharge_usd"] == "0.40000000"
    assert summary["cost_complete"] is False


@pytest.mark.asyncio
async def test_invoice_attestation_releases_hold_but_remains_operator_labeled():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, delivered=False)
    with pytest.raises(ModelBudgetExceeded, match="unreconciled"):
        await _reserve(ledger)
    # Inject signed-authorization verification, not any database operation.
    # The actual ModelUsageLedger method uses current PostgreSQL guard_sql.
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    attested = await ledger.reconcile_provider_invoice(
        "eng-1",
        call,
        expected_task_id="task-1",
        expected_model="openai/test",
        expected_operation="completion",
        expected_authorization_version=5,
        provider="openai",
        invoice_reference="invoice-001",
        invoice_line_id="line-001",
        invoice_sha256="a" * 64,
        billed_cost_usd="0.20000000",
        actor_id="senior-1",
        actor_role="senior_operator",
    )
    assert attested is True
    summary = await ledger.summary("eng-1")
    assert summary["outstanding_precharge_usd"] == "0"
    assert summary["provider_reported_cost_usd"] is None
    assert summary["operator_attested_invoice_cost_usd"] == "0.20000000"
    assert summary["cost_complete"] is True
    assert await _reserve(ledger)


@pytest.mark.asyncio
async def test_operator_invoice_token_claims_never_become_provider_reported_usage():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, delivered=False)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    assert await ledger.reconcile_provider_invoice(
        **_invoice_kwargs(call),
        input_tokens=200,
        output_tokens=25,
    )
    summary = await ledger.summary("eng-1")
    assert summary["provider_reported_cost_usd"] is None
    assert summary["provider_reported_input_tokens"] is None
    assert summary["provider_reported_output_tokens"] is None
    assert summary["operator_attested_invoice_input_tokens"] == 200
    assert summary["operator_attested_invoice_output_tokens"] == 25
    assert summary["operator_attested_invoice_cost_usd"] == "0.20000000"


@pytest.mark.asyncio
async def test_invoice_credit_restores_only_proven_capacity_and_cannot_be_replayed():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, 0.9)
    provider_fact = pool.rows[0].billed_cost_usd
    with pytest.raises(ModelBudgetExceeded, match="precharge"):
        await _reserve(ledger)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    credit = _adjust_kwargs(call)
    assert await ledger.adjust_provider_invoice(**credit)
    assert await ledger.adjust_provider_invoice(**credit) is False
    assert pool.rows[0].billed_cost_usd == provider_fact
    assert len(_events(pool, "llm.invoice_adjustment")) == 1
    summary = await ledger.summary("eng-1")
    assert summary["provider_reported_cost_usd"] == "0.90000000"
    assert summary["invoice_adjustment_total_usd"] == "-0.50000000"
    assert summary["invoice_adjusted_cost_usd"] == "0.40000000"
    assert await _reserve(ledger)
    with pytest.raises(ModelBudgetExceeded, match="precharge"):
        await _reserve(ledger)
    assert pool.rows[0].billed_cost_usd == provider_fact


@pytest.mark.asyncio
async def test_positive_invoice_adjustment_conserves_budget_and_denies_later_spend():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, 0.3)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    assert await ledger.adjust_provider_invoice(
        **_adjust_kwargs(call, delta="0.35000000"),
    )
    assert pool.rows[0].billed_cost_usd == Decimal("0.30000000")
    summary = await ledger.summary("eng-1")
    assert summary["invoice_adjusted_cost_usd"] == "0.65000000"
    with pytest.raises(ModelBudgetExceeded, match="precharge"):
        await _reserve(ledger)
    assert len(pool.rows) == 1


@pytest.mark.asyncio
async def test_invoice_credit_and_reservation_race_preserves_aggregate_signed_cap():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, 0.9)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)

    async def try_reserve():
        try:
            return await _reserve(ledger)
        except ModelBudgetExceeded as exc:
            return exc

    adjustment, attempted, repeated = await asyncio.gather(
        ledger.adjust_provider_invoice(**_adjust_kwargs(call)),
        try_reserve(),
        try_reserve(),
    )
    assert adjustment is True
    assert sum(isinstance(item, str) for item in (attempted, repeated)) <= 1
    assert all(isinstance(item, (str, ModelBudgetExceeded)) for item in (attempted, repeated))
    # Under either interleaving the committed bill is .9 - .5 = .4,
    # and at most one .4 pre-charge is allowed; no optimistic overrun.
    summary = await ledger.summary("eng-1")
    active_holds = sum(
        Decimal(event.payload["amount"])
        for event in _events(pool, "llm.precharge_reserved")
        if any(
            row.call_id == event.payload["call_id"] and row.status == "reserved"
            for row in pool.rows
        )
    )
    assert Decimal(summary["invoice_adjusted_cost_usd"] or "0") + active_holds <= Decimal("1")
    assert summary["provider_native_cost_ceiling_verified"] is False


@pytest.mark.asyncio
async def test_unknown_call_cannot_receive_unfounded_credit_or_reopen_admission():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, delivered=False)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    with pytest.raises(SupervisionConflict, match="settled"):
        await ledger.adjust_provider_invoice(**_adjust_kwargs(call))
    assert not _events(pool, "llm.invoice_adjustment")
    assert not _events(pool, "llm.precharge_settled")
    with pytest.raises(ModelBudgetExceeded, match="unreconciled"):
        await _reserve(ledger)


@pytest.mark.asyncio
async def test_invoice_reconciliation_event_failure_does_not_release_unknown_hold():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, delivered=False)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    pool.inject_failure = "llm.invoice_reconciled"
    with pytest.raises(ConnectionError, match="outbox"):
        await ledger.reconcile_provider_invoice(**_invoice_kwargs(call))
    assert pool.rows[0].status == "unknown"
    assert pool.rows[0].billed_cost_usd is None
    assert not _events(pool, "llm.invoice_reconciled")
    with pytest.raises(ModelBudgetExceeded, match="unreconciled"):
        await _reserve(ledger)


@pytest.mark.asyncio
async def test_settlement_races_reconciliation_without_double_refund():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    results = await asyncio.gather(
        _settle(ledger, call, cost=0.1),
        ledger.reconcile_provider_invoice(**_invoice_kwargs(call, amount="0.2")),
        return_exceptions=True,
    )
    assert pool.rows[0].status == "settled"
    assert sum(x is True for x in results) == 1
    # A provider settlement wins => invoice rejected; an invoice wins =>
    # a delayed provider settlement fails its one-shot CAS, never overwrites.
    assert results[0] is False or isinstance(results[1], SupervisionConflict)
    assert len(_events(pool, "llm.precharge_settled")) <= 1
    assert len(_events(pool, "llm.invoice_reconciled")) <= 1
    assert (
        len(_events(pool, "llm.precharge_settled")) + len(_events(pool, "llm.invoice_reconciled"))
        == 1
    )
    assert await _reserve(ledger)


@pytest.mark.asyncio
async def test_provider_over_operator_estimate_records_true_overage_and_blocks_future():
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, cost=1.1)
    assert pool.rows[0].billed_cost_usd == Decimal("1.10000000")
    over = _events(pool, "llm.precharge_settled")[0]
    assert over.payload["status"] == "over_estimate"
    assert over.payload["excess_usd"] == "0.70000000"
    assert over.payload["released_usd"] == "0"
    with pytest.raises(ModelBudgetExceeded, match="quota exhausted"):
        await _reserve(ledger)
    summary = await ledger.summary("eng-1")
    assert summary["provider_reported_cost_usd"] == "1.10000000"
    assert summary["provider_native_cost_ceiling_verified"] is False


@pytest.mark.asyncio
async def test_commit_failure_cannot_leave_an_untracked_hold_or_provider_admission():
    pool, ledger, _ = _pool_fixture()
    pool.inject_failure = "llm.precharge_reserved"
    with pytest.raises(ConnectionError, match="outbox"):
        await _reserve(ledger)
    assert pool.rows == [] and pool.events == []
    pool.inject_failure = None
    call = await _reserve(ledger)
    assert call and len(pool.rows) == 1


@pytest.mark.asyncio
async def test_settlement_event_outage_rolls_back_bill_and_refund():
    pool, ledger, _ = _pool_fixture()
    call = await _reserve(ledger)
    pool.inject_failure = "llm.precharge_settled"
    with pytest.raises(ConnectionError):
        await _settle(ledger, call, 0.01)
    assert pool.rows[0].status == "reserved"
    assert pool.rows[0].billed_cost_usd is None
    assert not _events(pool, "llm.precharge_settled")
    pool.inject_failure = None
    assert await _settle(ledger, call, 0.01)


@pytest.mark.asyncio
async def test_unknown_billing_event_write_failure_cannot_create_free_retry():
    pool, ledger, _ = _pool_fixture()
    call = await _reserve(ledger)
    pool.inject_failure = "llm.provider_usage"
    with pytest.raises(ConnectionError):
        await _settle(ledger, call, delivered=False)
    assert pool.rows[0].status == "reserved"
    assert not _events(pool, "llm.precharge_settled")
    pool.inject_failure = None
    assert await _settle(ledger, call, delivered=False)


@pytest.mark.asyncio
async def test_concurrent_reserve_and_settle_serialized_by_one_engagement_lock():
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    results = await asyncio.gather(
        _settle(ledger, call, cost=0.01),
        _reserve(ledger),
        _reserve(ledger),
        return_exceptions=True,
    )
    assert results[0] is True
    assert sum(isinstance(result, str) for result in results[1:]) == 2
    # A third reservation after settlement would commit 0.81 <= 1.00.
    # One more call must be blocked, not admitted optimistically.
    with pytest.raises(ModelBudgetExceeded):
        await _reserve(ledger)


@pytest.mark.asyncio
async def test_signed_call_budget_still_caps_parallel_admissions():
    pool, ledger, _ = _pool_fixture(cost=2, ceiling=0.1, count=1)
    results = await asyncio.gather(_reserve(ledger), _reserve(ledger), return_exceptions=True)
    assert sum(isinstance(x, str) for x in results) == 1
    assert any(isinstance(x, ModelBudgetExceeded) for x in results)


@pytest.mark.asyncio
async def test_missing_signed_task_version_denies_precharge_atomically():
    pool, ledger, task = _pool_fixture(signed_version=None)
    with pytest.raises(ModelBudgetExceeded, match="version"):
        await _reserve(ledger)
    assert not pool.rows and not pool.events


@pytest.mark.asyncio
async def test_real_client_mocked_provider_reserves_settles_and_preserves_unknown_cost():
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.5)
    client = LiteLLMClient(
        primary_model="openai/test",
        fallback_model="openai/alternate",
        usage_store=ledger,
    )
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    try:
        with (
            patch("ai_osop.core.llm_client.settings.mock_llm", False),
            patch(
                "ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock
            ) as provider,
        ):
            provider.return_value = _response(0.03)
            assert await client.complete([{"role": "user", "content": "Local test"}]) == "synthetic"
            assert provider.await_count == 1
            assert len(_events(pool, "llm.precharge_settled")) == 1
            provider.side_effect = TimeoutError("ambiguous transport")
            with pytest.raises(ModelOutcomeUncertain):
                await client.complete([{"role": "user", "content": "Local test"}])
            assert provider.await_count == 2  # No fallback or retry to paid provider.
            assert [row.status for row in pool.rows] == ["settled", "unknown"]
    finally:
        RequestContext.clear()


@pytest.mark.asyncio
async def test_client_refuses_paid_provider_without_signed_cost_precharge():
    pool, ledger, _ = _pool_fixture(cost=1)
    pool.roe.pop("llm_precharge_max_call_usd")
    client = LiteLLMClient(
        primary_model="openai/test",
        fallback_model="openai/alternate",
        usage_store=ledger,
    )
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    try:
        with (
            patch("ai_osop.core.llm_client.settings.mock_llm", False),
            patch(
                "ai_osop.core.llm_client.litellm.acompletion",
                new_callable=AsyncMock,
            ) as provider,
        ):
            with pytest.raises(ModelBudgetExceeded, match="precharge"):
                await client.complete([{"role": "user", "content": "Offline"}])
            provider.assert_not_awaited()
            assert pool.rows == [] and pool.events == []
    finally:
        RequestContext.clear()
