"""Deterministic, offline invoice attestation and adjustment fences."""

import copy
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.memory.model_usage import (
    ModelBudgetExceeded,
    ModelOutcomeUncertain,
    ModelUsageLedger,
    _amount,
)
from ai_osop.memory.supervision_store import SupervisionConflict


_DIGEST = "a" * 64


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return SimpleNamespace(all=lambda: self.value)

    def one(self):
        return self.value


class _FakeDB:
    """Serial DB with transactional rollback for deterministic injection tests."""

    def __init__(self, row=None, events=None):
        self.rows = [row] if row else []
        self.events = list(events or [])
        self.added = []
        self.sql = []

    def __call__(self):
        return self

    def begin(self):
        return _Txn(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def execute(self, stmt):
        self.sql.append(str(stmt))
        query = str(stmt)
        if "supervision_events" in query:
            return _Result(list(self.events))
        if "supervision_controls" in query:
            return _Result(None)
        if "supervision_model_usage" in query:
            if "count(" in query:
                rows = self.rows
                return _Result(
                    (
                        len(rows),
                        sum(row.status == "settled" for row in rows),
                        sum(row.status != "settled" for row in rows),
                        sum(row.billed_cost_usd is None for row in rows),
                        sum((row.billed_cost_usd or Decimal(0) for row in rows), Decimal(0)),
                        None,
                        None,
                    )
                )
            return _Result(
                list(self.rows)
                if "FOR UPDATE" not in query
                else (self.rows[0] if self.rows else None)
            )
        raise AssertionError(f"Unrecognized SQL: {query}")

    def add(self, value):
        self.added.append(value)


class _Txn:
    def __init__(self, db):
        self.db = db

    async def __aenter__(self):
        self.snapshot = copy.deepcopy((self.db.rows, self.db.events, self.db.added))
        return self.db

    async def __aexit__(self, kind, *_):
        if kind:
            self.db.rows, self.db.events, self.db.added = self.snapshot
        return False


def _row(status="unknown", billed_cost=None):
    return SimpleNamespace(
        call_id="call-1",
        engagement_id="eng-1",
        task_id="task-1",
        model="openai/gpt-test",
        operation="completion",
        status=status,
        billed_cost_usd=billed_cost,
        input_tokens=None,
        output_tokens=None,
        updated_at=None,
    )


def _options(**overrides):
    args = dict(
        engagement_id="eng-1",
        call_id="call-1",
        expected_task_id="task-1",
        expected_model="openai/gpt-test",
        expected_operation="completion",
        expected_authorization_version=7,
        provider="openai",
        invoice_reference="inv-123",
        invoice_line_id="line-123",
        invoice_sha256=_DIGEST,
        billed_cost_usd="0.01500000",
        actor_id="senior-1",
        actor_role="senior_operator",
        input_tokens=20,
        output_tokens=4,
    )
    args.update(overrides)
    return args


@pytest.fixture
def ledger(monkeypatch):
    from ai_osop.memory.authorization_store import guard_sql

    db = _FakeDB(_row())
    store = ModelUsageLedger(SimpleNamespace(_async_session=db))
    engagement = SimpleNamespace(
        roe={"llm_cost_budget_usd": 0.02, "llm_precharge_max_call_usd": 0.005},
        scope={"engagement_id": "eng-1", "domains": ["example.test"]},
    )
    task = SimpleNamespace(
        payload={"_authorization_version": 7},
        status="running",
        flow_id=None,
        approval_required=False,
        type="summarize_context",
    )
    guard = AsyncMock(return_value=(engagement, task))
    signed = AsyncMock(return_value=SimpleNamespace(version=7))
    monkeypatch.setattr(ModelUsageLedger, "_guard", guard)
    monkeypatch.setattr("ai_osop.memory.authorization_store.guard_sql", signed)

    async def event_writer(_db, engagement_id, task_id, kind, actor_id, payload, idempotency_key):
        db.events.append(
            SimpleNamespace(
                engagement_id=engagement_id,
                task_id=task_id,
                kind=kind,
                actor_id=actor_id,
                payload=payload,
                idempotency_key=idempotency_key,
            )
        )
        return True

    append = AsyncMock(side_effect=event_writer)
    monkeypatch.setattr(store, "_append_event", append)
    return SimpleNamespace(db=db, store=store, guard=guard, signed=signed, append=append)


@pytest.mark.asyncio
async def test_invoice_reconciles_unknown_exactly_once_without_provider_invocation(ledger):
    args = _options()
    assert await ledger.store.reconcile_provider_invoice(**args) is True
    row = ledger.db.rows[0]
    assert row.status == "settled"
    assert row.billed_cost_usd == Decimal("0.01500000")
    assert (row.input_tokens, row.output_tokens) == (20, 4)
    assert await ledger.store.reconcile_provider_invoice(**args) is False
    assert len(ledger.db.events) == 1
    event = ledger.db.events[0]
    assert event.kind == "llm.invoice_reconciled"
    assert event.payload["status"] == "operator_attested"
    assert event.payload["version"] == 7
    assert event.payload["invoice_sha256"] == _DIGEST
    assert "inv-123" not in str(event.payload)
    assert "line-123" not in str(event.payload)
    assert len(event.payload["invoice_line_sha256"]) == 64
    summary = await ledger.store.summary("eng-1")
    assert summary["provider_reported_cost_usd"] is None
    assert summary["operator_attested_invoice_cost_usd"] == "0.01500000"
    ledger.signed.assert_awaited_with(ledger.db, "eng-1", expected_version=7)
    assert any("FOR UPDATE" in text for text in ledger.db.sql)
    assert ledger.guard.await_args.kwargs["actor_role"] == "senior_operator"


@pytest.mark.parametrize("status", ["reserved", "unknown"])
@pytest.mark.asyncio
async def test_disconnected_provider_settlement_can_be_attested_from_invoice(ledger, status):
    ledger.db.rows[0].status = status
    assert await ledger.store.reconcile_provider_invoice(**_options())
    assert ledger.db.rows[0].status == "settled"


@pytest.mark.asyncio
async def test_missing_price_from_provider_keeps_original_facts_immutable(ledger):
    row = ledger.db.rows[0]
    row.status = "settled"
    row.input_tokens = 111
    row.output_tokens = 22
    args = _options(input_tokens=None, output_tokens=None)
    assert await ledger.store.reconcile_provider_invoice(**args)
    assert row.status == "settled"
    assert row.billed_cost_usd is None
    assert (row.input_tokens, row.output_tokens) == (111, 22)
    assert await ledger.store.reconcile_provider_invoice(**args) is False
    summary = await ledger.store.summary("eng-1")
    assert summary["cost_complete"] is True
    assert summary["invoice_adjusted_cost_usd"] == "0.01500000"
    assert summary["unpriced_calls"] == 1  # Original provider field remains NULL.
    assert summary["provider_reported_cost_usd"] is None


@pytest.mark.asyncio
async def test_previously_billed_provider_facts_are_immutable(ledger):
    ledger.db.rows[0].status = "settled"
    ledger.db.rows[0].billed_cost_usd = Decimal("0.0012")
    with pytest.raises(SupervisionConflict, match="requires an adjustment"):
        await ledger.store.reconcile_provider_invoice(**_options())
    assert ledger.db.events == []


@pytest.mark.asyncio
async def test_replayed_invoice_with_changed_billing_facts_is_rejected(ledger):
    assert await ledger.store.reconcile_provider_invoice(**_options())
    for altered in (
        {"invoice_line_id": "line-999"},
        {"billed_cost_usd": "0.01600000"},
        {"input_tokens": 21},
    ):
        with pytest.raises(SupervisionConflict, match="immutable"):
            await ledger.store.reconcile_provider_invoice(**_options(**altered))
    assert len(ledger.db.events) == 1


@pytest.mark.asyncio
async def test_adjustment_is_append_only_exact_and_idempotent(ledger):
    row = ledger.db.rows[0]
    row.status = "settled"
    row.billed_cost_usd = Decimal("0.012")
    args = _options()
    args.pop("billed_cost_usd")
    args.pop("input_tokens")
    args.pop("output_tokens")
    args.update(adjustment_id="adjust-1", cost_delta_usd="-0.00200000")
    assert await ledger.store.adjust_provider_invoice(**args)
    assert await ledger.store.adjust_provider_invoice(**args) is False
    assert len(ledger.db.events) == 1
    assert row.billed_cost_usd == Decimal("0.012")
    assert ledger.db.events[0].kind == "llm.invoice_adjustment"
    assert ledger.db.events[0].payload["amount"] == "-0.00200000"
    summary = await ledger.store.summary("eng-1")
    assert summary["invoice_adjusted_cost_usd"] == "0.01000000"
    assert summary["invoice_adjustment_total_usd"] == "-0.00200000"


@pytest.mark.asyncio
async def test_different_adjustment_cannot_reuse_identifier_or_invoice_line(ledger):
    ledger.db.rows[0].status = "settled"
    ledger.db.rows[0].billed_cost_usd = Decimal("0.005")
    args = _options()
    args.pop("billed_cost_usd")
    args.pop("input_tokens")
    args.pop("output_tokens")
    args.update(adjustment_id="adj-1", cost_delta_usd="0.001")
    assert await ledger.store.adjust_provider_invoice(**args)
    with pytest.raises(SupervisionConflict, match="different facts"):
        await ledger.store.adjust_provider_invoice(**dict(args, cost_delta_usd="0.002"))
    with pytest.raises(SupervisionConflict, match="already allocated"):
        await ledger.store.adjust_provider_invoice(**dict(args, adjustment_id="adj-2"))
    assert len(ledger.db.events) == 1


@pytest.mark.asyncio
async def test_invoice_line_cannot_be_allocated_to_a_second_call(ledger):
    assert await ledger.store.reconcile_provider_invoice(**_options())
    ledger.db.rows[0] = _row("unknown")
    ledger.db.rows[0].call_id = "call-2"
    with pytest.raises(SupervisionConflict, match="already allocated"):
        await ledger.store.reconcile_provider_invoice(**_options(call_id="call-2"))
    assert ledger.db.rows[0].status == "unknown"
    assert len(ledger.db.events) == 1


@pytest.mark.asyncio
async def test_adjustment_cannot_credit_more_than_the_billed_cost(ledger):
    ledger.db.rows[0].status = "settled"
    ledger.db.rows[0].billed_cost_usd = Decimal("0.01")
    args = _options()
    args.pop("billed_cost_usd")
    args.pop("input_tokens")
    args.pop("output_tokens")
    with pytest.raises(SupervisionConflict, match="bounds"):
        await ledger.store.adjust_provider_invoice(
            **dict(args, adjustment_id="adj-overdraw", cost_delta_usd="-0.02")
        )
    assert ledger.db.events == []


@pytest.mark.parametrize(
    "change",
    [
        {"expected_task_id": "task-foreign"},
        {"expected_model": "openai/gpt-another"},
        {"expected_operation": "embedding"},
        {"provider": "anthropic"},
        {"expected_authorization_version": 8},
        {"invoice_sha256": "not-a-digest"},
        {"billed_cost_usd": "NaN"},
        {"billed_cost_usd": "0.000000001"},
        {"billed_cost_usd": 0.005},
        {"billed_cost_usd": "-0.5"},
        {"actor_role": "operator"},
        {"actor_id": ""},
    ],
)
@pytest.mark.asyncio
async def test_mismatched_or_unverifiable_invoice_denied(ledger, change):
    before = copy.deepcopy(ledger.db.rows[0].__dict__)
    options = _options(**change)
    if "expected_authorization_version" in change:
        ledger.signed.side_effect = PermissionError("signed revision changed")
    with pytest.raises((ValueError, PermissionError, SupervisionConflict)):
        await ledger.store.reconcile_provider_invoice(**options)
    assert ledger.db.rows[0].__dict__ == before
    assert ledger.db.events == []


@pytest.mark.asyncio
async def test_revoked_signer_or_write_failure_preserves_unsettled_call(ledger):
    ledger.signed.side_effect = PermissionError("revoked signed key")
    with pytest.raises(PermissionError):
        await ledger.store.reconcile_provider_invoice(**_options())
    assert ledger.db.rows[0].status == "unknown"
    ledger.signed.side_effect = None
    ledger.append.side_effect = ConnectionError("outbox database unavailable")
    with pytest.raises(ConnectionError):
        await ledger.store.reconcile_provider_invoice(**_options())
    assert ledger.db.rows[0].status == "unknown"
    assert ledger.db.events == []


@pytest.mark.asyncio
async def test_task_signed_revision_change_blocks_invoice_even_with_valid_signer(ledger):
    ledger.guard.return_value[1].payload["_authorization_version"] = 8
    with pytest.raises(PermissionError, match="changed"):
        await ledger.store.reconcile_provider_invoice(**_options())
    assert ledger.db.events == []
    assert ledger.db.rows[0].status == "unknown"


@pytest.mark.asyncio
async def test_signed_budget_counts_operator_adjustments_before_another_reservation(ledger):
    row = ledger.db.rows[0]
    row.status = "settled"
    row.billed_cost_usd = Decimal("0.01200000")
    args = _options()
    args.pop("billed_cost_usd")
    args.pop("input_tokens")
    args.pop("output_tokens")
    assert await ledger.store.adjust_provider_invoice(
        **dict(args, adjustment_id="adj-1", cost_delta_usd="0.00800000")
    )
    with pytest.raises(ModelBudgetExceeded, match="quota exhausted"):
        await ledger.store.reserve("eng-1", "task-1", "openai/gpt-test", "completion")
    assert ledger.db.added == []


@pytest.mark.parametrize("value", ["0", "1.00000000", "2.1", Decimal("0.00000001")])
def test_exact_cost_validation_preserves_precision(value):
    assert _amount(value) == Decimal(value).quantize(Decimal("0.00000001"))


@pytest.mark.asyncio
async def test_provider_cost_excess_precision_denies_lossy_postgres_rounding(ledger):
    row = ledger.db.rows[0]
    row.status = "reserved"
    response = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=10,
            completion_tokens=3,
            billed_cost_usd=0.000000001,
        )
    )
    with pytest.raises(ValueError, match="monetary amount"):
        await ledger.store.settle("call-1", "eng-1", response, delivered=True)
    assert row.status == "reserved"


@pytest.mark.asyncio
async def test_llm_client_never_reports_uncommitted_cost_as_billed(monkeypatch):
    from ai_osop.core import llm_client
    from ai_osop.core.telemetry import RequestContext

    usage = SimpleNamespace(prompt_tokens=10, completion_tokens=3, billed_cost_usd=0.01)
    response = SimpleNamespace(
        usage=usage,
        choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
    )
    provider = AsyncMock(return_value=response)
    reserve = AsyncMock(return_value="call-1")
    settle = AsyncMock(side_effect=ConnectionError("DB commit unknown"))
    metering = SimpleNamespace(reserve=reserve, settle=settle)
    cost_metric = MagicMock()
    call_metric = MagicMock()
    provenance = AsyncMock()
    monkeypatch.setattr(llm_client.litellm, "acompletion", provider)
    monkeypatch.setattr("ai_osop.core.observability.record_engagement_cost", cost_metric)
    monkeypatch.setattr("ai_osop.core.observability.record_llm_call", call_metric)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    try:
        client = llm_client.LiteLLMClient(
            usage_store=metering,
            provenance_callback=provenance,
        )
        with pytest.raises(ModelOutcomeUncertain, match="persisted"):
            await client.complete([{"role": "user", "content": "Synthetic"}])
        await client.drain_provenance()
        provider.assert_awaited_once()
        settle.assert_awaited_once()
        cost_metric.assert_not_called()
        assert call_metric.call_args.kwargs["cost_usd"] is None
        provenance.assert_awaited_once()
        action = provenance.await_args.args[0]
        assert action["outcome"] == "unknown"
        assert action["safe_metadata"]["cost_source"] == "unavailable"
        assert "cost_usd" not in action["safe_metadata"]
    finally:
        RequestContext.clear()
