"""Provider-project observations vs per-call corrections, with PG lock emulation."""

import asyncio
import copy
import hashlib
import importlib.util
import time
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ai_osop.api.routers import provider_invoices
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelUsageLedger
from ai_osop.memory.provider_invoice_trust import ProviderCostInvalid
from ai_osop.memory.supervision_store import SupervisionConflict

_spec = importlib.util.spec_from_file_location(
    "_model_precharge_harness",
    Path(__file__).with_name("test_model_precharge_budget.py"),
)
assert _spec is not None and _spec.loader is not None
_harness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_harness)
_adjust_kwargs = _harness._adjust_kwargs
_events = _harness._events
_pool_fixture = _harness._pool_fixture
_reserve = _harness._reserve
_settle = _harness._settle

_PROJECT = "proj_AggregateEvidenceA"


def _observation(*, cost="0.300000001", end=None):
    project_hash = hashlib.sha256(_PROJECT.encode()).hexdigest()
    utc_day = int(time.time()) // 86400 * 86400
    end = end or utc_day
    return {
        "source": "openai_organization_costs_api",
        "source_authenticated": True,
        "source_scope": "configured_openai_project",
        "project_sha256": project_hash,
        "start_time": end - 86400,
        "end_time": end,
        "provider_cost_usd": cost,
        "provider_cost_data_present": cost is not None,
        "currency": "USD",
        "pages": 1,
        "buckets": 1 if cost is not None else 0,
        "cost_lines": 1 if cost is not None else 0,
        "individual_call_cost_verified": False,
        "provider_hard_cost_cap_verified": False,
        "ledger_mutated": False,
        "source_checked_at_utc": int(time.time()),
    }


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _AuditDatabase:
    """The same PG engagement-row lock serializes competing audit transactions."""

    def __init__(self):
        self.events = []
        self.lock = asyncio.Lock()
        self.owner = "senior-1"
        self.fail = False
        self.sql = []

    def __call__(self):
        return _AuditSession(self)


class _AuditSession:
    def __init__(self, pool):
        self.pool = pool

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def begin(self):
        return _AuditTransaction(self.pool)

    async def execute(self, query):
        sql = str(query)
        self.pool.sql.append(sql)
        if "FROM session_states" in sql:
            assert "FOR UPDATE" in sql
            return _Result(self.pool.owner)
        if "FROM supervision_events" in sql:
            parameters = query.compile().params
            key = next(
                (v for k, v in parameters.items() if "idempotency_key" in k),
                None,
            )
            return _Result(
                next((event for event in self.pool.events if event.idempotency_key == key), None)
            )
        raise AssertionError(sql)


class _AuditTransaction:
    def __init__(self, pool):
        self.pool = pool

    async def __aenter__(self):
        await self.pool.lock.acquire()
        self.original = copy.deepcopy(self.pool.events)
        return self

    async def __aexit__(self, exc_type, *_):
        if exc_type:
            self.pool.events = self.original
        self.pool.lock.release()
        return False


@pytest.fixture
def audited(monkeypatch):
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_TRUST_MODE", "openai_costs")
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_OPENAI_PROJECT_ID", _PROJECT)
    db = _AuditDatabase()
    ledger = ModelUsageLedger(SimpleNamespace(_async_session=db))

    async def append(
        _db,
        engagement_id,
        task_id,
        kind,
        actor_id,
        payload,
        idempotency_key,
    ):
        assert db.lock.locked()
        if db.fail:
            raise ConnectionError("simulated durable outbox failure")
        db.events.append(
            SimpleNamespace(
                engagement_id=engagement_id,
                task_id=task_id,
                kind=kind,
                actor_id=actor_id,
                payload=copy.deepcopy(payload),
                idempotency_key=idempotency_key,
            ),
        )

    ledger._append_event = AsyncMock(side_effect=append)
    return SimpleNamespace(db=db, ledger=ledger)


@pytest.mark.asyncio
async def test_audit_only_stores_bound_digest_no_amount_or_model_call(audited):
    assert await audited.ledger.audit_openai_cost_observation(
        "eng-1",
        "senior-1",
        _observation(),
    )
    event = audited.db.events[0]
    assert event.kind == "llm.provider_cost_observed"
    assert event.task_id is None
    assert event.payload["source"] == "openai_organization_costs_api"
    assert event.payload["source_authenticated"] is True
    assert event.payload["per_call_cost_verified"] is False
    assert event.payload["provider_native_cap_verified"] is False
    assert len(event.payload["snapshot_sha256"]) == 64
    assert "cost_usd" not in event.payload
    assert "call_id" not in event.payload
    assert _PROJECT not in str(event.payload)
    assert "0.300000001" not in str(event.payload)
    assert len(audited.db.events) == 1


@pytest.mark.asyncio
async def test_snapshot_replay_is_idempotent_and_concurrent_posting_is_atomic(audited):
    results = await asyncio.gather(
        *(
            audited.ledger.audit_openai_cost_observation(
                "eng-1",
                "senior-1",
                _observation(),
            )
            for _ in range(12)
        )
    )
    assert results.count(True) == 1
    assert results.count(False) == 11
    assert len(audited.db.events) == 1
    assert all("FOR UPDATE" in sql for sql in audited.db.sql if "FROM session_states" in sql)


@pytest.mark.asyncio
async def test_provider_corrected_aggregate_is_append_only_distinct_digest(audited):
    assert await audited.ledger.audit_openai_cost_observation(
        "eng-1",
        "senior-1",
        _observation(cost="0.3"),
    )
    assert await audited.ledger.audit_openai_cost_observation(
        "eng-1",
        "senior-1",
        _observation(cost="0.2"),
    )
    assert len(audited.db.events) == 2
    assert (
        audited.db.events[0].payload["snapshot_sha256"]
        != audited.db.events[1].payload["snapshot_sha256"]
    )
    assert not await audited.ledger.audit_openai_cost_observation(
        "eng-1",
        "senior-1",
        _observation(cost="0.3"),
    )
    assert len(audited.db.events) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        {"source_authenticated": False},
        {"individual_call_cost_verified": True},
        {"source": "operator_attested"},
        {"project_sha256": "f" * 64},
        {"provider_cost_usd": "-10"},
        {"provider_cost_usd": "not-number"},
        {"provider_cost_usd": None},
        {"cost_lines": 100000},
        {"ledger_mutated": True},
    ],
)
async def test_source_claim_or_wrong_project_cannot_self_attest(audited, fault):
    with pytest.raises((ProviderCostInvalid, ValueError)):
        await audited.ledger.audit_openai_cost_observation(
            "eng-1",
            "senior-1",
            {**_observation(), **fault},
        )
    assert not audited.db.events


@pytest.mark.asyncio
async def test_owner_conflict_and_outbox_failure_never_claim_audit_success(audited):
    audited.db.owner = "someone-else"
    with pytest.raises(PermissionError):
        await audited.ledger.audit_openai_cost_observation(
            "eng-1",
            "senior-1",
            _observation(),
        )
    audited.db.owner = "senior-1"
    audited.db.fail = True
    with pytest.raises(ConnectionError):
        await audited.ledger.audit_openai_cost_observation(
            "eng-1",
            "senior-1",
            _observation(),
        )
    assert audited.db.events == []


@pytest.mark.asyncio
async def test_conflicting_duplicate_audit_event_fails_closed(audited):
    evidence = _observation()
    assert await audited.ledger.audit_openai_cost_observation(
        "eng-1",
        "senior-1",
        evidence,
    )
    audited.db.events[0].payload["source_authenticated"] = False
    with pytest.raises(SupervisionConflict):
        await audited.ledger.audit_openai_cost_observation(
            "eng-1",
            "senior-1",
            evidence,
        )


@pytest.mark.asyncio
async def test_balanced_operator_credit_and_charge_are_not_provider_authoritative():
    pool, ledger, task = _pool_fixture(cost=2, ceiling=0.4)
    original = await _reserve(ledger)
    assert await _settle(ledger, original, cost=0.9)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    first = _adjust_kwargs(original)
    assert await ledger.adjust_provider_invoice(**first)
    assert not await ledger.adjust_provider_invoice(**first)
    credit = _events(pool, "llm.invoice_adjustment")[0]
    posting = credit.payload["posting"]
    assert posting == {
        "version": 1,
        "expense_debit_usd": "0",
        "expense_credit_usd": "0.50000000",
        "payable_debit_usd": "0.50000000",
        "payable_credit_usd": "0",
        "balance_before_usd": "0.90000000",
        "balance_after_usd": "0.40000000",
    }
    assert credit.payload["status"] == "operator_attested"
    charge = _adjust_kwargs(
        original,
        adjustment_id="adj-second",
        line="different-line",
        delta="0.25000000",
    )
    assert await ledger.adjust_provider_invoice(**charge)
    second = _events(pool, "llm.invoice_adjustment")[1]
    assert second.payload["posting"]["expense_debit_usd"] == "0.25000000"
    assert second.payload["posting"]["payable_credit_usd"] == "0.25000000"
    assert second.payload["posting"]["balance_before_usd"] == "0.40000000"
    assert second.payload["posting"]["balance_after_usd"] == "0.65000000"
    assert pool.rows[0].billed_cost_usd == Decimal("0.90000000")
    summary = await ledger.summary("eng-1")
    assert summary["provider_reported_cost_usd"] == "0.90000000"
    assert summary["invoice_adjusted_cost_usd"] == "0.65000000"


@pytest.mark.asyncio
async def test_tampered_double_entry_blocks_spend_and_summary():
    pool, ledger, task = _pool_fixture(cost=1, ceiling=0.4)
    original = await _reserve(ledger)
    assert await _settle(ledger, original, cost=0.9)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    assert await ledger.adjust_provider_invoice(**_adjust_kwargs(original))
    event = _events(pool, "llm.invoice_adjustment")[0]
    event.payload["posting"]["expense_credit_usd"] = "0.99999999"
    with pytest.raises(ModelBudgetExceeded, match="unbalanced"):
        await ledger.summary("eng-1")
    with pytest.raises(ModelBudgetExceeded, match="unbalanced"):
        await _reserve(ledger)
    assert len(pool.rows) == 1


@pytest.mark.asyncio
async def test_concurrent_credit_competition_refuses_overrefund():
    pool, ledger, task = _pool_fixture(cost=2, ceiling=0.4)
    original = await _reserve(ledger)
    assert await _settle(ledger, original, cost=0.4)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    competing = [
        _adjust_kwargs(original, adjustment_id=f"adj-{i}", line=f"line-{i}", delta="-0.30000000")
        for i in range(4)
    ]
    results = await asyncio.gather(
        *(ledger.adjust_provider_invoice(**args) for args in competing),
        return_exceptions=True,
    )
    assert sum(value is True for value in results) == 1
    assert sum(isinstance(value, SupervisionConflict) for value in results) == 3
    summary = await ledger.summary("eng-1")
    assert summary["invoice_adjusted_cost_usd"] == "0.10000000"
    assert len(_events(pool, "llm.invoice_adjustment")) == 1


@pytest.mark.asyncio
async def test_zero_and_signed_negative_zero_corrections_cannot_mint_events():
    pool, ledger, task = _pool_fixture(cost=2, ceiling=0.4)
    original = await _reserve(ledger)
    assert await _settle(ledger, original, cost=0.4)
    ledger._signed_invoice_guard = AsyncMock(return_value=task)
    for delta in ("0", "0.00000000", "-0", "-0.00000000"):
        with pytest.raises(ValueError, match="must change"):
            await ledger.adjust_provider_invoice(**_adjust_kwargs(original, delta=delta))
    assert not _events(pool, "llm.invoice_adjustment")


@pytest.mark.asyncio
async def test_provider_aggregate_provenance_never_unlocks_unknown_call():
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.4)
    call = await _reserve(ledger)
    assert await _settle(ledger, call, delivered=False)
    assert pool.rows[0].status == "unknown"
    with pytest.raises(ModelBudgetExceeded, match="unreconciled"):
        await _reserve(ledger)
    # Provider-wide daily snapshot has no call ID and cannot settle UNKNOWN.
    audited = _observation()
    assert audited["individual_call_cost_verified"] is False
    assert pool.rows[0].billed_cost_usd is None
    assert not _events(pool, "llm.precharge_settled")
    with pytest.raises(ModelBudgetExceeded, match="unreconciled"):
        await _reserve(ledger)


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_TRUST_MODE", "openai_costs")
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_OPENAI_PROJECT_ID", _PROJECT)
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_OPENAI_ENGAGEMENT_ID", "eng-1")
    operator = {"sub": "senior-1", "role": "senior_operator"}
    fake = SimpleNamespace(
        summary=AsyncMock(
            return_value={
                "provider_reported_cost_usd": None,
                "operator_attested_invoice_cost_usd": None,
                "invoice_adjusted_cost_usd": None,
                "unreconciled_cost_calls": 1,
            }
        ),
        audit_openai_cost_observation=AsyncMock(return_value=True),
    )
    source = SimpleNamespace(observe=AsyncMock(return_value=_observation()))
    monkeypatch.setattr(provider_invoices, "OpenAICostSource", lambda: source)
    owner = AsyncMock(return_value=fake)
    monkeypatch.setattr(provider_invoices, "_owned_ledger", owner)
    app = FastAPI()
    app.include_router(provider_invoices.router)
    app.dependency_overrides[provider_invoices._verified_senior] = lambda: operator
    return SimpleNamespace(client=TestClient(app), owner=owner, ledger=fake, source=source)


def test_real_observation_route_appends_aggregate_without_mutating_cost_ledger(api):
    today = int(time.time()) // 86400 * 86400
    path = "/supervision/engagements/eng-1/model-usage/provider-costs/openai/observe"
    reply = api.client.post(path, json={"start_time": today - 86400, "end_time": today})
    assert reply.status_code == 200
    data = reply.json()
    assert data["observation_recorded"] is True
    assert data["ledger_mutated"] is False
    assert data["individual_call_cost_verified"] is False
    assert data["provider_project_comparable_to_engagement"] is False
    assert data["local_ledger"]["unreconciled_cost_calls"] == 1
    api.ledger.audit_openai_cost_observation.assert_awaited_once_with(
        "eng-1",
        "senior-1",
        _observation(),
    )
    api.ledger.summary.assert_awaited_once_with("eng-1")


def test_aggregate_audit_outage_fails_closed_without_claiming_recorded(api):
    today = int(time.time()) // 86400 * 86400
    api.ledger.audit_openai_cost_observation.side_effect = OSError("PG down secret")
    reply = api.client.post(
        "/supervision/engagements/eng-1/model-usage/provider-costs/openai/observe",
        json={"start_time": today - 86400, "end_time": today},
    )
    assert reply.status_code == 503
    assert "secret" not in reply.text


def test_per_call_source_verification_denies_missing_authoritative_identity(api):
    path = "/supervision/engagements/eng-1/model-usage/calls/call-1/invoice/verify-source"
    reply = api.client.post(path)
    assert reply.status_code == 409
    assert reply.json() == {
        "detail": "Provider cost source does not attest individual model calls",
    }
    api.source.observe.assert_not_awaited()
    api.ledger.audit_openai_cost_observation.assert_not_awaited()


def test_per_call_source_verification_requires_owner_first(api):
    api.owner.side_effect = HTTPException(status_code=403, detail="Engagement access denied")
    reply = api.client.post(
        "/supervision/engagements/eng-1/model-usage/calls/call-1/invoice/verify-source",
    )
    assert reply.status_code == 403
    api.source.observe.assert_not_awaited()
