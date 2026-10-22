"""Transactional model-spend admission against deterministic PostgreSQL surrogates.

Only the production ModelUsageLedger.reserve and its SQLAlchemy WHERE/FOR
UPDATE statements are exercised. No application DB, provider, external target,
network or billing API is accessed. Fake signed-ROE guard and shared
transaction are deliberately NOT evidence of live PostgreSQL qualification.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core import provider_routing
from ai_osop.memory.model_usage import (
    ModelBudgetExceeded,
    ModelUsageLedger,
)
from ai_osop.memory.supervision_store import SupervisionConflict


class _Result:
    def __init__(self, row=None):
        self.row = row

    def scalar_one_or_none(self):
        return self.row

    def scalars(self):
        return SimpleNamespace(all=lambda: self.row)


def _task():
    return SimpleNamespace(
        id="task-reservation",
        engagement_id="eng-reservation",
        status="running",
        agent_type="vuln_analysis",
        assigned_agent_id="agent-claimed",
        started_at=datetime.utcnow() - timedelta(seconds=10),
        completed_at=None,
        flow_id="flow-reservation",
        payload={"_authorization_version": 3, "_flow_revision": 7},
        type="planner_inference",
        approval_required=False,
    )


class _Database:
    def __init__(self):
        self.task = _task()
        self.flow = SimpleNamespace(status="running", revision=7)
        self.lease = SimpleNamespace(
            state="dispatched",
            owner_id="temporal-agent-claim",
            lease_id="lease-execution-current",
            expires_at=datetime.utcnow() + timedelta(minutes=5),
        )
        self.guard_task = copy.deepcopy(self.task)
        self.engagement = SimpleNamespace(
            roe={
                "llm_call_budget_total": 2,
                "llm_cost_budget_usd": 1.0,
                "llm_precharge_max_call_usd": 0.4,
            },
            scope={"engagement_id": "eng-reservation", "domains": ["test.invalid"]},
        )
        self.model_calls = []
        self.precharges = []
        self.queries = []
        self.guard_seen = False
        self.guard_revoke = False
        self.task_after_guard = None
        self.active_transaction = False
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def begin(self):
        return _Transaction(self)

    async def execute(self, stmt):
        assert self.active_transaction, "All model admission SELECTs must use the guard's transaction"
        sql = str(stmt)
        self.queries.append(sql)
        if "FROM tasks" in sql:
            assert "FOR UPDATE" in sql, "TaskORM must be reloaded with PG row lock"
            assert self.guard_seen, "Task lock must follow signed ROE guard"
            if self.task_after_guard is not None:
                self.task = self.task_after_guard
            return _Result(self.task)
        if "FROM execution_flows" in sql:
            assert "FOR UPDATE" in sql, "ExecutionFlowORM revision must be locked"
            return _Result(self.flow)
        if "FROM supervision_execution_leases" in sql:
            assert "FOR UPDATE" in sql, "Current execution lease must be locked"
            return _Result(self.lease)
        if "FROM supervision_controls" in sql:
            return _Result(None)
        if "FROM supervision_model_usage" in sql:
            return _Result(list(self.model_calls))
        raise AssertionError(f"Unexpected SQL admission operation: {sql}")

    def add(self, row):
        assert self.active_transaction
        self.model_calls.append(row)


class _Transaction:
    def __init__(self, db):
        self.db = db

    async def __aenter__(self):
        assert not self.db.active_transaction
        self.db.active_transaction = True
        self.calls_before = list(self.db.model_calls)
        self.precharges_before = list(self.db.precharges)
        return self.db

    async def __aexit__(self, exc_type, *_args):
        if exc_type is None:
            self.db.commits += 1
        else:
            self.db.rollbacks += 1
            self.db.model_calls[:] = self.calls_before
            self.db.precharges[:] = self.precharges_before
        self.db.active_transaction = False
        return False


def _ledger(db):
    ledger = ModelUsageLedger(SimpleNamespace(_async_session=lambda: db))

    async def signed_guard(session, engagement_id, task_id, *, require_window=False):
        assert session is db
        assert db.active_transaction
        assert require_window is True
        assert engagement_id == "eng-reservation"
        assert task_id == "task-reservation"
        db.guard_seen = True
        if db.guard_revoke:
            raise SupervisionConflict("signed ROE revoked")
        return db.engagement, db.guard_task

    async def append_event(
        session,
        engagement_id,
        task_id,
        kind,
        actor,
        payload,
        *,
        idempotency_key,
    ):
        assert session is db and db.active_transaction and db.guard_seen
        assert kind == "llm.precharge_reserved"
        assert engagement_id == "eng-reservation"
        assert task_id == "task-reservation"
        db.precharges.append(dict(payload))
        return True

    async def invoice_events(_session, _engagement_id):
        return []

    async def precharge_events(_session, _engagement_id):
        return {item["call_id"]: __import__("decimal").Decimal(item["amount"]) for item in db.precharges}

    ledger._guard = AsyncMock(side_effect=signed_guard)
    ledger._append_event = AsyncMock(side_effect=append_event)
    ledger._invoice_events = AsyncMock(side_effect=invoice_events)
    ledger._precharge_events = AsyncMock(side_effect=precharge_events)
    return ledger


@pytest.fixture(autouse=True)
def _authorized_v2_fixture(monkeypatch):
    monkeypatch.delenv("OSOP_VERIFIED_PROVIDER_ROUTES_JSON", raising=False)
    # The already-authorized v2 routing scope is an independent gate tested
    # elsewhere. This fixture isolates the *reservation-time* SQL recheck.
    # Never conflate a mocked preflight with real signed authorization.
    permitted = SimpleNamespace(
        version=2, resolve=lambda model, operation: (model, operation)
    )
    monkeypatch.setattr(provider_routing, "configured_routes", lambda: permitted)


async def _reserve(ledger):
    return await ledger.reserve(
        "eng-reservation", "task-reservation", "openai/test-model", "completion"
    )


@pytest.mark.asyncio
async def test_valid_signed_running_flow_and_lease_reserve_in_same_transaction():
    db = _Database()
    ledger = _ledger(db)
    call_id = await _reserve(ledger)
    assert call_id.startswith("call-")
    assert db.guard_seen
    ledger._guard.assert_awaited_once_with(
        db, "eng-reservation", "task-reservation", require_window=True
    )
    assert db.commits == 1 and db.rollbacks == 0
    assert [r.call_id for r in db.model_calls] == [call_id]
    assert db.model_calls[0].status == "reserved"
    assert db.precharges == [
        {
            "status": "reserved",
            "call_id": call_id,
            "amount": "0.40000000",
            "version": 3,
            "source": "signed_operator_worst_case",
        }
    ]
    sql = "\n".join(db.queries)
    assert sql.index("FROM tasks") < sql.index("FROM execution_flows")
    assert sql.index("FROM execution_flows") < sql.index("FROM supervision_execution_leases")
    assert sql.index("FROM supervision_execution_leases") < sql.index(
        "FROM supervision_model_usage"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "scheduled",
        "dispatching",
        "pending",
        "completed",
        "missing_task",
        "unassigned",
        "blank_assignee",
        "missing_start",
        "completed_timestamp",
        "missing_flow",
        "malformed_flow",
        "missing_signed_version",
        "bool_signed_version",
        "missing_revision",
        "bool_revision",
        "mismatched_two_revisions",
        "stopped_flow",
        "pending_flow",
        "stale_flow_revision",
        "missing_flow_record",
        "missing_lease",
        "reserved_lease",
        "released_lease",
        "unknown_lease",
        "expired_lease",
        "owner_missing",
        "owner_malformed",
        "lease_id_missing",
        "lease_id_malformed",
        "task_changed_after_guard",
        "authorization_revoked",
    ],
)
async def test_adversarial_claim_flow_lease_and_signed_roe_denied_without_precharge(change):
    db = _Database()
    ledger = _ledger(db)
    if change in {"scheduled", "dispatching", "pending", "completed"}:
        db.task.status = change
        db.guard_task.status = change
    elif change == "missing_task":
        db.task = None
    elif change == "unassigned":
        db.task.assigned_agent_id = db.guard_task.assigned_agent_id = None
    elif change == "blank_assignee":
        db.task.assigned_agent_id = db.guard_task.assigned_agent_id = "  "
    elif change == "missing_start":
        db.task.started_at = db.guard_task.started_at = None
    elif change == "completed_timestamp":
        db.task.completed_at = db.guard_task.completed_at = datetime.utcnow()
    elif change == "missing_flow":
        db.task.flow_id = db.guard_task.flow_id = None
    elif change == "malformed_flow":
        db.task.flow_id = db.guard_task.flow_id = "../other"
    elif change == "missing_signed_version":
        db.task.payload.pop("_authorization_version")
        db.guard_task.payload.pop("_authorization_version")
    elif change == "bool_signed_version":
        db.task.payload["_authorization_version"] = True
        db.guard_task.payload["_authorization_version"] = True
    elif change == "missing_revision":
        db.task.payload.pop("_flow_revision")
        db.guard_task.payload.pop("_flow_revision")
    elif change == "bool_revision":
        db.task.payload["_flow_revision"] = True
        db.guard_task.payload["_flow_revision"] = True
    elif change == "mismatched_two_revisions":
        db.task.payload["planner_flow_revision"] = 6
        db.guard_task.payload["planner_flow_revision"] = 6
    elif change == "stopped_flow":
        db.flow.status = "paused"
    elif change == "pending_flow":
        db.flow.status = "pending"
    elif change == "stale_flow_revision":
        db.flow.revision = 8
    elif change == "missing_flow_record":
        db.flow = None
    elif change == "missing_lease":
        db.lease = None
    elif change in {"reserved_lease", "released_lease", "unknown_lease"}:
        db.lease.state = change.removesuffix("_lease")
    elif change == "expired_lease":
        db.lease.expires_at = datetime.utcnow() - timedelta(seconds=1)
    elif change == "owner_missing":
        db.lease.owner_id = None
    elif change == "owner_malformed":
        db.lease.owner_id = "../../external"
    elif change == "lease_id_missing":
        db.lease.lease_id = None
    elif change == "lease_id_malformed":
        db.lease.lease_id = "not-a-lease"
    elif change == "task_changed_after_guard":
        db.task_after_guard = copy.deepcopy(db.task)
        db.task_after_guard.assigned_agent_id = "agent-other"
    elif change == "authorization_revoked":
        db.guard_revoke = True
    with pytest.raises(ModelBudgetExceeded):
        await _reserve(ledger)
    assert db.model_calls == []
    assert db.precharges == []
    assert db.rollbacks == 1


@pytest.mark.asyncio
async def test_budget_exhaustion_and_ambiguous_previous_usage_still_deny():
    db = _Database()
    db.engagement.roe["llm_call_budget_total"] = 10
    ledger = _ledger(db)
    call_id = await _reserve(ledger)
    assert call_id
    # The signed 1 USD engagement ceiling holds only two 0.40 USD
    # reservations. A third is denied, including the pending hold.
    await _reserve(ledger)
    with pytest.raises(ModelBudgetExceeded, match="precharge exceeds signed cost budget"):
        await _reserve(ledger)
    assert len(db.model_calls) == 2
    assert len(db.precharges) == 2
    # If a call's settlement is uncertain, its cost is NOT zero and further
    # admission must be blocked even with fresh Task/Flow/lease evidence.
    db.model_calls[0].status = "unknown"
    with pytest.raises(ModelBudgetExceeded, match="unreconciled outcome"):
        await _reserve(ledger)
    assert len(db.model_calls) == 2
    assert len(db.precharges) == 2


@pytest.mark.asyncio
async def test_policy_declared_v2_requires_existing_authenticated_dispatch_scope(monkeypatch):
    # No caller-synthesized admission/ContextVar: v2 resolve remains its own
    # independent gate, even when the SQL Task/Flow/lease are otherwise valid.
    monkeypatch.setenv(
        "OSOP_VERIFIED_PROVIDER_ROUTES_JSON",
        json.dumps({
            "version": 2,
            "routes": [{
                "provider": "openai",
                "model": "openai/test-model",
                "operations": ["completion"],
                "credential_env": "OPENAI_API_KEY",
                "allowed_roles": ["vuln_analysis"],
                "capabilities": ["text_completion"],
                "max_output_tokens": 1000,
                "budget_source": "signed_postgres_roe",
            }],
        }),
    )
    monkeypatch.setattr(
        provider_routing, "configured_routes", provider_routing.ProviderRoutes.from_environment
    )
    db = _Database()
    with pytest.raises(ModelBudgetExceeded):
        await _reserve(_ledger(db))
    assert db.model_calls == db.precharges == []
