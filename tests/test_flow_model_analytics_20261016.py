"""PG-only per-Flow model usage aggregates with unknown billing boundaries."""

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

from ai_osop.api.deps import state
from ai_osop.api.routers import flows
from ai_osop.memory.flow_model_analytics import (
    FlowModelAnalyticsUnavailable,
    read_flow_model_analytics,
)


ENGAGEMENT = "eng-flow-usage"
FLOW = "flow-flow-usage"


class PgSession:
    def __init__(self, rows, *, fail=False):
        self.rows = rows
        self.fail = fail
        self.queries = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def execute(self, statement):
        self.queries.append(statement)
        if self.fail:
            raise ConnectionError("synthetic private DB transport")
        return SimpleNamespace(all=lambda: list(self.rows))


def fixture(rows, *, fail=False):
    db = PgSession(rows, fail=fail)
    memory = SimpleNamespace(_async_session=lambda: db)
    return db, memory


@pytest.mark.asyncio
async def test_pg_flow_attribution_joins_tenant_task_and_exposes_no_call_ids():
    db, memory = fixture(
        [
            ("gpt-model", "completion", "workflow", 3, 2, 1, 1, 1, 2, 280, 90, Decimal("0.123")),
            ("small-model", "embedding", "recon", 1, 1, 0, 0, 0, 0, 100, 0, Decimal("0.02")),
        ]
    )
    response = await read_flow_model_analytics(memory, engagement_id=ENGAGEMENT, flow_id=FLOW)
    assert response["calls"] == 4
    assert response["unknown_outcome_calls"] == 1
    assert response["unpriced_calls"] == 1
    assert response["provider_native_cost_verified"] is False
    assert response["attribution"] == "same_tenant_task_flow_join_only"
    assert response["unattributed_model_calls_included"] is False
    first, second = response["groups"]
    assert first["known_ledger_cost_usd"] == "0.12300000"
    assert first["input_tokens"] is None and first["output_tokens"] is None
    assert first["total_cost_complete"] is False
    assert second["input_tokens"] == 100
    assert second["total_cost_complete"] is True
    assert "call_id" not in str(response) and "task_id" not in str(response)

    statement = str(db.queries[0].compile(dialect=postgresql.dialect()))
    params = db.queries[0].compile(dialect=postgresql.dialect()).params
    assert "JOIN tasks ON supervision_model_usage.task_id = tasks.id" in statement
    assert "supervision_model_usage.engagement_id = tasks.engagement_id" in statement
    assert "tasks.flow_id" in statement
    assert ENGAGEMENT in params.values() and FLOW in params.values()
    assert 201 in params.values()
    assert not any(isinstance(param, str) and "password" in param for param in params.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rows",
    [
        [("gpt", "completion", "workflow", 2, 3, 0, 0, 0, 0, 1, 2, 0)],
        [("gpt", "completion", "workflow", 1, 1, 0, 0, 0, 0, 1, 2, Decimal("-1"))],
        [("gpt", "completion", "workflow", 1, 1, 0, 0, 0, 0, 1, 2, Decimal("NaN"))],
        [("gpt", "completion", "workflow", 1, 1, 0, 0, 0, 0, 1, 2, Decimal("1e20"))],
        [("gpt", "unrecognized", "workflow", 1, 1, 0, 0, 0, 0, 1, 2, 0)],
        [("gpt", "completion", "workflow", 0, 0, 0, 0, 0, 0, 0, 0, 0)],
    ],
)
async def test_pg_corrupt_groups_fail_closed(rows):
    _, memory = fixture(rows)
    with pytest.raises(FlowModelAnalyticsUnavailable):
        await read_flow_model_analytics(memory, engagement_id=ENGAGEMENT, flow_id=FLOW)


@pytest.mark.asyncio
async def test_pg_group_limit_refuses_partial_dashboard():
    rows = [("gpt", "completion", "workflow", 1, 1, 0, 0, 0, 0, 1, 2, 0)] * 201
    _, memory = fixture(rows)
    with pytest.raises(FlowModelAnalyticsUnavailable, match="too many"):
        await read_flow_model_analytics(memory, engagement_id=ENGAGEMENT, flow_id=FLOW)


@pytest.mark.asyncio
async def test_flow_route_rechecks_ownership_and_hides_db_failure(monkeypatch):
    _, memory = fixture([], fail=True)
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=memory))
    owner = AsyncMock(return_value=SimpleNamespace(id=FLOW, engagement_id=ENGAGEMENT))
    monkeypatch.setattr(flows, "_owned_flow", owner)
    with pytest.raises(HTTPException) as failure:
        await flows.get_flow_model_analytics(FLOW, {"sub": "owner", "role": "operator"})
    assert failure.value.status_code == 503
    assert "private" not in str(failure.value.detail)
    owner.assert_awaited_once_with(FLOW, {"sub": "owner", "role": "operator"})
    _, healthy = fixture([])
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=healthy))
    result = await flows.get_flow_model_analytics(FLOW, {"sub": "owner", "role": "operator"})
    assert result["groups"] == [] and result["calls"] == 0


@pytest.mark.asyncio
async def test_flow_route_does_not_run_query_for_foreign_tenant(monkeypatch):
    db, memory = fixture([])
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=memory))
    monkeypatch.setattr(
        flows,
        "_owned_flow",
        AsyncMock(side_effect=HTTPException(403, "denied")),
    )
    with pytest.raises(HTTPException) as failure:
        await flows.get_flow_model_analytics(FLOW, {"sub": "foreign"})
    assert failure.value.status_code == 403
    assert db.queries == []
