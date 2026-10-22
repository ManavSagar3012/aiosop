"""Operator review surfaces unknown paid usage but grants no retry authority."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

from ai_osop.memory.model_usage import ModelUsageLedger
from ai_osop.api.deps import state
from ai_osop.api.routers import supervision


class _Session:
    def __init__(self):
        self.sql = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def execute(self, sql):
        self.sql = sql
        entries = [
            SimpleNamespace(call_id="call-unknown-1", task_id="task-A",
                operation="completion", status="unknown",
                created_at=datetime(2026, 10, 14)),
            SimpleNamespace(call_id="call-reserved-2", task_id="task-A",
                operation="embedding", status="reserved",
                created_at=datetime(2026, 10, 13)),
        ]
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: entries))


@pytest.mark.asyncio
async def test_unreconciled_call_inventory_is_owned_and_cost_remains_unknown():
    db = _Session()
    ledger = ModelUsageLedger.__new__(ModelUsageLedger)
    ledger._sessions = lambda: db
    calls = await ledger.list_unreconciled("eng-signed", limit=5)
    assert len(calls) == 2
    assert {row["status"] for row in calls} == {"unknown", "reserved"}
    assert all(row["provider_cost_usd"] is None for row in calls)
    assert all(row["safe_to_retry"] is False for row in calls)
    assert all(row["invoice_reconciled"] is False for row in calls)
    compiled = db.sql.compile(dialect=postgresql.dialect())
    assert "supervision_model_usage.engagement_id =" in str(compiled)
    assert "supervision_model_usage.status IN" in str(compiled)
    assert "eng-signed" in compiled.params.values()


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "x" * 65, None])
async def test_invalid_engagement_rejected_without_query(bad):
    ledger = ModelUsageLedger.__new__(ModelUsageLedger)
    with pytest.raises(ValueError):
        await ledger.list_unreconciled(bad)


@pytest.mark.asyncio
async def test_operator_scope_guard_blocks_listing_before_ledger(monkeypatch):
    guard = AsyncMock(side_effect=HTTPException(status_code=403, detail="denied"))
    monkeypatch.setattr(supervision, "_access", guard)
    with pytest.raises(HTTPException) as err:
        await supervision.get_unreconciled_model_calls(
            "eng-foreign", 100, {"sub": "operator", "role": "operator"},
        )
    assert err.value.status_code == 403
    guard.assert_awaited_once()
