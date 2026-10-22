"""Durable MCP status cannot reopen an already admitted remote cancellation."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.supervision_store import (
    SupervisionStore,
    _next_mcp_dispatch_status,
)
from tests.test_signed_mcp_receipt_ledger import setup_store, signer


@pytest.mark.parametrize(
    "kind,status,expected",
    [
        ("execution_started", "accepted", "cancel_requested"),
        ("execution_finished", "success", "cancel_requested"),
        ("execution_unknown", "unknown", "cancel_requested"),
        ("execution_failed", "error", "cancel_requested"),
        ("reconciliation_result", "running", "cancel_requested"),
        ("reconciliation_result", "unknown", "cancel_requested"),
        ("cancellation_result", "not_supported", "cancel_requested"),
        ("cancellation_result", "unknown", "cancel_requested"),
        ("cancellation_result", "confirmed_stopped", "confirmed_stopped"),
        ("reconciliation_result", "confirmed_finished", "confirmed_finished"),
    ],
)
def test_committed_remote_stop_intent_survives_late_or_ambiguous_events(
    kind, status, expected,
):
    assert _next_mcp_dispatch_status("cancel_requested", kind, status) == expected


@pytest.mark.parametrize(
    "original,kind,status,expected",
    [
        ("accepted_unconfirmed", "execution_started", "accepted", "started_unknown"),
        ("started_unknown", "execution_finished", "success", "provider_returned"),
        ("outcome_unknown", "execution_started", "accepted", "outcome_unknown"),
        ("provider_returned", "execution_started", "accepted", "provider_returned"),
        ("provider_running", "execution_started", "accepted", "provider_running"),
        ("provider_running", "reconciliation_result", "unknown", "provider_running"),
        ("confirmed_finished", "cancellation_result", "confirmed_stopped", "confirmed_finished"),
        ("confirmed_stopped", "reconciliation_result", "running", "confirmed_stopped"),
    ],
)
def test_durable_remote_state_does_not_downgrade(original, kind, status, expected):
    assert _next_mcp_dispatch_status(original, kind, status) == expected


@pytest.mark.asyncio
async def test_reconciled_remote_running_cannot_reopen_one_shot_stop_claim(monkeypatch):
    store, db = setup_store()
    db.dispatch.status = "cancel_requested"
    args = ("eng-existing", "task-running", "mcp-local", "req-one-shot")
    assert await store.record_mcp_dispatch_event(
        *args, "reconciliation_result", "running"
    )
    assert db.dispatch.status == "cancel_requested"
    assert store._append_event.await_args.args[5]["status"] == "running"
    # A provider can say RUNNING after local stop intent; that does not
    # authorize another remote cancellation. The signed event remains visible
    # as a weaker observation, not as cancellation confirmation.


@pytest.mark.asyncio
async def test_unverified_terminal_after_stop_keeps_unknown(monkeypatch):
    from ai_osop.core.config import settings

    monkeypatch.setattr(settings, "environment", "production")
    store, db = setup_store()
    db.dispatch.status = "cancel_requested"
    assert await store.record_mcp_dispatch_event(
        "eng-existing", "task-running", "mcp-local", "req-one-shot",
        "reconciliation_result", "confirmed_stopped",
    )
    assert db.dispatch.status == "cancel_requested"
    assert store._append_event.await_args.args[5]["status"] == "unknown"


@pytest.mark.asyncio
async def test_original_pinned_provider_receipt_can_settle_stop_after_intent(
    signer, monkeypatch,
):
    from ai_osop.core.config import settings

    monkeypatch.setattr(settings, "environment", "production")
    store, db = setup_store()
    db.dispatch.status = "cancel_requested"
    receipt = signer(status="cancelled", stopped=True)
    assert await store.record_mcp_dispatch_event(
        "eng-live", "task-allowed", "scanner", "req-remote",
        "cancellation_result", "confirmed_stopped", attested_receipt=receipt,
    )
    assert db.dispatch.status == "confirmed_stopped"
    assert "provider_receipt_sha256" in store._append_event.await_args.args[5]
