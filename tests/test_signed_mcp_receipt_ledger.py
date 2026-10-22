"""A verified provider signature is needed at the durable PostgreSQL boundary."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import settings
from ai_osop.memory.supervision_store import SupervisionStore
from tests.test_mcp_signed_provider_receipts import signer


class FakeTransaction:
    def __init__(self):
        self.dispatch = SimpleNamespace(status="outcome_unknown", updated_at=None)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def begin(self):
        return self

    async def execute(self, query):
        return SimpleNamespace(scalar_one_or_none=lambda: self.dispatch)


def setup_store():
    db = FakeTransaction()
    store = SupervisionStore(
        SimpleNamespace(_async_session=lambda: db),
    )
    store._guard = AsyncMock(return_value=True)
    store._append_event = AsyncMock(return_value=True)
    return store, db


@pytest.mark.asyncio
async def test_confirmed_remote_outcome_requires_signed_provider_proof(signer, monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    store, db = setup_store()
    args = ("eng-live", "task-allowed", "scanner", "req-remote", "reconciliation_result")
    assert await store.record_mcp_dispatch_event(*args, "confirmed_finished")
    assert db.dispatch.status == "outcome_unknown"
    payload = store._append_event.await_args.args[5]
    assert payload["status"] == "unknown"
    assert "provider_receipt_sha256" not in payload

    verified = signer(status="completed")
    assert await store.record_mcp_dispatch_event(
        *args, "confirmed_finished", attested_receipt=verified,
    )
    assert db.dispatch.status == "confirmed_finished"
    payload = store._append_event.await_args.args[5]
    assert payload["status"] == "confirmed_finished"
    assert len(payload["provider_receipt_sha256"]) == 64
    assert payload["provider_signing_kid"] == "mock-signer"
    assert "signature" not in str(payload)


@pytest.mark.asyncio
async def test_cannot_mislabel_a_genuine_signed_running_receipt_as_stopped(signer, monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    store, db = setup_store()
    receipt = signer(status="running", stopped=False)
    assert await store.record_mcp_dispatch_event(
        "eng-live", "task-allowed", "scanner", "req-remote",
        "cancellation_result", "confirmed_stopped", attested_receipt=receipt,
    )
    assert db.dispatch.status == "outcome_unknown"
    assert store._append_event.await_args.args[5]["status"] == "unknown"


@pytest.mark.asyncio
async def test_missing_or_retired_signature_never_confirms_termination(signer, monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    store, db = setup_store()
    receipt = signer(status="cancelled", stopped=True)
    monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "{}")
    assert await store.record_mcp_dispatch_event(
        "eng-live", "task-allowed", "scanner", "req-remote",
        "cancellation_result", "confirmed_stopped", attested_receipt=receipt,
    )
    assert db.dispatch.status == "outcome_unknown"
    assert store._append_event.await_args.args[5]["status"] == "unknown"
