"""A known, compiled-in audit HMAC key must not attest production records."""

import hashlib
import hmac
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import settings
from ai_osop.core.exceptions import MemoryException
from ai_osop.core.models import AuditEvent
from ai_osop.memory.session_memory import SessionMemory


def event():
    return AuditEvent(
        event_type="operator.review", severity="info", actor_type="operator",
        actor_id="trusted-senior", action={"status": "review"},
        result={"status": "recorded"}, context={}, engagement_id="eng-signed",
    )


@pytest.mark.parametrize("configured", [None, "too-short", "default-insecure-audit-key"])
@pytest.mark.asyncio
async def test_production_refuses_known_or_weak_audit_hmac_without_db_writes(monkeypatch, configured):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "audit_hmac_key", configured)
    memory = SessionMemory.__new__(SessionMemory)
    memory._async_session = MagicMock(side_effect=AssertionError("No audit read/write is allowed"))
    record = event()
    with pytest.raises(MemoryException, match="signing key unavailable"):
        await memory.write_audit_event(record)
    assert record.integrity_hash is None
    memory._async_session.assert_not_called()


@pytest.mark.asyncio
async def test_configured_production_key_deterministically_signs_audit_event(monkeypatch):
    key = "A" * 40
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "audit_hmac_key", key)
    memory = SessionMemory.__new__(SessionMemory)
    db = AsyncMock()
    db.execute.side_effect = [
        SimpleNamespace(scalar_one_or_none=lambda: "eng-signed"),
        SimpleNamespace(one_or_none=lambda: None),
        SimpleNamespace(rowcount=1),
    ]
    transaction = MagicMock()
    transaction.__aenter__ = AsyncMock(return_value=None)
    transaction.__aexit__ = AsyncMock(return_value=False)
    db.begin = MagicMock(return_value=transaction)
    session_context = MagicMock()
    session_context.__aenter__ = AsyncMock(return_value=db)
    session_context.__aexit__ = AsyncMock(return_value=None)
    memory._async_session = MagicMock(return_value=session_context)
    record = event()
    await memory.write_audit_event(record)
    canonical = f"{record.event_id}:{record.timestamp.isoformat()}:{record.actor_id}:{record.event_type}"
    expected = hmac.new(key.encode("utf-8"), canonical.encode(), hashlib.sha256).hexdigest()
    assert record.integrity_hash == expected
    assert db.execute.await_count == 3
    transaction.__aexit__.assert_awaited_once()
