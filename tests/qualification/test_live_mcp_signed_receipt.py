"""Signed MCP status evidence through real disposable PostgreSQL and outbox.

The shared signed engagement fixture refuses non-disposable connection URLs.
No target, provider service, paid model or application database is contacted.
"""

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, update

from ai_osop.core.config import settings
from ai_osop.memory.session_memory import TaskORM
from ai_osop.memory.supervision_store import (
    SupervisionEventORM, SupervisionStore,
)
from tests.qualification.test_live_planner_execution import live


def _signed_receipt(engagement, task, server, request_id, monkeypatch):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({server: {"provider-qual": base64.b64encode(public).decode()}}),
    )
    claims = {
        "request_id": request_id, "engagement_id": engagement,
        "task_id": task, "server_id": server, "status": "completed",
        "verified": True, "stopped": False, "issued_at": int(time.time()),
    }
    canonical = json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode()
    signature = base64.urlsafe_b64encode(private.sign(canonical)).decode().rstrip("=")
    return {**claims, "attestation": {"kid": "provider-qual", "signature": signature}}


@pytest.mark.asyncio
async def test_live_signed_mcp_provider_receipt_is_audited_and_durable(live, monkeypatch):
    maker, planner, _, flow, parent = live
    monkeypatch.setattr(settings, "environment", "production")
    async with maker() as session, session.begin():
        await session.execute(
            update(TaskORM).where(TaskORM.id == parent.id).values(status="running"),
        )
    store = SupervisionStore(planner.session_memory)
    server, request_id = "provider-qual", "req-qual-" + flow.id[-12:]
    args = (flow.engagement_id, parent.id, server, request_id)
    assert await store.claim_mcp_dispatch(*args, "passive_probe")
    assert await store.record_mcp_dispatch_event(
        *args, "reconciliation_result", "confirmed_finished",
    )
    assert (await store.get_mcp_dispatch(*args))["status"] == "outcome_unknown"

    receipt = _signed_receipt(*args, monkeypatch)
    assert await store.record_mcp_dispatch_event(
        *args, "reconciliation_result", "confirmed_finished",
        attested_receipt=receipt,
    )
    claim = await store.get_mcp_dispatch(*args)
    assert claim["status"] == "confirmed_finished"
    async with maker() as db:
        events = (
            await db.execute(
                select(SupervisionEventORM).where(
                    SupervisionEventORM.engagement_id == flow.engagement_id,
                    SupervisionEventORM.kind == "agent.mcp.reconciliation_result",
                ),
            )
        ).scalars().all()
    assert any(
        event.payload.get("provider_signing_kid") == "provider-qual"
        and len(event.payload.get("provider_receipt_sha256", "")) == 64
        for event in events
    )
    assert "signature" not in json.dumps([event.payload for event in events])


@pytest.mark.asyncio
async def test_live_event_outbox_fault_rolls_back_provider_confirmation(live, monkeypatch):
    maker, planner, _, flow, parent = live
    monkeypatch.setattr(settings, "environment", "production")
    async with maker() as db, db.begin():
        await db.execute(
            update(TaskORM).where(TaskORM.id == parent.id).values(status="running"),
        )
    store = SupervisionStore(planner.session_memory)
    args = (flow.engagement_id, parent.id, "provider-qual", "req-rollback-" + flow.id[-8:])
    assert await store.claim_mcp_dispatch(*args, "passive_probe")
    receipt = _signed_receipt(*args, monkeypatch)
    original = store._append_event

    async def broken(*_args, **_kwargs):
        raise RuntimeError("injected disposable outbox failure")

    store._append_event = broken
    try:
        with pytest.raises(RuntimeError):
            await store.record_mcp_dispatch_event(
                *args, "reconciliation_result", "confirmed_finished",
                attested_receipt=receipt,
            )
    finally:
        store._append_event = original
    assert (await store.get_mcp_dispatch(*args))["status"] == "accepted_unconfirmed"
