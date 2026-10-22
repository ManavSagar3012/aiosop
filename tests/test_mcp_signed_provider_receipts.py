"""Pinned Ed25519 provider receipts; never elevate an unsigned provider flag."""

import base64
import json
import time
from unittest.mock import AsyncMock

import aiohttp
from aiohttp import web
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.mcp.protocol import (
    MCPExecuteRequest,
    _verified_remote_cancel, _verified_remote_status,
)
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.test_remote_execution_receipts import known_execution, remote_connection

_IDENTITY = dict(
    request_id="req-remote", engagement_id="eng-live",
    task_id="task-allowed", server_id="scanner",
)


@pytest.fixture
def signer(monkeypatch):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({"scanner": {"mock-signer": base64.b64encode(public).decode()}}),
    )

    def sign(*, status="completed", stopped=False, verified=True, offset=0, **override):
        claims = {
            **_IDENTITY, "status": status, "verified": verified,
            "stopped": stopped, "issued_at": int(time.time()) + offset,
            **override,
        }
        canonical = json.dumps(
            claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode()
        signature = base64.urlsafe_b64encode(key.sign(canonical)).decode().rstrip("=")
        return {**claims, "attestation": {"kid": "mock-signer", "signature": signature}}

    return sign


def test_valid_status_and_cancelled_assertions_require_trusted_signature(signer):
    done = signer(status="completed")
    assert provider_receipt_is_signed(done, "scanner", "req-remote", "eng-live", "task-allowed")
    assert _verified_remote_status(
        done, "req-remote", "eng-live", "task-allowed", "scanner",
        require_bound_identity=True, require_signature=True,
    ) == "confirmed_finished"
    stopped = signer(status="cancelled", stopped=True)
    assert _verified_remote_cancel(
        stopped, "req-remote", "eng-live", "task-allowed", "scanner",
        require_bound_identity=True, require_signature=True,
    ) == "confirmed_stopped"


@pytest.mark.parametrize("mutation", [
    "unsigned", "false_status", "foreign_engagement", "foreign_server",
    "invalid_signature", "wrong_kid", "stale", "future", "extra",
    "missing", "nested_failure", "wrong_claim_type", "noncanonical_encoding",
])
def test_untrusted_or_unbound_assertions_never_promote_remote_outcome(signer, mutation):
    receipt = signer(status="cancelled", stopped=True)
    if mutation == "unsigned":
        receipt.pop("attestation")
    elif mutation == "false_status":
        receipt["status"] = "completed"
    elif mutation == "foreign_engagement":
        receipt["engagement_id"] = "foreign"
    elif mutation == "foreign_server":
        receipt["server_id"] = "foreign"
    elif mutation == "invalid_signature":
        receipt["attestation"]["signature"] = "x" * 86
    elif mutation == "noncanonical_encoding":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        original = receipt["attestation"]["signature"]
        index = alphabet.index(original[-1])
        altered = (index & ~15) | ((index + 1) & 15)
        assert altered != index
        receipt["attestation"]["signature"] = original[:-1] + alphabet[altered]
    elif mutation == "wrong_kid":
        receipt["attestation"]["kid"] = "unexpected-key"
    elif mutation == "stale":
        receipt = signer(status="cancelled", stopped=True, offset=-300)
    elif mutation == "future":
        receipt = signer(status="cancelled", stopped=True, offset=300)
    elif mutation == "extra":
        receipt["operator_approved"] = True
    elif mutation == "missing":
        receipt.pop("task_id")
    elif mutation == "wrong_claim_type":
        receipt["issued_at"] = True
    elif mutation == "nested_failure":
        receipt = {"status": "error", "result": receipt}
    assert _verified_remote_cancel(
        receipt, "req-remote", "eng-live", "task-allowed", "scanner",
        require_bound_identity=True, require_signature=True,
    ) == "unknown"


def test_missing_or_inaccessible_key_store_never_bypasses_signature(signer, monkeypatch):
    receipt = signer()
    monkeypatch.delenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON")
    assert not provider_receipt_is_signed(
        receipt, "scanner", "req-remote", "eng-live", "task-allowed",
    )


@pytest.mark.asyncio
async def test_remote_authenticated_cancel_without_provider_signature_stays_unknown(signer):
    conn = await known_execution(remote_connection(
        capabilities=["mcp_cancel_request_v1", "mcp_bound_receipts_v1"],
        remote_response={
            **_IDENTITY, "status": "cancelled", "stopped": True,
            "verified": True,
        },
    ))
    conn._requires_bound_provider_receipt = lambda: True
    conn._requires_signed_provider_receipt = lambda: True
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    result = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "unknown"
    assert conn._executions["req-remote"].outcome == "unknown"


@pytest.mark.asyncio
async def test_remote_authenticated_cancel_with_pinned_provider_proof(signer):
    conn = await known_execution(remote_connection(
        capabilities=["mcp_cancel_request_v1", "mcp_bound_receipts_v1"],
        remote_response=signer(status="cancelled", stopped=True),
    ))
    conn._requires_bound_provider_receipt = lambda: True
    conn._requires_signed_provider_receipt = lambda: True
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    result = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "confirmed_stopped"
    assert conn._executions["req-remote"].outcome == "confirmed_stopped"


@pytest.mark.asyncio
async def test_cached_proof_is_downgraded_when_provider_signing_key_is_retired(signer, monkeypatch):
    conn = await known_execution(remote_connection(
        capabilities=["mcp_cancel_request_v1", "mcp_bound_receipts_v1"],
        remote_response=signer(status="cancelled", stopped=True),
    ))
    conn._requires_bound_provider_receipt = lambda: True
    conn._requires_signed_provider_receipt = lambda: True
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    first = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert first["status"] == "confirmed_stopped"
    monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "{}")
    subsequent = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert subsequent["status"] == "unknown"
    assert subsequent["reason"] == "provider_receipt_no_longer_trusted"
    conn._session.post.assert_called_once()


@pytest.mark.asyncio
async def test_real_loopback_signed_status_uses_original_inert_execution(signer):
    """Local HTTP provider retains original tuple; no external execution."""
    dispatch = {}
    calls = []

    async def accept(request):
        message = await request.json()
        calls.append("accept")
        dispatch[message["request_id"]] = message.get("execution_binding")
        return web.json_response({
            "request_id": message["request_id"], "status": "success", "result": {},
        })

    async def lookup(request):
        message = await request.json()
        calls.append("lookup")
        original = dispatch.get(message["request_id"])
        if original is None:
            return web.json_response({
                "request_id": message["request_id"], "status": "unknown",
            })
        return web.json_response(signer(**original, status="completed"))

    application = web.Application()
    application.router.add_post("/mcp/execute", accept)
    application.router.add_post("/mcp/request/status", lookup)
    runner = web.AppRunner(application)
    await runner.setup()
    listener = web.TCPSite(runner, "127.0.0.1", 0)
    await listener.start()
    port = listener._server.sockets[0].getsockname()[1]
    try:
        connection = remote_connection(capabilities=[
            "mcp_bound_receipts_v1", "mcp_request_status_v1",
        ])
        connection.host, connection.port = "127.0.0.1", port
        connection._requires_bound_provider_receipt = lambda: True
        connection._requires_signed_provider_receipt = lambda: True
        events = AsyncMock(return_value=True)
        connection.set_execution_event_callback(events)
        async with aiohttp.ClientSession() as client:
            connection._session = client
            first = await connection.execute(MCPExecuteRequest(
                request_id="req-remote", tool_name="scan_target",
                parameters={"url": "https://example.com/inert-only"},
            ))
            second = await connection.reconcile_execution(
                "req-remote", "eng-live", "task-allowed",
            )
        assert first.status == "success"
        assert second["status"] == "confirmed_finished"
        assert dispatch["req-remote"] == _IDENTITY
        assert calls == ["accept", "lookup"]
        result_events = [
            call for call in events.await_args_list
            if call.args[2] == "reconciliation_result"
        ]
        assert len(result_events) == 1
        proof = result_events[0].args[3]["attested_receipt"]
        assert provider_receipt_is_signed(
            proof, "scanner", "req-remote", "eng-live", "task-allowed",
        )
    finally:
        await runner.cleanup()
