"""A provider's execution reply is never sufficient signed replay proof."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest


@pytest.fixture(autouse=True)
def clear_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


def configured(monkeypatch, response):
    import ai_osop.mcp.protocol as protocol

    monkeypatch.setattr(protocol, "check_tool_authorization", AsyncMock(return_value=None))
    monkeypatch.setattr(protocol, "check_tool_budget", AsyncMock(return_value=None))
    conn = MCPConnection("browser-mcp", "localhost", 8091)
    conn._initialized = True
    conn._tools["execute"] = SimpleNamespace(timeout_seconds=10, requires_approval=True)
    # Production MCPConnection treats a non-200/missing HTTP status as an
    # ambiguous remote outcome. Model a genuine successful HTTP response so
    # these tests exercise signed inline receipt validation instead of the
    # transport-failure branch.
    remote = SimpleNamespace(status=200, json=AsyncMock(return_value=response))
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=remote)
    context.__aexit__ = AsyncMock(return_value=False)
    conn._session = SimpleNamespace(post=MagicMock(return_value=context))
    conn._requires_bound_provider_receipt = lambda: True
    callback = AsyncMock(return_value=True)
    conn.set_execution_event_callback(callback)
    RequestContext.bind(engagement_id="eng-owned", task_id="task-approved")
    return conn, callback


@pytest.mark.asyncio
async def test_signed_dispatch_rejects_provider_substituted_request_id(monkeypatch):
    conn, callback = configured(
        monkeypatch,
        {
            "request_id": "req-from-unrelated-execution",
            "status": "success",
            "result": {"status_code": 200},
        },
    )
    result = await conn.execute(
        MCPExecuteRequest(
            request_id="req-signed-execution",
            tool_name="execute",
            parameters={"url": "https://authorized.example", "action": "navigate"},
        )
    )
    assert result.request_id == "req-signed-execution"
    assert result.status == "unknown"
    assert not any(call.args[2] == "reconciliation_result" for call in callback.await_args_list)


@pytest.mark.asyncio
async def test_unsigned_http_success_never_confirms_signed_provider_outcome(monkeypatch):
    conn, callback = configured(
        monkeypatch,
        {
            "request_id": "req-signed-execution",
            "status": "success",
            "result": {"status_code": 200},
        },
    )
    result = await conn.execute(
        MCPExecuteRequest(
            request_id="req-signed-execution",
            tool_name="execute",
            parameters={"url": "https://authorized.example", "action": "navigate"},
        )
    )
    assert result.status == "success"  # a transport result, NOT a verified effect
    assert not any(call.args[2] == "reconciliation_result" for call in callback.await_args_list)


@pytest.mark.asyncio
async def test_only_provider_signed_original_tuple_is_forwarded_to_durable_writer(monkeypatch):
    import ai_osop.mcp.protocol as protocol

    signed = {
        "request_id": "req-signed-execution",
        "engagement_id": "eng-owned",
        "task_id": "task-approved",
        "server_id": "browser-mcp",
        "status": "succeeded",
        "verified": True,
        "stopped": False,
        "issued_at": 123,
        "attestation": {"kid": "trusted", "signature": "X" * 86},
    }
    conn, callback = configured(
        monkeypatch,
        {
            "request_id": "req-signed-execution",
            "status": "success",
            "result": {"status_code": 200},
            "provider_receipt": signed,
        },
    )
    verifier = MagicMock(return_value=True)
    monkeypatch.setattr(protocol, "provider_receipt_is_signed", verifier)
    result = await conn.execute(
        MCPExecuteRequest(
            request_id="req-signed-execution",
            tool_name="execute",
            parameters={"url": "https://authorized.example", "action": "navigate"},
        )
    )
    assert result.status == "success"
    attestations = [
        call for call in callback.await_args_list if call.args[2] == "reconciliation_result"
    ]
    assert len(attestations) == 1
    assert attestations[0].args[3]["status"] == "confirmed_finished"
    assert attestations[0].args[3]["attested_receipt"] == signed
    verifier.assert_called_once_with(
        signed, "browser-mcp", "req-signed-execution", "eng-owned", "task-approved"
    )


@pytest.mark.asyncio
async def test_lost_durable_receipt_commit_quarantines_provider_claim(monkeypatch):
    import ai_osop.mcp.protocol as protocol

    receipt = {"verified": True, "status": "succeeded"}
    conn, callback = configured(
        monkeypatch,
        {
            "request_id": "req-signed-execution",
            "status": "success",
            "result": {},
            "provider_receipt": receipt,
        },
    )
    monkeypatch.setattr(protocol, "provider_receipt_is_signed", lambda *_: True)

    async def writer(_, __, kind, ___):
        return kind != "reconciliation_result"

    callback.side_effect = writer
    result = await conn.execute(
        MCPExecuteRequest(
            request_id="req-signed-execution",
            tool_name="execute",
            parameters={"url": "https://authorized.example"},
        )
    )
    assert result.status == "unknown"
    assert any(call.args[2] == "reconciliation_result" for call in callback.await_args_list)
