"""Original 0027 Action settlement receives only durably accepted signed testimony.

In-memory transport/event doubles: these are not native SourceMap or real PG
qualification, and provider testimony is not independent target observation.
"""

import base64
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest


ENGAGEMENT = "eng-receipt-bridge"
TASK = "task-receipt-bridge"
REQUEST = "req-" + "a" * 48
SERVER = "source-map-mcp"


def _signed(private):
    claims = {
        "request_id": REQUEST,
        "engagement_id": ENGAGEMENT,
        "task_id": TASK,
        "server_id": SERVER,
        "status": "succeeded",
        "verified": True,
        "stopped": False,
        "issued_at": int(time.time()),
    }
    canonical = json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return {
        **claims,
        "attestation": {
            "kid": "sourcemap-worker-v1",
            "signature": base64.urlsafe_b64encode(private.sign(canonical))
            .decode("ascii")
            .rstrip("="),
        },
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["valid", "invalid_signature", "failed_audit", "provider_metadata_only", "wrong_task"],
)
async def test_signed_provider_receipt_requires_verification_and_durable_event(monkeypatch, case):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({SERVER: {"sourcemap-worker-v1": base64.b64encode(public).decode("ascii")}}),
    )
    private = Ed25519PrivateKey.generate() if case == "invalid_signature" else key
    receipt = _signed(private)
    if case == "wrong_task":
        receipt["task_id"] = "task-other"

    envelope = {
        "request_id": REQUEST,
        "status": "success",
        "result": {"source_count": 1, "credentials_disclosed": False},
        # Never trust provider-authored settlement metadata without an
        # independently checked, auditable receipt from the original call.
        "metadata": {"signed_provider_receipt": {"forged": True}, "source": "local"},
    }
    if case != "provider_metadata_only":
        envelope["provider_receipt"] = receipt

    remote = AsyncMock()
    remote.status = 200
    remote.json.return_value = envelope
    post_ctx = MagicMock()
    post_ctx.__aenter__ = AsyncMock(return_value=remote)
    post_ctx.__aexit__ = AsyncMock(return_value=None)
    session = MagicMock()
    session.post.return_value = post_ctx

    events = []

    async def write_event(engagement, task, kind, metadata):
        events.append((engagement, task, kind, metadata))
        return not (case == "failed_audit" and kind == "reconciliation_result")

    conn = MCPConnection(SERVER, "127.0.0.1", 8096)
    conn._session = session
    conn._initialized = True
    conn._capabilities = ["mcp_bound_receipts_v1"]
    conn._tools = {
        "inspect_local_original_sourcemap": SimpleNamespace(
            timeout_seconds=10, requires_approval=True
        )
    }
    conn._execution_event_callback = write_event
    req = MCPExecuteRequest(
        tool_name="inspect_local_original_sourcemap",
        parameters={"artifact_sha256": "b" * 64},
        request_id=REQUEST,
    )
    RequestContext.bind(
        engagement_id=ENGAGEMENT,
        task_id=TASK,
        flow_id="flow-receipt",
        subtask_id="subtask-receipt",
    )
    try:
        with (
            patch(
                "ai_osop.mcp.protocol.check_tool_authorization",
                new=AsyncMock(return_value=None),
            ),
            patch("ai_osop.mcp.protocol.check_tool_budget", new=AsyncMock(return_value=None)),
        ):
            result = await conn.execute(req)
    finally:
        RequestContext.clear()

    if case != "failed_audit":
        assert result.metadata.get("source") == "local"
    if case == "valid":
        assert result.status == "success"
        assert result.metadata["signed_provider_receipt"] == receipt
        assert any(kind == "reconciliation_result" for _, _, kind, _ in events)
    else:
        assert "signed_provider_receipt" not in result.metadata
        if case == "failed_audit":
            assert result.status == "unknown"
        else:
            assert result.status == "success"
        if case != "failed_audit":
            assert not any(
                kind == "reconciliation_result" and metadata.get("status") == "confirmed_finished"
                for _, _, kind, metadata in events
            )
