"""Adversarial MCP HTTP response contracts using only local in-memory doubles.

No scanner/provider, application database, Docker, target, or network contact.
Cryptographically authentic provider receipts remain provider testimony only.
"""

import base64
import json
import time
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import ai_osop.mcp.protocol as protocol
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest

REQUEST = "req-trust-boundary-20261021"
ENGAGEMENT = "eng-trust-boundary"
TASK = "task-trust-boundary"
SERVER = "recon-mcp"


class Stream:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.offset = 0

    async def read(self, length: int) -> bytes:
        item = self.body[self.offset : self.offset + length]
        self.offset += len(item)
        return item


class Reply:
    status = 200
    content_type = "application/json"
    content_length: Optional[int] = None

    def __init__(self, body: bytes) -> None:
        self.content = Stream(body)

    async def __aenter__(self) -> "Reply":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None


class Session:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.posts = []

    def post(self, url: str, **kwargs: Any) -> Reply:
        self.posts.append((url, kwargs))
        return Reply(self.body)


@pytest.fixture(autouse=True)
def _clear_request_context() -> Any:
    RequestContext.clear()
    yield
    RequestContext.clear()


def signed_receipt(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({SERVER: {"local-test-issuer": base64.b64encode(pub).decode("ascii")}}),
    )
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
    message = json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return {
        **claims,
        "attestation": {
            "kid": "local-test-issuer",
            "signature": base64.urlsafe_b64encode(key.sign(message)).decode("ascii").rstrip("="),
        },
    }


async def dispatch(
    monkeypatch: pytest.MonkeyPatch,
    envelope: Dict[str, Any],
    *,
    drop_ack_for: Optional[str] = None,
) -> tuple[Any, Session, list[tuple[str, Dict[str, Any]]], MCPConnection, bytes]:
    monkeypatch.setattr(protocol, "check_tool_authorization", AsyncMock(return_value=None))
    monkeypatch.setattr(protocol, "check_tool_budget", AsyncMock(return_value=None))
    raw = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    session = Session(raw)
    events: list[tuple[str, Dict[str, Any]]] = []

    async def writer(engagement: str, task: str, kind: str, metadata: Dict[str, Any]) -> bool:
        assert engagement == ENGAGEMENT and task == TASK
        events.append((kind, metadata))
        return kind != drop_ack_for

    conn = MCPConnection(SERVER, "127.0.0.1", 8082)
    conn._session = session
    conn._initialized = True
    conn._capabilities = ["mcp_bound_receipts_v1"]
    conn._tools["authority_status"] = SimpleNamespace(timeout_seconds=5, requires_approval=False)
    conn.set_execution_event_callback(writer)
    RequestContext.bind(
        engagement_id=ENGAGEMENT,
        task_id=TASK,
        flow_id="flow-trust-boundary",
        subtask_id="subtask-trust-boundary",
    )
    result = await conn.execute(
        MCPExecuteRequest(tool_name="authority_status", parameters={}, request_id=REQUEST)
    )
    return result, session, events, conn, raw


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "contradiction",
    [
        {"isError": True},
        {"isError": "true"},
        {"isError": 1},
        {"isError": None},
        {"error": "provider internal failure"},
        {"error": {}},
    ],
    ids=[
        "boolean-error",
        "string-error",
        "numeric-error",
        "null-error",
        "text-error",
        "object-error",
    ],
)
async def test_contradictory_provider_http200_cannot_settle_or_leak_to_consumers(
    monkeypatch: pytest.MonkeyPatch, contradiction: Dict[str, Any]
) -> None:
    receipt = signed_receipt(monkeypatch)
    envelope = {
        "request_id": REQUEST,
        "status": "success",
        "result": {"items": 2, "target_effect_verified": True},
        "metadata": {"signed_provider_receipt": {"verified": True}},
        "provider_receipt": receipt,
        **contradiction,
    }
    response, session, events, conn, raw = await dispatch(monkeypatch, envelope)
    assert response.status == "unknown"
    assert response.result is None
    assert not response.metadata.get("signed_provider_receipt")
    assert response._untrusted_provider_body_bytes == raw
    assert response._untrusted_provider_payload == envelope
    assert "target_effect_verified" not in response.model_dump_json()
    assert "provider internal failure" not in response.model_dump_json()
    assert len(session.posts) == 1
    assert session.posts[0][0].endswith("/mcp/execute")
    assert [kind for kind, _ in events].count("execution_unknown") == 1
    assert not any(kind in {"execution_finished", "reconciliation_result"} for kind, _ in events)
    assert conn._executions[REQUEST].outcome == "unknown"
    # An ambiguous effect cannot be retransmitted on the same original ID.
    retried = await conn.execute(
        MCPExecuteRequest(tool_name="authority_status", parameters={}, request_id=REQUEST)
    )
    assert retried.status == "duplicate_request"
    assert len(session.posts) == 1


@pytest.mark.asyncio
async def test_valid_signed_provider_receipt_preserves_ordinary_facts_and_not_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = signed_receipt(monkeypatch)
    response, _, events, _, raw = await dispatch(
        monkeypatch,
        {
            "request_id": REQUEST,
            "status": "success",
            "isError": False,
            "error": None,
            "result": {"items": 2, "target_effect_verified": True},
            "provider_receipt": receipt,
        },
    )
    assert response.status == "success"
    assert response.result == {"items": 2}
    assert response.metadata["signed_provider_receipt"] == receipt
    assert response.provider_provenance.target_effect_verified is False
    assert response._untrusted_provider_body_bytes == raw
    assert [kind for kind, _ in events].count("reconciliation_result") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("ack_loss", ["execution_finished", "reconciliation_result"])
async def test_lost_durable_ack_keeps_original_wire_private_and_outcome_unknown(
    monkeypatch: pytest.MonkeyPatch, ack_loss: str
) -> None:
    receipt = signed_receipt(monkeypatch)
    response, session, events, conn, raw = await dispatch(
        monkeypatch,
        {
            "request_id": REQUEST,
            "status": "success",
            "result": {"items": 2, "target_effect_verified": True},
            "provider_receipt": receipt,
        },
        drop_ack_for=ack_loss,
    )
    assert response.status == "unknown"
    assert response.result is None
    assert response.metadata.get("signed_provider_receipt") is None
    assert response._untrusted_provider_body_bytes == raw
    assert response._untrusted_provider_payload["provider_receipt"] == receipt
    assert response.provider_provenance.target_effect_verified is False
    assert response.model_dump()["provider_provenance"]["target_effect_verified"] is False
    assert [kind for kind, _ in events].count(ack_loss) == 1
    if ack_loss == "execution_finished":
        assert not any(kind == "reconciliation_result" for kind, _ in events)
    # Awaiting or losing acknowledgment never restarts original remote work.
    assert len(session.posts) == 1
    second = await conn.execute(
        MCPExecuteRequest(tool_name="authority_status", parameters={}, request_id=REQUEST)
    )
    assert second.status == "duplicate_request"
    assert len(session.posts) == 1
