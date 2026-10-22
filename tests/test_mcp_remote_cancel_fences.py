"""Remote MCP cancellation must preserve signed authority and provider proof."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry, _RemoteExecution


def _connection(response=None, *, capabilities=None, bound=False):
    conn = MCPConnection("scanner", "localhost", 8080)
    conn._initialized = True
    conn._capabilities = capabilities or [
        "mcp_cancel_request_v1",
        "mcp_request_status_v1",
    ]
    if bound:
        conn._capabilities.append("mcp_bound_receipts_v1")
    conn._executions["req-original"] = _RemoteExecution(
        engagement_id="eng-live",
        task_id="task-live",
        tool_name="scan_target",
        parameters={"url": "https://example.com"},
    )
    response = response or {
        "request_id": "req-original",
        "status": "cancelled",
        "verified": True,
        "stopped": True,
    }
    if bound:
        response = {
            "engagement_id": "eng-live", "task_id": "task-live",
            "server_id": "scanner", **response,
        }
    resp = SimpleNamespace(status=200, json=AsyncMock(return_value=response))
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=resp)
    context.__aexit__ = AsyncMock(return_value=False)
    conn._session = SimpleNamespace(post=MagicMock(return_value=context))
    return conn


def _signed_memory():
    memory = SessionMemory()
    scope = ScopeDefinition(
        engagement_id="eng-live",
        domains=["example.com"],
        authorization_ref="signed-roe",
    )
    memory.load_session_state = AsyncMock(
        return_value=SessionState(
            session_id="eng-live",
            scope=scope,
            phase="reconnaissance",
        )
    )
    memory.load_task_authoritative = AsyncMock(
        return_value=Task(
            id="task-live",
            type="full_recon",
            agent_type=AgentType.RECON,
            status="running",
            engagement_id="eng-live",
            payload={"_authorization_version": 7},
        )
    )
    memory.load_task = AsyncMock(side_effect=AssertionError("no Redis trust"))
    memory.is_task_approved = AsyncMock(return_value=True)
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=7))
    return memory


@pytest.mark.parametrize(
    "reply",
    [
        {
            "status": "error",
            "result": {
                "request_id": "req-original",
                "status": "cancelled",
                "verified": True,
                "stopped": True,
            },
        },
        {
            "status": "success",
            "error": "failed",
            "result": {
                "request_id": "req-original",
                "status": "cancelled",
                "verified": True,
                "stopped": True,
            },
        },
        {
            "request_id": "req-original",
            "status": "cancelled",
            "verified": True,
            "stopped": True,
            "engagement_id": "eng-foreign",
        },
        {
            "request_id": "req-original",
            "status": "cancelled",
            "verified": True,
            "stopped": True,
            "task_id": "task-foreign",
        },
        {
            "request_id": "req-original",
            "status": "cancelled",
            "verified": True,
            "stopped": True,
            "server_id": "other",
        },
        {
            "status": "success",
            "engagement_id": "eng-foreign",
            "result": {
                "request_id": "req-original",
                "status": "cancelled",
                "verified": True,
                "stopped": True,
            },
        },
        {
            "status": "success",
            "result": {
                "request_id": "req-original",
                "status": ["cancelled"],
                "verified": True,
                "stopped": True,
            },
        },
    ],
)
@pytest.mark.asyncio
async def test_cancellation_disregards_contradictory_or_malformed_provider_receipts(reply):
    conn = _connection(reply)
    memory = _signed_memory()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    result = await conn.request_cancellation("req-original", "eng-live", "task-live")
    assert result["status"] == "unknown"
    assert conn._executions["req-original"].outcome == "unknown"


@pytest.mark.parametrize(
    "reply",
    [
        {
            "status": "error",
            "result": {"request_id": "req-original", "status": "completed", "verified": True},
        },
        {
            "status": "success",
            "result": {
                "request_id": "req-original",
                "status": "cancelled",
                "verified": True,
                "stopped": True,
                "task_id": "task-foreign",
            },
        },
        {
            "request_id": "req-original",
            "status": "completed",
            "verified": True,
            "server_id": "other",
        },
        {"request_id": "req-original", "status": {"completed": True}, "verified": True},
    ],
)
@pytest.mark.asyncio
async def test_status_does_not_promote_untrusted_provider_receipts(reply):
    conn = _connection(reply)
    conn.set_budget_callback(_signed_memory().consume_mcp_tool_budget)
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    result = await conn.reconcile_execution("req-original", "eng-live", "task-live")
    assert result["status"] == "unknown"
    assert conn._executions["req-original"].outcome == "unknown"


@pytest.mark.asyncio
async def test_cancel_cached_receipt_rechecks_signer_and_approval():
    memory = _signed_memory()
    conn = _connection(bound=True)
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    confirmed = await conn.request_cancellation("req-original", "eng-live", "task-live")
    assert confirmed["status"] == "confirmed_stopped"
    memory.assert_signed_authorization.side_effect = PermissionError("revoked signing key secret")
    denied = await conn.request_cancellation("req-original", "eng-live", "task-live")
    assert denied["status"] == "denied"
    assert "secret" not in str(denied)
    conn._session.post.assert_called_once()

    memory.assert_signed_authorization.side_effect = None
    conn._executions["req-original"].requires_approval = True
    memory.is_task_approved.return_value = False
    rejected = await conn.request_cancellation("req-original", "eng-live", "task-live")
    assert rejected["status"] == "denied"
    conn._session.post.assert_called_once()


@pytest.mark.asyncio
async def test_registry_cached_control_rechecks_revocation_without_repeating_remote_stop():
    memory = _signed_memory()
    registry = MCPRegistry()
    conn = _connection(bound=True)
    registry._servers["scanner"] = conn
    registry.set_budget_callback(memory.consume_mcp_tool_budget)
    registry.set_execution_event_callback(AsyncMock(return_value=True))

    first = await registry.cancel_task_execution("task-live", "eng-live", "control-1")
    assert first["status"] == "confirmed_stopped"
    first["executions"][0]["status"] = "tampered"
    repeated = await registry.cancel_task_execution("task-live", "eng-live", "control-1")
    assert repeated["status"] == "confirmed_stopped"
    assert repeated["executions"][0]["status"] == "confirmed_stopped"
    conn._session.post.assert_called_once()
    memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    denied = await registry.cancel_task_execution("task-live", "eng-live", "control-1")
    assert denied["status"] == "denied"
    conn._session.post.assert_called_once()


@pytest.mark.asyncio
async def test_live_status_failure_to_commit_audit_keeps_execution_unknown():
    memory = _signed_memory()
    conn = _connection(
        {"request_id": "req-original", "status": "cancelled", "verified": True, "stopped": True}
    )
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    events = AsyncMock(side_effect=[True, False])
    conn.set_execution_event_callback(events)
    result = await conn.reconcile_execution("req-original", "eng-live", "task-live")
    assert result["status"] == "unknown"
    assert result["reason"] == "audit_unavailable"
    assert conn._executions["req-original"].outcome == "unknown"
    assert "req-original" not in conn._cancel_receipts
    assert events.await_count == 2


@pytest.mark.asyncio
async def test_persisted_status_queries_require_fresh_signed_version_and_owner():
    memory = _signed_memory()
    conn = _connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    events = AsyncMock(return_value=True)
    conn.set_execution_event_callback(events)
    claim = {
        "server_id": "scanner",
        "request_id": "req-original",
        "engagement_id": "eng-live",
        "task_id": "task-live",
        "tool_name": "scan_target",
        "authorization_version": 7,
        "status": "outcome_unknown",
    }
    memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    revoked = await conn.reconcile_persisted_status(claim)
    assert revoked["status"] == "denied"
    conn._session.post.assert_not_called()
    events.assert_not_awaited()

    memory.assert_signed_authorization.side_effect = None
    stale = await conn.reconcile_persisted_status(dict(claim, authorization_version=6))
    assert stale["status"] == "denied"
    conn._session.post.assert_not_called()

    memory.load_task_authoritative.return_value.engagement_id = "eng-foreign"
    foreign = await conn.reconcile_persisted_status(claim)
    assert foreign["status"] == "denied"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_persisted_provider_status_does_not_assume_remote_stop_on_failure():
    conn = _connection(
        {"request_id": "req-original", "status": "running", "verified": True},
        bound=True,
    )
    memory = _signed_memory()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    claim = {
        "server_id": "scanner",
        "request_id": "req-original",
        "engagement_id": "eng-live",
        "task_id": "task-live",
        "tool_name": "scan_target",
        "authorization_version": 7,
        "status": "outcome_unknown",
    }
    result = await conn.reconcile_persisted_status(claim)
    assert result["status"] == "running"
    conn._session.post.assert_called_once()
    conn._session.post.reset_mock()
    memory.assert_signed_authorization.side_effect = OSError("PG unavailable")
    blocked = await conn.reconcile_persisted_status(claim)
    assert blocked["status"] == "denied"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_cross_tenant_requests_never_send_provider_actions():
    memory = _signed_memory()
    conn = _connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    denied = await conn.request_cancellation("req-original", "eng-foreign", "task-live")
    unknown = await conn.reconcile_execution("req-original", "eng-live", "task-foreign")
    assert denied["status"] == "unknown"
    assert unknown["status"] == "unknown"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_production_authority_requires_durable_writer_before_provider_contact():
    memory = _signed_memory()
    conn = _connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    cancellation = await conn.request_cancellation("req-original", "eng-live", "task-live")
    observation = await conn.reconcile_execution("req-original", "eng-live", "task-live")
    assert cancellation["status"] == "unknown"
    assert observation["status"] == "unknown"
    assert cancellation["reason"] == observation["reason"] == "durable_writer_unavailable"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_concurrent_duplicate_provider_cancellation_emits_one_action():
    memory = _signed_memory()
    conn = _connection(bound=True)
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    first, second = await asyncio.gather(
        conn.request_cancellation("req-original", "eng-live", "task-live"),
        conn.request_cancellation("req-original", "eng-live", "task-live"),
    )
    assert first == second
    assert first["status"] == "confirmed_stopped"
    conn._session.post.assert_called_once()
