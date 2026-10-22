"""Direct MCP transport is an authorization boundary, not a quota-only gate."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest, MCPRegistry


@pytest.fixture(autouse=True)
def clear_request_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


class Persistence:
    def __init__(self, scope=None, *, phase="reconnaissance"):
        scope = scope or ScopeDefinition(
            engagement_id="eng-live",
            domains=["example.com"],
            authorization_ref="signed-roe",
        )
        self.session = SessionState(
            session_id="eng-live", phase=phase, scope=scope
        )
        self.task = Task(
            id="task-allowed",
            type="full_recon",
            agent_type=AgentType.RECON,
            engagement_id="eng-live",
            payload={"approval_id": "apr-valid"},
            status="running",
        )
        self.load_session_state = AsyncMock(return_value=self.session)
        self.load_task = AsyncMock(return_value=self.task)
        self.is_task_approved = AsyncMock(return_value=False)
        self.quota = AsyncMock(return_value=True)

    async def consume_mcp_tool_budget(self, engagement, qualified_name, agent):
        return await self.quota(engagement, qualified_name, agent)


def connection(tool="scan_target", *, approval=False, response=None):
    conn = MCPConnection("scanner", "localhost", 8080)
    conn._initialized = True
    conn._tools[tool] = SimpleNamespace(
        name=tool,
        timeout_seconds=5,
        requires_approval=approval,
        scope_check=False,  # Untrusted MCP definition cannot waive ROE.
    )
    result = response or {
        "request_id": "req-stub", "status": "success", "result": {"items": 2}
    }
    mock_response = SimpleNamespace(status=200, json=AsyncMock(return_value=result))
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=mock_response)
    context.__aexit__ = AsyncMock(return_value=False)
    conn._session = SimpleNamespace(post=MagicMock(return_value=context))
    return conn


def call(tool="scan_target", params=None):
    return MCPExecuteRequest(
        tool_name=tool,
        parameters=params if params is not None else {"url": "https://example.com"},
    )


@pytest.mark.asyncio
async def test_secondary_and_nested_foreign_targets_never_reach_transport():
    memory = Persistence()
    conn = connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")
    provenance = AsyncMock()
    conn.set_provenance_callback(provenance)

    result = await conn.execute(call(params={
        "url": "https://example.com",
        "options": {"target_url": "https://unauthorized.invalid/secret?token=private"},
    }))
    await conn._provenance_recorder.drain()
    assert result.status == "scope_denied"
    assert "private" not in str(result.model_dump())
    conn._session.post.assert_not_called()
    memory.quota.assert_not_awaited()
    assert provenance.await_count == 1
    audit = provenance.await_args.args[0]
    assert audit["outcome"] == "error"
    assert "unauthorized.invalid" not in str(audit)


@pytest.mark.asyncio
async def test_authorized_scoped_direct_target_proceeds_and_debits_once():
    memory = Persistence()
    conn = connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")

    result = await conn.execute(call())
    assert result.status == "success"
    conn._session.post.assert_called_once()
    memory.quota.assert_awaited_once_with(
        "eng-live", "scanner.scan_target", "agent-unspecified"
    )
    memory.is_task_approved.assert_not_awaited()


@pytest.mark.asyncio
async def test_postgres_backed_direct_connection_requires_durable_dispatch_writer():
    from ai_osop.memory.session_memory import SessionMemory

    # This is a REAL storage type, unlike the intentionally isolated mock
    # budget callbacks used by other transport unit tests. Direct calls must
    # not bypass the production global request-ID fence through a missing
    # event writer, even if a scope and target are supplied.
    authoritative = SessionMemory.__new__(SessionMemory)
    conn = connection()
    conn.set_budget_callback(authoritative.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")
    result = await conn.execute(call())
    assert result.status == "audit_unavailable"
    assert "Durable MCP dispatch" in result.error
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["missing_signature", "halted", "expired", "scope_missing"])
async def test_unusable_engagement_never_calls_target(invalid):
    memory = Persistence()
    if invalid == "missing_signature":
        memory.session.scope.authorization_ref = None
    elif invalid == "halted":
        memory.session.phase = "halted"
    elif invalid == "expired":
        memory.session.scope.testing_window_end = datetime.utcnow() - timedelta(seconds=1)
    else:
        memory.session.scope.domains.clear()
    conn = connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live")
    denied = await conn.execute(call())
    assert denied.status == "scope_denied"
    conn._session.post.assert_not_called()
    memory.quota.assert_not_awaited()


@pytest.mark.asyncio
async def test_active_scan_without_explicit_target_denied_even_with_valid_engagement():
    memory = Persistence()
    conn = connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live")
    denied = await conn.execute(call(params={"rate_limit": 1}))
    assert denied.status == "scope_denied"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("parameters", [
    {"base_url": "https://unauthorized.invalid/path"},
    {"urls": ["https://example.com", "https://unauthorized.invalid"]},
    {"url_prefix": "https://unauthorized.invalid"},
    {"request": {"target_host": "unauthorized.invalid"}},
    {"url": "https://example.com", "headers": {"Host": "unauthorized.invalid"}},
    {"URL": "https://unauthorized.invalid"},
    {
        "url": "https://example.com",
        "config": {"options": {"params": {"request": {
            "config": {"url": "https://unauthorized.invalid"},
        }}}},
    },
])
async def test_target_aliases_cannot_bypass_scope(parameters):
    memory = Persistence()
    conn = connection("get_scan_issues")
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live")
    denied = await conn.execute(call("get_scan_issues", parameters))
    assert denied.status == "scope_denied"
    conn._session.post.assert_not_called()
    memory.quota.assert_not_awaited()


@pytest.mark.asyncio
async def test_passive_scope_query_does_not_require_target():
    memory = Persistence()
    conn = connection("get_scan_issues")
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live")
    result = await conn.execute(call("get_scan_issues", {}))
    assert result.status == "success"
    conn._session.post.assert_called_once()


@pytest.mark.asyncio
async def test_scope_configured_approval_applies_to_passive_tool():
    memory = Persistence()
    memory.session.scope.approval_required_for = ["get_scan_issues"]
    conn = connection("get_scan_issues")
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")
    blocked = await conn.execute(call("get_scan_issues", {}))
    assert blocked.status == "approval_required"
    conn._session.post.assert_not_called()
    memory.quota.assert_not_awaited()

    memory.is_task_approved.return_value = True
    allowed = await conn.execute(call("get_scan_issues", {}))
    assert allowed.status == "success"
    conn._session.post.assert_called_once()


@pytest.mark.asyncio
async def test_roe_passive_only_blocks_active_scans_before_quota():
    memory = Persistence()
    memory.session.scope.restrictions = ["no_active_scanning"]
    conn = connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live")
    denied = await conn.execute(call())
    assert denied.status == "roe_denied"
    conn._session.post.assert_not_called()
    memory.quota.assert_not_awaited()


@pytest.mark.asyncio
async def test_allowed_techniques_block_unapproved_scan_type():
    memory = Persistence()
    memory.session.scope.allowed_techniques = ["passive_recon"]
    conn = connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live")
    denied = await conn.execute(call())
    assert denied.status == "roe_denied"
    conn._session.post.assert_not_called()

    memory.session.scope.allowed_techniques = ["active_scanning"]
    approved_scope = await conn.execute(call())
    assert approved_scope.status == "success"
    conn._session.post.assert_called_once()


@pytest.mark.asyncio
async def test_opaque_http_requests_are_rejected_even_with_cover_target():
    memory = Persistence()
    conn = connection("intruder_attack")
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live")
    denied = await conn.execute(call("intruder_attack", {
        "url": "https://example.com",
        "request": "GET http://outside.invalid/ HTTP/1.1\r\nHost: outside.invalid",
    }))
    assert denied.status == "scope_denied"
    conn._session.post.assert_not_called()
    memory.is_task_approved.assert_not_awaited()
    memory.quota.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,explicit", [
    ("sqlmap", False),
    ("extension_call", False),
    ("custom_extension", True),
])
async def test_consequential_tools_require_database_backed_approval(tool, explicit):
    memory = Persistence()
    conn = connection(tool, approval=explicit)
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")
    denied = await conn.execute(call(tool))
    assert denied.status == "approval_required"
    memory.is_task_approved.assert_awaited_once_with(
        "task-allowed", "eng-live", "apr-valid"
    )
    conn._session.post.assert_not_called()
    memory.quota.assert_not_awaited()


@pytest.mark.asyncio
async def test_forged_request_approval_id_cannot_override_durable_task():
    memory = Persistence()
    memory.task.payload.pop("approval_id")
    conn = connection("sqlmap")
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")
    denied = await conn.execute(call("sqlmap", {
        "url": "https://example.com",
        "operator_approved": True,
        "approval_id": "apr-forged",
    }))
    assert denied.status == "approval_required"
    memory.is_task_approved.assert_not_awaited()
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_approved_consequential_tool_uses_current_persisted_evidence():
    memory = Persistence()
    memory.is_task_approved.return_value = True
    conn = connection("sqlmap")
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")
    answer = await conn.execute(call("sqlmap"))
    assert answer.status == "success"
    conn._session.post.assert_called_once()
    memory.quota.assert_awaited_once()


@pytest.mark.asyncio
async def test_bootstrap_cannot_run_targeted_tool_without_signed_engagement():
    conn = connection()
    RequestContext.bind(engagement_id="eng-live", task_id="task-1")
    denied = await conn.execute(call())
    assert denied.status == "scope_unavailable"
    conn._session.post.assert_not_called()

    RequestContext.bind(engagement_id="api-bootstrap", task_id="")
    denied_bootstrap = await conn.execute(call())
    assert denied_bootstrap.status == "scope_denied"
    conn._session.post.assert_not_called()
    health = connection("get_status")
    harmless = await health.execute(call("get_status", {}))
    assert harmless.status == "success"
    health._session.post.assert_called_once()


@pytest.mark.asyncio
async def test_scope_lookup_exception_is_redacted_and_no_target_call():
    memory = Persistence()
    memory.load_session_state.side_effect = RuntimeError(
        "postgresql://admin:NEVER_LEAK@127.0.0.1/secret"
    )
    conn = connection()
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live")
    denied = await conn.execute(call())
    assert denied.status == "scope_unavailable"
    assert "NEVER_LEAK" not in str(denied.model_dump())
    conn._session.post.assert_not_called()
    memory.quota.assert_not_awaited()


@pytest.mark.asyncio
async def test_registry_and_broadcast_and_direct_use_same_denial_gate():
    memory = Persistence()
    registry = MCPRegistry()
    conn = connection("sqlmap")
    registry._servers[conn.server_id] = conn
    registry.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")
    one = await registry.execute_tool("scanner", "sqlmap", {"target": "https://example.com"})
    many = await registry.broadcast_execute("sqlmap", {"target": "https://example.com"})
    direct = await conn.execute(call("sqlmap"))
    assert [one.status, many["scanner"].status, direct.status] == [
        "approval_required", "approval_required", "approval_required"
    ]
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_transport_exception_and_remote_error_messages_redacted():
    conn = connection(
        "get_history",
        response={
            "request_id": "req-server", "status": "error",
            "error": "secret api key: NEVER_LEAK_UPSTREAM",
        },
    )
    remote = await conn.execute(call("get_history", {}))
    assert remote.status == "error"
    assert "NEVER_LEAK" not in str(remote.model_dump())

    conn._session.post.side_effect = RuntimeError(
        "Authorization Bearer NEVER_LEAK_TRANSPORT"
    )
    failed = await conn.execute(call("get_history", {}))
    assert failed.status == "unknown"
    assert "NEVER_LEAK" not in str(failed.model_dump())


@pytest.mark.asyncio
async def test_broadcast_exception_never_echoes_sensitive_exception_message():
    registry = MCPRegistry()
    conn = connection("get_history")
    conn.execute = AsyncMock(side_effect=RuntimeError("secret NEVER_LEAK_BROADCAST"))
    registry._servers["scanner"] = conn
    results = await registry.broadcast_execute("get_history", {})
    assert results["scanner"].status == "error"
    assert "NEVER_LEAK" not in str(results["scanner"].model_dump())


@pytest.mark.asyncio
async def test_connection_and_initialize_exceptions_are_redacted():
    conn = MCPConnection("scanner", "localhost", 8080)
    fake_session = MagicMock()
    fake_session.get.side_effect = RuntimeError(
        "Bearer NEVER_LEAK_HEALTHCHECK"
    )
    fake_session.close = AsyncMock()
    with patch("ai_osop.mcp.protocol.aiohttp.ClientSession", return_value=fake_session):
        with pytest.raises(Exception) as error:
            await conn.connect()
    assert "NEVER_LEAK" not in str(error.value)
    fake_session.close.assert_awaited_once()

    conn._session = fake_session
    fake_session.post.side_effect = RuntimeError(
        "API_KEY=NEVER_LEAK_INITIALIZE"
    )
    from ai_osop.mcp.protocol import MCPInitializeRequest

    with pytest.raises(Exception) as failed:
        await conn.initialize(
            MCPInitializeRequest(session_id="api-bootstrap", scope={})
        )
    assert "NEVER_LEAK" not in str(failed.value)
