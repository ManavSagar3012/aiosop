"""Regression tests for the client-side MCP execution gate (W3).

W3: ``requires_approval`` / ``scope_check`` were declared on ``MCPToolDefinition``
and even advertised by the Go MCP servers (``scope_check: true`` on recon/payload
tools), but the execute path ignored them — safety theater. These tests pin the
fail-closed enforcement now wired into ``MCPRegistry.execute_tool`` via
``MCPExecutionGate``.
"""

from unittest.mock import AsyncMock

import pytest

from ai_osop.core.exceptions import MCPApprovalRequired, MCPScopeDenied
from ai_osop.mcp.protocol import MCPExecuteResponse, MCPExecutionGate, MCPRegistry


class _Conn:
    """Minimal connection: owns its tool defs and a stub execute()."""

    def __init__(self, tools) -> None:
        from ai_osop.mcp.protocol import MCPToolDefinition

        self._tools = {name: MCPToolDefinition(**defn) for name, defn in tools.items()}
        self.execute = AsyncMock(
            return_value=MCPExecuteResponse(request_id="r", status="success", result={})
        )


def _registry(conn) -> MCPRegistry:
    reg = MCPRegistry()
    reg._servers = {"srv": conn}
    return reg


def _tool(**overrides):
    base = {
        "name": "t",
        "description": "d",
        "parameters": [],
        "returns": {},
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_approval_flagged_tool_fail_closed_without_gate() -> None:
    """A requires_approval=True tool must NOT execute when no approval is wired."""
    reg = _registry(_Conn({"t": _tool(name="t", requires_approval=True)}))
    reg.execution_gate = MCPExecutionGate()  # no is_approved wired

    with pytest.raises(MCPApprovalRequired):
        await reg.execute_tool("srv", "t", {"url": "https://target.example.com/"})
    reg._servers["srv"].execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_approval_flagged_tool_executes_when_approved() -> None:
    reg = _registry(_Conn({"t": _tool(name="t", requires_approval=True)}))
    reg.execution_gate = MCPExecutionGate(is_approved=lambda s, t, p: True)

    await reg.execute_tool("srv", "t", {"url": "https://target.example.com/"})
    reg._servers["srv"].execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_scope_flagged_tool_blocked_when_out_of_scope() -> None:
    """A scope_check=True tool whose target host is out of scope is refused
    before the request leaves the process (defense-in-depth on the server check)."""
    reg = _registry(_Conn({"t": _tool(name="t", scope_check=True)}))
    reg.execution_gate = MCPExecutionGate(host_in_scope=lambda h: h == "in.example.com")

    with pytest.raises(MCPScopeDenied):
        await reg.execute_tool("srv", "t", {"url": "https://evil.example.com/"})
    reg._servers["srv"].execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_scope_flagged_tool_allowed_when_in_scope() -> None:
    reg = _registry(_Conn({"t": _tool(name="t", scope_check=True)}))
    reg.execution_gate = MCPExecutionGate(host_in_scope=lambda h: h == "in.example.com")

    await reg.execute_tool("srv", "t", {"url": "https://in.example.com/"})
    reg._servers["srv"].execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_trust_server_scope_skips_client_scope_check() -> None:
    """A caller may opt out of the client-side scope check when the server
    already enforces it (read-only recon listings) — but approval is never
    skippable, so a tool flagged for approval still gates."""
    reg = _registry(_Conn({"t": _tool(name="t", scope_check=True)}))
    reg.execution_gate = MCPExecutionGate(host_in_scope=lambda h: False)  # deny all

    await reg.execute_tool(
        "srv", "t", {"url": "https://evil.example.com/"}, trust_server_scope=True
    )
    reg._servers["srv"].execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_scope_check_noop_when_no_host_extracted() -> None:
    """Recon tools pass LIST params (targets/urls) with no scalar host; the
    client scope check must not false-block them (server-side check still holds)."""
    reg = _registry(_Conn({"t": _tool(name="t", scope_check=True)}))
    reg.execution_gate = MCPExecutionGate(host_in_scope=lambda h: False)  # deny all

    await reg.execute_tool("srv", "t", {"targets": ["1.2.3.4", "example.com"]})
    reg._servers["srv"].execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_gate_none_preserves_legacy_behavior() -> None:
    """With no gate wired (the default until the orchestrator sets one), the
    flags are NOT enforced client-side — existing behavior is preserved. The
    approval gate only becomes fail-closed once a gate is configured."""
    reg = _registry(_Conn({"t": _tool(name="t", requires_approval=True, scope_check=True)}))
    reg.execution_gate = None

    await reg.execute_tool("srv", "t", {"url": "https://evil.example.com/"})
    reg._servers["srv"].execute.assert_awaited_once()


def test_unknown_tool_rejected_when_schemas_registered():
    from ai_osop.core.exceptions import ScopeValidationError
    from ai_osop.mcp.protocol import MCPExecutionGate

    gate = MCPExecutionGate()
    gate.register_tool_schema("scan_endpoint", {"url": str, "timeout_s": int})
    with pytest.raises(ScopeValidationError):
        gate.check_params("unknown_tool", {"url": "http://x"})
    with pytest.raises(ScopeValidationError):
        gate.check_params("scan_endpoint", {"url": "http://x", "bad_arg": 1})
    # Known tool with declared params still passes
    gate.check_params("scan_endpoint", {"url": "http://x", "timeout_s": 5})


def test_unregistered_tool_fails_closed_for_write_ops():
    from ai_osop.core.exceptions import ScopeValidationError
    from ai_osop.mcp.protocol import MCPExecutionGate

    gate = MCPExecutionGate()
    with pytest.raises(ScopeValidationError):
        gate.check_params("totally_new_tool", {"target": "http://x"})
