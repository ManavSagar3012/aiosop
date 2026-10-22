"""Original 0027 UNKNOWN gate -> 0029 signed grant -> ephemeral native transport.

Isolated controlled store doubles demonstrate the production executor call order;
separate 0029 tests cover transactional PostgreSQL CAS and native Go httptest
covers actual pinned TLS redemption. None claims real target-side effects.
"""

import base64
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.mcp.protocol import MCPExecuteResponse, MCPToolDefinition, SideEffectClass
from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor


EID = "eng-native-dispatch"
FID = "flow-native-dispatch"
TASK = "task-native-dispatch"
STEP = "subtask-native-dispatch"
ACTION = "action-" + "a" * 32
REQ = "req-" + "b" * 48
SHA = "c" * 64
PARAM_SHA = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
BINDING = {
    "engagement_id": EID,
    "flow_id": FID,
    "revision": 5,
    "version": 3,
    "authorization_id": "signed-roe-ref",
    "authorization_sha256": SHA,
}
OWNER = {"sub": "owner-native", "role": "operator", "claims": {"exp": 2000000000}}


def grant_doc():
    now = int(time.time())
    claims = {
        "version": 1,
        "grant_id": "ngr-" + "d" * 32,
        "request_id": REQ,
        "engagement_id": EID,
        "flow_id": FID,
        "task_id": TASK,
        "subtask_id": STEP,
        "action_id": ACTION,
        "server_id": "recon-mcp",
        "tool_name": "authority_status",
        "parameters_sha256": PARAM_SHA,
        "manifest_sha256": "e" * 64,
        "authorization_version": 3,
        "authorization_sha256": SHA,
        "lease_id": "lease-native-dispatch",
        "resource_sha256": None,
        "issued_at": now - 1,
        "expires_at": now + 20,
        "side_effect_class": "READ_ONLY",
    }
    sig = base64.urlsafe_b64encode(b"z" * 64).decode("ascii").rstrip("=")
    return {"claims": claims, "kid": "native-test-key", "signature": sig}


def fixture(monkeypatch, *, fail_issue=False):
    from ai_osop.memory import native_mcp_execution_grants as grant_mod

    called = []

    async def reservation(*args, **kwargs):
        called.append("reserve")
        return {
            "admitted_for_dispatch": True,
            "request_id": REQ,
            "reservation_token": "res-" + "f" * 64,
            "parameters": {},
            "parameters_sha256": PARAM_SHA,
        }

    async def marker(*args, **kwargs):
        assert called == ["reserve"]
        called.append("0027_unknown_committed")
        return {"status": "unknown", "dispatch_attempt_committed": True}

    async def settled(*args, **kwargs):
        called.append("0027_unknown_readback")
        assert args[4] == "unknown"
        return {"action_id": ACTION, "status": "unknown"}

    class Store:
        get = AsyncMock(
            return_value={
                "status": "prepared",
                "action_id": ACTION,
                "task_id": TASK,
                "subtask_id": STEP,
                "server_id": "recon-mcp",
                "tool_name": "authority_status",
            }
        )

        reserve = staticmethod(reservation)
        mark_dispatched = staticmethod(marker)
        settle = staticmethod(settled)

    store = Store()

    class FakeNativeStore:
        def __init__(self, action_store):
            assert action_store is store

        async def issue(self, binding, actor, action, request, **kwargs):
            assert called == ["reserve", "0027_unknown_committed"]
            assert (actor, action, request) == (OWNER["sub"], ACTION, REQ)
            assert kwargs["resource_sha256"] is None
            called.append("0029_signed_grant")
            if fail_issue:
                raise OSError("private PG grant commit outcome is UNKNOWN")
            return {"status": "issued", "token": grant_doc()}

    monkeypatch.setattr(grant_mod, "NativeMCPExecutionGrantStore", FakeNativeStore)

    async def remote(*args, **kwargs):
        assert called == ["reserve", "0027_unknown_committed", "0029_signed_grant"]
        assert args == ("recon-mcp", "authority_status", {})
        assert kwargs["request_id"] == REQ
        assert kwargs["native_grant"] and "Bearer" not in kwargs["native_grant"]
        called.append("native_inert_http_only")
        # A provider success envelope is NOT separately verified target effect.
        return MCPExecuteResponse(
            request_id=REQ, status="success", result={"status": "grant_durably_redeemed"}
        )

    tool = MCPToolDefinition(
        name="authority_status",
        description="Inert native authority redemption status; no target, scan or provider execution.",
        parameters=[],
        returns={"status": "string"},
        timeout_seconds=5,
        requires_approval=True,
        scope_check=True,
        side_effect_class=SideEffectClass.READ_ONLY,
    )
    connection = SimpleNamespace(
        server_id="recon-mcp",
        _initialized=True,
        _tools={"authority_status": tool},
        get_circuit_state=lambda: "closed",
    )
    registry = SimpleNamespace(
        _servers={"recon-mcp": connection}, execute_tool=AsyncMock(side_effect=remote)
    )
    service = object.__new__(FlowMCPActionExecutor)
    service.registry = registry
    service.store = store
    service._authority = AsyncMock(return_value=True)
    service._task = AsyncMock(return_value=True)
    service._admit = AsyncMock(return_value=({}, PARAM_SHA))
    return service, registry, called


@pytest.mark.asyncio
async def test_real_executor_orders_original_unknown_before_native_grant_and_one_http(monkeypatch):
    service, registry, called = fixture(monkeypatch)
    result = await service.dispatch(dict(BINDING), dict(OWNER), ACTION)
    assert result == {"action_id": ACTION, "status": "unknown"}
    assert called == [
        "reserve",
        "0027_unknown_committed",
        "0029_signed_grant",
        "native_inert_http_only",
        "0027_unknown_readback",
    ]
    registry.execute_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_native_issue_unknown_never_contacts_server_or_retries_action(monkeypatch):
    service, registry, called = fixture(monkeypatch, fail_issue=True)
    result = await service.dispatch(dict(BINDING), dict(OWNER), ACTION)
    assert result["status"] == "unknown"
    assert called == [
        "reserve",
        "0027_unknown_committed",
        "0029_signed_grant",
        "0027_unknown_readback",
    ]
    registry.execute_tool.assert_not_awaited()
