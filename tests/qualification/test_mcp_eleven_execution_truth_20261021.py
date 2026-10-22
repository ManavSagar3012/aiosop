"""Real MCP client execution gates through one owned disposable loopback server.

These tests *never* generate ROE signatures, Task approvals, grant tokens or
fake database records. A controlled provider can testify, not authorize or
prove an independent target effect. Every tested tool is inert in the fixture.
"""

from __future__ import annotations

import asyncio
import ast
import json
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPRegistry, SideEffectClass
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.flow_mcp_action_executor import (
    FlowMCPActionDenied,
    FlowMCPActionExecutor,
    _bounded_params,
    _manifest_sha256,
    _tool_definition,
)


ROOT = Path(__file__).resolve().parents[2]
GO_SIX = (
    "recon-mcp",
    "payload-mcp",
    "nuclei-mcp",
    "shodan-mcp",
    "threat-intel-mcp",
    "security-bridge",
)
PY_NATIVE_FOUR = ("browser-mcp", "source-map-mcp", "cloud-mcp", "turbo-intruder-mcp")
EXTERNAL_ONE = ("burp-mcp",)
ELEVEN = (*GO_SIX, *EXTERNAL_ONE, *PY_NATIVE_FOUR)


def _actual_startup_names() -> list[str]:
    tree = ast.parse((ROOT / "src/ai_osop/api/main.py").read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "configured_mcp_server_specs"
    )
    declared = next(
        statement.value
        for statement in function.body
        if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.List)
    )
    return [item.elts[0].value for item in declared.elts]


class FixtureServer:
    """One disposable loopback HTTP server, never the configured service port."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.manifest = {
            "server_id": name,
            "status": "ready",
            "version": "fixture-only-0",
            "capabilities": [
                "mcp_bound_receipts_v1",
                "mcp_request_status_v1",
                "mcp_cancel_request_v1",
            ],
            "tools": [
                {
                    "name": "list_tools",
                    "description": "Inert fixture discovery only",
                    "side_effect_class": "READ_ONLY",
                    "requires_approval": False,
                    "scope_check": True,
                    "timeout_seconds": 4,
                    "parameters": [],
                    "returns": {"type": "object"},
                },
                {
                    "name": "scan_target",
                    "description": "NEVER EXECUTABLE fixture declaration",
                    "side_effect_class": "RECON_ACTIVE",
                    "requires_approval": True,
                    "scope_check": True,
                    "timeout_seconds": 4,
                    "parameters": [
                        {
                            "name": "target",
                            "type": "string",
                            "required": True,
                            "description": "Uncontacted invalid destination",
                        }
                    ],
                    "returns": {"type": "object"},
                },
            ],
        }

    async def health(self, _: web.Request) -> web.Response:
        self.calls.append(("health", {}))
        return web.json_response({"status": "healthy"})

    async def initialize(self, request: web.Request) -> web.Response:
        body = await request.json()
        self.calls.append(("initialize", body))
        return web.json_response(self.manifest)

    async def execute(self, request: web.Request) -> web.Response:
        body = await request.json()
        self.calls.append(("execute", body))
        if body.get("tool_name") != "list_tools" or body.get("parameters") != {}:
            return web.json_response(
                {"status": "error", "error": "untrusted_tool_denied"}, status=503
            )
        if body.get("request_id", "").startswith("req-lost-"):
            # Deliberately ambiguous: receiving the request before 503 gives
            # no evidence the remote tool ran, completed or stopped.
            return web.json_response({"status": "success", "result": {"count": 1}}, status=503)
        return web.json_response(
            {
                "request_id": body["request_id"],
                "status": "success",
                "result": {
                    "tool_count": 2,
                    "target_effect_verified": True,
                    "nested": [{"production_certified": True, "source": "controlled-localhost"}],
                },
                "metadata": {
                    "signed_provider_receipt": {"verified": True},
                    "production_certified": True,
                    "provider_annotation": "fixture_untrusted",
                },
                "provider_receipt": {
                    "request_id": body["request_id"],
                    "engagement_id": "api-bootstrap",
                    "task_id": "task-local",
                    "server_id": self.name,
                    "status": "succeeded",
                    "verified": True,
                    "stopped": True,
                    "issued_at": int(time.time()),
                    "attestation": {"kid": "not-enrolled", "signature": "A" * 86},
                },
            }
        )

    async def status(self, request: web.Request) -> web.Response:
        self.calls.append(("status", await request.json()))
        return web.json_response(
            {
                "status": "success",
                "result": {"status": "unknown", "verified": False},
            }
        )

    async def cancel(self, request: web.Request) -> web.Response:
        self.calls.append(("cancel", await request.json()))
        return web.json_response(
            {
                "status": "success",
                "result": {"status": "accepted", "verified": False},
            }
        )


@asynccontextmanager
async def _owned_local(name: str) -> AsyncIterator[tuple[int, FixtureServer]]:
    fixture = FixtureServer(name)
    app = web.Application()
    app.router.add_get("/health", fixture.health)
    app.router.add_post("/mcp/initialize", fixture.initialize)
    app.router.add_post("/mcp/execute", fixture.execute)
    app.router.add_post("/mcp/request/status", fixture.status)
    app.router.add_post("/mcp/cancel", fixture.cancel)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        assert site._server is not None
        address = site._server.sockets[0].getsockname()
        assert address[0] == "127.0.0.1"
        yield int(address[1]), fixture
    finally:
        await runner.cleanup()


def test_startup_inventories_exact_eleven_but_no_registered_provider_is_qualified() -> None:
    actual = _actual_startup_names()
    assert len(actual) == len(set(actual)) == 11
    assert set(actual) == set(ELEVEN)


@pytest.mark.parametrize("name", ELEVEN)
def test_eleven_registry_schema_authority_quota_original_action_and_truth(name: str) -> None:
    asyncio.run(_exercise_one(name))


async def _exercise_one(name: str) -> None:
    async with _owned_local(name) as (port, fixture):
        registry = MCPRegistry()
        try:
            connection = await registry.register_server(name, "127.0.0.1", port)
            negotiated = await registry.initialize_server(
                name, scope={"fixture_only": True}, credentials={}, session_id="local-fixture"
            )
            assert negotiated.server_id == name and negotiated.status == "ready"
            assert set(connection._tools) == {"list_tools", "scan_target"}
            assert connection._initialized is True
            assert len([item for item, _ in fixture.calls if item == "initialize"]) == 1

            # Source-of-truth Flow tool schema rejects a forged consequential
            # declaration *even after* an otherwise valid handshake.
            definition = _tool_definition(registry, name, "list_tools")
            assert definition.side_effect_class is SideEffectClass.READ_ONLY
            assert _bounded_params({}, definition) == {}
            assert len(_manifest_sha256(name, definition)) == 64
            with pytest.raises(FlowMCPActionDenied, match="independent high-risk authorization"):
                _tool_definition(registry, name, "scan_target")
            with pytest.raises(FlowMCPActionDenied):
                _bounded_params({"target": "https://do-not-contact.invalid"}, definition)

            # Missing signed Task/Flow/ROE: a target-bearing consequential
            # call must stop BEFORE quota, durable log, and provider I/O.
            RequestContext.bind(
                engagement_id="eng-unapproved",
                task_id="task-unapproved",
                flow_id="flow-unapproved",
                subtask_id="subtask-unapproved",
            )
            try:
                denied = await registry.execute_tool(
                    name,
                    "scan_target",
                    {"target": "https://do-not-contact.invalid"},
                    request_id=f"req-active-{uuid.uuid4().hex}",
                )
                assert denied.status in {
                    "scope_unavailable",
                    "approval_unavailable",
                    "approval_required",
                }
            finally:
                RequestContext.clear()
            assert not any(kind == "execute" for kind, _ in fixture.calls)

            # Quota ownership is a separate gate; returning False cannot be
            # overwritten by the remote manifest's status or provider booleans.
            reservations: list[tuple[str, str, str | None]] = []

            async def exhausted(engagement: str, qualified: str, agent: str | None) -> bool:
                reservations.append((engagement, qualified, agent))
                return False

            registry.set_budget_callback(exhausted)
            RequestContext.bind(engagement_id="eng-quota-fixture", task_id="task-quota-fixture")
            try:
                quota = await registry.execute_tool(
                    name, "list_tools", {}, request_id=f"req-quota-{uuid.uuid4().hex}"
                )
                assert quota.status == "quota_exceeded"
            finally:
                RequestContext.clear()
            assert reservations == [
                ("eng-quota-fixture", f"{name}.list_tools", "agent-unspecified")
            ]
            assert not any(kind == "execute" for kind, _ in fixture.calls)

            # The real 0027 Flow executor cannot be constructed from arbitrary
            # mocks or a registry without a SessionMemory budget and log writer.
            with pytest.raises(
                FlowMCPActionDenied, match="Production Flow MCP authority unavailable"
            ):
                FlowMCPActionExecutor(None, registry, object())  # type: ignore[arg-type]

            # No independently signed Flow or Task exists here. A real
            # SessionMemory shell with ONLY three inert read stubs returns no
            # authorization; no store query or remote request is permitted.
            memory = SessionMemory.__new__(SessionMemory)
            memory.assert_signed_authorization = AsyncMock(return_value=None)
            memory.load_session_state = AsyncMock(return_value=None)
            memory.load_flow = AsyncMock(return_value=None)
            memory.load_task_authoritative = AsyncMock(return_value=None)

            class NeverUseStore:
                async def get(self, *args: Any, **kwargs: Any) -> None:
                    raise AssertionError("Store consulted without verified Flow authorization")

            events = AsyncMock(return_value=True)
            registry.set_budget_callback(memory.consume_mcp_tool_budget)
            registry.set_execution_event_callback(events)
            executor = FlowMCPActionExecutor(memory, registry, NeverUseStore())
            with pytest.raises(FlowMCPActionDenied, match="signed Flow ownership or ROE changed"):
                await executor.dispatch(
                    {
                        "engagement_id": "eng-unapproved",
                        "flow_id": "flow-unapproved",
                        "revision": 0,
                        "version": 1,
                    },
                    {
                        "role": "operator",
                        "sub": "test-only-not-a-real-principal",
                        "claims": {"exp": int(time.time()) + 100},
                    },
                    "action-" + "a" * 32,
                )
            assert not any(kind == "execute" for kind, _ in fixture.calls)

            # Explicit API bootstrap permits only INERT, unapproved discovery.
            # This next HTTP response is a fixture's provider testimony, not
            # a real signed Flow action, target effect or production receipt.
            registry.set_budget_callback(None)
            RequestContext.bind(engagement_id="api-bootstrap", task_id="task-local")
            try:
                request_id = "req-inert-" + uuid.uuid4().hex
                observed = await registry.execute_tool(
                    name, "list_tools", {}, request_id=request_id
                )
                assert observed.status == "success" and observed.request_id == request_id
                assert observed.result == {
                    "tool_count": 2,
                    "nested": [{"source": "controlled-localhost"}],
                }
                assert observed.metadata == {"provider_annotation": "fixture_untrusted"}
                assert observed.provider_provenance is not None
                assert observed.provider_provenance.status_source == "untrusted_provider"
                assert observed.provider_provenance.target_effect_verified is False
                assert observed.metadata.get("signed_provider_receipt") is None

                # One-shot locally tracked request IDs cannot be replayed, even
                # when previous remote response was a successful 200.
                duplicate = await registry.execute_tool(
                    name,
                    "list_tools",
                    {},
                    request_id=request_id,
                )
                assert duplicate.status == "duplicate_request"
                assert len([item for item, _ in fixture.calls if item == "execute"]) == 1

                # Provider ACK is lost after arrival: genuine registry HTTP 503
                # must become UNKNOWN; a duplicate request_id must not resubmit.
                unknown_id = "req-lost-" + uuid.uuid4().hex
                unknown = await registry.execute_tool(
                    name,
                    "list_tools",
                    {},
                    request_id=unknown_id,
                )
                assert unknown.status == "unknown"
                retry = await registry.execute_tool(
                    name,
                    "list_tools",
                    {},
                    request_id=unknown_id,
                )
                assert retry.status == "duplicate_request"
                assert len([item for item, _ in fixture.calls if item == "execute"]) == 2

                # Source cancellation/status is not authorized merely by
                # knowing a bootstrap request ID. We NEVER forge permission
                # to send controls; require denial before network.
                before = len(fixture.calls)
                cancelled = await registry.request_cancellation(
                    name, unknown_id, "api-bootstrap", "task-local"
                )
                queried = await registry.reconcile_execution(
                    name, unknown_id, "api-bootstrap", "task-local"
                )
                assert cancelled["status"] == queried["status"] == "denied"
                assert len(fixture.calls) == before
                assert not any(item in {"status", "cancel"} for item, _ in fixture.calls)

                # Even a structurally plausible post-restart claim cannot
                # authorize status or cancellation when its real SessionMemory
                # lacks an independently verified committed Task. No forged
                # human approval, token, signer or DB row is substituted.
                registry.set_budget_callback(memory.consume_mcp_tool_budget)
                recovered_claim = {
                    "request_id": unknown_id,
                    "engagement_id": "eng-unapproved",
                    "task_id": "task-unapproved",
                    "server_id": name,
                    "authorization_version": 1,
                    "status": "outcome_unknown",
                    "tool_name": "list_tools",
                }
                recovered_status = await connection.reconcile_persisted_status(recovered_claim)
                recovered_stop = await connection.cancel_persisted_execution(
                    {**recovered_claim, "status": "cancel_requested"}
                )
                assert recovered_status["status"] == recovered_stop["status"] == "denied"
                assert len(fixture.calls) == before
                assert memory.load_task_authoritative.await_count >= 2
            finally:
                RequestContext.clear()

            assert [kind for kind, _ in fixture.calls] == [
                "health",
                "initialize",
                "execute",
                "execute",
            ]
            assert events.await_count > 0
            # Explicitly no independent target activity was attempted.
            assert all(
                body.get("tool_name") == "list_tools"
                for kind, body in fixture.calls
                if kind == "execute"
            )
        finally:
            await registry.close_all()


def test_actual_go_native_and_cloud_static_only_are_not_fixture_readiness() -> None:
    """Classification check from production source, never an invented live run."""
    sdk = (ROOT / "mcp-servers/go/sdk/server.go").read_text(encoding="utf-8")
    assert "s.verifyAndRedeemAuthorityStatus(" in sdk
    assert "return []Tool{authorityStatusTool()}" in sdk
    assert "item.Handler = nil" in sdk
    assert '"native_target_execution_enabled": false' in sdk
    for name in GO_SIX:
        command = (ROOT / f"mcp-servers/go/cmd/{name}/main.go").read_text(encoding="utf-8")
        assert f'sdk.NewServer("{name}")' in command
    cloud_source = (ROOT / "mcp-servers/python/cloud_mcp.py").read_text(encoding="utf-8")
    assert "OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED" in cloud_source
    assert '"validation_state": "STATIC_IAC_ONLY"' in cloud_source
    assert '"live_cloud_account_verified": False' in cloud_source
    assert '"target_effect_verified": False' in cloud_source
    assert "_response(503" in cloud_source
    turbo_source = (ROOT / "mcp-servers/python/turbo_intruder_mcp.py").read_text(encoding="utf-8")
    assert '"execution_enabled": False' in turbo_source
    assert "status_code=503" in turbo_source
