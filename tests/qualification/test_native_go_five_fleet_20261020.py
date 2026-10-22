"""Opt-in actual five native Go binaries -> pinned HTTPS FastAPI -> signed PG.

Genuine production MCP initialization and 0027/0029 admission; distinct
fresh Go process, loopback port and service TLS trust root per native server.
Only the *inert built-in* ``authority_status`` is called. All scanner, target,
HTTP-provider, cloud, paid-API and external target handlers remain uninvoked.

The PostgreSQL container is a fresh owned/cached PG16 from the earlier opt-in
fixture. Its creation, all ports and every started service are locally owned.
This is not certification of scanner execution or independent target effects.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import time
from types import SimpleNamespace
from typing import Any

import aiohttp
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from sqlalchemy import text

from ai_osop.api.routers import native_mcp_redemption as redemption
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied
from ai_osop.memory.native_mcp_execution_grants import _native_manifest_sha256
from ai_osop.memory.supervision_store import SupervisionStore
from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor
from tests.qualification import test_native_joined_signed_0029_pg_20261020 as signed_0029
from tests.qualification.native_go_fleet_helper_20261020 import (
    _SERVERS,
    native_go_fleet_mounted_fastapi,
)
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    _OWNER,
    _case,
    disposable_native_pg,
)


_KID = "fleet-issuer-0029"
_EXPECTED_NATIVE_RESULT = {
    "status": "grant_durably_redeemed",
    "tool_name": "authority_status",
    "native_target_execution_enabled": False,
    "target_contacted": False,
    "provider_contacted": False,
}


def _trust(monkeypatch: Any, server_id: str) -> tuple[Ed25519PrivateKey, bytes, str]:
    key = Ed25519PrivateKey.generate()
    secret = "disposable-" + server_id + "-" + hashlib.sha256(os.urandom(32)).hexdigest()
    raw_private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_encoded = base64.urlsafe_b64encode(raw_public).decode("ascii").rstrip("=")
    monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID", _KID)
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON",
        json.dumps({_KID: base64.b64encode(raw_private).decode("ascii")}),
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
        json.dumps({_KID: public_encoded}),
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
        json.dumps({server_id: secret}),
    )
    return key, raw_public, secret


def _set_durable_callbacks(registry: MCPRegistry, memory: Any) -> None:
    """Actual supervision writer, no fake durable receipt or source method."""
    supervision = SupervisionStore(memory)
    registry.set_budget_callback(memory.consume_mcp_tool_budget)

    async def event_writer(
        engagement_id: str, task_id: str, kind: str, metadata: dict[str, Any]
    ) -> bool:
        request_id = metadata.get("request_id", "")
        server_id = metadata.get("server_id", "")
        if kind == "dispatch_accepted":
            return await supervision.claim_mcp_dispatch(
                engagement_id,
                task_id,
                server_id,
                request_id,
                metadata.get("tool_name", ""),
            )
        return await supervision.record_mcp_dispatch_event(
            engagement_id,
            task_id,
            server_id,
            request_id,
            kind,
            metadata.get("status", "unknown"),
            attested_receipt=metadata.get("attested_receipt"),
        )

    registry.set_execution_event_callback(event_writer)


async def _assert_sql_audit(
    engine: Any, *, case: Any, server_id: str, grant_status: str = "redeemed"
) -> str:
    async with engine.connect() as db:
        original = (
            (
                await db.execute(
                    text(
                        "SELECT action_id,engagement_id,server_id,tool_name,status,revision,"
                        "cancel_requested,request_id,parameters_sha256,declaration_sha256 "
                        "FROM flow_mcp_action_dispatches WHERE action_id=:action"
                    ),
                    {"action": case.action_id},
                )
            )
            .mappings()
            .one()
        )
        assert original["engagement_id"] == case.binding["engagement_id"]
        assert original["server_id"] == server_id
        assert original["tool_name"] == "authority_status"
        assert original["status"] == "unknown" and original["revision"] == 3
        assert original["cancel_requested"] is False
        assert original["request_id"] == case.request_id
        assert original["parameters_sha256"] == hashlib.sha256(b"{}").hexdigest()
        assert original["declaration_sha256"] == _native_manifest_sha256(server_id)
        action_history = (
            await db.execute(
                text(
                    "SELECT kind,status,revision FROM flow_mcp_action_dispatch_events "
                    "WHERE action_id=:action ORDER BY revision"
                ),
                {"action": case.action_id},
            )
        ).all()
        assert [tuple(r) for r in action_history] == [
            ("prepared", "prepared", 1),
            ("reserved", "reserved", 2),
            ("dispatch_attempted", "unknown", 3),
        ]
        issued = (
            (
                await db.execute(
                    text(
                        "SELECT grant_id,engagement_id,action_id,request_id,server_id,"
                        "tool_name,status,revision,manifest_sha256,parameters_sha256 "
                        "FROM native_mcp_execution_grants WHERE action_id=:action"
                    ),
                    {"action": case.action_id},
                )
            )
            .mappings()
            .all()
        )
        assert len(issued) == 1
        grant = issued[0]
        assert grant["engagement_id"] == case.binding["engagement_id"]
        assert grant["action_id"] == case.action_id
        assert grant["request_id"] == case.request_id
        assert grant["server_id"] == server_id
        assert grant["tool_name"] == "authority_status"
        assert grant["manifest_sha256"] == _native_manifest_sha256(server_id)
        assert grant["parameters_sha256"] == hashlib.sha256(b"{}").hexdigest()
        assert grant["status"] == grant_status
        assert grant["revision"] == (2 if grant_status == "redeemed" else 1)
        grant_history = (
            await db.execute(
                text(
                    "SELECT kind,status,revision FROM native_mcp_execution_grant_events "
                    "WHERE grant_id=:id ORDER BY revision"
                ),
                {"id": grant["grant_id"]},
            )
        ).all()
        expected = [("issued", "issued", 1)]
        if grant_status == "redeemed":
            expected.append(("redeemed", "redeemed", 2))
        assert [tuple(r) for r in grant_history] == expected
        return grant["grant_id"]


@pytest.mark.asyncio(scope="module")
@pytest.mark.parametrize("server_id", sorted(_SERVERS))
async def test_five_real_go_cmd_native_signed_one_use(
    disposable_native_pg: Any, monkeypatch: Any, server_id: str
) -> None:
    """One ACTUAL binary/server/HTTPS root and real signed PG action per ID."""
    private, issuer_public_raw, service_secret = _trust(monkeypatch, server_id)
    registry = MCPRegistry()
    async with native_go_fleet_mounted_fastapi(
        server_id=server_id,
        registry=registry,
        issuer_kid=_KID,
        issuer_public_raw=issuer_public_raw,
        service_secret=service_secret,
        initialization_engagement_id="eng-five-fleet-catalog-init",
    ) as native:
        # Existing fixture is ONLY a real-Postgres data seeder. Override its
        # server ID (not any source/authority/approval implementation) so all
        # downstream production SQL and Ed25519 claims bind this actual cmd.
        monkeypatch.setattr(signed_0029, "_SERVER", server_id)
        case = await _case(disposable_native_pg, registry, monkeypatch, private, dispatch=False)
        redemption.state["orchestrator"] = SimpleNamespace(
            session_memory=case.original.memory, mcp_registry=registry
        )
        _set_durable_callbacks(registry, case.original.memory)
        executor = FlowMCPActionExecutor(case.original.memory, registry, case.original)
        result = await executor.dispatch(
            dict(case.binding),
            {"sub": _OWNER, "role": "operator", "claims": {"exp": int(time.time()) + 300}},
            case.action_id,
        )
        assert result["status"] == "unknown"  # Inert ACK is not an effect receipt.
        assert result["action_id"] == case.action_id
        assert registry.call_counts[server_id] == 1
        await _assert_sql_audit(disposable_native_pg, case=case, server_id=server_id)

        # Revisit actual binary HTTP handler directly: no user-provided header
        # can create an authorization. No original scanner handler is called.
        async with aiohttp.ClientSession() as client:
            url = f"http://127.0.0.1:{native.native_port}/mcp/execute"
            async with client.post(
                url,
                json={
                    "tool_name": "authority_status",
                    "parameters": {},
                    "request_id": "req-no-native-grant",
                },
            ) as untrusted:
                assert untrusted.status == 503

            # A separate real signed Task creates a second original UNKNOWN;
            # the native Go process consumes its one-use grant over pinned TLS.
            replay_case = await _case(
                disposable_native_pg, registry, monkeypatch, private, dispatch=True
            )
            redemption.state["orchestrator"] = SimpleNamespace(
                session_memory=replay_case.original.memory, mcp_registry=registry
            )
            issued = await replay_case.grants.issue(
                replay_case.binding,
                _OWNER,
                replay_case.action_id,
                replay_case.request_id,
                ttl_seconds=60,
            )
            body = {
                "tool_name": "authority_status",
                "parameters": {},
                "request_id": replay_case.request_id,
                "timeout_override": None,
            }
            header = {"X-OSOP-Native-Grant": issued["native_grant_header"]}
            async with client.post(url, json=body, headers=header) as first:
                assert first.status == 200
                accepted = await first.json()
                assert accepted["request_id"] == replay_case.request_id
                assert accepted["status"] == "success"
                assert accepted["result"] == _EXPECTED_NATIVE_RESULT
            async with client.post(url, json=body, headers=header) as replay:
                assert replay.status == 503
            grant_id = await _assert_sql_audit(
                disposable_native_pg, case=replay_case, server_id=server_id
            )
            assert grant_id == issued["grant_id"]
            with pytest.raises(MCPActionDenied):
                await replay_case.grants.redeem(
                    issued["token"], server_id=server_id, server_secret=service_secret
                )
