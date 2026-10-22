"""Opt-in: original signed Flow Action executor -> real Go -> TLS FastAPI -> PG.

Never executes a scanner/target/provider. ALL transport endpoints are newly
allocated loopback listeners; PG is an exclusively owned disposable container.
This is not a multi-replica/real target-effect production certificate.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import json
import time
from types import SimpleNamespace
from typing import Any

import aiohttp
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import text

from ai_osop.api.routers import native_mcp_redemption as redemption
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.supervision_store import SupervisionStore
from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor
from tests.qualification.native_go_joined_transport_20261020 import (
    native_go_mounted_fastapi,
)
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    _KID,
    _OWNER,
    _SECRET,
    _case,
    disposable_native_pg,
    signing_material,
)


@pytest.mark.asyncio(scope="module")
async def test_actual_go_recon_mcp_end_to_end_signed_flow_native_grant(
    disposable_native_pg: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    registry = MCPRegistry()
    issuer_pub = signing_material.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    async with native_go_mounted_fastapi(
        memory=object(),  # replaced with this run's actual signed Task/PG memory
        registry=registry,
        issuer_kid=_KID,
        issuer_public_raw=issuer_pub,
        service_secret=_SECRET,
        initialization_engagement_id="eng-disposable-negotiation",
    ) as live:
        case = await _case(
            disposable_native_pg, registry, monkeypatch, signing_material, dispatch=False
        )
        redemption.state["orchestrator"] = SimpleNamespace(
            session_memory=case.original.memory, mcp_registry=registry
        )
        memory = case.original.memory
        supervision = SupervisionStore(memory)
        registry.set_budget_callback(memory.consume_mcp_tool_budget)

        async def durable_mcp_event(
            engagement_id: str, task_id: str, kind: str, metadata: dict[str, Any]
        ) -> bool:
            remote_id = metadata.get("request_id", "")
            server_id = metadata.get("server_id", "")
            if kind == "dispatch_accepted":
                return await supervision.claim_mcp_dispatch(
                    engagement_id,
                    task_id,
                    server_id,
                    remote_id,
                    metadata.get("tool_name", ""),
                )
            return await supervision.record_mcp_dispatch_event(
                engagement_id,
                task_id,
                server_id,
                remote_id,
                kind,
                metadata.get("status", "unknown"),
                attested_receipt=metadata.get("attested_receipt"),
            )

        registry.set_execution_event_callback(durable_mcp_event)
        executor = FlowMCPActionExecutor(memory, registry, case.original)
        result = await executor.dispatch(
            dict(case.binding),
            {
                "sub": _OWNER,
                "role": "operator",
                "claims": {"exp": int(time.time()) + 300},
            },
            case.action_id,
        )
        assert result["action_id"] == case.action_id
        # The real native Go ACK is inert provider testimony, not a signed
        # independently verified target effect or authoritative completion.
        assert result["status"] == "unknown"
        assert registry.call_counts["recon-mcp"] == 1

        async with disposable_native_pg.connect() as db:
            original = (
                await db.execute(
                    text(
                        "SELECT status,revision FROM flow_mcp_action_dispatches "
                        "WHERE action_id=:id"
                    ),
                    {"id": case.action_id},
                )
            ).one()
            assert tuple(original) == ("unknown", 3)
            grants = (
                await db.execute(
                    text(
                        "SELECT grant_id,status,revision,request_id "
                        "FROM native_mcp_execution_grants WHERE action_id=:id"
                    ),
                    {"id": case.action_id},
                )
            ).all()
            assert len(grants) == 1
            grant = grants[0]
            assert grant.status == "redeemed"
            assert grant.revision == 2
            assert grant.request_id == case.request_id
            events = (
                await db.execute(
                    text(
                        "SELECT kind,status,revision FROM native_mcp_execution_grant_events "
                        "WHERE grant_id=:id ORDER BY revision"
                    ),
                    {"id": grant.grant_id},
                )
            ).all()
            assert [tuple(row) for row in events] == [
                ("issued", "issued", 1),
                ("redeemed", "redeemed", 2),
            ]

        # Direct attempts to use legacy real cmd-registered native tools
        # remain HTTP 503, even if the caller forges a READ_ONLY metadata flag.
        async with aiohttp.ClientSession() as client:
            for malicious in (
                {"tool_name": "nmap_scan", "parameters": {"target": "127.0.0.1"}},
                {
                    "tool_name": "authority_status",
                    "parameters": {},
                    "request_id": "req-unauthorized",
                },
            ):
                async with client.post(
                    f"http://127.0.0.1:{live.port}/mcp/execute", json=malicious
                ) as response:
                    assert response.status == 503

            # The native server must verify a SECOND genuine signed source
            # grant independently of the Python client's in-process nonce
            # cache. Concurrent real Go HTTP handlers both ask actual FastAPI
            # and PostgreSQL; one (and only one) may redeem.
            simultaneous = await _case(
                disposable_native_pg, registry, monkeypatch, signing_material
            )
            redemption.state["orchestrator"] = SimpleNamespace(
                session_memory=simultaneous.original.memory, mcp_registry=registry
            )
            issued = await simultaneous.grants.issue(
                simultaneous.binding,
                _OWNER,
                simultaneous.action_id,
                simultaneous.request_id,
                ttl_seconds=60,
            )
            body = {
                "tool_name": "authority_status",
                "parameters": {},
                "request_id": simultaneous.request_id,
                "timeout_override": None,
            }
            url = f"http://127.0.0.1:{live.port}/mcp/execute"
            grant_headers = {"X-OSOP-Native-Grant": issued["native_grant_header"]}

            # Forge the tenant inside an otherwise correctly signed envelope;
            # the original signature must never authorize the changed claim.
            altered = copy.deepcopy(issued["token"])
            altered["claims"]["engagement_id"] = "eng-cross-tenant-denied"
            forged_header = (
                base64.urlsafe_b64encode(
                    json.dumps(
                        altered, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    ).encode("ascii")
                )
                .decode("ascii")
                .rstrip("=")
            )
            async with client.post(
                url, json=body, headers={"X-OSOP-Native-Grant": forged_header}
            ) as response:
                assert response.status == 503

            untrusted_kid = copy.deepcopy(issued["token"])
            untrusted_kid["kid"] = "independent-unknown-issuer"
            wrong_key_header = (
                base64.urlsafe_b64encode(
                    json.dumps(
                        untrusted_kid, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    ).encode("ascii")
                )
                .decode("ascii")
                .rstrip("=")
            )
            async with client.post(
                url, json=body, headers={"X-OSOP-Native-Grant": wrong_key_header}
            ) as response:
                assert response.status == 503

            # Request-id swaps and malformed native MCP execute schema cannot
            # redeem this grant, even when its Ed25519 proof is otherwise valid.
            for invalid in (
                {**body, "request_id": "req-swapped-disposable"},
                {**body, "parameters": {"target": "127.0.0.1"}},
                {**body, "tool_name": "nmap_scan"},
                {**body, "unexpected": "unreviewed-extension"},
            ):
                async with client.post(url, json=invalid, headers=grant_headers) as response:
                    assert response.status == 503
            async with disposable_native_pg.connect() as db:
                assert (
                    await db.execute(
                        text(
                            "SELECT status FROM native_mcp_execution_grants " "WHERE grant_id=:id"
                        ),
                        {"id": issued["grant_id"]},
                    )
                ).scalar_one() == "issued"

            attempts = await asyncio.gather(
                client.post(url, json=body, headers=grant_headers),
                client.post(url, json=body, headers=grant_headers),
            )
            try:
                assert sorted(reply.status for reply in attempts) == [200, 503]
                authorized = next(reply for reply in attempts if reply.status == 200)
                assert (await authorized.json())["result"] == {
                    "status": "grant_durably_redeemed",
                    "tool_name": "authority_status",
                    "native_target_execution_enabled": False,
                    "target_contacted": False,
                    "provider_contacted": False,
                }
            finally:
                for reply in attempts:
                    reply.release()
            async with client.post(url, json=body, headers=grant_headers) as replay:
                assert replay.status == 503

            # After issuance, a DIFFERENT human reviewer's revocation must
            # stop the real Go → FastAPI → PG call at the source authority.
            revoked = await _case(disposable_native_pg, registry, monkeypatch, signing_material)
            redemption.state["orchestrator"] = SimpleNamespace(
                session_memory=revoked.original.memory, mcp_registry=registry
            )
            forbidden = await revoked.grants.issue(
                revoked.binding, _OWNER, revoked.action_id, revoked.request_id
            )
            async with disposable_native_pg.begin() as db:
                await db.execute(
                    text(
                        "UPDATE operator_subject_controls SET disabled=true "
                        "WHERE actor_id='operator-independent-reviewer'"
                    )
                )
            async with client.post(
                url,
                json={**body, "request_id": revoked.request_id},
                headers={"X-OSOP-Native-Grant": forbidden["native_grant_header"]},
            ) as response:
                assert response.status == 503
            async with disposable_native_pg.connect() as db:
                assert (
                    await db.execute(
                        text(
                            "SELECT status FROM native_mcp_execution_grants " "WHERE grant_id=:id"
                        ),
                        {"id": forbidden["grant_id"]},
                    )
                ).scalar_one() == "issued"
        async with disposable_native_pg.connect() as db:
            assert (
                await db.execute(
                    text(
                        "SELECT count(*) FROM native_mcp_execution_grants "
                        "WHERE action_id=:id AND status='redeemed'"
                    ),
                    {"id": case.action_id},
                )
            ).scalar_one() == 1
