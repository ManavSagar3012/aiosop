"""Real Go + signed Flow + independently reviewed original-byte resource proof.

No host filesystem staging or executable resource content: an immutable,
independently reviewed 0026-compatible BYTEA manifest SHA is carried through
the full 0027/0029 grant and re-read at redemption. Tool is inert only.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

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
from tests.qualification.test_native_reviewed_resource_pg_20261020 import (
    _reviewed_resource,
)


@pytest.mark.asyncio(scope="module")
async def test_actual_go_native_reads_independently_reviewed_resource_manifest(
    disposable_native_pg: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    registry = MCPRegistry()
    issuer_pub = signing_material.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    async with native_go_mounted_fastapi(
        memory=object(),
        registry=registry,
        issuer_kid=_KID,
        issuer_public_raw=issuer_pub,
        service_secret=_SECRET,
        initialization_engagement_id="eng-reviewed-resource-qualification",
    ):
        case = await _case(
            disposable_native_pg, registry, monkeypatch, signing_material, dispatch=False
        )
        artifact_id, digest, expected_bytes = await _reviewed_resource(disposable_native_pg, case)
        redemption.state["orchestrator"] = SimpleNamespace(
            session_memory=case.original.memory, mcp_registry=registry
        )
        memory = case.original.memory
        supervisor = SupervisionStore(memory)
        registry.set_budget_callback(memory.consume_mcp_tool_budget)

        async def original_audit_event(
            engagement_id: str, task_id: str, kind: str, metadata: dict[str, Any]
        ) -> bool:
            rid = metadata.get("request_id", "")
            server = metadata.get("server_id", "")
            if kind == "dispatch_accepted":
                return await supervisor.claim_mcp_dispatch(
                    engagement_id, task_id, server, rid, metadata.get("tool_name", "")
                )
            return await supervisor.record_mcp_dispatch_event(
                engagement_id,
                task_id,
                server,
                rid,
                kind,
                metadata.get("status", "unknown"),
                attested_receipt=metadata.get("attested_receipt"),
            )

        registry.set_execution_event_callback(original_audit_event)
        result = await FlowMCPActionExecutor(memory, registry, case.original).dispatch(
            dict(case.binding),
            {
                "sub": _OWNER,
                "role": "operator",
                "claims": {"exp": int(time.time()) + 300},
            },
            case.action_id,
        )
        assert result["status"] == "unknown"
        async with disposable_native_pg.connect() as db:
            original = (
                await db.execute(
                    text(
                        "SELECT status FROM flow_mcp_action_dispatches " "WHERE action_id=:action"
                    ),
                    {"action": case.action_id},
                )
            ).scalar_one()
            assert original == "unknown"
            issued = (
                (
                    await db.execute(
                        text(
                            "SELECT grant_id,status,revision,resource_sha256 "
                            "FROM native_mcp_execution_grants WHERE action_id=:action"
                        ),
                        {"action": case.action_id},
                    )
                )
                .mappings()
                .one()
            )
            assert issued["status"] == "redeemed"
            assert issued["revision"] == 2
            assert issued["resource_sha256"] == digest
            # A new 0030 immutable one-use OFFER is committed independently
            # from the 0029 redemption, before bytes cross pinned HTTPS.
            # This does not assert worker receipt or filesystem staging.
            offer = (
                (
                    await db.execute(
                        text(
                            "SELECT grant_id,engagement_id,flow_id,action_id,request_id,"
                            "server_id,manifest_sha256,file_count,total_size_bytes,status "
                            "FROM native_mcp_resource_offers WHERE grant_id=:id"
                        ),
                        {"id": issued["grant_id"]},
                    )
                )
                .mappings()
                .one()
            )
            assert offer["grant_id"] == issued["grant_id"]
            assert offer["engagement_id"] == case.binding["engagement_id"]
            assert offer["flow_id"] == case.binding["flow_id"]
            assert offer["action_id"] == case.action_id
            assert offer["request_id"] == case.request_id
            assert offer["server_id"] == "recon-mcp"
            assert offer["manifest_sha256"] == digest
            assert offer["file_count"] == 1
            assert offer["total_size_bytes"] == len(expected_bytes)
            assert offer["status"] == "offered"
            original_bytes = (
                await db.execute(
                    text("SELECT content FROM flow_artifacts WHERE id=:artifact"),
                    {"artifact": artifact_id},
                )
            ).scalar_one()
            assert original_bytes == expected_bytes
            events = (
                await db.execute(
                    text(
                        "SELECT kind,status FROM native_mcp_execution_grant_events "
                        "WHERE grant_id=:id ORDER BY revision"
                    ),
                    {"id": issued["grant_id"]},
                )
            ).all()
            assert [tuple(row) for row in events] == [
                ("issued", "issued"),
                ("redeemed", "redeemed"),
            ]
