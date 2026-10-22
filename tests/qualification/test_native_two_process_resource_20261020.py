"""Two independently launched real Go native workers, one signed byte offer.

Only explicitly disposable local PostgreSQL, mounted FastAPI and loopback
processes. This is NOT multi-replica deployment certification or a scan.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aiohttp
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import text

from ai_osop.api.routers import native_mcp_redemption as redemption
from ai_osop.mcp.protocol import MCPRegistry
from tests.qualification.native_go_joined_transport_20261020 import (
    _free_loopback_port,
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
from tests.qualification.test_native_reviewed_resource_pg_20261020 import _reviewed_resource


async def _signed_original_resource(case: Any, pg: Any) -> dict:
    _artifact, digest, _bytes = await _reviewed_resource(pg, case)
    claimed = await case.original.reserve(case.binding, _OWNER, case.action_id)
    sent = await case.original.mark_dispatched(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        claimed["reservation_token"],
    )
    assert sent["status"] == "unknown"
    return await case.grants.issue(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        resource_sha256=digest,
    )


@pytest.mark.asyncio(scope="module")
async def test_two_real_go_processes_offer_one_signed_resource_and_never_replay(
    disposable_native_pg: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    registry = MCPRegistry()
    pub = signing_material.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    async with native_go_mounted_fastapi(
        memory=object(),
        registry=registry,
        issuer_kid=_KID,
        issuer_public_raw=pub,
        service_secret=_SECRET,
        initialization_engagement_id="eng-two-native-worker-qualification",
    ) as original:
        second_port = _free_loopback_port()
        assert second_port != original.port
        second_env = {**original.native_env, "OSOP_RECON_MCP_LOCAL_PORT": str(second_port)}
        second = await asyncio.create_subprocess_exec(
            original.native_binary,
            cwd=str(Path(__file__).resolve().parents[2] / "mcp-servers" / "go"),
            env=second_env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        other_registry = MCPRegistry()
        try:
            for _ in range(70):
                if second.returncode is not None:
                    raise RuntimeError("Second independently launched native Go exited")
                try:
                    await other_registry.register_server("recon-mcp", "127.0.0.1", second_port)
                    break
                except Exception:
                    await asyncio.sleep(0.1)
            negotiated = await other_registry.initialize_server(
                "recon-mcp", {}, {}, "eng-second-native-independent-initialization"
            )
            assert negotiated.status == "ready"
            assert [tool.name for tool in negotiated.tools] == ["authority_status"]

            case = await _case(
                disposable_native_pg,
                registry,
                monkeypatch,
                signing_material,
                dispatch=False,
            )
            token = await _signed_original_resource(case, disposable_native_pg)
            redemption.state["orchestrator"] = SimpleNamespace(
                session_memory=case.original.memory, mcp_registry=registry
            )
            request = {
                "tool_name": "authority_status",
                "parameters": {},
                "request_id": case.request_id,
                "timeout_override": None,
            }
            headers = {"X-OSOP-Native-Grant": token["native_grant_header"]}
            async with aiohttp.ClientSession() as client:

                async def invoke(port: int) -> tuple[int, dict]:
                    async with client.post(
                        f"http://127.0.0.1:{port}/mcp/execute",
                        json=request,
                        headers=headers,
                    ) as reply:
                        return reply.status, await reply.json()

                answers = await asyncio.gather(invoke(original.port), invoke(second_port))
                async with disposable_native_pg.connect() as inspect:
                    observed = (
                        await inspect.execute(
                            text(
                                "SELECT status FROM native_mcp_execution_grants "
                                "WHERE grant_id=:id"
                            ),
                            {"id": token["grant_id"]},
                        )
                    ).scalar_one()
                    offered = (
                        await inspect.execute(
                            text(
                                "SELECT count(*) FROM native_mcp_resource_offers "
                                "WHERE grant_id=:id"
                            ),
                            {"id": token["grant_id"]},
                        )
                    ).scalar_one()
                diagnostics = []
                if sorted(status for status, _ in answers) != [200, 503]:
                    for proc in (original.native_process, second):
                        for _ in range(4):
                            try:
                                record = await asyncio.wait_for(proc.stderr.readline(), timeout=0.2)
                            except asyncio.TimeoutError:
                                break
                            if not record:
                                break
                            diagnostics.append(record.decode(errors="replace")[:320])
                assert sorted(status for status, _ in answers) == [200, 503], (
                    f"Two independent worker response statuses: {answers}; "
                    f"durable grant={observed}, resource offers={offered}, "
                    f"safe local stage diagnostics={diagnostics}"
                )
                accepted = next(data for status, data in answers if status == 200)
                assert accepted["result"]["resource_bytes_received_verified"] is True
                assert accepted["result"]["target_contacted"] is False
                assert accepted["result"]["provider_contacted"] is False
                # One centrally redeemed signature and one original-byte offer
                # across two different Go PIDs. Neither process may replay.
                assert (await invoke(original.port))[0] == 503
                assert (await invoke(second_port))[0] == 503

            async with disposable_native_pg.connect() as db:
                assert (
                    await db.execute(
                        text(
                            "SELECT status FROM flow_mcp_action_dispatches " "WHERE action_id=:id"
                        ),
                        {"id": case.action_id},
                    )
                ).scalar_one() == "unknown"
                assert (
                    await db.execute(
                        text(
                            "SELECT status FROM native_mcp_execution_grants " "WHERE grant_id=:id"
                        ),
                        {"id": token["grant_id"]},
                    )
                ).scalar_one() == "redeemed"
                assert (
                    await db.execute(
                        text(
                            "SELECT count(*) FROM native_mcp_resource_offers " "WHERE grant_id=:id"
                        ),
                        {"id": token["grant_id"]},
                    )
                ).scalar_one() == 1
        finally:
            await other_registry.close_all()
            if second.returncode is None:
                second.terminate()
                try:
                    await asyncio.wait_for(second.wait(), timeout=3)
                except asyncio.TimeoutError:
                    second.kill()
                    await asyncio.wait_for(second.wait(), timeout=3)


@pytest.mark.asyncio(scope="module")
@pytest.mark.parametrize("rotation", ["issuer", "service"])
async def test_live_issuer_or_service_rotation_denies_native_offer_without_replay(
    disposable_native_pg: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
    rotation: str,
) -> None:
    registry = MCPRegistry()
    pub = signing_material.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    async with native_go_mounted_fastapi(
        memory=object(),
        registry=registry,
        issuer_kid=_KID,
        issuer_public_raw=pub,
        service_secret=_SECRET,
        initialization_engagement_id="eng-native-rotation-qualification",
    ) as live:
        case = await _case(
            disposable_native_pg,
            registry,
            monkeypatch,
            signing_material,
            dispatch=False,
        )
        issued = await _signed_original_resource(case, disposable_native_pg)
        redemption.state["orchestrator"] = SimpleNamespace(
            session_memory=case.original.memory, mcp_registry=registry
        )
        if rotation == "issuer":
            monkeypatch.setenv(
                "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
                json.dumps({"new-independent-issuer": "A" * 43}),
            )
        else:
            monkeypatch.setenv(
                "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
                json.dumps({"recon-mcp": "different-rotated-native-secret" * 2}),
            )
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"http://127.0.0.1:{live.port}/mcp/execute",
                json={
                    "tool_name": "authority_status",
                    "parameters": {},
                    "request_id": case.request_id,
                    "timeout_override": None,
                },
                headers={"X-OSOP-Native-Grant": issued["native_grant_header"]},
            ) as response:
                assert response.status == 503
        async with disposable_native_pg.connect() as db:
            assert (
                await db.execute(
                    text("SELECT status FROM native_mcp_execution_grants " "WHERE grant_id=:id"),
                    {"id": issued["grant_id"]},
                )
            ).scalar_one() == "issued"
            assert (
                await db.execute(
                    text("SELECT count(*) FROM native_mcp_resource_offers " "WHERE grant_id=:id"),
                    {"id": issued["grant_id"]},
                )
            ).scalar_one() == 0
        # Never retry this consequential/ambiguous original Action even after
        # an administrator restores credentials or re-enables trust roots.
