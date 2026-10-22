"""Opt-in real 0030 PostgreSQL one-use resource delivery and mounted API.

Source authority is the original real independently approved 0027/0029 Action;
no _source, Task, ROE, reviewer or lease checks are replaced. No host files,
external provider, target, or application PostgreSQL instance is accessed.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ai_osop.api.routers import native_mcp_redemption as redemption
from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied
from ai_osop.memory.native_mcp_resource_delivery import NativeMCPResourceDelivery
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    _OWNER,
    _SECRET,
    _SERVER,
    _case,
    disposable_native_pg,
    initialized_catalog,
    signing_material,
)
from tests.qualification.test_native_reviewed_resource_pg_20261020 import _reviewed_resource


async def _redeemed_case(
    engine: Any,
    registry: Any,
    monkeypatch: Any,
    key: Ed25519PrivateKey,
    *,
    reviewer: str = "independent-senior-resource-offer",
) -> tuple[Any, str, dict[str, Any]]:
    case = await _case(engine, registry, monkeypatch, key, dispatch=False)
    _artifact, digest, _bytes = await _reviewed_resource(engine, case, reviewer=reviewer)
    reservation = await case.original.reserve(case.binding, _OWNER, case.action_id)
    await case.original.mark_dispatched(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        reservation["reservation_token"],
    )
    issued = await case.grants.issue(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        resource_sha256=digest,
    )
    confirmed = await case.grants.redeem(
        issued["token"],
        server_id=_SERVER,
        server_secret=_SECRET,
    )
    assert confirmed["durably_redeemed"] is True
    return case, digest, issued


@pytest.mark.asyncio(scope="module")
async def test_real_postgres_concurrent_offers_one_winner_and_immutable_audit(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case, digest, issued = await _redeemed_case(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material
    )
    delivery = NativeMCPResourceDelivery(case.original)
    results = await asyncio.gather(
        delivery.offer(issued["token"], server_id=_SERVER, server_secret=_SECRET),
        delivery.offer(issued["token"], server_id=_SERVER, server_secret=_SECRET),
        return_exceptions=True,
    )
    accepted = [r for r in results if isinstance(r, dict)]
    rejected = [r for r in results if isinstance(r, Exception)]
    assert len(accepted) == 1 and len(rejected) == 1
    assert isinstance(rejected[0], MCPActionDenied)
    assert accepted[0]["grant_id"] == issued["grant_id"]
    assert accepted[0]["manifest_sha256"] == digest
    assert accepted[0]["manifest"]["artifact_bytes_untrusted"] is True
    assert accepted[0]["manifest"]["host_files_created"] is False
    assert accepted[0]["manifest"]["read_only"] is True
    assert len(accepted[0]["files"]) == 1
    async with disposable_native_pg.connect() as db:
        row = (
            await db.execute(
                text(
                    "SELECT status,request_id,file_count,total_size_bytes,"
                    "manifest_sha256 FROM native_mcp_resource_offers WHERE grant_id=:grant"
                ),
                {"grant": issued["grant_id"]},
            )
        ).one()
        assert row.status == "offered"
        assert row.request_id == case.request_id
        assert row.file_count == 1
        assert row.total_size_bytes > 0
        assert row.manifest_sha256 == digest
    with pytest.raises(MCPActionDenied):
        await delivery.offer(
            issued["token"],
            server_id=_SERVER,
            server_secret=_SECRET,
        )


@pytest.mark.asyncio(scope="module")
async def test_mounted_api_checks_independent_service_key_and_live_resource_reviewer(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    from ai_osop.api.main import app

    case, digest, issued = await _redeemed_case(
        disposable_native_pg,
        initialized_catalog,
        monkeypatch,
        signing_material,
        reviewer="independent-senior-resource-api",
    )
    old = redemption.state.get("orchestrator")
    redemption.state["orchestrator"] = SimpleNamespace(
        session_memory=case.original.memory, mcp_registry=initialized_catalog
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://localhost"
        ) as http:
            route = "/native-grants/resources"
            good = {
                "X-OSOP-Native-Server-ID": _SERVER,
                "Authorization": "Bearer " + _SECRET,
                "Content-Type": "application/json",
            }
            bad = {**good, "Authorization": "Bearer " + "z" * 40}
            assert (await http.post(route, json=issued["token"], headers=bad)).status_code == 409
            result = await http.post(route, json=issued["token"], headers=good)
            assert result.status_code == 200
            payload = result.json()
            assert payload["manifest_sha256"] == digest
            assert payload["manifest"]["content_executed"] is False
            assert result.headers["cache-control"] == "private, no-store"
            # Transaction committed before response; a second request MUST
            # never offer the same original bytes despite HTTP ambiguity.
            assert (await http.post(route, json=issued["token"], headers=good)).status_code == 409

            denied, _digest2, other = await _redeemed_case(
                disposable_native_pg,
                initialized_catalog,
                monkeypatch,
                signing_material,
                reviewer="independent-senior-resource-revoked",
            )
            redemption.state["orchestrator"] = SimpleNamespace(
                session_memory=denied.original.memory, mcp_registry=initialized_catalog
            )
            async with disposable_native_pg.begin() as db:
                await db.execute(
                    text(
                        "UPDATE operator_subject_controls SET disabled=true "
                        "WHERE actor_id='independent-senior-resource-revoked'"
                    )
                )
            assert (await http.post(route, json=other["token"], headers=good)).status_code == 409
            async with disposable_native_pg.connect() as db:
                assert (
                    await db.execute(
                        text(
                            "SELECT count(*) FROM native_mcp_resource_offers " "WHERE grant_id=:id"
                        ),
                        {"id": other["grant_id"]},
                    )
                ).scalar_one() == 0
    finally:
        if old is None:
            redemption.state.pop("orchestrator", None)
        else:
            redemption.state["orchestrator"] = old


@pytest.mark.asyncio(scope="module")
async def test_offer_post_insert_failure_rolls_back_and_never_forces_action_replay(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case, _digest, issued = await _redeemed_case(
        disposable_native_pg,
        initialized_catalog,
        monkeypatch,
        signing_material,
        reviewer="independent-senior-atomic-offer",
    )
    async with disposable_native_pg.begin() as db:
        await db.execute(
            text(
                "CREATE FUNCTION native_qual_fail_original_resource_offer() RETURNS trigger "
                "LANGUAGE plpgsql AS $$ BEGIN "
                "RAISE EXCEPTION 'disposable post-insert original-byte crash'; END; $$"
            )
        )
        await db.execute(
            text(
                "CREATE TRIGGER trg_qual_fail_native_offer "
                "AFTER INSERT ON native_mcp_resource_offers FOR EACH ROW "
                "EXECUTE FUNCTION native_qual_fail_original_resource_offer()"
            )
        )
    try:
        with pytest.raises(MCPActionDenied):
            await NativeMCPResourceDelivery(case.original).offer(
                issued["token"],
                server_id=_SERVER,
                server_secret=_SECRET,
            )
        async with disposable_native_pg.connect() as db:
            assert (
                await db.execute(
                    text("SELECT count(*) FROM native_mcp_resource_offers WHERE grant_id=:id"),
                    {"id": issued["grant_id"]},
                )
            ).scalar_one() == 0
            assert (
                await db.execute(
                    text("SELECT status FROM flow_mcp_action_dispatches WHERE action_id=:id"),
                    {"id": case.action_id},
                )
            ).scalar_one() == "unknown"
            assert (
                await db.execute(
                    text("SELECT status FROM native_mcp_execution_grants WHERE grant_id=:id"),
                    {"id": issued["grant_id"]},
                )
            ).scalar_one() == "redeemed"
        # This is a deliberately injected ambiguous server failure, not
        # authorization to send an original Action again.
    finally:
        async with disposable_native_pg.begin() as db:
            await db.execute(
                text(
                    "DROP TRIGGER IF EXISTS trg_qual_fail_native_offer "
                    "ON native_mcp_resource_offers"
                )
            )
            await db.execute(
                text("DROP FUNCTION IF EXISTS native_qual_fail_original_resource_offer()")
            )
