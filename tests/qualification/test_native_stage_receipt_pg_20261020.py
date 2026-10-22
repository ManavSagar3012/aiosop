"""Disposable PostgreSQL current-source-gated one-use native stage testimony.

The separate Ed25519 native key is a worker identity, NOT independent external
OS sandbox attestation or evidence that a target was contacted.
"""

from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import time
from types import SimpleNamespace
from typing import Any

import pytest
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied
from ai_osop.memory.native_mcp_resource_delivery import NativeMCPResourceDelivery
from ai_osop.memory.native_mcp_stage_receipts import (
    DOMAIN,
    NativeStageReceiptStore,
    _canonical,
    readback_digest,
)
from ai_osop.api.routers import native_mcp_redemption as redemption
from tests.qualification.test_native_folder_stage_pg_20261020 import (
    _approved_folder_case,
)
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    _OWNER,
    _SERVER,
    _SECRET,
    disposable_native_pg,
    initialized_catalog,
    signing_material,
)


async def _offered(
    engine: Any,
    registry: Any,
    monkeypatch: Any,
    signer: Ed25519PrivateKey,
) -> tuple[Any, dict, dict]:
    case, digest, _folder_id, _stage, _full = await _approved_folder_case(
        engine, registry, monkeypatch, signer
    )
    lease = await case.original.reserve(case.binding, _OWNER, case.action_id)
    await case.original.mark_dispatched(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        lease["reservation_token"],
    )
    token = await case.grants.issue(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        resource_sha256=digest,
    )
    await case.grants.redeem(token["token"], server_id=_SERVER, server_secret=_SECRET)
    offer = await NativeMCPResourceDelivery(case.original).offer(
        token["token"], server_id=_SERVER, server_secret=_SECRET
    )
    return case, token, offer


def _receipt(
    monkeypatch: Any,
    token: dict,
    offer: dict,
    private: Ed25519PrivateKey,
) -> dict:
    kid = "independent-sandbox-worker-v1"
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_NATIVE_STAGE_RECEIPT_TRUST_JSON",
        json.dumps(
            {
                _SERVER: {
                    "kid": kid,
                    "public_key": base64.urlsafe_b64encode(public).decode().rstrip("="),
                }
            }
        ),
    )
    claims = {
        "version": 1,
        "grant_id": token["grant_id"],
        "request_id": token["token"]["claims"]["request_id"],
        "server_id": _SERVER,
        "resource_sha256": token["token"]["claims"]["resource_sha256"],
        "folder_staging_sha256": offer["folder_staging"]["staging_sha256"],
        "readback_sha256": readback_digest(
            token["grant_id"],
            token["token"]["claims"]["request_id"],
            offer["folder_staging"],
        ),
        "verified_at": int(time.time()),
    }
    signature = private.sign(DOMAIN + _canonical(claims))
    return {
        "claims": claims,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
    }


@pytest.mark.asyncio(scope="module")
async def test_durable_worker_ed25519_stage_report_unique_and_current_source_bound(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case, token, offer = await _offered(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material
    )
    key = Ed25519PrivateKey.generate()
    receipt = _receipt(monkeypatch, token, offer, key)
    store = NativeStageReceiptStore(case.original)
    attempts = await asyncio.gather(
        store.record(token["token"], receipt, server_id=_SERVER, server_secret=_SECRET),
        NativeStageReceiptStore(case.original).record(
            token["token"], receipt, server_id=_SERVER, server_secret=_SECRET
        ),
        return_exceptions=True,
    )
    accepted = [item for item in attempts if isinstance(item, dict)]
    rejected = [item for item in attempts if isinstance(item, Exception)]
    assert len(accepted) == 1 and len(rejected) == 1
    assert isinstance(rejected[0], MCPActionDenied)
    result = accepted[0]
    assert result["worker_stage_report_durable"] is True
    assert result["independent_target_effect_verified"] is False
    assert result["receipt_sha256"] == hashlib.sha256(_canonical(receipt["claims"])).hexdigest()
    async with disposable_native_pg.connect() as db:
        row = (
            await db.execute(
                text(
                    "SELECT status,worker_key_id,folder_staging_sha256 "
                    "FROM native_mcp_stage_receipts WHERE grant_id=:id"
                ),
                {"id": token["grant_id"]},
            )
        ).one()
        assert row.status == "worker_reported"
        assert row.worker_key_id == receipt["kid"]
        assert row.folder_staging_sha256 == offer["folder_staging"]["staging_sha256"]
    with pytest.raises(MCPActionDenied):
        await store.record(token["token"], receipt, server_id=_SERVER, server_secret=_SECRET)


@pytest.mark.asyncio(scope="module")
async def test_worker_receipt_revoked_source_and_wrong_signature_never_records(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case, token, offer = await _offered(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material
    )
    key = Ed25519PrivateKey.generate()
    receipt = _receipt(monkeypatch, token, offer, key)
    forged = {**receipt, "signature": "A" * 86}
    store = NativeStageReceiptStore(case.original)
    with pytest.raises(MCPActionDenied):
        await store.record(token["token"], forged, server_id=_SERVER, server_secret=_SECRET)
    async with disposable_native_pg.begin() as db:
        await db.execute(
            text(
                "UPDATE operator_subject_controls SET disabled=true "
                "WHERE actor_id='independent-staging-senior'"
            )
        )
    with pytest.raises(MCPActionDenied):
        await store.record(token["token"], receipt, server_id=_SERVER, server_secret=_SECRET)
    async with disposable_native_pg.connect() as db:
        assert (
            await db.execute(
                text("SELECT count(*) FROM native_mcp_stage_receipts WHERE grant_id=:id"),
                {"id": token["grant_id"]},
            )
        ).scalar_one() == 0


@pytest.mark.asyncio(scope="module")
async def test_real_mounted_stage_receipt_fastapi_postgres_and_ambiguous_ack_replay(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    from ai_osop.api.main import app

    case, token, offer = await _offered(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material
    )
    receipt = _receipt(monkeypatch, token, offer, Ed25519PrivateKey.generate())
    old = redemption.state.get("orchestrator")
    redemption.state["orchestrator"] = SimpleNamespace(
        session_memory=case.original.memory, mcp_registry=initialized_catalog
    )
    try:
        headers = {
            "X-OSOP-Native-Server-ID": _SERVER,
            "Authorization": "Bearer " + _SECRET,
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://localhost"
        ) as client:
            route = "/native-grants/stage-receipt"
            response = await client.post(
                route,
                json={"grant": token["token"], "receipt": receipt},
                headers=headers,
            )
            assert response.status_code == 200
            assert response.json()["worker_stage_report_durable"] is True
            assert response.json()["independent_target_effect_verified"] is False
            assert response.headers["cache-control"] == "private, no-store"
            oversized = await client.post(route, content=b"x" * 8200, headers=headers)
            assert oversized.status_code == 403
            # The second call is an intentional replay probe, not a retry
            # offered by the production Go worker or original 0027 Action.
            repeated = await client.post(
                route,
                json={"grant": token["token"], "receipt": receipt},
                headers=headers,
            )
            assert repeated.status_code == 409
        async with disposable_native_pg.connect() as db:
            assert (
                await db.execute(
                    text("SELECT status FROM flow_mcp_action_dispatches " "WHERE action_id=:id"),
                    {"id": case.action_id},
                )
            ).scalar_one() == "unknown"
            assert (
                await db.execute(
                    text("SELECT status FROM native_mcp_stage_receipts " "WHERE grant_id=:id"),
                    {"id": token["grant_id"]},
                )
            ).scalar_one() == "worker_reported"
    finally:
        if old is None:
            redemption.state.pop("orchestrator", None)
        else:
            redemption.state["orchestrator"] = old
