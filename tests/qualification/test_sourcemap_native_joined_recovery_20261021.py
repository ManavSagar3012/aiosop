"""Opt-in joined SourceMap recovery against disposable real PostgreSQL 0035.

The central source/status ASGI routers execute their real PostgreSQL-backed
authorization and Ed25519 issuance. Native HTTPX calls reach those routers via
in-process ASGI transport: TLS, separate processes and external targets are NOT
qualified here. The native artifact reader, fsynced journal and receipt signer
are real. No database/container is contacted without the existing explicit
OSOP_DISPOSABLE_NATIVE_0029_PG=1 fixture opt-in.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request
from sqlalchemy import text

from ai_osop.api.routers import native_sourcemap_source_authority as source_api
from ai_osop.api.routers import native_sourcemap_status_authority as status_api
from ai_osop.mcp.protocol import _verified_remote_status
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.qualification.test_sourcemap_real_pg_source_20261020 import (
    ISSUER_KID,
    NATIVE_TOKEN,
    ORIGINAL,
    RECEIPT_KID,
    SENIOR,
    SERVER,
    SERVICE_TOKEN,
    SHA,
    TOOL,
    _configure_independent_signers,
    _declared_native_registry,
    _native_module,
    _receipt_rows,
    _signed_original_case,
    disposable_native_pg,
)


STATUS_PATH = "/native-sourcemap/status-preflight"
STATUS_SERVICE = "distinct-original-sourcemap-recovery-status-principal"
SOURCE_PATH = "/native-sourcemap/source-preflight"
REAL_HTTPX_CLIENT = httpx.AsyncClient


async def _native_post(
    native: Any, path: str, data: dict[str, Any], *, bearer: str = NATIVE_TOKEN
) -> httpx.Response:
    async with REAL_HTTPX_CLIENT(
        transport=httpx.ASGITransport(app=native.app), base_url="http://native.local"
    ) as client:
        return await client.post(
            path,
            json=data,
            headers={"Authorization": "Bearer " + bearer},
        )


def _configure_join(
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
) -> tuple[Any, Path, Path, list[tuple[str, int, str]]]:
    """Connect real native outbound requests to real central mounted routers."""
    monkeypatch.setitem(
        source_api.state,
        "orchestrator",
        SimpleNamespace(session_memory=case["memory"], mcp_registry=case["registry"]),
    )
    central = FastAPI()
    central.include_router(source_api.router)
    central.include_router(status_api.router)
    history: list[tuple[str, int, str]] = []

    @central.middleware("http")
    async def observe(request: Request, call_next: Any) -> Any:
        result = await call_next(request)
        history.append(
            (request.url.path, result.status_code, request.headers.get("authorization", ""))
        )
        return result

    monkeypatch.setenv(
        "OSOP_SOURCEMAP_STATUS_URL", "https://sourcemap.authority.invalid" + STATUS_PATH
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", STATUS_SERVICE)
    original_root = Path(os.environ["OSOP_SOURCEMAP_ORIGINAL_READONLY_ROOT"])
    original = original_root / (SHA + ".map")
    original.write_bytes(ORIGINAL)
    original.chmod(stat.S_IREAD)
    journal = Path(os.environ["OSOP_SOURCEMAP_ONE_SHOT_ROOT"])

    def central_transport_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        # The fake CA file establishes native configuration only; intercepted
        # ASGI transport is explicitly NOT a cryptographic TLS handshake.
        assert kwargs.pop("verify") == os.environ["OSOP_SOURCEMAP_SOURCE_CA_BUNDLE"]
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert "transport" not in kwargs
        return REAL_HTTPX_CLIENT(*args, transport=httpx.ASGITransport(app=central), **kwargs)

    # The native module imports the shared httpx module; keep the unpatched
    # constructor for the actual native ASGI requests above.
    native = _native_module()
    monkeypatch.setattr(native.httpx, "AsyncClient", central_transport_client)
    return native, original, journal, history


async def _action_state(engine: Any, case: dict[str, Any]) -> tuple[str, bool, Optional[str], int]:
    async with engine.connect() as db:
        action = (
            (
                await db.execute(
                    text(
                        "SELECT status,cancel_requested,receipt_sha256 "
                        "FROM flow_mcp_action_dispatches WHERE action_id=:id"
                    ),
                    {"id": case["action"]},
                )
            )
            .mappings()
            .one()
        )
        attempts = (
            await db.execute(
                text(
                    "SELECT COUNT(*) FROM flow_mcp_action_dispatch_events "
                    "WHERE action_id=:id AND kind='dispatch_attempted'"
                ),
                {"id": case["action"]},
            )
        ).scalar_one()
    return action["status"], action["cancel_requested"], action["receipt_sha256"], attempts


def _status_identity(case: dict[str, Any]) -> dict[str, str]:
    return {
        "request_id": case["request_id"],
        "engagement_id": case["binding"]["engagement_id"],
        "task_id": case["task"],
        "server_id": SERVER,
    }


@pytest.mark.asyncio
async def test_real_0035_issuer_to_native_original_then_signed_journal_recovery(
    disposable_native_pg: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End-to-end in-process source/action/status join, including current PG denials."""
    central_signer, central_public = _configure_independent_signers(monkeypatch, tmp_path)
    initial_native = _native_module()
    registry = await _declared_native_registry(initial_native)
    case = await _signed_original_case(disposable_native_pg, monkeypatch, registry)
    native, artifact, journal, history = _configure_join(monkeypatch, case)
    identity = _status_identity(case)
    actual_reads: list[bytes] = []
    real_read = native._read_original_bytes

    def read_original(root: Path, digest: str) -> bytes:
        contents = real_read(root, digest)
        actual_reads.append(contents)
        return contents

    monkeypatch.setattr(native, "_read_original_bytes", read_original)
    assert artifact.read_bytes() == ORIGINAL
    assert (await _native_post(native, "/mcp/initialize", {})).json()["capabilities"] == [
        "mcp_bound_receipts_v1",
        "original_sourcemap_signed_preflight_v1",
        "mcp_request_status_v1",
    ]
    execution = {
        "tool_name": TOOL,
        "parameters": {"artifact_sha256": SHA},
        "request_id": case["request_id"],
        "execution_binding": identity,
    }
    performed = await _native_post(native, "/mcp/execute", execution)
    assert performed.status_code == 200, performed.text
    accepted = performed.json()
    assert accepted["status"] == "success"
    assert accepted["request_id"] == case["request_id"]
    assert accepted["result"]["source_original_bytes_sha256_verified"] is True
    assert accepted["result"]["source_side_signed_authorization_verified"] is True
    assert accepted["result"]["sources"] == ["source_0.js"]
    assert accepted["result"]["credentials_disclosed"] is False
    assert ORIGINAL not in performed.content
    assert b"sourcesContent" not in performed.content
    assert actual_reads == [ORIGINAL]
    provider_receipt = accepted["provider_receipt"]
    assert provider_receipt["attestation"]["kid"] == RECEIPT_KID
    assert provider_receipt_is_signed(
        provider_receipt, SERVER, case["request_id"], identity["engagement_id"], case["task"]
    )
    assert (
        _verified_remote_status(
            provider_receipt,
            case["request_id"],
            identity["engagement_id"],
            case["task"],
            SERVER,
            require_bound_identity=True,
            require_signature=True,
        )
        == "confirmed_finished"
    )
    assert history == [(SOURCE_PATH, 200, "Bearer " + SERVICE_TOKEN)]
    issued = await _receipt_rows(disposable_native_pg, case)
    assert len(issued) == 1
    assert issued[0]["kid"] == ISSUER_KID
    assert issued[0]["action_id"] == case["action"]
    assert issued[0]["artifact_sha256"] == SHA
    assert len(list(journal.glob("*.used"))) == 2
    assert len(list(journal.glob("completed-*.json"))) == 1
    assert len(list(journal.glob("request-index-*.json"))) == 1
    assert await _action_state(disposable_native_pg, case) == ("unknown", False, None, 1)

    # Reloading native code removes all process-local request cache. Status
    # still recovers only from fsynced request index + receipt + tombstones.
    reloaded = _native_module()

    def forbidden_original_read(*args: Any, **kwargs: Any) -> bytes:
        raise AssertionError("Journal status/replay must never read original bytes")

    monkeypatch.setattr(reloaded, "_read_original_bytes", forbidden_original_read)
    monkeypatch.setattr(reloaded, "_inspect_original_map", forbidden_original_read)
    monkeypatch.setattr(reloaded, "_reserve_original_once", forbidden_original_read)
    for _ in range(2):
        readback = await _native_post(reloaded, "/mcp/request/status", identity)
        assert readback.status_code == 200, readback.text
        signed = readback.json()
        assert signed["status"] == "succeeded"
        assert signed["verified"] is True
        assert signed["stopped"] is False
        assert provider_receipt_is_signed(
            signed, SERVER, identity["request_id"], identity["engagement_id"], identity["task_id"]
        )
        assert (
            _verified_remote_status(
                signed,
                identity["request_id"],
                identity["engagement_id"],
                identity["task_id"],
                SERVER,
                require_bound_identity=True,
                require_signature=True,
            )
            == "confirmed_finished"
        )
        assert ORIGINAL not in readback.content
        assert b"manifest_sha256" not in readback.content
    assert history[-2:] == [(STATUS_PATH, 200, "Bearer " + STATUS_SERVICE)] * 2
    assert await _action_state(disposable_native_pg, case) == ("unknown", False, None, 1)
    assert len(await _receipt_rows(disposable_native_pg, case)) == 1

    wrong_task = await _native_post(
        reloaded, "/mcp/request/status", {**identity, "task_id": "task-foreign"}
    )
    assert wrong_task.status_code == 503 and "attestation" not in wrong_task.json()
    assert len(history) == 3  # Wrong Task rejected by native durable identity before central.
    assert (
        await _native_post(reloaded, "/mcp/request/status", identity, bearer=SERVICE_TOKEN)
    ).status_code == 503
    assert len(history) == 3

    # Current independent senior authorization is queried from PostgreSQL on
    # every status readback; prior signed issuer status is never cached.
    async with disposable_native_pg.begin() as db:
        await db.execute(
            text("UPDATE operator_subject_controls SET disabled=true WHERE actor_id=:reviewer"),
            {"reviewer": SENIOR},
        )
    revoked = await _native_post(reloaded, "/mcp/request/status", identity)
    assert revoked.status_code == 503 and revoked.json()["status"] == "unknown"
    assert history[-1] == (STATUS_PATH, 409, "Bearer " + STATUS_SERVICE)
    async with disposable_native_pg.begin() as db:
        await db.execute(
            text("UPDATE operator_subject_controls SET disabled=false WHERE actor_id=:reviewer"),
            {"reviewer": SENIOR},
        )
        await db.execute(
            text("UPDATE supervision_execution_leases SET state='cancelled' WHERE task_id=:task"),
            {"task": case["task"]},
        )
    suspended = await _native_post(reloaded, "/mcp/request/status", identity)
    assert suspended.status_code == 503 and suspended.json()["status"] == "unknown"
    assert history[-1] == (STATUS_PATH, 409, "Bearer " + STATUS_SERVICE)
    async with disposable_native_pg.begin() as db:
        await db.execute(
            text("UPDATE supervision_execution_leases SET state='dispatched' WHERE task_id=:task"),
            {"task": case["task"]},
        )
    assert (await _native_post(reloaded, "/mcp/request/status", identity)).status_code == 200

    # The actual central status router will still return HTTP 200 when its
    # private issuer key is unexpectedly replaced. Native must reject that
    # envelope against the separately enrolled original issuer public root.
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_SIGNING_PRIVATE_KEY_B64",
        base64.b64encode(Ed25519PrivateKey.generate().private_bytes_raw()).decode("ascii"),
    )
    forged_signature = await _native_post(reloaded, "/mcp/request/status", identity)
    assert forged_signature.status_code == 503
    assert "attestation" not in forged_signature.json()
    assert history[-1] == (STATUS_PATH, 200, "Bearer " + STATUS_SERVICE)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_SIGNING_PRIVATE_KEY_B64",
        base64.b64encode(central_signer.private_bytes_raw()).decode("ascii"),
    )
    assert (await _native_post(reloaded, "/mcp/request/status", identity)).status_code == 200

    # Original execution was committed UNKNOWN before 0035 issuance. A replay
    # with the same Action/request cannot issue a second source permission.
    replay = await _native_post(reloaded, "/mcp/execute", execution)
    assert replay.status_code == 503
    assert "provider_receipt" not in replay.json()
    assert history[-1] == (SOURCE_PATH, 409, "Bearer " + SERVICE_TOKEN)
    assert actual_reads == [ORIGINAL]
    assert len(list(journal.glob("*.used"))) == 2
    assert len(list(journal.glob("completed-*.json"))) == 1
    assert len(await _receipt_rows(disposable_native_pg, case)) == 1
    assert await _action_state(disposable_native_pg, case) == ("unknown", False, None, 1)

    # Even an actual original signed native receipt cannot survive a modified
    # journal entry; a new central status permit must not be requested for it.
    recorded_history = len(history)
    completed = next(journal.glob("completed-*.json"))
    tampered = json.loads(completed.read_text(encoding="utf-8"))
    tampered["provider_receipt"]["attestation"]["signature"] = "A" * 86
    completed.write_text(json.dumps(tampered), encoding="utf-8")
    corrupt = await _native_post(reloaded, "/mcp/request/status", identity)
    assert corrupt.status_code == 503 and "attestation" not in corrupt.json()
    assert len(history) == recorded_history
    assert len(await _receipt_rows(disposable_native_pg, case)) == 1
    assert central_signer.public_key().public_bytes_raw() == central_public


@pytest.mark.asyncio
async def test_real_0035_issuer_with_missing_completed_index_remains_unknown(
    disposable_native_pg: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Simulate lost ACK after completed fsync but before request-index fsync."""
    _configure_independent_signers(monkeypatch, tmp_path)
    declaration_native = _native_module()
    registry = await _declared_native_registry(declaration_native)
    case = await _signed_original_case(disposable_native_pg, monkeypatch, registry)
    native, _, journal, history = _configure_join(monkeypatch, case)

    def interrupted_index(*args: Any, **kwargs: Any) -> None:
        raise OSError("synthetic index persistence interruption")

    monkeypatch.setattr(native, "_persist_request_index", interrupted_index)
    execution = {
        "tool_name": TOOL,
        "parameters": {"artifact_sha256": SHA},
        "request_id": case["request_id"],
        "execution_binding": _status_identity(case),
    }
    response = await _native_post(native, "/mcp/execute", execution)
    assert response.status_code == 503
    assert "provider_receipt" not in response.json()
    assert len(list(journal.glob("completed-*.json"))) == 1
    assert not list(journal.glob("request-index-*.json"))
    assert len(list(journal.glob("*.used"))) == 2
    assert len(await _receipt_rows(disposable_native_pg, case)) == 1

    reloaded = _native_module()
    status = await _native_post(reloaded, "/mcp/request/status", _status_identity(case))
    assert status.status_code == 503 and "attestation" not in status.json()
    assert history == [(SOURCE_PATH, 200, "Bearer " + SERVICE_TOKEN)]
    replay = await _native_post(reloaded, "/mcp/execute", execution)
    assert replay.status_code == 503 and "provider_receipt" not in replay.json()
    assert history[-1] == (SOURCE_PATH, 409, "Bearer " + SERVICE_TOKEN)
    assert not list(journal.glob("request-index-*.json"))
    assert len(await _receipt_rows(disposable_native_pg, case)) == 1
    assert await _action_state(disposable_native_pg, case) == ("unknown", False, None, 1)
