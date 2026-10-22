"""SourceMap original-Action status preflight; simulated SQL, NEVER a real PG run.

Exercises the production 0027/0035 source authority with a narrow FakePG row
store and a mounted FastAPI router. Signed source permission is read-only and
cannot replay the original Action, recover raw source bytes, or settle effects.
"""

from __future__ import annotations

import base64
import copy
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from ai_osop.api.routers import native_sourcemap_status_authority as api
from ai_osop.memory import sourcemap_status_authority as status
from ai_osop.memory.sourcemap_source_authority import SourceMapSourceDenied, canonical
from tests.test_native_sourcemap_source_authority_20261020 import (
    FakeLedger,
    FakePG,
    KID,
    SQLResult,
    fake_issuer,
    key,  # noqa: F401 -- authentic source signer fixture
    request_for,
)

SERVICE = "distinct-sourcemap-status-service-credential"
SOURCE = "different-sourcemap-original-issuer-credential"
NATIVE = "different-sourcemap-native-mcp-credential"


class StatusPG(FakePG):
    """Only the added 0035 immutable SELECT; delegate original checks unchanged."""

    async def execute(self, query, params=None):
        if "FROM native_sourcemap_source_preflights" in str(query):
            assert "FOR SHARE" in str(query)
            assert "INSERT" not in str(query) and "UPDATE" not in str(query)
            found = self.ledger.committed.get(params["request"])
            if (
                found is not None
                and found.get("action_id") == params["action"]
                and found.get("engagement_id") == params["eng"]
                and found.get("task_id") == params["task"]
            ):
                return SQLResult(row=copy.deepcopy(found))
            return SQLResult()
        return await super().execute(query, params)


async def _case(monkeypatch):
    ledger = FakeLedger()
    source, actions = fake_issuer(ledger, monkeypatch)
    request = request_for(ledger.row)
    original_receipt = await source.admit(request)
    ledger.committed[request["request_id"]]["committed_at"] = "fake-commit"
    actions._sessions = lambda: lambda: StatusPG(ledger)
    return ledger, actions, request, original_receipt


def _configure_service(monkeypatch):
    monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", SERVICE)
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", SOURCE)
    monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", NATIVE)


@pytest.mark.asyncio
async def test_status_permit_is_current_signed_readonly_and_original_unknown(key, monkeypatch):
    ledger, actions, request, issued = await _case(monkeypatch)
    result = await status.SourceMapStatusAuthorityStore(actions).admit(request)
    assert set(result) == {"claims", "kid", "signature"}
    assert result["kid"] == KID
    claims = result["claims"]
    assert set(claims) == status.STATUS_FIELDS
    assert claims["preflight_id"] == issued["claims"]["preflight_id"]
    assert claims["request_id"] == request["request_id"]
    assert claims["action_id"] == ledger.row["action_id"]
    assert claims["owner_id"] == ledger.row["owner_id"]
    assert claims["manifest_sha256"] == issued["claims"]["manifest_sha256"]
    assert claims["expires_at"] - claims["issued_at"] == 5
    key.public_key().verify(
        base64.urlsafe_b64decode(result["signature"] + "=="),
        status.STATUS_DOMAIN + canonical(claims),
    )
    assert ledger.row["status"] == "unknown"
    assert ledger.row["receipt_sha256"] is None
    assert ledger.committed[request["request_id"]]["claims_sha256"]
    assert len(ledger.committed) == 1
    # A non-consuming status permit may be issued again while current
    # independently signed original authority is still live.
    second = await status.SourceMapStatusAuthorityStore(actions).admit(request)
    assert second["claims"]["preflight_id"] == claims["preflight_id"]
    assert second["claims"]["status_id"] != claims["status_id"]
    assert len(ledger.committed) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "no-0035",
        "wrong-kid",
        "wrong-action",
        "wrong-owner",
        "wrong-manifest",
        "tampered-claims-sha",
        "forged-original-task",
        "revoked-reviewer",
        "canceled-original",
        "settled-original",
        "wrong-artifact",
    ],
)
async def test_status_permit_denies_stale_or_foreign_original_source(key, monkeypatch, failure):
    ledger, actions, request, _ = await _case(monkeypatch)
    original = ledger.committed[request["request_id"]]
    if failure == "no-0035":
        ledger.committed.clear()
    elif failure == "wrong-kid":
        original["kid"] = "old-source-issuer"
    elif failure == "wrong-action":
        original["action_id"] = "action-" + "f" * 32
    elif failure == "wrong-owner":
        original["owner_id"] = "operator-foreign"
    elif failure == "wrong-manifest":
        original["manifest_sha256"] = "1" * 64
    elif failure == "tampered-claims-sha":
        original["claims_sha256"] = "e" * 64
    elif failure == "forged-original-task":
        ledger.task_payload["resource_artifact_sha256"] = "a" * 64
    elif failure == "revoked-reviewer":
        ledger.senior_disabled = True
    elif failure == "canceled-original":
        ledger.row["cancel_requested"] = True
    elif failure == "settled-original":
        ledger.row["status"] = "finished"
    elif failure == "wrong-artifact":
        request["artifact_sha256"] = "f" * 64
    with pytest.raises(SourceMapSourceDenied):
        await status.SourceMapStatusAuthorityStore(actions).admit(request)
    assert len(ledger.committed) <= 1


@pytest.mark.asyncio
async def test_mounted_status_api_requires_distinct_bearer_and_denies_duplicates(key, monkeypatch):
    ledger, actions, original, _ = await _case(monkeypatch)
    _configure_service(monkeypatch)
    # Production actions require real DB memory/registry; this test patches
    # just that constructor and keeps the REAL FastAPI bearer, JSON and issuer.
    monkeypatch.setattr(api, "FlowMCPActionStore", lambda memory, registry: actions)
    monkeypatch.setitem(
        api.state,
        "orchestrator",
        SimpleNamespace(session_memory=object(), mcp_registry=object()),
    )
    app = FastAPI()
    app.include_router(api.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://status.local"
    ) as client:
        assert (
            await client.post("/native-sourcemap/status-preflight", json=original)
        ).status_code == 401
        invalid = await client.post(
            "/native-sourcemap/status-preflight",
            json=original,
            headers={"Authorization": "Bearer " + SOURCE},
        )
        assert invalid.status_code == 403
        success = await client.post(
            "/native-sourcemap/status-preflight",
            json=original,
            headers={"Authorization": "Bearer " + SERVICE},
        )
        assert success.status_code == 200
        assert success.headers["cache-control"] == "no-store"
        assert success.json()["claims"]["request_id"] == original["request_id"]
        assert len(ledger.committed) == 1
        duplicated = (
            b'{"request_id":"'
            + original["request_id"].encode("ascii")
            + b'","request_id":"'
            + original["request_id"].encode("ascii")
            + b'"}'
        )
        denied = await client.post(
            "/native-sourcemap/status-preflight",
            content=duplicated,
            headers={"Authorization": "Bearer " + SERVICE, "Content-Type": "application/json"},
        )
        assert denied.status_code == 422
