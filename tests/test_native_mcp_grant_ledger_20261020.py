"""Mounted signed current Flow native grant readback; never exposes capabilities."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import HTTPException, Response

from ai_osop.api.routers import native_mcp_grants as api


def _row():
    return {
        "grant_id": "ngr-" + "1" * 32,
        "action_id": "action-" + "2" * 32,
        "request_id": "req-" + "3" * 48,
        "server_id": "recon-mcp",
        "tool_name": "authority_status",
        "status": "redeemed",
        "issued_at": 1000000,
        "expires_at": 1000030,
        "reviewed_resource_bound": False,
        "resource_bytes_checked_at_redemption": False,
        "original_resource_bytes_offered_once": False,
        "approved_folder_staging_bound": False,
        "worker_stage_receipt_reported": False,
        "supervisor_lifecycle_observed": False,
        "supervisor_state": None,
        "supervisor_revision": None,
        "supervisor_cleanup_observed": False,
        "supervisor_recovery_required": False,
        "supervisor_recovery_intent_pending": False,
    }


class Result:
    def __init__(self, rows):
        self.rows = rows

    def mappings(self):
        return self

    def all(self):
        return self.rows


class Context:
    def __init__(self, thing):
        self.thing = thing

    async def __aenter__(self):
        return self.thing

    async def __aexit__(self, *_):
        return False


class DB:
    def __init__(self, rows):
        self.rows = rows
        self.execute = AsyncMock(side_effect=self._execute)

    def begin(self):
        return Context(self)

    async def _execute(self, sql, params):
        assert "native_mcp_execution_grants" in str(sql)
        assert "owner_id=:owner" in str(sql)
        assert params["eng"] == "eng-native-ledger"
        assert params["flow"] == "flow-native-ledger"
        assert params["owner"] == "owner"
        assert params["auth"] == "signed-roe-id"
        assert params["sha"] == "4" * 64
        return Result(self.rows)


def _fixture(monkeypatch, rows=None, revoked=False):
    db = DB([_row()] if rows is None else rows)

    async def signed_authority(binding, operator):
        binding["authorization_id"] = "signed-roe-id"
        binding["authorization_sha256"] = "4" * 64
        if revoked and authority.await_count > 1:
            raise PermissionError("private-revocation-details")

    authority = AsyncMock(side_effect=signed_authority)
    store = SimpleNamespace(_sessions=lambda: lambda: Context(db))
    service = SimpleNamespace(_authority=authority, store=store)
    monkeypatch.setattr(api, "_executor", lambda: service)
    return db, authority


async def _read():
    response = Response()
    result = await api.read_native_mcp_grant_ledger(
        "flow-native-ledger",
        response,
        expected_engagement_id="eng-native-ledger",
        expected_revision=3,
        expected_authorization_version=5,
        operator={"role": "operator", "sub": "owner", "claims": {"exp": 2000000000}},
    )
    return result, response


@pytest.mark.asyncio
async def test_signed_owner_live_authority_and_historical_provider_only_status(monkeypatch):
    db, authority = _fixture(monkeypatch)
    result, response = await _read()
    assert response.headers["Cache-Control"] == "private, no-store"
    assert result["source"] == "durable_native_grants"
    assert result["server_side_signed_authorization_verified"] is False
    assert result["independent_target_effect_verified"] is False
    assert result["grants"] == [_row()]
    assert authority.await_count == 2
    assert db.execute.await_count == 1
    assert "token" not in str(result).lower()


@pytest.mark.asyncio
async def test_historical_approved_resource_bytes_only_reveal_verified_flags(monkeypatch):
    row = _row()
    # Native grant resources are tied to original Task and immutable BYTEA;
    # operator readback must never return the actual private SHA or bytes.
    row["resource_sha256"] = "a" * 64
    _fixture(monkeypatch, rows=[row])
    result, _response = await _read()
    item = result["grants"][0]
    assert item["reviewed_resource_bound"] is True
    assert item["resource_bytes_checked_at_redemption"] is True
    assert item["original_resource_bytes_offered_once"] is False
    assert "resource_sha256" not in item
    assert "content" not in item

    row["status"] = "issued"
    _fixture(monkeypatch, rows=[row])
    pending, _response = await _read()
    assert pending["grants"][0]["reviewed_resource_bound"] is True
    assert pending["grants"][0]["resource_bytes_checked_at_redemption"] is False

    row["resource_sha256"] = "not-a-trusted-sha"
    _fixture(monkeypatch, rows=[row])
    with pytest.raises(HTTPException):
        await _read()


@pytest.mark.asyncio
async def test_resource_offer_is_immutable_source_history_not_worker_receipt(monkeypatch):
    row = _row()
    row["resource_sha256"] = "a" * 64
    row["resource_offer_status"] = "offered"
    _fixture(monkeypatch, rows=[row])
    result, _response = await _read()
    grant = result["grants"][0]
    assert grant["original_resource_bytes_offered_once"] is True
    assert grant["resource_bytes_checked_at_redemption"] is True
    assert "resource_sha256" not in grant
    assert "resource_offer_status" not in grant
    assert "worker_receipt_confirmed" not in grant

    forged = dict(row, status="issued")
    _fixture(monkeypatch, rows=[forged])
    with pytest.raises(HTTPException):
        await _read()


@pytest.mark.asyncio
async def test_task_pinned_folder_and_worker_signed_receipt_are_safe_status_only(monkeypatch):
    row = _row()
    row["resource_sha256"] = "a" * 64
    row["resource_offer_status"] = "offered"
    row["folder_staging_sha256"] = "b" * 64
    row["stage_receipt_status"] = "worker_reported"
    _fixture(monkeypatch, rows=[row])
    result, _ = await _read()
    grant = result["grants"][0]
    assert grant["approved_folder_staging_bound"] is True
    assert grant["worker_stage_receipt_reported"] is True
    assert result["independent_target_effect_verified"] is False
    for private in (
        "folder_staging_sha256",
        "stage_receipt_status",
        "worker_key_id",
        "signature",
        "staging_path",
        "artifact_bytes",
    ):
        assert private not in grant
    forged = dict(row, folder_staging_sha256=None)
    _fixture(monkeypatch, rows=[forged])
    with pytest.raises(HTTPException):
        await _read()


@pytest.mark.asyncio
async def test_supervisor_container_cleanup_is_separate_from_worker_testimony(monkeypatch):
    row = _row()
    row["supervisor_state"] = "reaped"
    row["supervisor_revision"] = 4
    _fixture(monkeypatch, rows=[row])
    result, _ = await _read()
    item = result["grants"][0]
    assert item["supervisor_lifecycle_observed"] is True
    assert item["supervisor_cleanup_observed"] is True
    assert item["worker_stage_receipt_reported"] is False
    assert result["independent_target_effect_verified"] is False
    for secret in ("container_id", "worker_id", "supervisor_key_id", "observed_sha256"):
        assert secret not in item
    _fixture(monkeypatch, rows=[dict(row, supervisor_state="unknown")])
    result, _ = await _read()
    assert result["grants"][0]["supervisor_recovery_required"] is True
    _fixture(
        monkeypatch,
        rows=[dict(row, supervisor_state="unknown", supervisor_recovery_intent_pending=True)],
    )
    marked, _ = await _read()
    assert marked["grants"][0]["supervisor_recovery_intent_pending"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "stale",
        "secret_row",
        "foreign_server",
        "forge_success",
        "overlong",
        "duplicate",
        "unknown_status",
    ],
)
async def test_metadata_fails_closed_under_foreign_or_malformed_rows(monkeypatch, failure):
    row = _row()
    rows = [row]
    if failure == "stale":
        _fixture(monkeypatch, rows, revoked=True)
    else:
        if failure == "secret_row":
            row["grant_id"] = "grant-private-secret"
        elif failure == "foreign_server":
            row["server_id"] = "foreign-secret-provider"
        elif failure == "forge_success":
            row["status"] = "target_effect_verified"
        elif failure == "overlong":
            rows = rows * 101
        elif failure == "duplicate":
            rows = [row, dict(row)]
        elif failure == "unknown_status":
            row["status"] = "success"
        _fixture(monkeypatch, rows)
    with pytest.raises(HTTPException) as raised:
        await _read()
    assert raised.value.status_code == 503
    assert "secret" not in str(raised.value.detail)


@pytest.mark.asyncio
async def test_anonymous_actual_mounted_get_denied_before_pg(monkeypatch):
    from ai_osop.api.main import app

    routes = [r for r in app.routes if r.path == "/flows/{flow_id}/native-mcp-grants"]
    assert len(routes) == 1 and routes[0].methods == {"GET"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/flows/flow-native-ledger/native-mcp-grants",
            params={
                "expected_engagement_id": "eng-native-ledger",
                "expected_revision": 3,
                "expected_authorization_version": 5,
            },
        )
    assert response.status_code == 401
