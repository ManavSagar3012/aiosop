"""Latest signed-ROE status is bounded, PostgreSQL-backed and owner-scoped."""

import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.authorization_store import AuthorizationDenied
from ai_osop.safety.signed_roe import canonical_json_bytes
from tests.test_engagement_report_api import report_harness


def _record(harness, *, status="revoked", version=4, expiry_days=1):
    policy = {
        "engagement_id": harness.session_id,
        "key_id": "trusted-public-kid-1",
        "version": version,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=expiry_days))
        .isoformat()
        .replace("+00:00", "Z"),
        "secret": "DO-NOT-LEAK-RAW-POLICY",
    }
    return {
        "version": version,
        "status": status,
        "kid": "trusted-public-kid-1",
        "policy_sha256": hashlib.sha256(canonical_json_bytes(policy)).hexdigest(),
        "canonical_policy": policy,
    }


class _Result:
    def __init__(self, row):
        self.row = row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row


class _Postgres:
    def __init__(self, harness, row, *, owner="alice", error=None):
        self.harness = harness
        self.row = row
        self.owner = owner
        self.error = error
        self.queries = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def begin(self):
        return self

    async def execute(self, statement, params):
        if self.error:
            raise self.error
        query = str(statement)
        self.queries.append((query, params))
        assert params == {"sid": self.harness.session_id}
        if "FROM session_states" in query:
            return _Result(
                {
                    "session_id": self.harness.session_id,
                    "created_by": self.owner,
                }
            )
        if "FROM signed_authorizations" in query:
            return _Result(self.row)
        raise AssertionError("Unexpected SQL request")


@pytest.fixture
def status_db(report_harness, monkeypatch):
    db = _Postgres(report_harness, _record(report_harness))
    monkeypatch.setattr(
        report_harness.memory,
        "_async_session",
        lambda: db,
        raising=False,
    )
    return db


def _get(harness, *, owner="alice", role="operator", sid=None):
    return harness.client.get(
        f"/engagements/{sid or harness.session_id}/authorization/status",
        headers=harness.auth(sub=owner, role=role),
    )


def test_revoked_latest_row_remains_visible_with_only_safe_metadata(report_harness, status_db):
    response = _get(report_harness)
    assert response.status_code == 200
    assert response.json() == {
        "status": "revoked",
        "version": 4,
        "key_id": "trusted-public-kid-1",
        "expires_at": status_db.row["canonical_policy"]["expires_at"],
        "policy_sha256": status_db.row["policy_sha256"],
        "remote_execution_outcome": "unknown",
    }
    assert len(status_db.queries) == 2
    assert "ORDER BY version DESC LIMIT 1" in status_db.queries[1][0]
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    for sensitive in (
        "DO-NOT-LEAK",
        "created_by",
        "signature",
        "authorization_id",
        "revocation_reason",
    ):
        assert sensitive not in response.text


def test_missing_signed_ledger_is_unverified_not_active(report_harness, status_db):
    status_db.row = None
    response = _get(report_harness)
    assert response.status_code == 200
    assert response.json() == {
        "status": "unverified",
        "version": None,
        "key_id": None,
        "expires_at": None,
        "policy_sha256": None,
        "remote_execution_outcome": "unknown",
    }


def test_expired_latest_row_is_not_active(report_harness, status_db):
    status_db.row = _record(report_harness, status="revoked", expiry_days=-1)
    # Revocation is never downgraded to an expiration message.
    assert _get(report_harness).json()["status"] == "revoked"


def test_active_record_requires_reverified_dispatch_signature(
    report_harness,
    status_db,
    monkeypatch,
):
    from ai_osop.memory import authorization_store

    status_db.row = _record(report_harness, status="active")
    guard = AsyncMock(return_value=SimpleNamespace(version=4))
    monkeypatch.setattr(authorization_store, "guard_sql", guard)
    response = _get(report_harness)
    assert response.status_code == 200
    assert response.json()["status"] == "active"
    guard.assert_awaited_once()
    assert guard.await_args.args[0] is status_db
    assert guard.await_args.args[1] == report_harness.session_id


def test_rotated_key_or_revoked_scope_never_claims_active(
    report_harness,
    status_db,
    monkeypatch,
):
    from ai_osop.memory import authorization_store

    status_db.row = _record(report_harness, status="active")
    monkeypatch.setattr(
        authorization_store,
        "guard_sql",
        AsyncMock(side_effect=AuthorizationDenied("retired signing key secret")),
    )
    response = _get(report_harness)
    assert response.status_code == 200
    assert response.json()["status"] == "unverified"
    assert "retired signing key" not in response.text


def test_expired_active_row_still_cannot_claim_current_authority(
    report_harness,
    status_db,
    monkeypatch,
):
    from ai_osop.memory import authorization_store

    status_db.row = _record(report_harness, status="active", expiry_days=-1)
    monkeypatch.setattr(
        authorization_store,
        "guard_sql",
        AsyncMock(side_effect=AuthorizationDenied("expired policy")),
    )
    response = _get(report_harness)
    assert response.status_code == 200
    assert response.json()["status"] == "expired"


@pytest.mark.parametrize(
    "owner,role,expected",
    [
        ("alice", "operator", 200),
        ("mallory", "operator", 403),
        ("mallory", "senior_operator", 200),
        ("alice", "viewer", 403),
    ],
)
def test_status_owner_scoped_role_enforced(report_harness, status_db, owner, role, expected):
    response = _get(report_harness, owner=owner, role=role)
    assert response.status_code == expected
    if role == "viewer":
        assert not status_db.queries
    elif expected == 403:
        assert len(status_db.queries) == 1


def test_durable_owner_change_overrides_stale_hot_cache(report_harness, status_db):
    status_db.owner = "bob"
    response = _get(report_harness)
    assert response.status_code == 403
    assert len(status_db.queries) == 1


def test_missing_auth_or_query_bearer_never_reads_pg(report_harness, status_db):
    url = f"/engagements/{report_harness.session_id}/authorization/status"
    assert report_harness.client.get(url).status_code == 403
    assert (
        report_harness.client.get(
            url + "?token=leaked",
            headers=report_harness.auth(),
        ).status_code
        == 403
    )
    assert status_db.queries == []


def test_pg_outage_returns_503_without_exception_secret(report_harness, status_db):
    status_db.error = ConnectionError("db-postgres-secret")
    response = _get(report_harness)
    assert response.status_code == 503
    assert "db-postgres-secret" not in response.text


def test_corrupt_authorization_record_fails_closed(report_harness, status_db):
    status_db.row = _record(report_harness, status="revoked")
    status_db.row["policy_sha256"] = "not-a-real-hash"
    response = _get(report_harness)
    assert response.status_code == 503
    assert "policy_sha256" not in response.text


def test_tampered_authorization_policy_is_not_represented_as_revoked_verification(
    report_harness,
    status_db,
):
    status_db.row["canonical_policy"]["expires_at"] = "2099-01-01T00:00:00Z"
    # Do not return metadata with a digest that no longer matches the stored
    # canonical bytes, including after its key was retired and state revoked.
    response = _get(report_harness)
    assert response.status_code == 503
    assert "2099" not in response.text


def test_authorization_dispatch_guard_database_error_is_503(
    report_harness,
    status_db,
    monkeypatch,
):
    from ai_osop.memory import authorization_store

    status_db.row = _record(report_harness, status="active")
    monkeypatch.setattr(
        authorization_store,
        "guard_sql",
        AsyncMock(side_effect=ConnectionError("signing-db-secret")),
    )
    response = _get(report_harness)
    assert response.status_code == 503
    assert "signing-db-secret" not in response.text


def test_bad_engagement_id_rejected_before_sql(report_harness, status_db):
    response = _get(report_harness, sid="invalid%2Fetc")
    assert response.status_code in {404, 422}
    assert status_db.queries == []
