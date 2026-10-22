"""Authenticated revocation does not claim remote execution has stopped."""

from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.authorization_store import AuthorizationStore
from tests.test_engagement_report_api import report_harness


def _post(harness, *, role="senior_operator", owner="alice", version=1):
    return harness.client.post(
        f"/engagements/{harness.session_id}/authorization/revoke",
        headers=harness.auth(sub=owner, role=role),
        json={"expected_version": version, "reason": "Signed scope authorization revoked"},
    )


def test_only_authenticated_senior_operator_can_revoke(report_harness, monkeypatch):
    store_revoke = AsyncMock(return_value=True)
    monkeypatch.setattr(AuthorizationStore, "revoke", store_revoke)
    h = report_harness
    assert _post(h, role="operator").status_code == 403
    assert h.client.post(
        f"/engagements/{h.session_id}/authorization/revoke",
        json={"expected_version": 1, "reason": "A legitimate long reason"},
    ).status_code in (401, 403)
    store_revoke.assert_not_awaited()


def test_revoked_policy_remains_revoked_even_when_halt_dispatch_fails(
    report_harness, monkeypatch,
):
    h = report_harness
    store_revoke = AsyncMock(return_value=True)
    monkeypatch.setattr(AuthorizationStore, "revoke", store_revoke)
    h.orch.halt_engagement = AsyncMock(side_effect=RuntimeError("not confirmed"))

    response = _post(h)
    assert response.status_code == 200
    assert response.json() == {
        "status": "revoked",
        "authorization_version": 1,
        "halt_request_accepted": False,
        "remote_execution_outcome": "unknown",
    }
    store_revoke.assert_awaited_once()


def test_stale_revocation_cas_does_not_request_halt(report_harness, monkeypatch):
    h = report_harness
    store_revoke = AsyncMock(return_value=False)
    monkeypatch.setattr(AuthorizationStore, "revoke", store_revoke)
    h.orch.halt_engagement = AsyncMock()
    response = _post(h, version=999)
    assert response.status_code == 409
    h.orch.halt_engagement.assert_not_awaited()


def test_confirmed_halt_request_is_not_reported_as_remote_termination(
    report_harness, monkeypatch,
):
    h = report_harness
    monkeypatch.setattr(AuthorizationStore, "revoke", AsyncMock(return_value=True))
    h.orch.halt_engagement = AsyncMock(return_value=None)
    response = _post(h)
    assert response.status_code == 200
    assert response.json()["halt_request_accepted"] is True
    assert response.json()["remote_execution_outcome"] == "unknown"
