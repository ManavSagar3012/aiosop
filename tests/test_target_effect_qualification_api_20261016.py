"""Joined authenticated route tests: durable UNKNOWN, no synthetic promotion.

These use isolated fixture Postgres doubles and an installed FastAPI router;
the actual migration schema is tested separately against disposable PG.
"""

from __future__ import annotations

import copy
from unittest.mock import AsyncMock

import pytest

from ai_osop.api.routers import verified_finding_reviews as route
from tests.test_verified_finding_review_api_20261016 import candidate_api  # noqa: F401
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


def _body(env):
    return {
        **env.body,
        "review_decision_id": "vfdec-" + "1" * 32,
        "review_decision_sha256": "f" * 64,
        "expected_qualification_revision": 0,
    }


def _root(env):
    return env.root.replace("finding-candidate-reviews", "finding-effect-qualifications")


@pytest.mark.parametrize("mode", ["write", "read"])
def test_qualified_unknown_uses_same_live_signed_checks(candidate_api, monkeypatch, mode):
    env = candidate_api
    actual = []

    async def check(db, **kwargs):
        assert db is env.db
        assert kwargs["engagement_id"] == "eng-tenant"
        assert kwargs["flow_id"] == "flow-owned"
        assert kwargs["finding_id"] == "vuln-123"
        assert kwargs["reviewer_sub"] == env.reviewer["sub"]
        assert kwargs["authorization_version"] == 5
        assert await kwargs["trusted_current_verifier"]() is True
        assert await kwargs["trusted_report_source_check"]("vuln-123", "a" * 64) is True
        if mode == "write":
            assert kwargs["review_decision_id"] == "vfdec-" + "1" * 32
            assert kwargs["review_decision_sha256"] == "f" * 64
            assert kwargs["expected_revision"] == 0
        actual.append(kwargs)
        return {
            "status": "UNKNOWN",
            "reason_code": "independent_target_effect_service_missing",
            "revision": 1,
            "finding_verified": False,
            "independent_target_effect_verified": False,
            "report_release_approved": False,
        }

    monkeypatch.setattr(
        route,
        (
            "record_unknown_effect_qualification"
            if mode == "write"
            else "read_target_effect_qualification"
        ),
        check,
    )
    if mode == "write":
        reply = env.client.post(_root(env), json=_body(env))
    else:
        reply = env.client.get(
            _root(env) + "/vuln-123",
            params={"report_id": env.body["report_id"], "expected_authorization_version": 5},
        )
    assert reply.status_code == 200, reply.text
    assert reply.json()["status"] == "UNKNOWN"
    assert reply.json()["finding_verified"] is False
    assert reply.json()["report_release_approved"] is False
    assert reply.headers["cache-control"] == "private, no-store"
    assert len(actual) == 1
    assert env.calls == []  # existing candidate append/read not called by route
    assert env.senior_check.await_count >= 2
    assert env.fingerprints.call_count >= 2
    assert env.db.begins == env.db.ended


@pytest.mark.parametrize(
    "attempt",
    [
        "verified",
        "release",
        "bad_decision",
        "bad_digest",
        "bad_revision",
        "changed_flow",
        "same_identity",
    ],
)
def test_unsafe_effect_qualification_rejected_before_store(candidate_api, monkeypatch, attempt):
    env = candidate_api
    store = AsyncMock()
    monkeypatch.setattr(route, "record_unknown_effect_qualification", store)
    body = copy.deepcopy(_body(env))
    if attempt == "verified":
        body["finding_verified"] = True
    elif attempt == "release":
        body["report_release_approved"] = True
    elif attempt == "bad_decision":
        body["review_decision_id"] = "fake"
    elif attempt == "bad_digest":
        body["review_decision_sha256"] = "not-a-digest"
    elif attempt == "bad_revision":
        body["expected_qualification_revision"] = -1
    elif attempt == "changed_flow":
        body["expected_flow_revision"] = -1
    elif attempt == "same_identity":
        body["target_task_id"] = body["source_task_id"]
    reply = env.client.post(_root(env), json=body)
    assert reply.status_code == 422
    store.assert_not_awaited()


@pytest.mark.parametrize(
    "break_boundary", ["revoked_senior", "no_report_source", "rotated_session", "wrong_owner"]
)
def test_effect_qualification_rechecks_senior_source_and_sessions(
    candidate_api, monkeypatch, break_boundary
):
    env = candidate_api
    store = AsyncMock()
    monkeypatch.setattr(route, "record_unknown_effect_qualification", store)
    if break_boundary == "revoked_senior":
        env.senior_check.side_effect = PermissionError("revoked")
    elif break_boundary == "no_report_source":
        env.source_check.return_value = False
    elif break_boundary == "rotated_session":
        env.fingerprints.side_effect = RuntimeError("rotated")
    elif break_boundary == "wrong_owner":
        env.db.owner = "other-owner"
    reply = env.client.post(_root(env), json=_body(env))
    assert reply.status_code in {403, 409, 503}
    store.assert_not_awaited()


def test_qualifier_denies_missing_review_without_inserting(candidate_api, monkeypatch):
    env = candidate_api
    store = AsyncMock()
    monkeypatch.setattr(route, "read_target_effect_qualification", store)
    env.db.archive = None
    reply = env.client.get(
        _root(env) + "/vuln-123",
        params={"report_id": env.body["report_id"], "expected_authorization_version": 5},
    )
    assert reply.status_code == 200
    assert reply.json()["status"] == "UNKNOWN"
    assert reply.json()["revision"] == 0
    assert reply.json()["finding_verified"] is False
    store.assert_not_awaited()
