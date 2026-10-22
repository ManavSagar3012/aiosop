"""Authenticated route contract only; witness/PG tests are separate.

No fixture-supplied result in this file proves a real target vulnerability.
The actual production ledger cryptographically verifies independent source
and target-side owner/access witness signatures before durable promotion.
"""

from unittest.mock import AsyncMock

import pytest

from ai_osop.api.routers import verified_finding_reviews as reviews
from ai_osop.core.independent_target_effect_observer import IndependentEffectUnavailable
from tests.test_verified_finding_review_api_20261016 import candidate_api  # noqa: F401
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


def _body(env):
    return {
        **env.body,
        "review_decision_id": "vfdec-" + "1" * 32,
        "review_decision_sha256": "f" * 64,
        "qualification_id": "teqa-" + "2" * 32,
        "qualification_sha256": "c" * 64,
        "expected_qualification_revision": 1,
    }


def _endpoint(env):
    return env.root.replace("finding-candidate-reviews", "finding-effect-verifications")


@pytest.mark.parametrize(
    "extra",
    [
        {"finding_verified": True},
        {"report_release_approved": True},
        {"observer_claims_json": "{}"},
        {"observer_signature_b64url": "signed_by_client"},
        {"expected_nonce": "a" * 32},
        {"qualification_id": "invalid"},
        {"qualification_sha256": "invalid"},
        {"expected_qualification_revision": 0},
        {"target_task_id": "task-duplicated-source", "source_task_id": "task-duplicated-source"},
    ],
)
def test_client_cannot_supply_verdict_nonce_proof_or_unpinned_revision(
    candidate_api,
    monkeypatch,
    extra,
):
    issue = AsyncMock()
    monkeypatch.setattr(reviews, "issue_independent_target_effect_challenge", issue)
    payload = {**_body(candidate_api), **extra}
    reply = candidate_api.client.post(_endpoint(candidate_api), json=payload)
    assert reply.status_code == 422, reply.text
    issue.assert_not_awaited()


@pytest.mark.parametrize("break_boundary", ["owner", "senior", "session", "report"])
def test_live_verification_preserves_current_signed_review_denials(
    candidate_api,
    monkeypatch,
    break_boundary,
):
    issue, fetch, admit = AsyncMock(), AsyncMock(), AsyncMock()
    monkeypatch.setattr(reviews, "issue_independent_target_effect_challenge", issue)
    monkeypatch.setattr(reviews, "fetch_independent_target_effect_signed_receipt", fetch)
    monkeypatch.setattr(reviews, "admit_independent_target_effect_verification", admit)
    if break_boundary == "owner":
        candidate_api.db.owner = "other-operator"
    elif break_boundary == "senior":
        candidate_api.senior_check.side_effect = PermissionError("senior revoked")
    elif break_boundary == "session":
        candidate_api.fingerprints.side_effect = RuntimeError("session rotated")
    else:
        candidate_api.source_check.return_value = False
    reply = candidate_api.client.post(_endpoint(candidate_api), json=_body(candidate_api))
    assert reply.status_code in (403, 409, 503), reply.text
    issue.assert_not_awaited()
    fetch.assert_not_awaited()
    admit.assert_not_awaited()


def test_missing_live_observer_stays_unverified_and_never_commits_receipt(
    candidate_api,
    proof_case,
    monkeypatch,
):
    candidate_api.db.flow = proof_case.flow
    issue = AsyncMock(
        return_value={
            "challenge_id": "itefc-" + "1" * 32,
            "expected_nonce": "f" * 32,
            "expires_at": 2080000000,
        }
    )
    fetch = AsyncMock(side_effect=IndependentEffectUnavailable("No external operator witness"))
    admit = AsyncMock()
    monkeypatch.setattr(reviews, "issue_independent_target_effect_challenge", issue)
    monkeypatch.setattr(reviews, "fetch_independent_target_effect_signed_receipt", fetch)
    monkeypatch.setattr(reviews, "admit_independent_target_effect_verification", admit)
    reply = candidate_api.client.post(_endpoint(candidate_api), json=_body(candidate_api))
    assert reply.status_code in (409, 503), reply.text
    assert "verified" not in reply.text.lower()
    admit.assert_not_awaited()
    if issue.await_count:
        assert issue.await_count == 1
        assert fetch.await_count <= 1
    assert candidate_api.db.begins == candidate_api.db.ended


def test_client_cannot_get_verification_without_existing_qualification(
    candidate_api,
    monkeypatch,
):
    issue = AsyncMock()
    monkeypatch.setattr(reviews, "issue_independent_target_effect_challenge", issue)
    payload = _body(candidate_api)
    payload.pop("qualification_id")
    reply = candidate_api.client.post(_endpoint(candidate_api), json=payload)
    assert reply.status_code == 422
    issue.assert_not_awaited()
