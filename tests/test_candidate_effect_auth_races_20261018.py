"""Route auth/flow/provenance race regression; no app database or remote target."""

from __future__ import annotations

import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.api.routers import verified_finding_reviews as route
from ai_osop.memory.verified_finding_decisions import FindingDecisionDenied
from ai_osop.memory.target_verified_promotions import TargetEffectQualificationDenied
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401
from tests.test_verified_finding_review_api_20261016 import (
    ENG,
    FINDING,
    FLOW,
    REPORT,
    SHA,
    candidate_api,
    report_source_case,  # noqa: F401
)

REVIEW = "/target-authority/finding-candidate-reviews"
EFFECT = "/target-authority/finding-effect-qualifications"


@pytest.fixture
def case(candidate_api):
    # The real guard_sql provides an independently verified full policy.
    # Older mock tests omit it, so enrich this isolated fixture only.
    candidate_api.signed_check.return_value.policy = {
        "created_by": candidate_api.reviewer["sub"],
    }
    return candidate_api


def _request(env, *, mode="post", changes=None):
    body = {**env.body, **(changes or {})}
    if mode == "post":
        return env.client.post(env.root, json=body)
    if mode == "get":
        return env.client.get(
            env.root + "/" + FINDING,
            params={
                "report_id": REPORT,
                "expected_authorization_version": 5,
            },
        )
    qualified = env.root.replace(REVIEW, EFFECT)
    if mode == "effect-post":
        return env.client.post(
            qualified,
            json={
                **body,
                "review_decision_id": "vfdec-" + "1" * 32,
                "review_decision_sha256": "c" * 64,
                "expected_qualification_revision": 0,
            },
        )
    if mode == "effect-get":
        return env.client.get(
            qualified + "/" + FINDING,
            params={
                "report_id": REPORT,
                "expected_authorization_version": 5,
            },
        )
    raise AssertionError(mode)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda source, target: setattr(source, "flow_id", "flow-foreign"),
        lambda source, target: setattr(target, "flow_id", "flow-foreign"),
        lambda source, target: setattr(source, "engagement_id", "eng-foreign"),
        lambda source, target: setattr(source, "status", "cancelled"),
        lambda source, target: setattr(target, "type", "research"),
        lambda source, target: setattr(source, "approval_required", False),
        lambda source, target: setattr(target, "max_retries", 1),
        lambda source, target: source.payload.update({"_flow_revision": 998}),
        lambda source, target: target.payload.update({"_authorization_version": 99}),
        lambda source, target: setattr(target, "parent_task_id", "task-other-parent"),
        lambda source, target: source.payload.update({"_comparison_role": "target"}),
        lambda source, target: target.payload.update({"user_label": "account_a"}),
    ],
    ids=[
        "source-cross-flow",
        "target-cross-flow",
        "source-cross-tenant",
        "source-not-completed",
        "target-wrong-type",
        "source-no-approval",
        "target-retries",
        "flow-revision-rotated",
        "roe-revision-rotated",
        "different-replay-parent",
        "source-role-swapped",
        "cross-identity-collapsed",
    ],
)
def test_route_rejects_foreign_or_changed_dual_tasks_before_store(case, mutate):
    source, target = case.db.tasks
    mutate(source, target)
    response = _request(case)
    assert response.status_code == 409, response.text
    assert "dual-identity" in response.json()["detail"]
    assert not case.calls
    assert case.dispatch_check.await_count == 0


@pytest.mark.parametrize("mode", ["post", "get", "effect-post", "effect-get"])
def test_all_four_paths_require_exact_flow_bound_dual_receipts(case, monkeypatch, mode):
    case.db.tasks[0].flow_id = "flow-foreign"
    effect_write = AsyncMock(return_value={"status": "UNKNOWN"})
    effect_read = AsyncMock(return_value={"status": "UNKNOWN"})
    monkeypatch.setattr(route, "record_unknown_effect_qualification", effect_write)
    monkeypatch.setattr(route, "read_target_effect_qualification", effect_read)
    response = _request(case, mode=mode)
    if mode.endswith("get"):
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "UNKNOWN"
        assert response.json()["finding_verified"] is False
    else:
        assert response.status_code == 409, response.text
    assert case.dispatch_check.await_count == 0
    assert not case.calls
    effect_write.assert_not_awaited()
    effect_read.assert_not_awaited()
    sql = [stmt for stmt, _ in case.db.queries if "FROM tasks" in stmt]
    assert sql and all("tasks.flow_id" in stmt for stmt in sql)
    assert case.db.begins == case.db.ended


def test_qualification_post_passes_same_transaction_cas_and_unknown_only(case, monkeypatch):
    called = []

    async def persist(db, **kwargs):
        called.append((db, kwargs))
        assert db is case.db
        assert await kwargs["trusted_current_verifier"]() is True
        assert await kwargs["trusted_report_source_check"](FINDING, SHA) is True
        return {
            "status": "UNKNOWN",
            "revision": 1,
            "qualification_id": "teqa-" + "b" * 32,
            "finding_verified": False,
            "independent_target_effect_verified": False,
            "report_release_approved": False,
        }

    monkeypatch.setattr(route, "record_unknown_effect_qualification", persist)
    response = _request(case, mode="effect-post")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "UNKNOWN"
    assert response.json()["finding_verified"] is False
    assert response.json()["independent_target_effect_verified"] is False
    assert response.json()["report_release_approved"] is False
    assert response.headers["cache-control"] == "private, no-store"
    assert len(called) == 1
    kwargs = called[0][1]
    assert kwargs["flow_id"] == FLOW
    assert kwargs["finding_id"] == FINDING
    assert kwargs["review_decision_id"] == "vfdec-" + "1" * 32
    assert kwargs["review_decision_sha256"] == "c" * 64
    assert kwargs["expected_revision"] == 0
    assert kwargs["authorization_version"] == 5
    assert kwargs["reviewer_role"] == "senior_operator"
    assert case.db.begins == case.db.ended
    assert case.senior_check.await_count >= 2
    assert case.signed_check.await_count >= 3


def test_effect_get_unknown_flags_and_no_writes(case, monkeypatch):
    reader = AsyncMock(
        return_value={
            "status": "UNKNOWN",
            "revision": 1,
            "reason_code": "independent_target_effect_service_missing",
            "finding_verified": False,
            "independent_target_effect_verified": False,
            "report_release_approved": False,
        }
    )
    monkeypatch.setattr(route, "read_target_effect_qualification", reader)
    response = _request(case, mode="effect-get")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "UNKNOWN"
    assert response.json()["finding_verified"] is False
    assert response.json()["report_release_approved"] is False
    reader.assert_awaited_once()
    assert not case.calls
    assert not any(
        query.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
        for query, _ in case.db.queries
    )


def test_signed_roe_rotated_after_last_review_await_cannot_return_current_receipt(
    case,
    monkeypatch,
):
    signed = case.signed_check.return_value
    changed = SimpleNamespace(**{**signed.__dict__, "policy_sha256": "8" * 64})
    counter = {"n": 0}

    async def guarded(*args, **kwargs):
        counter["n"] += 1
        return changed if counter["n"] >= 4 else signed

    monkeypatch.setattr(route, "guard_sql", guarded)
    response = _request(case)
    assert response.status_code == 409, response.text
    assert "authorization" in response.json()["detail"]
    assert len(case.calls) == 1  # Store awaited; final guard still denies return.
    assert counter["n"] >= 4
    assert case.db.begins == case.db.ended


@pytest.mark.parametrize("mode", ["post", "get", "effect-post", "effect-get"])
def test_reviewer_revoked_during_source_check_denies_all_paths(
    case,
    monkeypatch,
    mode,
):
    called = AsyncMock(return_value={"status": "UNKNOWN"})
    monkeypatch.setattr(route, "record_unknown_effect_qualification", called)
    monkeypatch.setattr(route, "read_target_effect_qualification", called)

    async def late_source_check(*args, **kwargs):
        case.senior_check.side_effect = route.ArtifactReviewDenied(403, "Revoked senior token")
        return True

    case.source_check.side_effect = late_source_check
    response = _request(case, mode=mode)
    assert response.status_code == 403, (mode, response.text)
    # Qualification store can be reached before the final reviewer fence;
    # an exception there must roll back its enclosing PG transaction.
    assert called.await_count == (1 if mode.startswith("effect") else 0)
    assert case.db.begins == case.db.ended


@pytest.mark.parametrize(
    "exc,status",
    [
        (FindingDecisionDenied(409, "stale review CAS"), 409),
        (TargetEffectQualificationDenied(409, "stale effect CAS"), 409),
        (TargetEffectQualificationDenied(503, "effect storage unavailable"), 503),
        (route.ArtifactReviewDenied(403, "token revoked"), 403),
        (RuntimeError("unexpected"), 503),
    ],
)
def test_production_denials_preserve_http_mapping_without_leaking_storage(
    case,
    monkeypatch,
    exc,
    status,
):
    async def fail(*args, **kwargs):
        raise exc

    monkeypatch.setattr(route, "append_candidate_review", fail)
    response = _request(case)
    assert response.status_code == status, response.text
    assert case.db.begins == case.db.ended
    if isinstance(exc, RuntimeError):
        assert "unexpected" not in response.text


def test_missing_signed_bearer_still_denied_for_qualification(case):
    case.app.dependency_overrides.clear()
    response = _request(case, mode="effect-post")
    assert response.status_code == 401
    assert case.calls == []


@pytest.mark.asyncio
async def test_report_source_rejects_tampered_flow_rev_and_unsigned_event(
    report_source_case,
    monkeypatch,
):
    report = report_source_case
    kwargs = dict(
        engagement_id=ENG,
        flow_id=FLOW,
        flow_revision=3,
        report_id=REPORT,
        signed=report.signed,
        finding_id=FINDING,
        evidence_sha256=SHA,
    )
    assert (
        await route._independent_report_source_check(
            report.db, report.orch, report.memory, **kwargs
        )
        is True
    )
    report.db.flow.revision = 4
    assert (
        await route._independent_report_source_check(
            report.db, report.orch, report.memory, **kwargs
        )
        is False
    )
    report.db.flow.revision = 3
    report.memory.verify_signed_graph_action.return_value = False
    assert (
        await route._independent_report_source_check(
            report.db, report.orch, report.memory, **kwargs
        )
        is False
    )
    report.memory.verify_signed_graph_action.return_value = True
    report.source.result["evidence_sha256"] = "9" * 64
    assert (
        await route._independent_report_source_check(
            report.db, report.orch, report.memory, **kwargs
        )
        is False
    )
