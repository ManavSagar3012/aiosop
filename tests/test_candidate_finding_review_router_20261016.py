"""Candidate finding review router must deny invalid authority before I/O."""

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError

from ai_osop.api.main import app
from ai_osop.api.routers import verified_finding_reviews as candidate


def _body(**updates):
    fields = {
        "finding_id": "vuln-local-1",
        "report_id": "report-eng-local-v1",
        "original_source_task_id": "task-original",
        "source_task_id": "task-source",
        "target_task_id": "task-target",
        "proof_sha256": "a" * 64,
        "audit_sha256": "b" * 64,
        "report_source_evidence_sha256": "c" * 64,
        "expected_authorization_version": 1,
        "expected_flow_revision": 1,
        "expected_review_revision": 0,
    }
    fields.update(updates)
    return candidate.CandidateReviewSubmission(**fields)


def test_candidate_review_is_registered_but_never_a_release_route():
    routes = {(route.path, tuple(sorted(getattr(route, "methods", ()) or ()))) for route in app.routes}
    assert (
        "/engagements/{engagement_id}/flows/{flow_id}/target-authority/finding-candidate-reviews",
        ("POST",),
    ) in routes


def test_candidate_review_rejects_forged_status_and_surplus_fields():
    with pytest.raises(ValidationError):
        _body(decision_status="verified")
    with pytest.raises(ValidationError):
        _body(report_release_approved=True)
    with pytest.raises(ValidationError):
        _body(expected_review_revision=-1)


@pytest.mark.asyncio
async def test_invalid_source_tuple_cannot_query_operator_or_provider(monkeypatch):
    access = AsyncMock()
    monkeypatch.setattr(candidate, "assert_engagement_access", access)
    with pytest.raises(HTTPException) as exc:
        await candidate.review_signed_finding_candidate(
            "eng-local", "flow-local", _body(target_task_id="task-source"),
            Response(), {"sub": "senior", "role": "senior_operator"},
        )
    assert exc.value.status_code == 422
    access.assert_not_awaited()


@pytest.mark.asyncio
async def test_wrong_signed_report_identity_denied_before_storage(monkeypatch):
    access = AsyncMock()
    monkeypatch.setattr(candidate, "assert_engagement_access", access)
    with pytest.raises(HTTPException) as exc:
        await candidate.review_signed_finding_candidate(
            "eng-local", "flow-local", _body(report_id="../../reports/other"),
            Response(), {"sub": "senior", "role": "senior_operator"},
        )
    assert exc.value.status_code == 422
    access.assert_not_awaited()
