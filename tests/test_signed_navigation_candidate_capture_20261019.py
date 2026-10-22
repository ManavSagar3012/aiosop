"""Signed browser-provider testimony is candidate evidence, never owner proof."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.routers import candidate_evidence_artifacts as api

ENGAGEMENT = "eng-navigation-candidate"
FLOW = "flow-navigation-candidate"
SOURCE = "task-navigation-candidate"
URL = "https://example.com/private?token=secret-never-expose"


def signed_fixture(monkeypatch):
    from ai_osop.core import diff_auth_engine
    from ai_osop.memory import graph_research_projection
    from ai_osop.safety import scope

    source = SimpleNamespace(
        id=SOURCE,
        type="navigate",
        status="completed",
        engagement_id=ENGAGEMENT,
        flow_id=FLOW,
        approval_required=True,
        payload={
            "_authorization_version": 3,
            "_flow_revision": 7,
            "operator_approved": True,
            "approval_id": "apr-senior-confirmed",
            "url": URL,
        },
        result={
            "status": "success",
            "verification_status": "provider_testimony_only",
            "remote_effect_verified": False,
            "authorization_violation_verified": False,
            "findings_count": 0,
            "redirected": False,
            "http_status_code": 200,
            "response_body_sha256": "b" * 64,
            "provider_evidence": {
                "provider_event_id": "evt-signed-origin",
                "provider_receipt_sha256": "c" * 64,
                "source_authenticity_verified": False,
                "target_effect_verified": False,
                "finding_verified": False,
            },
            "private_response_body": "private-owner-data-not-for-operator",
        },
    )
    memory = SimpleNamespace(
        assert_signed_authorization=AsyncMock(return_value=SimpleNamespace(version=3)),
        load_flow=AsyncMock(
            return_value=SimpleNamespace(
                id=FLOW, engagement_id=ENGAGEMENT, status="running", revision=7
            )
        ),
        load_session_state=AsyncMock(
            return_value=SimpleNamespace(phase="reconnaissance", scope=object())
        ),
        load_task_authoritative=AsyncMock(return_value=source),
        is_task_approved=AsyncMock(return_value=True),
    )
    create = AsyncMock(
        return_value=SimpleNamespace(id="ev-signed-candidate", merkle_leaf_hash="e" * 64)
    )
    verify = AsyncMock(return_value=True)
    monkeypatch.setattr(api, "SessionMemory", SimpleNamespace)
    monkeypatch.setattr(api, "assert_engagement_access", AsyncMock())
    monkeypatch.setitem(
        api.state,
        "orchestrator",
        SimpleNamespace(session_memory=memory, supervision_store=object()),
    )
    monkeypatch.setattr(
        scope, "ScopeEnforcer", lambda _: SimpleNamespace(validate_time_window=lambda: None)
    )
    monkeypatch.setattr(scope, "validate_payload_targets", lambda *a, **k: None)
    monkeypatch.setattr(graph_research_projection, "verify_signed_action_event", verify)
    monkeypatch.setattr(
        diff_auth_engine,
        "DifferentialAuthEngine",
        lambda _: SimpleNamespace(create_and_persist_evidence_artifact=create),
    )
    return source, memory, verify, create


async def invoke():
    return await api.capture_signed_navigation_candidate_evidence(
        ENGAGEMENT,
        "finding-review-1",
        api.SignedNavigationEvidenceRequest(
            flow_id=FLOW,
            source_task_id=SOURCE,
            expected_flow_revision=7,
            expected_authorization_version=3,
        ),
        Response(),
        operator={"sub": "real-reviewer", "role": "senior_operator"},
    )


@pytest.mark.asyncio
async def test_signed_navigation_candidate_admission_is_redacted_and_unverified(monkeypatch):
    _, memory, verify, create = signed_fixture(monkeypatch)
    result = await invoke()
    assert result == {
        "status": "candidate_evidence_recorded_unverified",
        "artifact_id": "ev-signed-candidate",
        "merkle_leaf_sha256": "e" * 64,
        "finding_verified": False,
        "independent_target_effect_verified": False,
        "safe_to_automatically_retry": False,
    }
    verify.assert_awaited_once()
    assert memory.assert_signed_authorization.await_count == 2
    create.assert_awaited_once()
    params = create.await_args.kwargs
    assert params["source_task_id"] == SOURCE
    assert params["artifact_id"].startswith("ev-")
    assert len(params["artifact_id"]) == 35
    assert params["response_status"] == 200
    assert params["response_body"]["schema"] == "ai-osop.signed-provider-summary.v1"
    assert params["response_body"]["browser_summary_body_sha256"] == "b" * 64
    assert "private_response_body" not in params["response_body"]
    assert "secret-never-expose" not in str(params["response_body"])
    assert "private-owner-data" not in str(params["response_body"])


@pytest.mark.asyncio
async def test_same_signed_candidate_cannot_mint_new_primary_key_on_repeat(monkeypatch):
    _, _, _, create = signed_fixture(monkeypatch)
    await invoke()
    first = create.await_args.kwargs["artifact_id"]
    await invoke()
    second = create.await_args.kwargs["artifact_id"]
    assert first == second
    assert create.await_count == 2
    # The actual PostgreSQL INSERT enforces this deterministic primary key.
    # A second POST never gets a new identity and must read back via GET.


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    ["unapproved", "provider_claim", "missing_event", "stale_flow", "unknown", "body_absent"],
)
async def test_candidate_admission_rejects_untrusted_observations(monkeypatch, fault):
    source, memory, verify, create = signed_fixture(monkeypatch)
    if fault == "unapproved":
        memory.is_task_approved.return_value = False
    elif fault == "provider_claim":
        source.result["provider_evidence"]["finding_verified"] = True
    elif fault == "missing_event":
        verify.return_value = False
    elif fault == "stale_flow":
        memory.load_flow.side_effect = [
            memory.load_flow.return_value,
            SimpleNamespace(id=FLOW, engagement_id=ENGAGEMENT, status="paused", revision=8),
        ]
    elif fault == "unknown":
        source.status = "dispatch_unknown"
    elif fault == "body_absent":
        source.result["response_body_sha256"] = None
    with pytest.raises(HTTPException) as failure:
        await invoke()
    assert failure.value.status_code == 503
    create.assert_not_awaited()


def test_signed_navigation_producer_is_mounted_and_denies_extra_fields():
    from ai_osop.api.main import app

    assert (
        "/engagements/{engagement_id}/findings/{finding_id}/candidate-evidence-artifacts/from-signed-navigation"
        in {route.path for route in app.routes}
    )
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        api.SignedNavigationEvidenceRequest(
            flow_id=FLOW,
            source_task_id=SOURCE,
            expected_flow_revision=7,
            expected_authorization_version=3,
            signed_provider_claim={"verified": True},
        )
