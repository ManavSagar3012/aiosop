"""Target-authority intake rejects missing tenant and signed trust boundaries."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError

from ai_osop.api.deps import state
from ai_osop.api.routers import target_authority
from ai_osop.api.routers.target_authority import TargetAssertionSubmission
from ai_osop.memory.session_memory import SessionMemory


def _input():
    return TargetAssertionSubmission(
        original_source_task_id="task-original",
        source_task_id="task-source",
        target_task_id="task-target",
        claims_json="{}",
        signature_b64url="A" * 86,
    )


def test_registered_proof_intake_has_no_execute_or_promote_route():
    urls = [item.path for item in target_authority.router.routes]
    assert urls == [
        "/engagements/{engagement_id}/flows/{flow_id}/target-authority/attestations",
        "/engagements/{engagement_id}/flows/{flow_id}/target-authority/attestations/{proof_sha256}/reverify",
        "/engagements/{engagement_id}/flows/{flow_id}/target-authority/attestations/{proof_sha256}/reverify",
    ]
    assert [route.methods for route in target_authority.router.routes] == [
        {"POST"},
        {"POST"},
        {"GET"},
    ]


def test_strict_signed_payload_does_not_accept_client_promoted_status():
    with pytest.raises(ValidationError):
        TargetAssertionSubmission(
            **{
                **_input().model_dump(),
                "finding_verified": True,
            }
        )
    with pytest.raises(ValidationError):
        TargetAssertionSubmission(
            **{
                **_input().model_dump(),
                "signature_b64url": "fake-signature",
            }
        )


@pytest.mark.asyncio
async def test_malformed_ids_denied_without_owner_or_database(monkeypatch):
    access = AsyncMock()
    monkeypatch.setattr(target_authority, "assert_engagement_access", access)
    with pytest.raises(HTTPException) as exc:
        await target_authority.admit_target_authority_assertion(
            "eng-../../foreign",
            "flow-good",
            _input(),
            Response(),
            operator={"role": "senior_operator", "sub": "owner"},
        )
    assert exc.value.status_code == 422
    access.assert_not_awaited()


@pytest.mark.asyncio
async def test_unavailable_real_pg_backend_denies_before_signature(monkeypatch):
    monkeypatch.setattr(target_authority, "assert_engagement_access", AsyncMock())
    old = state.get("orchestrator")
    memory = SessionMemory.__new__(SessionMemory)
    memory._async_session = None
    state["orchestrator"] = SimpleNamespace(session_memory=memory)
    try:
        with pytest.raises(HTTPException) as exc:
            await target_authority.admit_target_authority_assertion(
                "eng-owned",
                "flow-good",
                _input(),
                Response(),
                operator={"role": "senior_operator", "sub": "owner"},
            )
        assert exc.value.status_code == 503
        assert "unavailable" in exc.value.detail
    finally:
        if old is None:
            state.pop("orchestrator", None)
        else:
            state["orchestrator"] = old
