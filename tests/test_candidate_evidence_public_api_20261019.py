"""Mounted candidate-evidence readback cannot promote or disclose private data."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.routers import candidate_evidence_artifacts as api


_ENG = "eng-candidate-evidence"
_FLOW = "flow-candidate-evidence"
_TASK = "task-candidate-evidence"
_URL = "https://example.com/private?access_token=secret-do-not-return"


def _fixtures(monkeypatch):
    import hashlib

    memory = SimpleNamespace(
        assert_signed_authorization=AsyncMock(return_value=SimpleNamespace(version=3)),
        load_flow=AsyncMock(
            return_value=SimpleNamespace(id=_FLOW, engagement_id=_ENG, status="running", revision=7)
        ),
        list_finding_evidence=AsyncMock(),
        load_task_authoritative=AsyncMock(
            return_value=SimpleNamespace(
                id=_TASK,
                engagement_id=_ENG,
                flow_id=_FLOW,
                status="completed",
                payload={"_authorization_version": 3, "_flow_revision": 7, "url": _URL},
            )
        ),
    )
    artifact = SimpleNamespace(
        id="ev-candidate-1",
        engagement_id=_ENG,
        finding_id="finding-candidate-1",
        target_url=_URL,
        response_body_sha256="private-body-must-not-return",
        raw_storage_uri="file:///private/target-body",
        replay_recipe={
            "schema": "ai-osop.redacted-evidence-reference.v1",
            "source_task_id": _TASK,
            "original_url_sha256": hashlib.sha256(_URL.encode()).hexdigest(),
            "replayable": False,
            "finding_verified": False,
            "target_effect_verified": False,
            "private_response_body": "top-secret-target-body",
            "headers": {"authorization": "Bearer private-cookie"},
        },
        merkle_leaf_hash="a" * 64,
    )
    memory.list_finding_evidence.return_value = [artifact]
    monkeypatch.setattr(api, "SessionMemory", SimpleNamespace)
    monkeypatch.setattr(api, "assert_engagement_access", AsyncMock())
    monkeypatch.setitem(api.state, "orchestrator", SimpleNamespace(session_memory=memory))
    return memory, artifact


async def _read() -> dict:
    return await api.read_candidate_evidence_artifacts(
        _ENG,
        "finding-candidate-1",
        Response(),
        flow_id=_FLOW,
        expected_flow_revision=7,
        expected_authorization_version=3,
        operator={"sub": "reviewer", "role": "senior_operator"},
    )


@pytest.mark.asyncio
async def test_candidate_public_readback_only_metadata_no_private_fields(monkeypatch):
    memory, _ = _fixtures(monkeypatch)
    output = await _read()
    assert output["finding_verified"] is False
    assert output["independent_target_effect_verified"] is False
    assert output["artifacts"] == [
        {
            "artifact_id": "ev-candidate-1",
            "source_task_id": _TASK,
            "merkle_leaf_sha256": "a" * 64,
            "verification_state": "candidate_unverified",
            "independent_target_effect_verified": False,
        }
    ]
    text = str(output)
    assert all(
        secret not in text
        for secret in (
            "top-secret-target-body",
            "Bearer private-cookie",
            "access_token",
            "file:///private",
            "private-body-must-not-return",
        )
    )
    assert memory.assert_signed_authorization.await_count == 2
    api.assert_engagement_access.assert_awaited_once()


@pytest.mark.asyncio
async def test_candidate_public_readback_denies_revocation_after_await(monkeypatch):
    memory, _ = _fixtures(monkeypatch)
    memory.assert_signed_authorization.side_effect = [
        SimpleNamespace(version=3),
        PermissionError("revoked secret signer"),
    ]
    with pytest.raises(HTTPException) as exc:
        await _read()
    assert exc.value.status_code == 503
    assert "secret" not in str(exc.value.detail)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tampering", ["engagement_id", "finding_id", "status", "schema", "replayable", "_flow_revision"]
)
async def test_candidate_public_readback_fails_closed_for_foreign_or_stale_source(
    monkeypatch, tampering
):
    memory, artifact = _fixtures(monkeypatch)
    if tampering in {"engagement_id", "finding_id"}:
        setattr(artifact, tampering, "foreign")
    elif tampering == "status":
        memory.load_task_authoritative.return_value.status = "dispatch_unknown"
    elif tampering == "schema":
        artifact.replay_recipe["schema"] = "verified"
    elif tampering == "replayable":
        artifact.replay_recipe["replayable"] = True
    elif tampering == "_flow_revision":
        memory.load_task_authoritative.return_value.payload["_flow_revision"] = 6
    with pytest.raises(HTTPException) as exc:
        await _read()
    assert exc.value.status_code == 503


def test_candidate_evidence_router_is_mounted_in_actual_app():
    from ai_osop.api.main import app

    paths = {route.path for route in app.routes}
    assert (
        "/engagements/{engagement_id}/findings/{finding_id}/candidate-evidence-artifacts" in paths
    )
