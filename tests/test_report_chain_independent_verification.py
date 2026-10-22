"""Signed Flow revision / report Task provenance survives independent release checks.

Providers are not invoked. A signed remote status is not target-side evidence.
"""

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.deps import state
from ai_osop.api.routers import report_attestations as report_router
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.reporting.attestation import verify_report_files
from ai_osop.reporting.attestation import (
    ReportAttestationError,
    SCHEMA_V3,
    hash_evidence_snapshot,
    sign_report_attestation,
)
from tests.test_report_attestation import (
    ENGAGEMENT,
    EVIDENCE as PRODUCER_EVIDENCE,
    FINDING,
    reporting_agent,
    signer,
    install_signed_report_source,
)
from tests.test_report_attestations_api import (
    EVIDENCE,
    FID,
    RID,
    SID,
    _get,
    _Result,
    report_api,
)
from tests.test_report_evidence_release_fencing import _signed_generator


FLOW_ID = "flow-report-fixture"
REVISION = 7
STEP_ID = "subtask-report-fixture"


def _flow_report(report_api, monkeypatch):
    task = _signed_generator(report_api, monkeypatch)
    task["flow_id"] = FLOW_ID
    task["subtask_id"] = STEP_ID
    task["approval_required"] = True
    artifacts = dict(report_api.paths)
    artifacts["json"] = json.dumps(
        {
            "engagement_id": SID,
            "requires_approval": True,
            "verification_status": "verified_findings_only",
            "findings": [
                {
                    "id": FID,
                    "evidence_hash": hash_evidence_snapshot(EVIDENCE),
                }
            ],
        }
    ).encode()
    from ai_osop.safety.approval_binding import task_payload_sha256

    signed = sign_report_attestation(
        engagement_id=SID,
        report_id=RID,
        signer_key_id="attester-key-1",
        artifacts=artifacts,
        evidence_provenance=[
            {
                "finding_id": FID,
                "source_type": "validated_engagement_graph",
                "evidence_sha256": hash_evidence_snapshot(EVIDENCE),
            }
        ],
        generation_binding={
            "task_id": task["id"],
            "authorization_version": 3,
            "authorization_sha256": "a" * 64,
            "task_payload_sha256": task_payload_sha256(task["payload"]),
            "flow_id": FLOW_ID,
            "flow_revision": REVISION,
        },
    )
    assert signed["attestation"]["schema"] == SCHEMA_V3
    envelope_bytes = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    hashes = {kind: hashlib.sha256(blob).hexdigest() for kind, blob in artifacts.items()}
    hashes["attestation"] = hashlib.sha256(envelope_bytes).hexdigest()
    manifest = {
        "engagement_id": SID,
        "report_id": RID,
        "hash_algorithm": "sha256",
        "signature_status": "ed25519_signed",
        "artifacts": {kind: hashes[kind] for kind in artifacts},
        "attestation_sha256": hashes["attestation"],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    hashes["manifest"] = hashlib.sha256(manifest_bytes).hexdigest()
    for kind, blob in {
        **artifacts,
        "attestation": envelope_bytes,
        "manifest": manifest_bytes,
    }.items():
        (report_api.folder / f"{RID}.{kind}").write_bytes(blob)
    task["result"]["artifact_sha256"] = hashes
    flow = {
        "id": FLOW_ID,
        "engagement_id": SID,
        "revision": REVISION,
        "status": "running",
    }
    step = {
        "id": STEP_ID,
        "engagement_id": SID,
        "flow_id": FLOW_ID,
        "execution_task_id": task["id"],
        "status": "completed",
    }
    original_execute = report_api.db.execute

    async def execute(statement, params):
        sql = str(statement)
        if "FROM execution_flows" in sql:
            assert "FOR SHARE" in sql
            assert params == {"flow": FLOW_ID, "sid": SID}
            return _Result(flow.copy() if flow else None)
        if "FROM execution_subtasks" in sql:
            assert "FOR SHARE" in sql
            assert params == {"step": STEP_ID, "flow": FLOW_ID, "sid": SID}
            return _Result(step.copy() if step else None)
        return await original_execute(statement, params)

    monkeypatch.setattr(report_api.db, "execute", execute)
    return task, flow, step


def test_flow_signed_report_verifies_live_flow_revision_and_subtask(report_api, monkeypatch):
    task, flow, step = _flow_report(report_api, monkeypatch)
    response = _get(report_api)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["release_status"] == "signed_report_task_snapshot_verified"
    assert body["verification"]["source_authenticity_verified"] is False
    assert body["verification"]["exploit_success_verified"] is False
    assert body["operator_approval_verified"] is False
    assert (
        body["signed_attestation"]["attestation"]["generation_binding"]["flow_revision"] == REVISION
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "revision",
        "cancelled",
        "paused",
        "wrong_tenant",
        "missing_flow",
        "different_flow",
        "missing_subtask",
        "wrong_task",
        "wrong_step_tenant",
        "unfinished_subtask",
    ],
)
def test_live_flow_mutation_invalidates_signed_report_release(report_api, monkeypatch, mutation):
    task, flow, step = _flow_report(report_api, monkeypatch)
    if mutation == "revision":
        flow["revision"] += 1
    elif mutation in {"cancelled", "paused"}:
        flow["status"] = mutation
    elif mutation == "wrong_tenant":
        flow["engagement_id"] = "eng-foreign"
    elif mutation == "missing_flow":
        flow.clear()
    elif mutation == "different_flow":
        task["flow_id"] = "flow-foreign"
    elif mutation == "missing_subtask":
        step.clear()
    elif mutation == "wrong_task":
        step["execution_task_id"] = "task-foreign"
    elif mutation == "wrong_step_tenant":
        step["engagement_id"] = "eng-foreign"
    elif mutation == "unfinished_subtask":
        step["status"] = "running"
    result = _get(report_api)
    assert result.status_code == 503, (mutation, result.text)


def test_v2_report_from_flow_task_cannot_become_releasable(report_api, monkeypatch):
    task = _signed_generator(report_api, monkeypatch)
    task["flow_id"] = FLOW_ID
    task["approval_required"] = True
    response = _get(report_api)
    assert response.status_code == 503


def test_v3_cannot_fake_flow_binding_on_standalone_task(report_api, monkeypatch):
    task, flow, step = _flow_report(report_api, monkeypatch)
    task["flow_id"] = None
    task["subtask_id"] = None
    response = _get(report_api)
    assert response.status_code == 503


def test_invalid_flow_revision_not_signed_as_trusted(report_api):
    from ai_osop.safety.approval_binding import task_payload_sha256

    binding = {
        "task_id": "task-report",
        "authorization_version": 3,
        "authorization_sha256": "a" * 64,
        "task_payload_sha256": task_payload_sha256({"version": "v1"}),
        "flow_id": FLOW_ID,
        "flow_revision": True,
    }
    with pytest.raises(ReportAttestationError, match="Flow binding"):
        sign_report_attestation(
            engagement_id=SID,
            report_id=RID,
            signer_key_id="attester-key-1",
            artifacts={
                **report_api.paths,
                "json": json.dumps(
                    {
                        "engagement_id": SID,
                        "requires_approval": True,
                        "verification_status": "verified_findings_only",
                        "findings": [
                            {"id": FID, "evidence_hash": hash_evidence_snapshot(EVIDENCE)}
                        ],
                    }
                ).encode(),
            },
            evidence_provenance=[
                {
                    "finding_id": FID,
                    "source_type": "validated_engagement_graph",
                    "evidence_sha256": hash_evidence_snapshot(EVIDENCE),
                }
            ],
            generation_binding=binding,
        )


@pytest.mark.asyncio
async def test_reporting_agent_signs_actual_flow_task_revision(reporting_agent, signer):
    agent = reporting_agent
    install_signed_report_source(agent, flow_id=FLOW_ID, flow_revision=REVISION)
    task = agent.ctx.current_task
    task.status = "running"
    task.started_at = datetime.utcnow()
    task.assigned_agent_id = agent.ctx.agent_id
    task.approval_required = True
    task.flow_id = FLOW_ID
    task.subtask_id = STEP_ID
    task.payload = {
        "version": "v1",
        "require_attestation": True,
        "signer_key_id": "report-prod-kid",
        "_authorization_version": 2,
    }
    original_session = await agent.ctx.session_memory.load_session_state(ENGAGEMENT)
    durable = SessionMemory.__new__(SessionMemory)
    durable.load_session_state = AsyncMock(return_value=original_session)
    durable.load_task_authoritative = AsyncMock(return_value=task.model_copy(deep=True))
    durable.assert_signed_authorization = AsyncMock(
        return_value=SimpleNamespace(version=2, policy_sha256="a" * 64)
    )
    durable.load_flow = AsyncMock(
        return_value=SimpleNamespace(
            id=FLOW_ID,
            engagement_id=ENGAGEMENT,
            status="running",
            revision=REVISION,
        )
    )
    agent.ctx.session_memory = durable
    produced = await agent._execute(task)
    envelope = json.loads(Path(produced["report_paths"]["attestation"]).read_bytes())
    assert envelope["attestation"]["schema"] == SCHEMA_V3
    assert envelope["attestation"]["generation_binding"]["flow_id"] == FLOW_ID
    assert envelope["attestation"]["generation_binding"]["flow_revision"] == REVISION
    assert (
        verify_report_files(
            produced["report_paths"],
            evidence_by_finding={FINDING: PRODUCER_EVIDENCE},
            trusted_public_keys={"report-prod-kid": signer},
        )["source_authenticity_verified"]
        is False
    )
    durable.load_flow.assert_awaited_once_with(FLOW_ID)


def test_independent_verifier_rejects_ambiguous_file_json(tmp_path, signer):
    # Generated v1 fixture keeps sign-off semantics unchanged. Offline
    # verification must reject duplicate envelope/manifest keys, even if the
    # duplicate fields happen to have the same value.
    from tests.test_report_attestation import artifacts, provenance
    from ai_osop.reporting.attestation import sign_report_attestation

    envelope = sign_report_attestation(
        engagement_id=ENGAGEMENT,
        report_id=f"report-{ENGAGEMENT}-v1",
        signer_key_id="report-prod-kid",
        artifacts=artifacts(),
        evidence_provenance=provenance(),
    )
    report_root = tmp_path / ENGAGEMENT
    report_root.mkdir(exist_ok=True, parents=True)
    paths = {}
    files = artifacts()
    manifest = {
        "engagement_id": ENGAGEMENT,
        "report_id": f"report-{ENGAGEMENT}-v1",
        "hash_algorithm": "sha256",
        "signature_status": "ed25519_signed",
        "artifacts": {key: hashlib.sha256(value).hexdigest() for key, value in files.items()},
        "attestation_sha256": hashlib.sha256(
            json.dumps(envelope).encode(),
        ).hexdigest(),
    }
    files["attestation"] = json.dumps(envelope).encode()
    files["manifest"] = json.dumps(manifest).encode()
    for kind, blob in files.items():
        path = report_root / f"report-{ENGAGEMENT}-v1.{kind}"
        path.write_bytes(blob)
        paths[kind] = str(path)
    assert (
        verify_report_files(
            paths,
            evidence_by_finding={FINDING: PRODUCER_EVIDENCE},
            trusted_public_keys={"report-prod-kid": signer},
        )["status"]
        == "signature_and_snapshot_verified"
    )
    path = Path(paths["manifest"])
    path.write_bytes(b'{"engagement_id":"eng-false",' + path.read_bytes()[1:])
    with pytest.raises(ReportAttestationError, match="safely"):
        verify_report_files(
            paths,
            evidence_by_finding={FINDING: PRODUCER_EVIDENCE},
            trusted_public_keys={"report-prod-kid": signer},
        )


@pytest.mark.parametrize(
    "current_owner,approved_actor,status",
    [
        ("alice", "alice", 200),
        ("bob", "alice", 503),
        ("alice", "mallory", 503),
    ],
)
def test_human_release_status_requires_current_original_owner(
    monkeypatch,
    current_owner,
    approved_actor,
    status,
):
    """A stale approval from a previous/different owner is not an active release."""
    from tests.test_signed_report_human_release_api import (
        _DIGEST,
        _RID,
        _SID,
        _VERSION,
    )

    class Database:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def begin(self):
            return self

        async def execute(self, statement, *_args):
            if "FROM supervision_events" in str(statement):
                return SimpleNamespace(
                    scalar_one_or_none=lambda: SimpleNamespace(
                        id="evt-release",
                        actor_id=approved_actor,
                        payload={
                            "status": "human_release_approved",
                            "report_id": _RID,
                            "attestation_sha256": _DIGEST,
                            "authorization_version": _VERSION,
                        },
                    )
                )
            if "FROM session_states" in str(statement):
                return SimpleNamespace(
                    mappings=lambda: SimpleNamespace(
                        one_or_none=lambda: {"created_by": current_owner}
                    )
                )
            raise AssertionError("Unexpected signed report release SQL")

    db = Database()
    memory = SimpleNamespace(_async_session=lambda: db)
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=memory))

    async def verified(*_args, **_kwargs):
        return {}, {"attestation_sha256": _DIGEST}, SimpleNamespace(version=_VERSION)

    monkeypatch.setattr(report_router, "_verified_final_release_candidate", verified)
    app = FastAPI()
    app.include_router(report_router.router)
    app.dependency_overrides[report_router._report_operator] = lambda: {
        "sub": "independent-senior",
        "role": "senior_operator",
    }
    response = TestClient(app).get(f"/engagements/{_SID}/attestations/{_RID}/release")
    assert response.status_code == status, response.text
    if status == 200:
        assert response.json()["operator_approval_recorded"] is True
    else:
        assert "approved" not in response.text
