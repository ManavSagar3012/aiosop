"""A signed report draft needs live, owner-fenced generation evidence to release."""

import copy
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from ai_osop.api.routers import report_attestations
from ai_osop.reporting.attestation import (
    ReportAttestationError,
    SCHEMA_V2,
    hash_evidence_snapshot,
    sign_report_attestation,
)
from ai_osop.safety.approval_binding import task_payload_sha256
from tests.test_report_attestations_api import (
    EVIDENCE, FID, RID, SID, _get, _Result, report_api,
)


def _signed_generator(report_api, monkeypatch):
    """Construct the actual producer bytes plus a mocked *durable* Task row."""
    payload = {
        "version": "v1", "require_attestation": True,
        "signer_key_id": "attester-key-1", "_authorization_version": 3,
    }
    digest = hash_evidence_snapshot(EVIDENCE)
    artifacts = dict(report_api.paths)
    artifacts["json"] = json.dumps({
        "engagement_id": SID,
        "requires_approval": True,
        "signature_status": "ed25519_signed",
        "verification_status": "verified_findings_only",
        "findings": [{"id": FID, "evidence_hash": digest}],
    }).encode()
    signed = sign_report_attestation(
        engagement_id=SID, report_id=RID,
        signer_key_id="attester-key-1",
        artifacts=artifacts,
        evidence_provenance=[{
            "finding_id": FID, "source_type": "validated_engagement_graph",
            "evidence_sha256": digest,
        }],
        generation_binding={
            "task_id": "task-report-fixture",
            "authorization_version": 3,
            "authorization_sha256": "a" * 64,
            "task_payload_sha256": task_payload_sha256(payload),
        },
    )
    assert signed["attestation"]["schema"] == SCHEMA_V2
    envelope_bytes = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    hashes = {ext: hashlib.sha256(value).hexdigest() for ext, value in artifacts.items()}
    hashes["attestation"] = hashlib.sha256(envelope_bytes).hexdigest()
    manifest = {
        "engagement_id": SID, "report_id": RID,
        "hash_algorithm": "sha256", "signature_status": "ed25519_signed",
        "artifacts": {key: hashes[key] for key in artifacts},
        "attestation_sha256": hashes["attestation"],
    }
    manifest_bytes = json.dumps(manifest).encode()
    hashes["manifest"] = hashlib.sha256(manifest_bytes).hexdigest()
    for ext, value in {
        **artifacts, "attestation": envelope_bytes, "manifest": manifest_bytes,
    }.items():
        (report_api.folder / f"{RID}.{ext}").write_bytes(value)

    now = datetime.now(timezone.utc)
    row = {
        "id": "task-report-fixture", "engagement_id": SID,
        "type": "generate_report", "agent_type": "reporting",
        "status": "completed", "started_at": now,
        "completed_at": now, "payload": payload, "approval_required": True,
        "result": {
            "status": "success", "report_id": RID,
            "signature_status": "ed25519_signed", "requires_approval": True,
            "artifact_sha256": hashes,
        },
    }
    report_api.guard.return_value = SimpleNamespace(
        session_id=SID, version=3, policy_sha256="a" * 64,
    )
    report_api.db.generator_row = row
    original_execute = report_api.db.execute

    async def execute(stmt, params):
        if "FROM tasks" in str(stmt):
            report_api.db.calls.append((str(stmt), params))
            assert "FOR SHARE" in str(stmt)
            assert params == {"sid": SID, "task": "task-report-fixture"}
            return _Result(report_api.db.generator_row)
        return await original_execute(stmt, params)

    monkeypatch.setattr(report_api.db, "execute", execute)
    return row


def test_legacy_signed_snapshot_remains_draft_only(report_api):
    result = _get(report_api)
    assert result.status_code == 200
    body = result.json()
    assert body["release_status"] == "draft_snapshot_only"
    assert body["operator_approval_verified"] is False
    assert body["engagement_completion_verified"] is False
    assert body["verification"]["exploit_success_verified"] is False


def test_v2_release_requires_signed_task_and_all_artifact_receipts(report_api, monkeypatch):
    _signed_generator(report_api, monkeypatch)
    response = _get(report_api)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["release_status"] == "signed_report_task_snapshot_verified"
    assert body["operator_approval_verified"] is False
    assert body["engagement_completion_verified"] is False
    assert body["verification"]["source_authenticity_verified"] is False
    assert "HIDDEN-RAW-SECRET" not in response.text
    assert len(report_api.db.calls) == 2


@pytest.mark.parametrize("attack", [
    "wrong_engagement", "absent_task", "running", "unknown", "cancelled",
    "failed", "wrong_type", "wrong_agent", "no_start", "no_completion",
    "wrong_task_roeversion", "changed_task_target", "wrong_signer",
    "no_signature_intent", "wrong_report_id", "unsettled_result",
    "missing_approval_boundary", "wrong_manifest_receipt", "wrong_json_receipt",
    "missing_receipt",
])
def test_v2_rejects_foreign_stale_unknown_or_unsigned_generation(
    report_api, monkeypatch, attack,
):
    row = _signed_generator(report_api, monkeypatch)
    if attack == "wrong_engagement":
        row["engagement_id"] = "eng-other"
    elif attack == "absent_task":
        report_api.db.generator_row = None
    elif attack in {"running", "unknown", "cancelled", "failed"}:
        row["status"] = "dispatch_unknown" if attack == "unknown" else attack
    elif attack == "wrong_type":
        row["type"] = "compile_evidence"
    elif attack == "wrong_agent":
        row["agent_type"] = "recon"
    elif attack == "no_start":
        row["started_at"] = None
    elif attack == "no_completion":
        row["completed_at"] = None
    elif attack == "wrong_task_roeversion":
        row["payload"]["_authorization_version"] = 2
    elif attack == "changed_task_target":
        row["payload"]["target"] = "out-of-scope.invalid"
    elif attack == "wrong_signer":
        row["payload"]["signer_key_id"] = "different-signer"
    elif attack == "no_signature_intent":
        row["payload"]["require_attestation"] = False
    elif attack == "wrong_report_id":
        row["result"]["report_id"] = "report-foreign-v1"
    elif attack == "unsettled_result":
        row["result"]["status"] = "unknown"
    elif attack == "missing_approval_boundary":
        row["result"]["requires_approval"] = False
    elif attack == "wrong_manifest_receipt":
        row["result"]["artifact_sha256"]["manifest"] = "0" * 64
    elif attack == "wrong_json_receipt":
        row["result"]["artifact_sha256"]["json"] = "0" * 64
    elif attack == "missing_receipt":
        row["result"]["artifact_sha256"].pop("attestation")
    response = _get(report_api)
    assert response.status_code == 503, (attack, response.text)
    assert "secret" not in response.text.lower()
    assert "out-of-scope.invalid" not in response.text


@pytest.mark.parametrize("attack", ["version", "digest"])
def test_v2_rejects_current_signed_policy_rotation_before_task_read(
    report_api, monkeypatch, attack,
):
    _signed_generator(report_api, monkeypatch)
    if attack == "version":
        report_api.guard.return_value.version = 4
    else:
        report_api.guard.return_value.policy_sha256 = "b" * 64
    response = _get(report_api)
    assert response.status_code == 503
    assert len(report_api.db.calls) == 1


def test_v2_cross_tenant_json_cannot_be_signed(report_api):
    artifacts = dict(report_api.paths)
    artifacts["json"] = json.dumps({
        "engagement_id": "eng-foreign", "requires_approval": True,
        "findings": [{"id": FID, "evidence_hash": hash_evidence_snapshot(EVIDENCE)}],
    }).encode()
    with pytest.raises(ReportAttestationError, match="references"):
        sign_report_attestation(
            engagement_id=SID, report_id=RID,
            signer_key_id="attester-key-1", artifacts=artifacts,
            evidence_provenance=[{
                "finding_id": FID, "source_type": "validated_engagement_graph",
                "evidence_sha256": hash_evidence_snapshot(EVIDENCE),
            }],
            generation_binding={
                "task_id": "task-report-fixture", "authorization_version": 3,
                "authorization_sha256": "a" * 64,
                "task_payload_sha256": "b" * 64,
            },
        )


@pytest.mark.parametrize("claim", [
    "operator_approved", "report_approved", "certified",
    "source_authenticity_verified", "exploit_success_verified",
    "completeness_verified", "production_ready",
])
def test_even_trusted_signer_cannot_assert_unsupported_certification(report_api, claim):
    artifacts = copy.deepcopy(report_api.paths)
    data = json.loads(artifacts["json"])
    data[claim] = True
    artifacts["json"] = json.dumps(data).encode()
    with pytest.raises(ReportAttestationError, match="references"):
        sign_report_attestation(
            engagement_id=SID, report_id=RID,
            signer_key_id="attester-key-1", artifacts=artifacts,
            evidence_provenance=[{
                "finding_id": FID, "source_type": "validated_engagement_graph",
                "evidence_sha256": hash_evidence_snapshot(EVIDENCE),
            }],
        )


def test_duplicate_json_fields_cannot_be_attested(report_api):
    artifacts = dict(report_api.paths)
    artifacts["json"] = (
        b'{"engagement_id":"' + SID.encode() + b'",'
        b'"engagement_id":"eng-foreign",'
        b'"findings":[{"id":"' + FID.encode() + b'",'
        b'"evidence_hash":"' + hash_evidence_snapshot(EVIDENCE).encode() + b'"}]}'
    )
    with pytest.raises(ReportAttestationError, match="references"):
        sign_report_attestation(
            engagement_id=SID, report_id=RID, signer_key_id="attester-key-1",
            artifacts=artifacts,
            evidence_provenance=[{
                "finding_id": FID, "source_type": "validated_engagement_graph",
                "evidence_sha256": hash_evidence_snapshot(EVIDENCE),
            }],
        )


def test_duplicate_manifest_or_envelope_fields_never_verify(report_api):
    path = report_api.folder / f"{RID}.manifest"
    old = path.read_bytes()
    assert old.startswith(b"{")
    path.write_bytes(b'{"engagement_id":"eng-other",' + old[1:])
    assert _get(report_api).status_code == 503
    path.write_bytes(old)
    attestation = report_api.folder / f"{RID}.attestation"
    old = attestation.read_bytes()
    assert old.startswith(b"{")
    attestation.write_bytes(b'{"signature":"forged",' + old[1:])
    assert _get(report_api).status_code == 503
