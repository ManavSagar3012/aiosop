"""Signed comparison provider testimony never certifies a vulnerability report.

All tests use disposable signed artifact fixtures, stub graph and in-memory DB
adapters. No application DB, provider or external target is called.
"""

import hashlib
import json
from pathlib import Path

import pytest

from ai_osop.api.routers import report_attestations as reports
from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.context_compaction import task_assignment_sha256
from ai_osop.reporting.attestation import sign_report_attestation
from ai_osop.reporting.attested_storage import AttestedStorageUnavailable
from tests.test_report_attestations_api import FID, RID, SID, _get, report_api
from tests.test_report_source_provenance_gate import _candidate, lineage
from tests.test_reporting_agent import mock_context


def _resign_snapshot(lineage, *, modify_json=None, modify_md=None):
    """Sign the malicious claims using a trusted report key on purpose.

    Even fully valid Ed25519 artifact integrity and a completed generation
    Task do not make a target-side claim independently authoritative.
    """
    folder = lineage.report.folder
    blobs = {
        kind: (folder / f"{RID}.{kind}").read_bytes()
        for kind in ("md", "html", "graph.html", "json")
    }
    report_data = json.loads(blobs["json"])
    if modify_json is not None:
        modify_json(report_data)
    blobs["json"] = json.dumps(report_data, separators=(",", ":")).encode()
    if modify_md is not None:
        blobs["md"] = modify_md(blobs["md"])
    old = json.loads((folder / f"{RID}.attestation").read_bytes())["attestation"]
    signed = sign_report_attestation(
        engagement_id=SID,
        report_id=RID,
        signer_key_id="attester-key-1",
        artifacts=blobs,
        evidence_provenance=old["evidence_provenance"],
        generation_binding=old["generation_binding"],
    )
    envelope = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in blobs.items()}
    hashes["attestation"] = hashlib.sha256(envelope).hexdigest()
    manifest = {
        "engagement_id": SID,
        "report_id": RID,
        "hash_algorithm": "sha256",
        "signature_status": "ed25519_signed",
        "artifacts": {key: hashes[key] for key in blobs},
        "attestation_sha256": hashes["attestation"],
    }
    manifest_bytes = json.dumps(manifest).encode()
    hashes["manifest"] = hashlib.sha256(manifest_bytes).hexdigest()
    for key, contents in {
        **blobs, "attestation": envelope, "manifest": manifest_bytes,
    }.items():
        (folder / f"{RID}.{key}").write_bytes(contents)
    lineage.report.db.generator_row["result"]["artifact_sha256"] = hashes
    return hashes["attestation"]


def _approval(digest):
    return {
        "expected_authorization_version": 3,
        "expected_attestation_sha256": digest,
        "reason": "This report requires independent validation of actual target authority.",
        "approval_statement": "I approve releasing this exact signed report snapshot",
    }


@pytest.mark.asyncio
async def test_real_report_templates_render_graph_candidates_not_verified_vulnerabilities(
    mock_context, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    task = Task(
        type="generate_report", agent_type=AgentType.REPORTING,
        engagement_id="test-session", payload={"version": "v3"},
    )
    agent.ctx.current_task = task
    result = await agent._execute(task)
    assert result["verification_status"] == "graph_marked_candidates_unverified"
    md = Path(result["report_paths"]["md"]).read_text(encoding="utf-8")
    assert "## Verified Vulnerabilities" not in md
    assert "## Graph-Marked Findings (Target Verification UNKNOWN)" in md
    assert "High Vulnerabilities:" not in md
    assert "source authenticity is UNKNOWN" in md
    result_json = json.loads(Path(result["report_paths"]["json"]).read_bytes())
    assert result_json["source_authenticity_verified"] is False
    assert result_json["findings"][0]["validated"] is False
    assert result_json["findings"][0]["graph_validated"] is True
    assert result_json["findings"][0]["source_authenticity_verified"] is False


@pytest.mark.asyncio
async def test_signed_provider_receipt_and_graph_flag_remain_candidate_unknown(lineage):
    assert lineage.node["validated"] is True
    assert lineage.source.result["status"] == "success"
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only"):
        await _candidate(lineage)
    # Prove that a valid independently checked *provider* completion was
    # reached; the final release denial is the missing target-side authority.
    lineage.orch.session_memory.verify_signed_graph_action.assert_awaited_once()
    draft = _get(lineage.report)
    assert draft.status_code == 200
    assert draft.json()["verification"]["source_authenticity_verified"] is False
    assert draft.json()["independent_target_authority_verified"] is False
    assert draft.json()["finding_release_eligible"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("comparison", [
    "candidate_review", "expected_denial_observed", "inconclusive", "unknown",
])
async def test_signed_diff_comparison_cannot_promote_through_source_result(
    lineage, comparison,
):
    lineage.source.result["comparison_status"] = comparison
    lineage.node["source_task_sha256"] = task_assignment_sha256(lineage.source)
    _resign_snapshot(
        lineage,
        modify_json=lambda report: report["findings"][0]["source_binding"].update(
            source_task_sha256=lineage.node["source_task_sha256"],
        ),
    )
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only"):
        await _candidate(lineage)
    lineage.orch.session_memory.verify_signed_graph_action.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_navigate_source_is_not_target_authority(lineage):
    lineage.source.type = "navigate"
    lineage.node["source_task_sha256"] = task_assignment_sha256(lineage.source)
    _resign_snapshot(
        lineage,
        modify_json=lambda report: report["findings"][0]["source_binding"].update(
            source_task_sha256=lineage.node["source_task_sha256"],
        ),
    )
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only"):
        await _candidate(lineage)
    lineage.orch.session_memory.verify_signed_graph_action.assert_not_awaited()


@pytest.mark.parametrize("claim", [
    "target_authority_verified", "independent_target_effect_verified",
    "vulnerability_verified", "comparison_verified", "independently_validated",
    "validated",
])
def test_real_get_rejects_even_validly_signed_false_target_authority_claim(
    lineage, claim,
):
    _resign_snapshot(
        lineage,
        modify_json=lambda report: report["findings"][0].update({claim: True}),
    )
    response = _get(lineage.report)
    assert response.status_code == 503
    assert "secret" not in response.text.lower()


def test_nested_signed_target_verification_claim_is_not_trusted(lineage):
    _resign_snapshot(
        lineage,
        modify_json=lambda report: report["findings"][0].update(
            details={"target_authority_verified": True},
        ),
    )
    assert _get(lineage.report).status_code == 503


def test_real_get_rejects_trusted_signed_misleading_verified_heading(lineage):
    _resign_snapshot(
        lineage,
        modify_md=lambda original: original + b"\n## Verified Vulnerabilities\n",
    )
    response = _get(lineage.report)
    assert response.status_code == 503


@pytest.mark.parametrize("method", ["release", "download", "release_status"])
def test_real_public_release_and_download_refuse_provider_only_source(lineage, method):
    path = f"/engagements/{SID}/attestations/{RID}"
    auth = lineage.report.headers("alice", "senior_operator")
    if method == "release":
        digest = hashlib.sha256(
            (lineage.report.folder / f"{RID}.attestation").read_bytes(),
        ).hexdigest()
        reply = lineage.report.client.post(path + "/release", json=_approval(digest), headers=auth)
    elif method == "download":
        reply = lineage.report.client.get(path + "/artifacts/md", headers=auth)
    else:
        reply = lineage.report.client.get(path + "/release", headers=auth)
    assert reply.status_code == 503
    assert "HIDDEN-RAW-SECRET" not in reply.text


@pytest.mark.asyncio
async def test_source_verification_does_not_override_current_owner_and_roe(lineage):
    with pytest.raises(Exception) as foreign:
        await reports._verified_final_release_candidate(
            lineage.report.db, lineage.orch, SID, RID,
            {"role": "senior_operator", "sub": "foreign-user"},
        )
    assert getattr(foreign.value, "status_code", None) == 403
    lineage.report.guard.return_value.version = 4
    with pytest.raises(Exception):
        await _candidate(lineage)
    lineage.orch.session_memory.verify_signed_graph_action.assert_not_awaited()
