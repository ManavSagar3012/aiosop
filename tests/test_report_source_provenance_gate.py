"""Report release must not turn graph validated=true into source authenticity.

Exercises the production signed report candidate path, real graph evidence
query and real PostgreSQL signed MCP receipt verifier using deterministic
storage doubles. No target, model, live database or remote provider is called.
"""

import base64
import copy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.api.deps import state
from ai_osop.api.routers import report_attestations as report
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.graph_research_projection import verify_signed_action_event
from ai_osop.orchestrator.context_compaction import task_assignment_sha256
from ai_osop.reporting.attestation import (
    hash_evidence_snapshot,
    sign_report_attestation,
)
from ai_osop.reporting.attested_storage import AttestedStorageUnavailable
from tests.test_report_attestations_api import EVIDENCE, FID, RID, SID, report_api
from tests.test_report_evidence_release_fencing import _signed_generator

SOURCE_TASK = "task-report-source-verified"
SOURCE_FLOW = "flow-report-source-verified"
SOURCE_EVENT = "evt-report-source-verified"
RECEIPT_HASH = "b" * 64
REQUEST_ID = "request-report-source"
PROVIDER = "report-source-mcp"
KID = "report-source-kid"


@pytest.fixture
def lineage(report_api, monkeypatch):
    _signed_generator(report_api, monkeypatch)
    digest = hash_evidence_snapshot(EVIDENCE)
    task = Task(
        id=SOURCE_TASK,
        engagement_id=SID,
        flow_id=SOURCE_FLOW,
        type="recon",
        agent_type=AgentType.RECON,
        status="completed",
        payload={"_authorization_version": 3},
        result={"status": "success", "evidence_sha256": digest},
    )
    flow = SimpleNamespace(
        id=SOURCE_FLOW,
        engagement_id=SID,
        status="running",
        revision=4,
    )
    node = {
        "finding_id": FID,
        "validated": True,
        "evidence": json.dumps(EVIDENCE),
        "source_task_id": SOURCE_TASK,
        "source_task_sha256": task_assignment_sha256(task),
        "flow_id": SOURCE_FLOW,
        "flow_revision": 4,
        "authorization_version": 3,
        "authorization_sha256": "a" * 64,
        "source_event_id": SOURCE_EVENT,
        "provider_receipt_sha256": RECEIPT_HASH,
    }
    # Simulate the real ReportingAgent: graph *claims* are snapshotted in the
    # Ed25519-covered JSON artifact, even though signature != source proof.
    report_json = json.loads((report_api.folder / f"{RID}.json").read_bytes())
    report_json["findings"][0]["source_binding"] = {
        name: node[name]
        for name in (
            "source_task_id",
            "source_task_sha256",
            "flow_id",
            "flow_revision",
            "authorization_version",
            "authorization_sha256",
            "source_event_id",
            "provider_receipt_sha256",
        )
    }
    blobs = dict(report_api.paths)
    blobs["json"] = json.dumps(report_json).encode()
    old_attestation = json.loads((report_api.folder / f"{RID}.attestation").read_bytes())
    signed = sign_report_attestation(
        engagement_id=SID,
        report_id=RID,
        signer_key_id="attester-key-1",
        artifacts=blobs,
        evidence_provenance=old_attestation["attestation"]["evidence_provenance"],
        generation_binding=old_attestation["attestation"]["generation_binding"],
    )
    envelope = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    hashes = {name: hashlib.sha256(blob).hexdigest() for name, blob in blobs.items()}
    hashes["attestation"] = hashlib.sha256(envelope).hexdigest()
    manifest = {
        "engagement_id": SID,
        "report_id": RID,
        "hash_algorithm": "sha256",
        "signature_status": "ed25519_signed",
        "artifacts": {name: hashes[name] for name in blobs},
        "attestation_sha256": hashes["attestation"],
    }
    manifest_bytes = json.dumps(manifest).encode()
    hashes["manifest"] = hashlib.sha256(manifest_bytes).hexdigest()
    for name, blob in {
        **blobs,
        "attestation": envelope,
        "manifest": manifest_bytes,
    }.items():
        (report_api.folder / f"{RID}.{name}").write_bytes(blob)
    report_api.db.generator_row["result"]["artifact_sha256"] = hashes

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def run(self, statement, **params):
            assert "MATCH (v:Vulnerability {engagement_id: $sid})" in statement
            assert "v.source_task_id AS source_task_id" in statement
            assert params == {"sid": SID, "finding_ids": [FID], "limit": 2}
            return SimpleNamespace(data=AsyncMock(return_value=[dict(node)]))

    orch = state["orchestrator"]
    orch.graph_memory._driver.session = lambda: Session()
    orch.session_memory.load_task_authoritative = AsyncMock(return_value=task)
    orch.session_memory.load_flow = AsyncMock(return_value=flow)
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({PROVIDER: {KID: base64.b64encode(bytes([7]) * 32).decode()}}),
    )
    event = {
        "id": SOURCE_EVENT,
        "engagement_id": SID,
        "task_id": SOURCE_TASK,
        "kind": "agent.mcp.reconciliation_result",
        "payload": {
            "status": "confirmed_finished",
            "provider_receipt_status": "succeeded",
            "provider_receipt_sha256": RECEIPT_HASH,
            "provider_signing_kid": KID,
            "request_id": REQUEST_ID,
        },
    }
    dispatch = {
        "engagement_id": SID,
        "task_id": SOURCE_TASK,
        "server_id": PROVIDER,
        "request_id": REQUEST_ID,
        "authorization_version": 3,
        "status": "confirmed_finished",
    }
    supervision = SimpleNamespace(
        list_events=AsyncMock(return_value=[event]),
        list_mcp_dispatches=AsyncMock(return_value=[dispatch]),
        get_mcp_dispatch=AsyncMock(return_value=dispatch),
    )

    async def independently_verify(sid, tid, eid, receipt_sha, version):
        return await verify_signed_action_event(
            supervision=supervision,
            engagement_id=sid,
            task_id=tid,
            event_id=eid,
            provider_receipt_sha256=receipt_sha,
            authorization_version=version,
        )

    orch.session_memory.verify_signed_graph_action = AsyncMock(
        side_effect=independently_verify,
    )
    return SimpleNamespace(
        report=report_api,
        orch=orch,
        node=node,
        source=task,
        flow=flow,
        event=event,
        dispatch=dispatch,
        supervision=supervision,
    )


async def _candidate(case):
    from tests.test_report_attestations_api import RID

    return await report._verified_final_release_candidate(
        case.report.db,
        case.orch,
        SID,
        RID,
        {"role": "senior_operator", "sub": "alice"},
    )


@pytest.mark.asyncio
async def test_complete_signed_task_evidence_and_provider_receipt_is_not_target_proof(
    lineage,
):
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only"):
        await _candidate(lineage)
    assert lineage.orch.session_memory.verify_signed_graph_action.await_count == 1
    assert lineage.orch.session_memory.load_task_authoritative.await_count == 2
    assert lineage.orch.session_memory.load_flow.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing",
    [
        "source_task_id",
        "source_task_sha256",
        "source_event_id",
        "provider_receipt_sha256",
        "flow_id",
        "flow_revision",
        "authorization_version",
        "authorization_sha256",
    ],
)
async def test_manual_or_unattributed_graph_finding_never_passes_release(lineage, missing):
    lineage.node.pop(missing)
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only"):
        await _candidate(lineage)
    lineage.orch.session_memory.verify_signed_graph_action.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    [
        "different_tenant",
        "not_completed",
        "wrong_evidence_digest",
        "changed_source_assignment",
        "wrong_flow_revision",
        "revoked_flow",
        "untrusted_signer",
        "failed_provider",
        "wrong_provider_receipt",
        "wrong_dispatch_version",
        "absent_event",
        "postgres_unavailable",
        "changed_after_proof",
    ],
)
async def test_forged_or_unknown_provenance_does_not_admit_report_release(lineage, attack):
    if attack == "different_tenant":
        lineage.source.engagement_id = "eng-other-tenant"
    elif attack == "not_completed":
        lineage.source.status = "dispatch_unknown"
    elif attack == "wrong_evidence_digest":
        lineage.source.result["evidence_sha256"] = "f" * 64
    elif attack == "changed_source_assignment":
        lineage.node["source_task_sha256"] = "f" * 64
    elif attack == "wrong_flow_revision":
        lineage.node["flow_revision"] = 1000
    elif attack == "revoked_flow":
        lineage.flow.status = "paused"
    elif attack == "untrusted_signer":
        lineage.event["payload"]["provider_signing_kid"] = "retired-kid"
    elif attack == "failed_provider":
        lineage.event["payload"]["provider_receipt_status"] = "failed"
    elif attack == "wrong_provider_receipt":
        lineage.node["provider_receipt_sha256"] = "f" * 64
    elif attack == "wrong_dispatch_version":
        lineage.dispatch["authorization_version"] = 2
    elif attack == "absent_event":
        lineage.supervision.list_events.return_value = []
    elif attack == "postgres_unavailable":
        lineage.supervision.list_events.side_effect = OSError("password=secret")
    elif attack == "changed_after_proof":
        source_before = lineage.source.model_copy(deep=True)
        changed = lineage.source.model_copy(deep=True)
        changed.result = {**changed.result, "status": "failed"}
        lineage.orch.session_memory.load_task_authoritative.side_effect = [
            source_before,
            changed,
        ]
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only") as exc:
        await _candidate(lineage)
    assert "secret" not in str(exc.value)


@pytest.mark.asyncio
async def test_source_evidence_receipt_recheck_failure_blocks_release(lineage):
    lineage.supervision.get_mcp_dispatch.side_effect = OSError("db offline secret=NOTSAFE")
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only") as exc:
        await _candidate(lineage)
    assert "NOTSAFE" not in str(exc.value)


@pytest.mark.asyncio
async def test_graph_source_lineage_cannot_be_added_or_changed_after_report_signature(
    lineage,
):
    lineage.node["source_event_id"] = "evt-replacement-event"
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only"):
        await _candidate(lineage)
    lineage.orch.session_memory.verify_signed_graph_action.assert_not_awaited()


@pytest.mark.asyncio
async def test_unattributed_vulnerability_remains_verifiable_as_noncertified_draft(lineage):
    lineage.node.pop("source_event_id")
    from tests.test_report_attestations_api import _get

    response = _get(lineage.report)
    assert response.status_code == 200
    assert response.json()["verification"]["source_authenticity_verified"] is False
    with pytest.raises(AttestedStorageUnavailable, match="manual draft only"):
        await _candidate(lineage)


def test_real_senior_release_endpoint_denies_synthetic_graph_only_finding(lineage):
    lineage.node.pop("source_task_id")
    digest = hashlib.sha256((lineage.report.folder / f"{RID}.attestation").read_bytes()).hexdigest()
    result = lineage.report.client.post(
        f"/engagements/{SID}/attestations/{RID}/release",
        headers=lineage.report.headers("alice", "senior_operator"),
        json={
            "expected_authorization_version": 3,
            "expected_attestation_sha256": digest,
            "reason": "Manually recorded graph finding needs independent source review.",
            "approval_statement": "I approve releasing this exact signed report snapshot",
        },
    )
    assert result.status_code == 503
    assert "secret" not in result.text
    lineage.orch.session_memory.verify_signed_graph_action.assert_not_awaited()
