"""Candidate 0024 evidence references in independently verifiable signed drafts.

The signed report reflects immutable metadata links ONLY. Graph's validated
flag and a navigation provider's response never attest independent effects.
Tests use synthetic PostgreSQL method doubles and a real local Ed25519 signer.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import EvidenceArtifact, Task
from ai_osop.memory.session_memory import (
    _checked_evidence_artifact,
    evidence_artifact_leaf_sha256,
)
from ai_osop.reporting.attestation import ReportAttestationError, verify_report_files
from tests.test_report_attestation import (
    ENGAGEMENT,
    EVIDENCE,
    FINDING,
    install_signed_report_source,
    reporting_agent,
    signer,
)

FLOW = "flow-report-candidate"
SOURCE = "task-eligible-navigation-candidate"
APPROVAL = "apr-human-candidate-review"
ORIGINAL_URL = "https://example.test/restricted?private=not-in-report"
REDACTED_URL = "https://example.test/restricted?private=REDACTED"
PRIVATE = "Bearer never-output-this-private-token"


def _artifact(**changes):
    recipe = {
        "schema": "ai-osop.redacted-evidence-reference.v1",
        "source_task_id": SOURCE,
        "method": "GET",
        "url": REDACTED_URL,
        "original_url_sha256": hashlib.sha256(ORIGINAL_URL.encode()).hexdigest(),
        "request_header_names": [],
        "request_body_sha256": "a" * 64,
        "replayable": False,
        "finding_verified": False,
        "target_effect_verified": False,
    }
    artifact = EvidenceArtifact(
        id="ev-signed-candidate-20261019",
        engagement_id=ENGAGEMENT,
        finding_id=FINDING,
        source_tool="signed_browser_provider_summary",
        source_tool_version="1.0.0",
        target_url=REDACTED_URL,
        http_method="GET",
        request_headers_sha256="b" * 64,
        request_body_sha256="a" * 64,
        response_status=200,
        response_headers_sha256="c" * 64,
        response_body_sha256="d" * 64,
        approval_id=APPROVAL,
        replay_recipe=recipe,
        merkle_leaf_hash="0" * 64,
        captured_at=datetime(2026, 10, 19, 12, 0, 0),
    )
    for field, value in changes.items():
        setattr(artifact, field, value)
    artifact.merkle_leaf_hash = evidence_artifact_leaf_sha256(artifact)
    return _checked_evidence_artifact(artifact)


def _navigation(*, version=2, revision=3):
    return Task(
        id=SOURCE,
        type="navigate",
        engagement_id=ENGAGEMENT,
        agent_type=AgentType.WORKFLOW,
        flow_id=FLOW,
        status="completed",
        approval_required=True,
        payload={
            "_authorization_version": version,
            "_flow_revision": revision,
            "url": ORIGINAL_URL,
            "method": "GET",
            "operator_approved": True,
            "approval_id": APPROVAL,
            "headers": {"authorization": PRIVATE},
        },
        result={
            "status": "success",
            "verification_status": "provider_testimony_only",
            "remote_effect_verified": False,
            "authorization_violation_verified": False,
            "findings_count": 0,
            "redirected": False,
            "http_status_code": 200,
            "provider_evidence": {
                "provider_event_id": "evt-signed-navigation-source",
                "provider_receipt_sha256": "e" * 64,
                "source_authenticity_verified": False,
                "target_effect_verified": False,
                "finding_verified": False,
            },
            "private_response": PRIVATE,
        },
    )


def _prepare(agent, *, artifacts=None, source=None):
    memory = install_signed_report_source(agent, flow_id=FLOW, flow_revision=3)
    original_report_task = memory.load_task_authoritative.return_value
    navigation = source or _navigation()

    async def load_task(task_id):
        if task_id == original_report_task.id:
            return original_report_task.model_copy(deep=True)
        if task_id == SOURCE:
            return navigation.model_copy(deep=True)
        return None

    memory.load_task_authoritative = AsyncMock(side_effect=load_task)
    # Distinguishes a durable SQL-capable SessionMemory from __new__ legacy
    # fixture without touching a real database.
    memory._async_session = lambda: object()
    memory.list_finding_evidence = AsyncMock(
        return_value=[_artifact()] if artifacts is None else artifacts
    )
    memory.is_task_approved = AsyncMock(return_value=True)
    return memory, original_report_task, navigation


def _read(report):
    return json.loads(Path(report["report_paths"]["json"]).read_bytes())


@pytest.mark.asyncio
async def test_signed_report_carries_only_current_candidate_metadata_and_verifies_bytes(
    signer,
    reporting_agent,
):
    agent = reporting_agent
    memory, _, navigation = _prepare(agent)
    result = await agent._generate_report(agent.ctx.current_task.payload)
    report = _read(result)
    finding = report["findings"][0]
    refs = finding["candidate_evidence_artifacts"]
    assert len(refs) == 1
    assert refs[0] == {
        "schema": "ai-osop.candidate-artifact-reference.v1",
        "merkle_leaf_sha256": _artifact().merkle_leaf_hash,
        "source_task_id_sha256": hashlib.sha256(
            b"ai-osop-report-navigation-source-v1\0" + ENGAGEMENT.encode() + b"\0" + SOURCE.encode()
        ).hexdigest(),
        "verification_state": "candidate_unverified",
        "independent_target_effect_verified": False,
    }
    assert report["independent_target_effect_verified"] is False
    assert report["source_authenticity_verified"] is False
    assert finding["validated"] is False
    assert finding["source_provenance_status"] == "UNKNOWN_graph_flag_only"
    assert result["requires_approval"] is True
    assert memory.list_finding_evidence.await_args.args == (ENGAGEMENT, FINDING)
    assert memory.load_task_authoritative.await_count >= 4
    assert memory.assert_signed_authorization.await_count >= 4
    assert memory.is_task_approved.await_count == 1
    assert navigation.result["private_response"] == PRIVATE
    for path in result["report_paths"].values():
        payload = Path(path).read_bytes()
        assert PRIVATE.encode() not in payload
        assert ORIGINAL_URL.encode() not in payload
        assert REDACTED_URL.encode() not in payload
        assert SOURCE.encode() not in payload
        assert _artifact().id.encode() not in payload
    assert (
        verify_report_files(
            result["report_paths"],
            evidence_by_finding={FINDING: EVIDENCE},
            trusted_public_keys={"report-prod-kid": signer},
        )["status"]
        == "signature_and_snapshot_verified"
    )
    json_path = Path(result["report_paths"]["json"])
    original = json_path.read_bytes()
    json_path.write_bytes(original.replace(b"candidate_unverified", b"candidate_VERIFIED____", 1))
    with pytest.raises(ReportAttestationError, match="artifact bytes"):
        verify_report_files(
            result["report_paths"],
            evidence_by_finding={FINDING: EVIDENCE},
            trusted_public_keys={"report-prod-kid": signer},
        )


@pytest.mark.asyncio
async def test_legacy_synthetic_fixture_does_not_invent_candidate_artifacts(
    signer, reporting_agent
):
    agent = reporting_agent
    install_signed_report_source(agent, flow_id=FLOW, flow_revision=3)
    report = await agent._generate_report(agent.ctx.current_task.payload)
    finding = _read(report)["findings"][0]
    assert "candidate_evidence_artifacts" not in finding


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "foreign_tenant",
        "wrong_finding",
        "wrong_producer_type",
        "stale_source_flow",
        "revoked_approval",
        "tampered_leaf",
        "missing_evidence_store",
        "evidence_query_failure",
        "too_many",
        "changed_producer",
        "changed_generation_roe",
        "paused_flow",
    ],
)
async def test_corrupt_or_revoked_candidate_lineage_blocks_signing(
    signer,
    reporting_agent,
    failure,
):
    agent = reporting_agent
    memory, generating, navigation = _prepare(agent)
    artifact = _artifact()
    if failure == "foreign_tenant":
        artifact.engagement_id = "eng-other-tenant"
        artifact.merkle_leaf_hash = evidence_artifact_leaf_sha256(artifact)
    elif failure == "wrong_finding":
        artifact.finding_id = "vuln-other-source"
        artifact.merkle_leaf_hash = evidence_artifact_leaf_sha256(artifact)
    elif failure == "wrong_producer_type":
        navigation.type = "full_recon"
    elif failure == "stale_source_flow":
        navigation.payload["_flow_revision"] = 2
    elif failure == "revoked_approval":
        memory.is_task_approved.return_value = False
    elif failure == "tampered_leaf":
        artifact.merkle_leaf_hash = "f" * 64
    elif failure == "missing_evidence_store":
        memory._async_session = None
    elif failure == "evidence_query_failure":
        memory.list_finding_evidence.side_effect = OSError("PG partition")
    elif failure == "too_many":
        memory.list_finding_evidence.return_value = [_artifact()] * 13
    elif failure == "changed_producer":
        original = memory.load_task_authoritative.side_effect
        calls = 0

        async def mutate_producer(task_id):
            nonlocal calls
            item = await original(task_id)
            if task_id == SOURCE:
                calls += 1
                if calls > 1:
                    item.result["status"] = "failed"
            return item

        memory.load_task_authoritative.side_effect = mutate_producer
    elif failure == "changed_generation_roe":
        original = memory.assert_signed_authorization.return_value
        calls = 0

        async def mutate_roe(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls >= 4:
                raise PermissionError("revoked mid candidate read")
            return original

        memory.assert_signed_authorization.side_effect = mutate_roe
    elif failure == "paused_flow":
        original = memory.load_flow.return_value
        calls = 0

        async def mutate_flow(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 2:
                return SimpleNamespace(
                    id=original.id,
                    engagement_id=original.engagement_id,
                    status="paused",
                    revision=original.revision + 1,
                )
            return original

        memory.load_flow.side_effect = mutate_flow
    if failure in {"foreign_tenant", "wrong_finding", "tampered_leaf"}:
        memory.list_finding_evidence.return_value = [artifact]
    with pytest.raises(AgentException, match="candidate evidence"):
        await agent._generate_report(agent.ctx.current_task.payload)
    assert agent.generated_reports == {}
    assert not (Path("reports") / ENGAGEMENT).exists()


@pytest.mark.asyncio
async def test_empty_signed_ledger_is_explicitly_empty_not_verification(signer, reporting_agent):
    agent = reporting_agent
    memory, _, _ = _prepare(agent, artifacts=[])
    result = await agent._generate_report(agent.ctx.current_task.payload)
    report = _read(result)
    assert report["findings"][0]["candidate_evidence_artifacts"] == []
    assert report["independent_target_effect_verified"] is False
    assert report["requires_approval"] is True
    assert result["signature_status"] == "ed25519_signed"
