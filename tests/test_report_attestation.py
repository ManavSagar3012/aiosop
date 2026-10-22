"""Independent Ed25519 reporting evidence/manifest qualification."""

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.reporting.attestation import (
    ReportAttestationError,
    hash_evidence_snapshot,
    sign_report_attestation,
    verify_report_attestation,
    verify_report_files,
)

ENGAGEMENT = "eng-attest-fixture"
FINDING = "vuln-reproducible"
EVIDENCE = [{"type": "http", "event_id": "evt-trusted-fixture", "raw": "password=hidden"}]


@pytest.fixture
def signer(tmp_path, monkeypatch):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "report-signer-private.pem"
    path.write_bytes(private_pem)
    monkeypatch.setenv("OSOP_REPORT_SIGNING_KEY_FILE", str(path))
    monkeypatch.setenv(
        "OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON",
        json.dumps({"report-prod-kid": base64.b64encode(public).decode()}),
    )
    return public


def artifacts(evidence=EVIDENCE):
    report = {"findings": [{"id": FINDING, "evidence_hash": hash_evidence_snapshot(evidence)}]}
    return {
        "md": b"# Verified record, not exploitation claim",
        "html": b"<html><body>Report</body></html>",
        "graph.html": b"<html><body>Graph intentionally empty</body></html>",
        "json": json.dumps(report).encode(),
    }


def provenance(evidence=EVIDENCE):
    return [
        {
            "finding_id": FINDING,
            "source_type": "validated_engagement_graph",
            "evidence_sha256": hash_evidence_snapshot(evidence),
        }
    ]


def signed():
    return sign_report_attestation(
        engagement_id=ENGAGEMENT,
        report_id="report-eng-attest-fixture-v1",
        signer_key_id="report-prod-kid",
        artifacts=artifacts(),
        evidence_provenance=provenance(),
    )


def independently_verify(envelope, *, files=None, evidence=None, trusted=None):
    return verify_report_attestation(
        envelope,
        artifacts=artifacts() if files is None else files,
        evidence_by_finding={FINDING: EVIDENCE} if evidence is None else evidence,
        trusted_public_keys=trusted,
    )


def test_trusted_signature_verifies_independently_and_never_asserts_exploit(signer):
    envelope = signed()
    verified = independently_verify(envelope, trusted={"report-prod-kid": signer})
    assert verified == {
        "status": "signature_and_snapshot_verified",
        "report_id": "report-eng-attest-fixture-v1",
        "engagement_id": ENGAGEMENT,
        "signer_key_id": "report-prod-kid",
        "evidence_records_checked": 1,
        "source_authenticity_verified": False,
        "operator_approved": False,
        "exploit_success_verified": False,
    }
    serialized = json.dumps(envelope)
    assert "password=hidden" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert envelope["attestation"]["evidence_provenance"] == provenance()
    assert envelope["attestation"]["attestation_scope"]["completeness_verified"] is False


@pytest.mark.parametrize(
    "tamper",
    [
        "report-bytes",
        "evidence-bytes",
        "signature",
        "kid",
        "claims",
        "added-artifact",
        "missing-artifact",
        "missing-evidence",
        "extra-evidence",
        "unknown-provenance",
        "wrong-engagement",
        "wrong-report",
    ],
)
def test_tampering_is_not_independently_verified(signer, tamper):
    envelope = signed()
    files = artifacts()
    evidence = {FINDING: EVIDENCE}
    if tamper == "report-bytes":
        files["md"] = b"Tampered content"
    elif tamper == "evidence-bytes":
        evidence = {FINDING: [{"type": "http", "raw": "other-data"}]}
    elif tamper == "signature":
        # Always change the signature: Ed25519 output is random, so its
        # base64url representation may legitimately begin with 'A'.
        replacement = "B" if envelope["signature"][0] == "A" else "A"
        envelope["signature"] = replacement + envelope["signature"][1:]
    elif tamper == "kid":
        envelope["attestation"]["signer_key_id"] = "not-trusted"
    elif tamper == "claims":
        envelope["attestation"]["attestation_scope"]["exploit_success_verified"] = True
    elif tamper == "added-artifact":
        files["secret"] = b"unknown"
    elif tamper == "missing-artifact":
        del files["html"]
    elif tamper == "missing-evidence":
        evidence = {}
    elif tamper == "extra-evidence":
        evidence = {FINDING: EVIDENCE, "vuln-extra": EVIDENCE}
    elif tamper == "unknown-provenance":
        envelope["attestation"]["evidence_provenance"][0]["source_type"] = "user_claim"
    elif tamper == "wrong-engagement":
        envelope["attestation"]["engagement_id"] = "eng-foreign"
    else:
        envelope["attestation"]["report_id"] = "report-foreign"
    with pytest.raises(ReportAttestationError):
        independently_verify(
            envelope, files=files, evidence=evidence, trusted={"report-prod-kid": signer}
        )


@pytest.mark.parametrize(
    "case", ["missing-private", "missing-trust", "unknown-kid", "wrong-private"]
)
def test_signing_fails_closed_without_a_matching_allowlisted_secret(
    signer, monkeypatch, case, tmp_path
):
    if case == "missing-private":
        monkeypatch.delenv("OSOP_REPORT_SIGNING_KEY_FILE")
    elif case == "missing-trust":
        monkeypatch.delenv("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON")
    elif case == "wrong-private":
        replacement = Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path = tmp_path / "wrong-private.pem"
        path.write_bytes(replacement)
        monkeypatch.setenv("OSOP_REPORT_SIGNING_KEY_FILE", str(path))
    with pytest.raises(ReportAttestationError, match="key|signer"):
        sign_report_attestation(
            engagement_id=ENGAGEMENT,
            report_id="report-1",
            signer_key_id="unknown-kid" if case == "unknown-kid" else "report-prod-kid",
            artifacts=artifacts(),
            evidence_provenance=provenance(),
        )


@pytest.mark.parametrize(
    "invalid",
    [
        {"finding_id": FINDING, "source_type": "invented_receipt", "evidence_sha256": "0" * 64},
        {
            "finding_id": FINDING,
            "source_type": "validated_engagement_graph",
            "evidence_sha256": "bogus",
        },
        {
            "finding_id": FINDING,
            "source_type": "validated_engagement_graph",
            "evidence_sha256": "0" * 64,
            "operator_approved": True,
        },
    ],
)
def test_untrusted_or_self_declared_provenance_cannot_be_signed(signer, invalid):
    with pytest.raises(ReportAttestationError):
        sign_report_attestation(
            engagement_id=ENGAGEMENT,
            report_id="report-1",
            signer_key_id="report-prod-kid",
            artifacts=artifacts(),
            evidence_provenance=[invalid],
        )


def test_injected_signer_key_never_replaces_independent_allowlist(signer):
    envelope = signed()
    hostile = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    )
    with pytest.raises(ReportAttestationError, match="signature"):
        independently_verify(envelope, trusted={"report-prod-kid": hostile})
    with pytest.raises(ReportAttestationError, match="trusted"):
        independently_verify(envelope, trusted={})


def test_bad_base64_trust_registry_is_explicitly_rejected(signer, monkeypatch):
    monkeypatch.setenv("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON", '{"report-prod-kid":"%bad"}')
    with pytest.raises(ReportAttestationError, match="configuration is invalid"):
        signed()


def test_source_json_must_match_signed_evidence_even_when_signing(signer):
    inconsistent = artifacts()
    inconsistent["json"] = (
        b'{"findings":[{"id":"vuln-other","evidence_hash":"' + b"0" * 64 + b'"}]}'
    )
    with pytest.raises(ReportAttestationError, match="finding evidence"):
        sign_report_attestation(
            engagement_id=ENGAGEMENT,
            report_id="report-1",
            signer_key_id="report-prod-kid",
            artifacts=inconsistent,
            evidence_provenance=provenance(),
        )


class _GraphSession:
    def __init__(self, nodes):
        self.nodes = nodes

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def run(self, query, **kwargs):
        assert "v.validated = true" in query
        assert kwargs == {"eid": ENGAGEMENT, "limit": 201}
        return SimpleNamespace(data=AsyncMock(return_value=[{"v": item} for item in self.nodes]))


@pytest.fixture
async def reporting_agent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    context = SimpleNamespace(
        agent_id="report-fixture-agent",
        agent_type=AgentType.REPORTING,
        session_id=ENGAGEMENT,
        current_task=None,
        session_memory=SimpleNamespace(
            load_session_state=AsyncMock(
                return_value=SimpleNamespace(
                    session_id=ENGAGEMENT,
                    phase="reporting",
                    scope=SimpleNamespace(
                        authorization_ref="signed-fixture-roe",
                        domains=["example.test"],
                        ips=[],
                    ),
                )
            )
        ),
        graph_memory=SimpleNamespace(
            get_graph_stats=AsyncMock(return_value={"assets": 1, "endpoints": 1}),
            _driver=SimpleNamespace(
                session=lambda: _GraphSession(
                    [
                        {
                            "id": FINDING,
                            "title": "Persisted validation record",
                            "severity": "high",
                            "engagement_id": ENGAGEMENT,
                            "validated": True,
                            "evidence": json.dumps(EVIDENCE),
                        }
                    ]
                )
            ),
        ),
    )
    agent = ReportingAgent(context)
    await agent._setup_resources()
    task = Task(
        type="generate_report",
        priority=5,
        agent_type=AgentType.REPORTING,
        engagement_id=ENGAGEMENT,
        payload={"version": "v1"},
    )
    agent.ctx.current_task = task
    return agent


def install_signed_report_source(agent, *, flow_id=None, flow_revision=0):
    """Fully bound synthetic signed Task+graph source; NOT target verification."""
    task = agent.ctx.current_task
    task.status = "running"
    task.started_at = __import__("datetime").datetime.utcnow()
    task.assigned_agent_id = agent.ctx.agent_id
    task.approval_required = True
    task.flow_id = flow_id
    task.payload = {"version": "v1", "require_attestation": True,
                    "signer_key_id": "report-prod-kid", "_authorization_version": 2}
    previous = agent.ctx.session_memory
    durable = SessionMemory.__new__(SessionMemory)
    durable.load_session_state = previous.load_session_state
    durable.load_task_authoritative = AsyncMock(return_value=task.model_copy(deep=True))
    durable.assert_signed_authorization = AsyncMock(
        return_value=SimpleNamespace(version=2, policy_sha256="a" * 64))
    if flow_id:
        durable.load_flow = AsyncMock(return_value=SimpleNamespace(
            id=flow_id, engagement_id=ENGAGEMENT, status="running", revision=flow_revision))
    agent.ctx.session_memory = durable
    source = {
        "id": FINDING, "title": "Persisted validation record", "severity": "high",
        "engagement_id": ENGAGEMENT, "validated": True, "evidence": json.dumps(EVIDENCE),
        "source_task_id": "task-source-fixture", "source_task_sha256": "b" * 64,
        "flow_id": flow_id or "flow-source-fixture", "flow_revision": flow_revision,
        "authorization_version": 2, "authorization_sha256": "a" * 64,
        "source_event_id": "evt-trusted-fixture", "provider_receipt_sha256": "c" * 64,
    }
    agent.ctx.graph_memory._driver.session = lambda: _GraphSession([source])
    return durable


@pytest.mark.asyncio
async def test_signed_reporting_agent_produces_independently_verifiable_bundle(
    signer, reporting_agent
):
    agent = reporting_agent
    install_signed_report_source(agent)
    result = await agent._generate_report(
        {
            "version": "v1",
            "require_attestation": True,
            "signer_key_id": "report-prod-kid",
        }
    )
    assert result["signature_status"] == "ed25519_signed"
    assert result["requires_approval"] is True
    assert "attestation" in result["report_paths"]
    assert result["findings_included"] == 1
    assert (
        result["artifact_sha256"]["manifest"]
        == hashlib.sha256(Path(result["report_paths"]["manifest"]).read_bytes()).hexdigest()
    )
    verified = verify_report_files(
        result["report_paths"],
        evidence_by_finding={FINDING: EVIDENCE},
        trusted_public_keys={"report-prod-kid": signer},
    )
    assert verified["status"] == "signature_and_snapshot_verified"
    assert verified["evidence_records_checked"] == 1
    assert verified["operator_approved"] is False

    # The signed bundle's manifest is independently checked as well.
    manifest_path = Path(result["report_paths"]["manifest"])
    original = manifest_path.read_bytes()
    manifest = json.loads(original)
    manifest["signature_status"] = "not_signed"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ReportAttestationError, match="manifest"):
        verify_report_files(
            result["report_paths"],
            evidence_by_finding={FINDING: EVIDENCE},
            trusted_public_keys={"report-prod-kid": signer},
        )
    manifest_path.write_bytes(original)

    # The signature itself is never trusted without the signed artifact bytes.
    html_path = Path(result["report_paths"]["html"])
    html_path.write_bytes(html_path.read_bytes() + b"<!-- modified -->")
    with pytest.raises(ReportAttestationError, match="artifact bytes"):
        verify_report_files(
            result["report_paths"],
            evidence_by_finding={FINDING: EVIDENCE},
            trusted_public_keys={"report-prod-kid": signer},
        )


@pytest.mark.asyncio
async def test_signed_request_missing_key_leaves_no_partial_report(reporting_agent):
    agent = reporting_agent
    install_signed_report_source(agent)
    with pytest.raises(AgentException, match="attestation unavailable"):
        await agent._generate_report(
            {
                "version": "v2",
                "require_attestation": True,
                "signer_key_id": "report-prod-kid",
            }
        )
    assert not (Path("reports") / ENGAGEMENT).exists()
    assert agent.generated_reports == {}


@pytest.mark.asyncio
async def test_unsigned_default_remains_explicitly_unsigned(reporting_agent):
    result = await reporting_agent._generate_report({"version": "v3"})
    assert result["signature_status"] == "not_signed"
    assert "attestation" not in result["report_paths"]
    assert (
        json.loads(Path(result["report_paths"]["manifest"]).read_text())["signature_status"]
        == "not_signed"
    )
