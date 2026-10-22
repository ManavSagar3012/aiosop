"""Unit tests for immutable evidence ledger and artifact storage."""

import hashlib
import pytest
from datetime import datetime
from ai_osop.core.models import EvidenceArtifact, FindingStatus, Vulnerability
from ai_osop.core.config import Severity, VulnClass


def test_vulnerability_status_and_evidence_fields():
    vuln = Vulnerability(
        vuln_type=VulnClass.IDOR,
        severity=Severity.HIGH,
        title="BOLA in Document Resource",
        description="Cross-tenant access allowed without authorization check",
        tool_source="diff_auth_engine",
        confidence=0.95,
        engagement_id="eng-p1-test",
        finding_status=FindingStatus.VERIFIED,
        validation_authority="diff_auth_engine",
        validation_state="VALIDATED",
        evidence_artifact_ids=["ev-test-101"],
        merkle_leaf_hash="a" * 64,
    )
    assert vuln.finding_status == FindingStatus.VERIFIED
    assert vuln.validation_authority == "diff_auth_engine"
    assert len(vuln.evidence_artifact_ids) == 1
    assert len(vuln.merkle_leaf_hash) == 64


def test_evidence_artifact_merkle_leaf_hashing():
    req_body = b'{"action": "read", "id": 101}'
    resp_body = b'{"status": "ok", "data": "secret"}'
    req_sha = hashlib.sha256(req_body).hexdigest()
    resp_sha = hashlib.sha256(resp_body).hexdigest()

    merkle_leaf = hashlib.sha256(f"{req_sha}:{resp_sha}:eng-p1-test".encode()).hexdigest()

    artifact = EvidenceArtifact(
        engagement_id="eng-p1-test",
        finding_id="vuln-test-101",
        source_tool="diff_auth_engine",
        target_url="http://lab-target.local/api/v1/documents/doc-101",
        http_method="GET",
        request_headers_sha256="b" * 64,
        request_body_sha256=req_sha,
        response_status=200,
        response_headers_sha256="c" * 64,
        response_body_sha256=resp_sha,
        replay_recipe={
            "method": "GET",
            "url": "http://lab-target.local/api/v1/documents/doc-101",
            "headers": {"Authorization": "Bearer token-bob-secret-key-202"},
        },
        merkle_leaf_hash=merkle_leaf,
    )
    assert artifact.id.startswith("ev-")
    assert artifact.merkle_leaf_hash == merkle_leaf
    assert artifact.replay_recipe["method"] == "GET"
