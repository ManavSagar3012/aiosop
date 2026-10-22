"""Safe, independently checkable signed-report read API; no live app database."""

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from ai_osop.api.deps import state
from ai_osop.api.routers import report_attestations
from ai_osop.core.config import settings
from ai_osop.memory.authorization_store import AuthorizationDenied
from ai_osop.reporting.attestation import hash_evidence_snapshot, sign_report_attestation
from ai_osop.reporting.attested_storage import AttestedStorageUnavailable

SID = "eng-attested-api-test"
RID = f"report-{SID}-v1"
FID = "vuln-real-1"
EVIDENCE = [{"type": "http", "raw_request": "Authorization: Bearer HIDDEN-RAW-SECRET"}]


class _Result:
    def __init__(self, row):
        self.row = row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row


class _Database:
    def __init__(self):
        self.owner = "alice"
        self.missing = False
        self.error = None
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def begin(self):
        return self

    async def execute(self, statement, params):
        self.calls.append((str(statement), params))
        if self.error:
            raise self.error
        if "FROM session_states" in str(statement):
            return _Result(None if self.missing else {"session_id": SID, "created_by": self.owner})
        raise AssertionError("Unexpected DB SQL in route")


class _GraphSession:
    def __init__(self, fixture):
        self.fixture = fixture

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def run(self, statement, **params):
        self.fixture.graph_calls.append((statement, params))
        if self.fixture.graph_error:
            raise self.fixture.graph_error
        assert params == {"sid": SID, "finding_ids": [FID], "limit": 2}
        assert "v.validated = true" in statement
        assert "engagement_id: $sid" in statement
        rows = [
            {
                "finding_id": FID,
                "evidence": json.dumps(self.fixture.raw_evidence),
                "validated": True,
            }
        ]
        if self.fixture.graph_empty:
            rows = []
        return SimpleNamespace(data=AsyncMock(return_value=rows))


@pytest.fixture
def report_api(tmp_path, monkeypatch):
    root = tmp_path / "durable-signed-reports"
    folder = root / SID
    folder.mkdir(parents=True)
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pem = signer.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_path = tmp_path / "private_signer.pem"
    private_path.write_bytes(pem)
    monkeypatch.setenv("OSOP_ATTESTED_REPORT_ROOT", str(root.resolve()))
    monkeypatch.setenv("OSOP_REPORT_SIGNING_KEY_FILE", str(private_path))
    monkeypatch.setenv(
        "OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON",
        json.dumps(
            {
                "attester-key-1": base64.b64encode(public).decode("ascii"),
            }
        ),
    )
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "production-api-hs256-fixture")
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)

    files = {
        "md": b"# Restricted assessment - no raw evidence",
        "html": b"<html><body>Sanitized assessment</body></html>",
        "graph.html": b"<html><body>No validated exploit chain</body></html>",
        "json": json.dumps(
            {
                "findings": [
                    {
                        "id": FID,
                        "evidence_hash": hash_evidence_snapshot(EVIDENCE),
                    }
                ]
            }
        ).encode("utf-8"),
    }
    signed = sign_report_attestation(
        engagement_id=SID,
        report_id=RID,
        signer_key_id="attester-key-1",
        artifacts=files,
        evidence_provenance=[
            {
                "finding_id": FID,
                "source_type": "validated_engagement_graph",
                "evidence_sha256": hash_evidence_snapshot(EVIDENCE),
            }
        ],
    )
    envelope_bytes = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "engagement_id": SID,
        "report_id": RID,
        "hash_algorithm": "sha256",
        "signature_status": "ed25519_signed",
        "artifacts": {ext: hashlib.sha256(contents).hexdigest() for ext, contents in files.items()},
        "attestation_sha256": hashlib.sha256(envelope_bytes).hexdigest(),
    }
    for extension, contents in {
        **files,
        "attestation": envelope_bytes,
        "manifest": json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode(),
    }.items():
        (folder / f"{RID}.{extension}").write_bytes(contents)

    db = _Database()
    graph = SimpleNamespace(_driver=SimpleNamespace(session=lambda: _GraphSession(fixture)))
    orch = SimpleNamespace(
        session_memory=SimpleNamespace(_async_session=lambda: db), graph_memory=graph
    )
    monkeypatch.setitem(state, "orchestrator", orch)
    guard = AsyncMock(return_value=SimpleNamespace(session_id=SID, version=1))
    monkeypatch.setattr(report_attestations, "guard_sql", guard)
    app = FastAPI()
    app.include_router(report_attestations.router)
    client = TestClient(app)

    def headers(sub="alice", role="operator"):
        bearer = jwt.encode(
            {"sub": sub, "role": role, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        return {"Authorization": f"Bearer {bearer}"}

    fixture = SimpleNamespace(
        client=client,
        headers=headers,
        db=db,
        root=root,
        folder=folder,
        guard=guard,
        graph_calls=[],
        raw_evidence=EVIDENCE,
        graph_error=None,
        graph_empty=False,
        public=public,
        signed=signed,
        paths=files,
        manifest=manifest,
    )
    return fixture


def _get(fixture, sub="alice", role="operator", sid=SID, rid=RID):
    return fixture.client.get(
        f"/engagements/{sid}/attestations/{rid}", headers=fixture.headers(sub, role)
    )


def test_signed_bundle_owner_scoped_returns_only_safe_envelope_and_verified_provenance(report_api):
    response = _get(report_api)
    assert response.status_code == 200
    result = response.json()
    assert result["verification"] == {
        "status": "signature_and_snapshot_verified",
        "report_id": RID,
        "engagement_id": SID,
        "signer_key_id": "attester-key-1",
        "evidence_records_checked": 1,
        "source_authenticity_verified": False,
        "operator_approved": False,
        "exploit_success_verified": False,
    }
    assert result["manifest"] == report_api.manifest
    assert result["signed_attestation"] == report_api.signed
    assert result["signed_attestation"]["attestation"]["evidence_provenance"] == [
        {
            "finding_id": FID,
            "source_type": "validated_engagement_graph",
            "evidence_sha256": hash_evidence_snapshot(EVIDENCE),
        }
    ]
    assert "independent_verification" in result
    for forbidden in (
        "HIDDEN-RAW-SECRET",
        "BEGIN PRIVATE KEY",
        "raw_request",
        "created_by",
        "signed_roe",
        "authorization_ref",
    ):
        assert forbidden not in response.text
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    report_api.guard.assert_awaited_once_with(report_api.db, SID)
    assert len(report_api.graph_calls) == 1
    assert len(report_api.db.calls) == 1

    # Verify signature independently, not by trusting server's response label.
    signed = result["signed_attestation"]
    canonical = json.dumps(
        signed["attestation"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    raw = base64.urlsafe_b64decode(signed["signature"] + "==")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    Ed25519PublicKey.from_public_bytes(report_api.public).verify(raw, canonical)


@pytest.mark.parametrize(
    "sub,role,expected",
    [
        ("alice", "operator", 200),
        ("mallory", "operator", 403),
        ("mallory", "senior_operator", 200),
        ("alice", "viewer", 403),
    ],
)
def test_durable_owner_role_boundaries(report_api, sub, role, expected):
    response = _get(report_api, sub, role)
    assert response.status_code == expected
    if expected == 403:
        assert not report_api.graph_calls


def test_durable_owner_change_overrides_cached_operator(report_api):
    report_api.db.owner = "bob"
    assert _get(report_api).status_code == 403
    report_api.guard.assert_not_awaited()


@pytest.mark.parametrize("condition", ["revoked", "db_fail", "not_found"])
def test_denied_signed_trust_and_failed_durable_db_never_read_artifacts(
    report_api, condition, monkeypatch
):
    if condition == "revoked":
        report_api.guard.side_effect = AuthorizationDenied("revoked signer-secret-sentinel")
        expected = 403
    elif condition == "db_fail":
        report_api.db.error = RuntimeError("db-connection-password-sentinel")
        expected = 503
    else:
        report_api.db.missing = True
        expected = 404
    calls = []
    monkeypatch.setattr(
        report_attestations, "load_attested_bundle", lambda *args: calls.append(args)
    )
    response = _get(report_api)
    assert response.status_code == expected
    assert not calls
    assert "sentinel" not in response.text


@pytest.mark.parametrize(
    "attack",
    [
        "missing_manifest",
        "missing_attestation",
        "mutated_artifact",
        "mutated_evidence",
        "bad_manifest",
        "untrusted_signer",
        "graph_missing",
        "graph_down",
        "missing_root",
        "unsigned_manifest",
        "symlink",
    ],
)
def test_tampered_untrusted_or_missing_evidence_fails_closed(report_api, monkeypatch, attack):
    prefix = report_api.folder / RID
    if attack == "missing_manifest":
        (report_api.folder / f"{RID}.manifest").unlink()
    elif attack == "missing_attestation":
        (report_api.folder / f"{RID}.attestation").unlink()
    elif attack == "mutated_artifact":
        path = report_api.folder / f"{RID}.md"
        path.write_bytes(path.read_bytes() + b"\npost-signature modification")
    elif attack == "mutated_evidence":
        report_api.raw_evidence = [{"type": "other", "raw": "mismatch"}]
    elif attack == "bad_manifest":
        path = report_api.folder / f"{RID}.manifest"
        manifest = json.loads(path.read_text())
        manifest["attestation_sha256"] = "0" * 64
        path.write_text(json.dumps(manifest))
    elif attack == "untrusted_signer":
        monkeypatch.setenv("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON", "{}")
    elif attack == "graph_missing":
        report_api.graph_empty = True
    elif attack == "graph_down":
        report_api.graph_error = RuntimeError("graph-password-sentinel")
    elif attack == "missing_root":
        monkeypatch.delenv("OSOP_ATTESTED_REPORT_ROOT")
    elif attack == "unsigned_manifest":
        path = report_api.folder / f"{RID}.manifest"
        manifest = json.loads(path.read_text())
        manifest["signature_status"] = "not_signed"
        path.write_text(json.dumps(manifest))
    else:
        src = report_api.folder / f"{RID}.json"
        previous = Path.is_symlink
        monkeypatch.setattr(Path, "is_symlink", lambda path: path == src or previous(path))
    response = _get(report_api)
    assert response.status_code == 503
    assert "sentinel" not in response.text
    assert "PRIVATE" not in response.text
    assert "evidence_sha256" not in response.text


@pytest.mark.parametrize(
    "path",
    [
        "/engagements/eng-attested-api-test/attestations/../../etc/passwd",
        f"/engagements/{SID}/attestations/report-other-v1",
        f"/engagements/eng-other/attestations/{RID}",
        f"/engagements/{SID}/attestations/report-{SID}-v%2F1",
    ],
)
def test_untrusted_path_never_reaches_durable_db(report_api, path):
    response = report_api.client.get(path, headers=report_api.headers())
    assert response.status_code in {404, 422}
    assert not report_api.db.calls


def test_query_bearer_and_missing_auth_fail_before_db(report_api):
    url = f"/engagements/{SID}/attestations/{RID}"
    assert report_api.client.get(url).status_code == 403
    assert (
        report_api.client.get(url + "?token=sentinel", headers=report_api.headers()).status_code
        == 403
    )
    assert not report_api.db.calls


def test_root_must_be_absolute_and_signer_key_removed_denies(report_api, monkeypatch):
    monkeypatch.setenv("OSOP_ATTESTED_REPORT_ROOT", "reports")
    assert _get(report_api).status_code == 503
    monkeypatch.setenv("OSOP_ATTESTED_REPORT_ROOT", str(report_api.root))
    monkeypatch.delenv("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON")
    assert _get(report_api).status_code == 503


def test_bounded_files_never_expose_oversized_payloads(report_api):
    (report_api.folder / f"{RID}.md").write_bytes(b"X" * 2_000_001)
    response = _get(report_api)
    assert response.status_code == 503
    assert "XXXXX" not in response.text


def test_shared_dev_token_cannot_impersonate_a_signed_report_operator(report_api, monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret", None)
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "api_token", "legacy-shared-credential")
    response = report_api.client.get(
        f"/engagements/{SID}/attestations/{RID}",
        headers={"Authorization": "Bearer legacy-shared-credential"},
    )
    assert response.status_code == 503
    assert report_api.db.calls == []


def test_signed_report_rejects_nonexpiring_jwt(report_api):
    token = jwt.encode(
        {"sub": "alice", "role": "operator"},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    response = report_api.client.get(
        f"/engagements/{SID}/attestations/{RID}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert report_api.db.calls == []
