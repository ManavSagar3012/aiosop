"""Isolated ASGI qualification of ORIGINAL report handlers and senior custody.

The production API cannot be imported here (no SQLAlchemy/Neo4j/python-jose).
Instead the exact ORIGINAL decorated route function AST is compiled and
mounted onto a private in-memory FastAPI application.
Only external dependencies (JWT identity, PostgreSQL, graph) use isolated
doubles; actual report bytes, storage loader, report Ed25519 and generation
Task verifier run unmodified. This is NOT main.app, real JWT or live PG E2E.

No independently enrolled owner, replica, host or senior RELEASE signer is
created. A TEST-ONLY separate Ed25519 senior envelope never passes host/ledger
admission. No successful POST release or target effect is simulated.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import copy
import hashlib
import hmac
import json
import re
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from ai_osop.reporting import attestation
from ai_osop.reporting.attested_storage import (
    AttestedStorageUnavailable, load_attested_bundle, validated_report_id,
    verify_loaded_bundle,
)
from ai_osop.safety import independent_release_authority as senior_release
from ai_osop.safety import production_release_admission as production_admission
from ai_osop.safety.approval_binding import task_payload_sha256
from tests.test_production_release_admission_20261021 import (
    ENG, FINDING, FLOW, REPORT, _call, _pub, _sha, _signed_claim,
    case as original_signed_case,
)


ROOT = Path(__file__).resolve().parents[2]
ROUTER_FILE = ROOT / "src/ai_osop/api/routers/report_attestations.py"
MAIN_FILE = ROOT / "src/ai_osop/api/main.py"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _ReadResult:
    def __init__(self, row: Optional[dict[str, Any]]) -> None:
        self.row = row

    def mappings(self) -> "_ReadResult":
        return self

    def one_or_none(self) -> Optional[dict[str, Any]]:
        return copy.deepcopy(self.row)


class _ReadOnlyDB:
    """Durable row-shape fixture, never app database nor SQL executor."""

    def __init__(self, case: SimpleNamespace) -> None:
        self.case = case
        self.owner = case.claim["senior_sub"]
        self.operator_sub = self.owner
        self.role = "senior_operator"
        self.revoke_scope = False
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.writes = 0
        self.auth_checks = 0
        self.flow_revision = 3
        self.task_receipt_bad = False

    async def __aenter__(self) -> "_ReadOnlyDB":
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    def begin(self) -> "_ReadOnlyDB":
        return self

    async def execute(self, query: str, params: dict[str, Any]) -> _ReadResult:
        sql = str(query)
        if not (sql.lstrip().upper().startswith("SELECT ") and "FOR SHARE" in sql):
            self.writes += 1
            pytest.fail("Original report HTTP test crossed a write boundary: " + sql)
        self.queries.append((sql, dict(params)))
        if "FROM session_states" in sql:
            return _ReadResult({"session_id": ENG, "created_by": self.owner})
        if "FROM execution_flows" in sql:
            return _ReadResult({
                "id": FLOW, "engagement_id": ENG,
                "revision": self.flow_revision, "status": "running",
            })
        if "FROM tasks" in sql:
            envelope = json.loads(self.case.originals["attestation"])["attestation"]
            task_payload = {
                "require_attestation": True, "signer_key_id": "test-reporter",
                "version": "r1", "_authorization_version": 1, "_flow_revision": 3,
            }
            assert envelope["generation_binding"]["task_payload_sha256"] == (
                task_payload_sha256(task_payload)
            )
            hashes = {kind: _sha(blob) for kind, blob in self.case.originals.items()}
            if self.task_receipt_bad:
                hashes["manifest"] = "0" * 64
            return _ReadResult({
                "id": envelope["generation_binding"]["task_id"],
                "engagement_id": ENG,
                "type": "generate_report", "agent_type": "reporting",
                "status": "completed", "payload": task_payload,
                "result": {
                    "status": "success", "signature_status": "ed25519_signed",
                    "report_id": REPORT, "requires_approval": True,
                    "artifact_sha256": hashes,
                },
                "started_at": "read-only-fixture-start",
                "completed_at": "read-only-fixture-complete",
                "flow_id": FLOW, "subtask_id": None, "approval_required": True,
            })
        pytest.fail("Unexpected SQL boundary in mounted original handler: " + sql)


class _RevokedAuthorization(Exception):
    pass


class _SupervisionConflict(Exception):
    pass


def _build_isolated_original_asgi(
    case: SimpleNamespace,
) -> tuple[FastAPI, _ReadOnlyDB, dict[str, Any]]:
    """Compile source AST, retaining ALL original HTTP handler decorators/body.

    This is deliberately NOT an import of main.app and does NOT substitute
    implementation body, target-owner signatures or forged success flags.
    """
    source = ROUTER_FILE.read_text(encoding="utf-8")
    syntax = ast.parse(source, filename=str(ROUTER_FILE))
    names = (
        "_refuse_unsupported_target_promotion",
        "_verify_generation_release",
        "_release_key",
        "_attested_nonempty_findings",
        "_verify_signed_finding_sources",
        "_verified_final_release_candidate",
        "get_signed_report_attestation",
        "get_signed_report_release_status",
        "download_verified_signed_report_artifact",
        "approve_signed_report_release",
    )
    definitions = {
        node.name: node
        for node in syntax.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    assert all(name in definitions for name in names + ("FinalReportSignoff",))
    db = _ReadOnlyDB(case)

    async def _operator() -> dict[str, Any]:
        # External JWT only. Explicitly not a test of authentication middleware.
        return {
            "sub": db.operator_sub,
            "role": db.role,
            "_reviewer_token_sha256": "f" * 64,
            "_reviewer_expires_at": int(time.time()) + 60,
        }

    async def _guard_sql(
        actual_db: _ReadOnlyDB,
        engagement_id: str,
        expected_version: Optional[int] = None,
    ) -> SimpleNamespace:
        assert actual_db is db and engagement_id == ENG
        db.auth_checks += 1
        if db.revoke_scope or (expected_version is not None and expected_version != 1):
            raise _RevokedAuthorization("signed scope revoked")
        return SimpleNamespace(
            session_id=ENG, version=1, policy_sha256="e" * 64,
            authorization_id="auth-custody-only",
        )

    async def _evidence(
        graph: Any, engagement_id: str, loaded: dict[str, Any],
        *, source_records: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        assert engagement_id == ENG and graph is None and loaded["attestation"]
        # Fixture graph bytes reproduce the saved evidence, NOT authenticated
        # target-owner observations or signed source lineage.
        if source_records is not None:
            source_records.clear()
        return copy.deepcopy(case.evidence)

    namespace: dict[str, Any] = {
        "__name__": "qualification_isolated_original_report_handlers",
        "__builtins__": __builtins__,
        "router": APIRouter(prefix="/engagements", tags=["signed-report-attestations"]),
        "APIRouter": APIRouter, "Depends": Depends, "Response": Response,
        "HTTPException": HTTPException, "BaseModel": BaseModel,
        "ConfigDict": ConfigDict, "Field": Field, "StrictInt": StrictInt,
        "Dict": Dict, "Optional": Optional, "Any": Any,
        "asyncio": asyncio, "hmac": hmac, "hashlib": hashlib, "json": json,
        "re": re, "datetime": datetime, "timezone": timezone,
        "state": {"orchestrator": SimpleNamespace(
            session_memory=SimpleNamespace(_async_session=lambda: db),
            graph_memory=None,
        )},
        "_report_operator": _operator,
        "guard_sql": _guard_sql,
        "AuthorizationDenied": _RevokedAuthorization,
        "_graph_evidence": _evidence,
        "load_attested_bundle": load_attested_bundle,
        "verify_loaded_bundle": verify_loaded_bundle,
        "validated_report_id": validated_report_id,
        "AttestedStorageUnavailable": AttestedStorageUnavailable,
        "ReportAttestationError": attestation.ReportAttestationError,
        "_unique_object_pairs": attestation._unique_object_pairs,
        "ARTIFACT_ALLOWLIST": attestation.ARTIFACT_ALLOWLIST,
        "SCHEMA_V3": attestation.SCHEMA_V3,
        "task_payload_sha256": task_payload_sha256,
        "text": lambda sql: sql,
        "select": lambda *args: pytest.fail("No release event selection is justified"),
        "SupervisionConflict": _SupervisionConflict,
        "SupervisionStore": None,
        "SupervisionEventORM": None,
        "_safe_payload": lambda value: value,
        "_REPORT_TIMEOUT_SECONDS": 5.0,
        "_SOURCE_BINDING_FIELDS": (
            "source_task_id", "source_task_sha256", "flow_id", "flow_revision",
            "authorization_version", "authorization_sha256", "source_event_id",
            "provider_receipt_sha256",
        ),
        "_SOURCE_ID": re.compile(r"task-[A-Za-z0-9._-]{1,78}\Z"),
        "_EVENT_ID": re.compile(r"evt-[A-Za-z0-9._-]{1,60}\Z"),
        "_SHA": re.compile(r"[0-9a-f]{64}\Z"),
        "_COMPARISON_SOURCE_TYPES": frozenset(),
        "_COMPARISON_OUTCOMES": frozenset(),
    }
    unsupported = next(
        node for node in syntax.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and
                target.id == "_UNSUPPORTED_TARGET_AUTHORITY_CLAIMS"
                for target in node.targets)
    )
    sequence = [
        unsupported, definitions["FinalReportSignoff"],
        *(definitions[name] for name in names),
    ]
    # Pydantic v2 resolves annotations using the defining module's namespace.
    # This ephemeral test-only module contains the real extracted definitions
    # but is NOT registered as an API or installed into the application.
    module = types.ModuleType(namespace["__name__"])
    module.__dict__.update(namespace)
    namespace = module.__dict__
    sys.modules[module.__name__] = module
    compiled = ast.fix_missing_locations(ast.Module(body=sequence, type_ignores=[]))
    exec(compile(compiled, str(ROUTER_FILE), "exec"), namespace)
    api = FastAPI()
    api.include_router(namespace["router"])
    return api, db, namespace


def _urls() -> dict[str, str]:
    prefix = f"/engagements/{ENG}/attestations/{REPORT}"
    return {
        "attestation": prefix,
        "release": prefix + "/release",
        "artifact": prefix + "/artifacts/json",
    }


async def _http(app: FastAPI, method: str, path: str, **kwargs: Any) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://qualification.invalid",
        timeout=10.0,
    ) as client:
        return await client.request(method, path, **kwargs)


def _signoff(case: SimpleNamespace) -> dict[str, Any]:
    return {
        "expected_authorization_version": 1,
        "expected_attestation_sha256": _sha(case.originals["attestation"]),
        "reason": "Test-only signed snapshot review; no original target proof",
        "approval_statement": "I approve releasing this exact signed report snapshot",
    }


def test_real_main_mount_source_and_exact_route_templates(
    original_signed_case: SimpleNamespace,
) -> None:
    assert "app.include_router(report_attestations.router)" in MAIN_FILE.read_text(
        encoding="utf-8"
    )
    api, _, namespace = _build_isolated_original_asgi(original_signed_case)
    route_map = {
        (route.path, method)
        for route in api.routes
        for method in getattr(route, "methods", frozenset())
    }
    assert (
        "/engagements/{session_id}/attestations/{report_id}", "GET"
    ) in route_map
    assert (
        "/engagements/{session_id}/attestations/{report_id}/release", "GET"
    ) in route_map
    assert (
        "/engagements/{session_id}/attestations/{report_id}/release", "POST"
    ) in route_map
    assert (
        "/engagements/{session_id}/attestations/{report_id}/artifacts/{artifact_kind}",
        "GET",
    ) in route_map
    assert "verify_current_release_ledger_join" not in namespace


@pytest.mark.anyio
async def test_original_signed_v3_http_attestation_is_snapshot_only(
    original_signed_case: SimpleNamespace,
) -> None:
    api, db, _ = _build_isolated_original_asgi(original_signed_case)
    response = await _http(api, "GET", _urls()["attestation"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["release_status"] == "signed_report_task_snapshot_verified"
    assert body["independent_target_authority_verified"] is False
    assert body["finding_release_eligible"] is False
    assert body["operator_approval_verified"] is False
    assert body["verification"]["operator_approved"] is False
    assert body["verification"]["source_authenticity_verified"] is False
    assert body["verification"]["exploit_success_verified"] is False
    assert body["manifest"]["attestation_sha256"] == _sha(
        original_signed_case.originals["attestation"]
    )
    assert response.headers["cache-control"] == "private, no-store"
    assert not db.writes
    assert any("FROM tasks" in sql for sql, _ in db.queries)
    assert any("FROM execution_flows" in sql for sql, _ in db.queries)


@pytest.mark.anyio
@pytest.mark.parametrize("method,kind", [
    ("GET", "release"), ("POST", "release"), ("GET", "artifact"),
])
async def test_http_release_and_download_denied_without_0022_current_owner(
    original_signed_case: SimpleNamespace, method: str, kind: str,
) -> None:
    api, db, _ = _build_isolated_original_asgi(original_signed_case)
    kwargs = {"json": _signoff(original_signed_case)} if method == "POST" else {}
    response = await _http(api, method, _urls()[kind], **kwargs)
    assert response.status_code == 503, response.text
    assert "release_event_id" not in response.text
    assert "human_release_approved" not in response.text
    assert not db.writes
    assert any("FROM tasks" in sql for sql, _ in db.queries)
    assert db.auth_checks >= 1


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", [
    "manifest_whitespace", "manifest_reordered",
    "json_mutation", "attestation_signature", "artifact_receipt",
])
async def test_original_bytes_and_receipt_tamper_fail_http(
    original_signed_case: SimpleNamespace, mutation: str,
) -> None:
    api, db, _ = _build_isolated_original_asgi(original_signed_case)
    directory = original_signed_case.folder
    if mutation == "manifest_whitespace":
        target = directory / f"{REPORT}.manifest"
        target.write_bytes(target.read_bytes() + b"\n")
    elif mutation == "manifest_reordered":
        target = directory / f"{REPORT}.manifest"
        original = json.loads(target.read_bytes())
        target.write_bytes(json.dumps(
            dict(reversed(list(original.items()))),
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8"))
    elif mutation == "json_mutation":
        target = directory / f"{REPORT}.json"
        target.write_bytes(target.read_bytes() + b" ")
    elif mutation == "attestation_signature":
        target = directory / f"{REPORT}.attestation"
        envelope = json.loads(target.read_bytes())
        envelope["signature"] = "A" * 86
        target.write_bytes(attestation._canonical(envelope))
    else:
        db.task_receipt_bad = True
    response = await _http(api, "GET", _urls()["attestation"])
    assert response.status_code == 503, response.text
    assert not db.writes
    if mutation.startswith("manifest_"):
        with pytest.raises(AttestedStorageUnavailable):
            load_attested_bundle(ENG, REPORT)
    if mutation == "artifact_receipt":
        assert any("FROM tasks" in sql for sql, _ in db.queries)


@pytest.mark.anyio
@pytest.mark.parametrize("attack", [
    "signed_roe_revoked", "wrong_owner", "report_key_revoked",
    "wrong_flow_revision", "operator_not_senior",
])
async def test_http_current_authority_and_report_trust_revocations(
    original_signed_case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    api, db, _ = _build_isolated_original_asgi(original_signed_case)
    if attack == "signed_roe_revoked":
        db.revoke_scope = True
    elif attack == "wrong_owner":
        db.owner = "not-the-authorized-session-owner"
        # Keep operator identity constant; only current durable owner changes.
    elif attack == "report_key_revoked":
        monkeypatch.delenv("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON", raising=False)
    elif attack == "wrong_flow_revision":
        db.flow_revision = 22
    else:
        db.role = "operator"
    endpoint = _urls()["release"]
    response = await _http(
        api, "POST", endpoint, json=_signoff(original_signed_case),
    )
    assert response.status_code in (403, 503), response.text
    assert not db.writes
    if attack == "operator_not_senior":
        assert response.status_code == 403


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", [
    "forged_report_as_senior", "expired_senior", "missing_target_owner",
    "senior_claim_replayed", "unavailable_host_ledger",
])
async def test_independently_signed_senior_not_promoted_by_mounted_http(
    original_signed_case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    case = original_signed_case
    claim = copy.deepcopy(case.claim)
    signer = case.senior
    if mutation == "forged_report_as_senior":
        signer = case.reporter
    elif mutation == "expired_senior":
        now = int(time.time())
        claim["issued_at"], claim["expires_at"] = now - 400, now - 200
    elif mutation == "missing_target_owner":
        claim["target_owner_receipts"] = []
    elif mutation == "senior_claim_replayed":
        # A previous syntactically signed claim still needs current one-use
        # durable release receipt/ACK finality. No such ledger is enrolled.
        pass
    signed = _signed_claim(claim, signer)
    # Valid signature math and role separation do NOT assert enrollment.
    if mutation in ("senior_claim_replayed", "unavailable_host_ledger"):
        checked = senior_release._verify_signature(
            senior_release._json(signed), case.trust.senior_public_key,
            domain=senior_release.RELEASE_DOMAIN,
        )
        assert checked == claim
        assert _pub(case.senior) != _pub(case.reporter)
        fake_sql = types.ModuleType("sqlalchemy")
        fake_sql.text = lambda sql: sql
        monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sql)
    with pytest.raises(production_admission.ProductionReleaseDenied):
        await _call(case, signed=signed)
    # Neither signed senior bytes nor untrusted test headers are an input to
    # mounted report release. Actual current 0022 target authority is missing.
    api, db, namespace = _build_isolated_original_asgi(case)
    sent = base64.urlsafe_b64encode(signed).decode("ascii")
    response = await _http(
        api, "GET", _urls()["release"],
        headers={"X-Independent-Senior-Release": sent},
    )
    assert response.status_code == 503, response.text
    assert "verify_current_release_ledger_join" not in namespace
    assert not db.writes
    assert "human_release_approved" not in response.text


@pytest.mark.anyio
async def test_original_report_http_readback_ignores_lost_ack_without_owner_evidence(
    original_signed_case: SimpleNamespace,
) -> None:
    api, db, _ = _build_isolated_original_asgi(original_signed_case)
    one = await _http(api, "GET", _urls()["release"])
    two = await _http(api, "GET", _urls()["release"])
    assert (one.status_code, two.status_code) == (503, 503)
    assert one.json() == two.json()
    assert db.writes == 0
    assert db.auth_checks == 2
