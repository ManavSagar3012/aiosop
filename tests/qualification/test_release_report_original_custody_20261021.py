"""Read-only custody/release qualification of the ORIGINAL signed report paths.

This suite calls production report storage and signature verification. For the
API's private read-only candidate it executes the unchanged function AST with
in-memory DB/graph boundary doubles because this test Python lacks SQLAlchemy
and Neo4j. Only a disposable REPORT-attestation fixture key is generated.
No senior, target-owner, provider, host or replica release signer is minted.
No real approval/release event is appended and no application DB is accessed.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import copy
import hashlib
import json
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Dict, Optional

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from ai_osop.reporting import attestation
from ai_osop.reporting.attested_storage import (
    AttestedStorageUnavailable,
    load_attested_bundle,
    verify_loaded_bundle,
)
from ai_osop.safety import independent_release_authority as senior_release
from ai_osop.safety.approval_binding import task_payload_sha256

ROOT = Path(__file__).resolve().parents[2]
ROUTER_PATH = ROOT / "src/ai_osop/api/routers/report_attestations.py"
SUPERVISION_PATH = ROOT / "src/ai_osop/memory/supervision_store.py"
MIGRATION_ROOT = ROOT / "migrations/versions"
EFFECT_STORE_PATH = ROOT / "src/ai_osop/memory/independent_target_effect_verifications.py"
SID = "eng-original-custody-20261021"
RID = f"report-{SID}-v3"
FLOW = "flow-original-custody"
FINDING = "finding-custody"
POLICY = "a" * 64
TASK = "task-original-report"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_ast(*names: str) -> dict[str, Any]:
    """Load exact existing read-only route function bodies, without imports.

    This is not an ASGI or PostgreSQL test; the real router imports unavailable
    app services in this isolated interpreter. A source change alters executed
    code, rather than a reimplemented test copy silently continuing to pass.
    """
    tree = ast.parse(ROUTER_PATH.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    missing = set(names) - set(functions)
    assert not missing, f"Production route functions disappeared: {sorted(missing)}"
    unsupported = next(
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_UNSUPPORTED_TARGET_AUTHORITY_CLAIMS"
                for t in node.targets)
    )
    namespace: dict[str, Any] = {
        "__builtins__": __builtins__,
        "Any": Any, "Dict": Dict, "Optional": Optional,
        "json": json, "hashlib": hashlib, "re": re, "asyncio": asyncio,
        "hmac": __import__("hmac"),
        "text": lambda statement: statement,
        "HTTPException": HTTPException,
        "AttestedStorageUnavailable": AttestedStorageUnavailable,
        "ReportAttestationError": attestation.ReportAttestationError,
        "ARTIFACT_ALLOWLIST": attestation.ARTIFACT_ALLOWLIST,
        "SCHEMA_V3": attestation.SCHEMA_V3,
        "_unique_object_pairs": attestation._unique_object_pairs,
        "task_payload_sha256": task_payload_sha256,
        "load_attested_bundle": load_attested_bundle,
        "verify_loaded_bundle": verify_loaded_bundle,
    }
    module = ast.Module(body=[unsupported, *(functions[name] for name in names)], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(ROUTER_PATH), "exec"), namespace)
    return namespace


@pytest.fixture
def report_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    # Fixture-only REPORT signature. No test creates a release/senior signer.
    reporter = Ed25519PrivateKey.generate()
    public = reporter.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = "fixture-report-root"
    monkeypatch.setenv(
        "OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON",
        json.dumps({kid: base64.b64encode(public).decode("ascii")}),
    )
    root = tmp_path / "reports"
    folder = root / SID
    folder.mkdir(parents=True)
    monkeypatch.setenv("OSOP_ATTESTED_REPORT_ROOT", str(root.resolve()))
    original_evidence = [{"source": "signed-fixture-only", "observation": "not target proof"}]
    evidence = {FINDING: original_evidence}
    evidence_hash = attestation.hash_evidence_snapshot(original_evidence)
    payload = {
        "version": "v3", "signer_key_id": kid, "require_attestation": True,
        "_authorization_version": 4, "_flow_revision": 3,
    }
    artifacts = {
        "md": b"# Custody report\nNot independently certified.\n",
        "html": b"<h1>Custody report</h1>",
        "graph.html": b"<div>Graph snapshot (unverified source)</div>",
        "json": attestation._canonical({
            "engagement_id": SID,
            "requires_approval": True,
            "verification_status": "verified_findings_only",
            "findings": [{"id": FINDING, "evidence_hash": evidence_hash}],
        }),
    }
    bound = {
        "task_id": TASK, "authorization_version": 4,
        "authorization_sha256": POLICY,
        "task_payload_sha256": task_payload_sha256(payload),
        "flow_id": FLOW, "flow_revision": 3,
    }
    attested = attestation._build_payload(
        engagement_id=SID, report_id=RID, signer_key_id=kid,
        artifacts=artifacts,
        provenance=[{
            "finding_id": FINDING,
            "source_type": "validated_engagement_graph",
            "evidence_sha256": evidence_hash,
        }],
        generation_binding=bound,
    )
    envelope = {
        "attestation": attested,
        "signature": base64.urlsafe_b64encode(
            reporter.sign(attestation._canonical(attested))
        ).rstrip(b"=").decode("ascii"),
    }
    original_attestation = attestation._canonical(envelope)
    manifest = {
        "engagement_id": SID, "report_id": RID,
        "hash_algorithm": "sha256", "signature_status": "ed25519_signed",
        "artifacts": attested["artifacts"],
        "attestation_sha256": _sha(original_attestation),
    }
    original_manifest = attestation._canonical(manifest)
    originals = {
        **artifacts, "attestation": original_attestation, "manifest": original_manifest,
    }
    for kind, content in originals.items():
        (folder / f"{RID}.{kind}").write_bytes(content)
    task = {
        "id": TASK, "engagement_id": SID, "type": "generate_report",
        "agent_type": "reporting", "status": "completed",
        "payload": payload, "result": {
            "status": "success", "signature_status": "ed25519_signed",
            "report_id": RID, "requires_approval": True,
            "artifact_sha256": {kind: _sha(blob) for kind, blob in originals.items()},
        },
        "started_at": "synthetic-start", "completed_at": "synthetic-end",
        "flow_id": FLOW, "subtask_id": None, "approval_required": True,
    }
    return SimpleNamespace(
        directory=folder, originals=originals, evidence=evidence,
        task=task, reporter_key_id=kid,
    )


class _Rows:
    def __init__(self, row: Optional[dict[str, Any]]) -> None:
        self.row = row

    def mappings(self) -> "_Rows":
        return self

    def one_or_none(self) -> Optional[dict[str, Any]]:
        return copy.deepcopy(self.row)


class _ReadOnlyDB:
    def __init__(self, fixture: SimpleNamespace) -> None:
        self.owner = "senior-owner"
        self.flow_revision = 3
        self.flow_status = "running"
        self.task = copy.deepcopy(fixture.task)
        self.queries: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, statement: str, params: dict[str, Any]) -> _Rows:
        sql = str(statement)
        self.queries.append((sql, dict(params)))
        assert sql.strip().upper().startswith("SELECT "), "Only read-only SQL is allowed"
        assert "FOR SHARE" in sql, "Current authority must hold shared row fences"
        if "FROM session_states" in sql:
            return _Rows({"session_id": SID, "created_by": self.owner})
        if "FROM tasks" in sql:
            return _Rows(self.task)
        if "FROM execution_flows" in sql:
            return _Rows({
                "id": FLOW, "engagement_id": SID,
                "status": self.flow_status, "revision": self.flow_revision,
            })
        pytest.fail("Unexpected SQL in production read-only candidate: " + sql)


class _DeniedROE(Exception):
    pass


def _candidate(report_fixture: SimpleNamespace, db: _ReadOnlyDB) -> dict[str, Any]:
    ns = _source_ast(
        "_refuse_unsupported_target_promotion",
        "_verify_generation_release",
        "_verify_signed_finding_sources",
        "_verified_final_release_candidate",
    )
    ns["AuthorizationDenied"] = _DeniedROE
    ns["signed_calls"] = 0
    ns["signed_authorization"] = SimpleNamespace(
        session_id=SID, authorization_id="auth-original-custody",
        version=4, policy_sha256=POLICY,
    )

    async def guard_sql(
        actual_db: _ReadOnlyDB, sid: str, expected_version: Optional[int] = None
    ) -> SimpleNamespace:
        assert actual_db is db and sid == SID
        ns["signed_calls"] += 1
        if expected_version is not None and expected_version != 4:
            raise _DeniedROE("Version invalid")
        if ns.get("revoke_on_second") and ns["signed_calls"] > 1:
            raise _DeniedROE("Signed ROE revoked during external check")
        return ns["signed_authorization"]

    async def independent_graph(
        graph: Any, sid: str, loaded: dict[str, Any],
        *, source_records: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        assert sid == SID and graph is None and loaded["artifacts"]
        # This fixture reproduces an already fetched graph snapshot. It has NO
        # current owner-side witness or verified MCP/task source provenance.
        if source_records is not None:
            source_records.clear()
        return copy.deepcopy(report_fixture.evidence)

    ns["guard_sql"] = guard_sql
    ns["_graph_evidence"] = independent_graph
    ns["_SOURCE_BINDING_FIELDS"] = (
        "source_task_id", "source_task_sha256", "flow_id", "flow_revision",
        "authorization_version", "authorization_sha256",
        "source_event_id", "provider_receipt_sha256",
    )
    orch = SimpleNamespace(
        graph_memory=None,
        session_memory=SimpleNamespace(
            load_task_authoritative=lambda *_: None,
            load_flow=lambda *_: None,
            verify_signed_graph_action=lambda *_: False,
        ),
    )
    ns["orch"] = orch
    return ns


def test_exact_original_disk_bytes_pass_only_report_snapshot_verification(
    report_fixture: SimpleNamespace
) -> None:
    loaded = load_attested_bundle(SID, RID)
    assert loaded["attestation_sha256"] == _sha(report_fixture.originals["attestation"])
    assert loaded["manifest_sha256"] == _sha(report_fixture.originals["manifest"])
    assert loaded["artifacts"] == {
        kind: report_fixture.originals[kind]
        for kind in attestation.ARTIFACT_ALLOWLIST
    }
    result = verify_loaded_bundle(
        loaded, session_id=SID, report_id=RID,
        evidence_by_finding=report_fixture.evidence,
    )
    assert result["release_status"] == "generation_binding_pending_verification"
    assert result["operator_approval_verified"] is False
    assert result["verification"]["source_authenticity_verified"] is False
    assert result["verification"]["exploit_success_verified"] is False


@pytest.mark.parametrize("kind", ["md", "html", "graph.html", "json", "attestation"])
def test_original_byte_change_blocks_report_verification(
    report_fixture: SimpleNamespace, kind: str
) -> None:
    path = report_fixture.directory / f"{RID}.{kind}"
    raw = path.read_bytes()
    path.write_bytes(raw + b" ")
    loaded = load_attested_bundle(SID, RID)
    with pytest.raises(AttestedStorageUnavailable):
        verify_loaded_bundle(
            loaded, session_id=SID, report_id=RID,
            evidence_by_finding=report_fixture.evidence,
        )


@pytest.mark.anyio
async def test_manifest_original_byte_change_requires_generation_task_receipt(
    report_fixture: SimpleNamespace
) -> None:
    # The production loader must now reject a byte-different, semantically
    # equivalent ORIGINAL manifest BEFORE returning any parsed snapshot.
    path = report_fixture.directory / f"{RID}.manifest"
    before = path.read_bytes()
    path.write_bytes(before + b" ")
    assert json.loads(path.read_bytes()) == json.loads(before)
    with pytest.raises(AttestedStorageUnavailable):
        load_attested_bundle(SID, RID)


@pytest.mark.anyio
async def test_generation_task_still_rejects_stale_manifest_sha_if_loader_bypassed(
    report_fixture: SimpleNamespace
) -> None:
    # Separate defense in depth: call the UNCHANGED production generation
    # Task+Flow verification body directly on a saved snapshot whose manifest
    # digest is forged after a successful canonical on-disk read. This does NOT
    # bypass real storage in production or mint a human release approval.
    loaded = load_attested_bundle(SID, RID)
    assert verify_loaded_bundle(
        loaded, session_id=SID, report_id=RID,
        evidence_by_finding=report_fixture.evidence,
    )["release_status"] == "generation_binding_pending_verification"
    loaded["manifest_sha256"] = "0" * 64
    assert loaded["manifest_sha256"] != _sha(report_fixture.originals["manifest"])
    db = _ReadOnlyDB(report_fixture)
    ns = _candidate(report_fixture, db)
    with pytest.raises(AttestedStorageUnavailable, match="artifact receipt"):
        await ns["_verify_generation_release"](
            db, session_id=SID, report_id=RID,
            loaded=loaded, current_authorization=ns["signed_authorization"],
        )
    assert any("FROM tasks" in sql for sql, _ in db.queries)
    assert any("FROM execution_flows" in sql for sql, _ in db.queries)


@pytest.mark.parametrize(
    "mutation",
    [
        "trailing_space", "leading_space", "trailing_newline", "indent",
        "reverse_key_order", "alternate_separators", "ascii_escape",
        "utf8_bom", "duplicate_key", "nonfinite_value",
    ],
)
def test_manifest_noncanonical_original_encoding_denied_before_snapshot(
    report_fixture: SimpleNamespace, mutation: str
) -> None:
    # Real on-disk fixture is written in the exact ReportingAgent writer form.
    # Every mutation either retains semantic JSON (first eight cases, except
    # BOM) or is structurally unsafe (duplicate keys / nonfinite literal).
    # No later Task SHA proof should be needed for an invalid original.
    path = report_fixture.directory / f"{RID}.manifest"
    original = path.read_bytes()
    decoded = json.loads(original)
    if mutation == "trailing_space":
        changed = original + b" "
    elif mutation == "leading_space":
        changed = b" " + original
    elif mutation == "trailing_newline":
        changed = original + b"\n"
    elif mutation == "indent":
        changed = json.dumps(decoded, indent=2, ensure_ascii=False).encode("utf-8")
    elif mutation == "reverse_key_order":
        changed = json.dumps(
            {key: decoded[key] for key in reversed(list(decoded))},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
    elif mutation == "alternate_separators":
        changed = json.dumps(decoded, sort_keys=True).encode("utf-8")
    elif mutation == "ascii_escape":
        changed = original.replace(b'"sha256"', b'"\\u0073ha256"', 1)
    elif mutation == "utf8_bom":
        changed = b"\xef\xbb\xbf" + original
    elif mutation == "duplicate_key":
        changed = original[:-1] + b',"hash_algorithm":"sha256"}'
    else:
        changed = original[:-1] + b',"unknown_float":NaN}'
    assert changed != original
    if mutation in {
        "trailing_space", "leading_space", "trailing_newline",
        "indent", "reverse_key_order", "alternate_separators", "ascii_escape",
    }:
        assert json.loads(changed) == decoded
    path.write_bytes(changed)
    with pytest.raises(AttestedStorageUnavailable):
        load_attested_bundle(SID, RID)


def test_semantically_same_attestation_reencoding_changes_original_custody_digest(
    report_fixture: SimpleNamespace
) -> None:
    path = report_fixture.directory / f"{RID}.attestation"
    original = path.read_bytes()
    rewritten = json.dumps(json.loads(original), indent=2).encode("utf-8")
    assert json.loads(rewritten) == json.loads(original)
    assert rewritten != original
    path.write_bytes(rewritten)
    loaded = load_attested_bundle(SID, RID)
    assert loaded["attestation_sha256"] != _sha(original)
    with pytest.raises(AttestedStorageUnavailable):
        verify_loaded_bundle(
            loaded, session_id=SID, report_id=RID,
            evidence_by_finding=report_fixture.evidence,
        )


def test_current_report_signer_revocation_invalidates_cached_original_bundle(
    report_fixture: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = load_attested_bundle(SID, RID)
    verify_loaded_bundle(
        original, session_id=SID, report_id=RID,
        evidence_by_finding=report_fixture.evidence,
    )
    monkeypatch.delenv("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON", raising=False)
    with pytest.raises(AttestedStorageUnavailable):
        verify_loaded_bundle(
            original, session_id=SID, report_id=RID,
            evidence_by_finding=report_fixture.evidence,
        )


@pytest.mark.parametrize("replacement", [[], [{"source": "untrusted", "observation": "forged"}]])
def test_graph_evidence_absence_or_substitution_blocks_original(
    report_fixture: SimpleNamespace, replacement: list[dict[str, Any]]
) -> None:
    loaded = load_attested_bundle(SID, RID)
    with pytest.raises(AttestedStorageUnavailable):
        verify_loaded_bundle(
            loaded, session_id=SID, report_id=RID,
            evidence_by_finding={FINDING: replacement},
        )


@pytest.mark.anyio
async def test_actual_original_read_candidate_refuses_unproven_0016_0021_0022_source(
    report_fixture: SimpleNamespace
) -> None:
    db = _ReadOnlyDB(report_fixture)
    ns = _candidate(report_fixture, db)
    with pytest.raises(AttestedStorageUnavailable, match="source provenance unverified"):
        await ns["_verified_final_release_candidate"](
            db, ns["orch"], SID, RID,
            {"sub": "senior-owner", "role": "senior_operator"},
        )
    assert any("FROM tasks" in q for q, _ in db.queries)
    assert any("FROM execution_flows" in q for q, _ in db.queries)
    assert ns["signed_calls"] == 1


@pytest.mark.anyio
@pytest.mark.parametrize("attack", [
    "wrong_owner", "flow_revision", "halted_flow", "generation_task_changed",
    "tampered_receipt", "uncompleted_task",
])
async def test_actual_generation_task_and_flow_custody_join_denies_mutations(
    report_fixture: SimpleNamespace, attack: str
) -> None:
    db = _ReadOnlyDB(report_fixture)
    if attack == "wrong_owner":
        db.owner = "another-owner"
    elif attack == "flow_revision":
        db.flow_revision += 1
    elif attack == "halted_flow":
        db.flow_status = "halted"
    elif attack == "generation_task_changed":
        db.task["payload"]["version"] = "substituted"
    elif attack == "tampered_receipt":
        db.task["result"]["artifact_sha256"]["attestation"] = "0" * 64
    elif attack == "uncompleted_task":
        db.task["status"] = "running"
    ns = _candidate(report_fixture, db)
    expected = HTTPException if attack == "wrong_owner" else AttestedStorageUnavailable
    with pytest.raises(expected):
        await ns["_verified_final_release_candidate"](
            db, ns["orch"], SID, RID,
            {"sub": "senior-owner", "role": "senior_operator"},
        )


@pytest.mark.anyio
async def test_current_roe_revoked_after_independent_source_wait_denies(
    report_fixture: SimpleNamespace
) -> None:
    db = _ReadOnlyDB(report_fixture)
    ns = _candidate(report_fixture, db)
    ns["revoke_on_second"] = True

    async def admitted_for_race_only(*args: Any, **kwargs: Any) -> None:
        # Test-only isolation of the downstream reread; this returns no
        # independently trusted target effects and issues no release event.
        return None

    ns["_verify_signed_finding_sources"] = admitted_for_race_only
    with pytest.raises(HTTPException) as denied:
        await ns["_verified_final_release_candidate"](
            db, ns["orch"], SID, RID,
            {"sub": "senior-owner", "role": "senior_operator"},
        )
    assert denied.value.status_code == 403
    assert ns["signed_calls"] == 2


def test_lost_ack_idempotency_key_is_snapshot_bound_not_release_proof() -> None:
    ns = _source_ast("_release_key")
    make_key = ns["_release_key"]
    same = make_key(SID, RID, 4, "d" * 64)
    assert same == make_key(SID, RID, 4, "d" * 64)
    assert same != make_key(SID, RID, 5, "d" * 64)
    assert same != make_key(SID, RID, 4, "e" * 64)
    assert same != make_key("eng-foreign", RID, 4, "d" * 64)
    # This is a deterministic key and does NOT imply that an ambiguous DB ACK
    # committed. The original PG table supplies the uniqueness constraint.
    supervision = SUPERVISION_PATH.read_text(encoding="utf-8")
    assert 'UniqueConstraint("engagement_id", "idempotency_key"' in supervision
    assert 'name="uq_supervision_event_dedupe"' in supervision


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", [
    "no_row", "foreign_flow", "foreign_finding", "wrong_verdict_digest",
    "not_verified", "release_promoted", "signature_missing", "nonce_corrupt",
    "live_source_unavailable",
])
async def test_actual_0022_readback_never_promotes_cached_or_forged_verdict(
    mutation: str
) -> None:
    # The unchanged 0022 store readback is executed without importing the
    # absent database stack. Signed *owner* keys are never fabricated here.
    tree = ast.parse(EFFECT_STORE_PATH.read_text(encoding="utf-8"))
    definitions = {
        n.name: n for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    required = ("_unknown", "_exact", "read_independent_target_effect_verification")
    assert all(name in definitions for name in required)
    sig = "b" * 64
    nonce = "a" * 32
    witness = attestation._canonical({"nonce": nonce})
    row = {
        "engagement_id": SID, "flow_id": FLOW, "finding_id": FINDING,
        "status": "VERIFIED", "finding_verified": True,
        "independent_effect_verified": True, "report_release_approved": False,
        "verdict_sha256": sig,
        "review_decision_id": "vfdec-" + "1" * 32,
        "qualification_id": "teqa-" + "2" * 32,
        "review_decision_sha256": "c" * 64,
        "qualification_sha256": "d" * 64,
        "authorization_version": 4, "senior_reviewer_sub": "senior-owner",
        "qualification_revision": 1, "flow_revision": 3,
        "signed_verdict_json": witness, "verdict_signature_b64url": "A" * 86,
        "verifier_nonce_sha256": _sha(nonce.encode("ascii")),
    }
    if mutation == "no_row":
        row = None
    elif mutation == "foreign_flow":
        row["flow_id"] = "flow-foreign"
    elif mutation == "foreign_finding":
        row["finding_id"] = "other-finding"
    elif mutation == "wrong_verdict_digest":
        row["verdict_sha256"] = "e" * 64
    elif mutation == "not_verified":
        row["independent_effect_verified"] = False
    elif mutation == "release_promoted":
        row["report_release_approved"] = True
    elif mutation == "signature_missing":
        row["signed_verdict_json"] = None
    elif mutation == "nonce_corrupt":
        row["verifier_nonce_sha256"] = "f" * 64
    ns: dict[str, Any] = {
        "__builtins__": __builtins__,
        "Any": Any, "Dict": Dict, "Awaitable": Awaitable, "Callable": Callable,
        "hashlib": hashlib, "re": re,
        "_ENG": re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z"),
        "_FLOW": re.compile(r"flow-[A-Za-z0-9._-]{1,59}\Z"),
        "_FIND": re.compile(r"[A-Za-z0-9_.-]{1,128}\Z"),
        "_SHA": re.compile(r"[0-9a-f]{64}\Z"),
        "_SUB": re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}\Z"),
        "_REVIEW": re.compile(r"vfdec-[0-9a-f]{32}\Z"),
        "_QUAL": re.compile(r"teqa-[0-9a-f]{32}\Z"),
        "_CURRENT_PROMOTION": (
            "SELECT * FROM independent_target_effect_verifications "
            "WHERE engagement_id=:eng AND flow_id=:flow "
            "AND finding_id=:finding FOR SHARE"
        ),
        "_strict_json": lambda raw, max_bytes: json.loads(
            raw.decode("utf-8"), object_pairs_hook=attestation._unique_object_pairs
        ),
        "_canonical": attestation._canonical,
    }
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(
                body=[definitions[name] for name in required], type_ignores=[]
            )), str(EFFECT_STORE_PATH), "exec"
        ), ns
    )

    class _Ledger:
        def in_transaction(self) -> bool:
            return True

        async def execute(self, sql: str, params: dict[str, str]) -> _Rows:
            assert "FOR SHARE" in sql and params == {
                "eng": SID, "flow": FLOW, "finding": FINDING,
            }
            return _Rows(row)

    async def unresolved() -> bool:
        # Even a nominally VERIFIED historical DB row has no independently
        # enrolled current owner/observer verifier or original Task ancestry.
        return mutation != "live_source_unavailable"

    async def denied_current(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Real current independent owner/witness keys unavailable")

    ns["_current"] = denied_current
    result = await ns["read_independent_target_effect_verification"](
        _Ledger(), engagement_id=SID, flow_id=FLOW, finding_id=FINDING,
        evidence_sha256=sig, authorization_version=4,
        reviewer_sub="senior-owner", reviewer_role="senior_operator",
        reviewer_token_sha256="f" * 64, reviewer_expires_at=1800000300,
        trusted_current_verifier=unresolved,
        trusted_report_source_check=lambda *a: unresolved(),
        trusted_anonymous_signed_dispatch_check=lambda *a: unresolved(),
    )
    assert result["status"] == "UNKNOWN"
    assert result["finding_verified"] is False
    assert result["report_release_approved"] is False
    assert result["finding_release_eligible"] is False


def test_release_status_and_external_senior_verifier_remain_separate_contracts() -> None:
    tree = ast.parse(ROUTER_PATH.read_text(encoding="utf-8"))
    status = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "get_signed_report_release_status"
    )
    names = {n.id for n in ast.walk(status) if isinstance(n, ast.Name)}
    assert "_verified_final_release_candidate" in names
    assert "_release_key" in names
    assert "verify_current_release_ledger_join" not in names
    sqls = {
        name for name in (
            "independent_senior_release_key_enrollments",
            "independent_release_host_key_enrollments",
            "independent_release_replica_qualifications",
            "independent_release_qualification_run_receipts",
            "independent_senior_release_receipts",
        )
        if any(name in path.read_text(encoding="utf-8") for path in MIGRATION_ROOT.glob("*.py"))
    }
    assert sqls == set(), "Release tables are now durable; update the qualification"


@pytest.mark.anyio
async def test_no_independent_senior_signature_never_enters_read_only_release_join(
    report_fixture: SimpleNamespace
) -> None:
    # Deterministic PUBLIC-only placeholders; there is no corresponding signer
    # or signed senior envelope, and no host-registered release service.
    def root(label: str) -> bytes:
        return hashlib.sha256(("unregistered-" + label).encode("ascii")).digest()

    trust = senior_release.PinnedReleaseTrust(
        senior_key_id="unregistered-senior",
        senior_public_key=root("senior"),
        host_public_key=root("host"),
        report_signer_keys=(root("report"),),
        provider_signer_keys=(root("provider"),),
        target_owner_keys=(root("target"),),
        replica_signer_roots={"replica-one": root("replica1"), "replica-two": root("replica2")},
    )
    class _ForbiddenDB:
        def in_transaction(self) -> bool:
            return True

        async def execute(self, *args: Any, **kwargs: Any) -> None:
            pytest.fail("Unsigned senior release reached a durable ledger")

    with pytest.raises(senior_release.IndependentReleaseDenied):
        await senior_release.verify_current_release_ledger_join(
            b"", db=_ForbiddenDB(), trust=trust,
            current_authority=object.__new__(senior_release.PinnedHostCurrentAuthority),
            expected_engagement_id=SID, expected_report_id=RID,
            original_attestation_bytes=report_fixture.originals["attestation"],
            original_manifest_bytes=report_fixture.originals["manifest"],
            archived_artifacts={
                k: report_fixture.originals[k] for k in attestation.ARTIFACT_ALLOWLIST
            },
            evidence_by_finding=report_fixture.evidence,
        )


@pytest.mark.anyio
async def test_unavailable_current_replica_ledger_is_not_assumed_qualified(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exercise the real read-only ledger accessor, not invented positive
    # response flags. There is no signed independent senior or replica claim.
    sql_module = types.ModuleType("sqlalchemy")
    sql_module.text = lambda query: query
    monkeypatch.setitem(sys.modules, "sqlalchemy", sql_module)
    class _UnavailableReplicaDB:
        def __init__(self) -> None:
            self.queries: list[str] = []

        async def execute(self, query: str, args: dict[str, str]) -> _Rows:
            self.queries.append(query)
            assert str(query).startswith("SELECT ") and "FOR SHARE" in str(query)
            assert args["eng"] == SID
            return _Rows(None)

    db = _UnavailableReplicaDB()
    with pytest.raises(senior_release.IndependentReleaseDenied):
        await senior_release._locked_row(
            db,
            "SELECT * FROM independent_release_replica_qualifications "
            "WHERE engagement_id=:eng AND flow_id=:flow FOR SHARE",
            eng=SID, flow=FLOW,
        )
    assert len(db.queries) == 1


@pytest.mark.parametrize("kind", ["report", "target_owner", "replica", "release"])
def test_existing_migrations_do_not_certify_missing_release_root(kind: str) -> None:
    migrations = "\n".join(
        p.read_text(encoding="utf-8") for p in MIGRATION_ROOT.glob("*.py")
    )
    if kind == "report":
        assert "report_release_approved = false" in migrations
    elif kind == "target_owner":
        assert "target_authority_nonce_receipts" in migrations
        assert "independent_target_effect_verifications" in migrations
    elif kind == "replica":
        assert "independent_release_replica_qualifications" not in migrations
        assert "independent_release_qualification_run_receipts" not in migrations
    else:
        assert "independent_senior_release_receipts" not in migrations
        assert "independent_senior_release_key_enrollments" not in migrations
