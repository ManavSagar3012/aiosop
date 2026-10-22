"""Negative and custody-contract tests for unmounted production admission.

ALL signing keys in this file are ephemeral, IN-MEMORY cryptographic fixtures.
They are NOT independently enrolled, never supplied to the application as a
production senior/host/owner credential, and never issue production approval.
SQL uses an isolated SELECT-only fake: no application DB, provider, target,
Docker, host service or production certificate is involved.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import sys
import time
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, Optional

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.reporting import attestation as report_attestation
from ai_osop.safety import independent_release_authority as senior_verifier
from ai_osop.safety import production_release_admission as admission
from ai_osop.safety.approval_binding import task_payload_sha256

ENG = "eng-custody-host-only"
FLOW = "flow-custody-host-only"
REPORT = f"report-{ENG}-r1"
FINDING = "finding-original-source"
NOW = int(time.time())


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _signature(raw: bytes, signer: Ed25519PrivateKey) -> str:
    return base64.urlsafe_b64encode(signer.sign(raw)).decode("ascii").rstrip("=")


def _signed_claim(claim: Mapping[str, Any], signer: Ed25519PrivateKey) -> bytes:
    return senior_verifier._canonical({
        "claim": claim,
        "signature": _signature(
            senior_verifier.RELEASE_DOMAIN + senior_verifier._canonical(claim),
            signer,
        ),
    })


class _Selection:
    def __init__(self, row: Optional[Mapping[str, Any]]) -> None:
        self.row = row

    def mappings(self) -> "_Selection":
        return self

    def one_or_none(self) -> Optional[dict[str, Any]]:
        return copy.deepcopy(dict(self.row)) if self.row is not None else None


class _ReadOnlyPgDouble:
    """SQL interface fake; dialect marker is NOT proof of real PostgreSQL."""

    def __init__(self, row: Optional[dict[str, Any]] = None) -> None:
        self.row = row
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.active = True
        self.name = "postgresql"

    def in_transaction(self) -> bool:
        return self.active

    def get_bind(self) -> SimpleNamespace:
        return SimpleNamespace(dialect=SimpleNamespace(name=self.name))

    async def execute(self, sql: Any, params: dict[str, Any]) -> _Selection:
        statement = str(sql)
        assert statement.startswith("SELECT ")
        assert "FOR SHARE" in statement
        assert (
            "independent_senior_release_receipts" in statement
            or "independent_release_replica_qualifications" in statement
        )
        self.calls.append((statement, params))
        return _Selection(self.row)


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    reporter, senior, host, owner, provider, replica1, replica2 = (
        Ed25519PrivateKey.generate() for _ in range(7)
    )
    trust = senior_verifier.PinnedReleaseTrust(
        senior_key_id="test-only-unenrolled-senior",
        senior_public_key=_pub(senior),
        host_public_key=_pub(host),
        report_signer_keys=(_pub(reporter),),
        provider_signer_keys=(_pub(provider),),
        target_owner_keys=(_pub(owner),),
        replica_signer_roots={"replica-1": _pub(replica1), "replica-2": _pub(replica2)},
    )
    root = tmp_path / "reports"
    folder = root / ENG
    folder.mkdir(parents=True)
    monkeypatch.setenv("OSOP_ATTESTED_REPORT_ROOT", str(root.resolve()))
    monkeypatch.setenv(
        "OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON",
        json.dumps({"test-reporter": base64.b64encode(_pub(reporter)).decode("ascii")}),
    )
    snapshot = [{"source": "report fixture only", "observation": "not target proof"}]
    evidence = {FINDING: snapshot}
    finding_sha = report_attestation.hash_evidence_snapshot(snapshot)
    task_payload = {
        "require_attestation": True,
        "signer_key_id": "test-reporter",
        "version": "r1",
        "_authorization_version": 1,
        "_flow_revision": 3,
    }
    artifacts = {
        "md": b"# Report\nUnreleased\n",
        "html": b"<p>Unreleased</p>",
        "graph.html": b"<div>Unverified graph snapshot</div>",
        "json": report_attestation._canonical({
            "engagement_id": ENG,
            "requires_approval": True,
            "verification_status": "verified_findings_only",
            "findings": [{"id": FINDING, "evidence_hash": finding_sha}],
        }),
    }
    report_claim = report_attestation._build_payload(
        engagement_id=ENG,
        report_id=REPORT,
        signer_key_id="test-reporter",
        artifacts=artifacts,
        provenance=[{
            "finding_id": FINDING,
            "source_type": "validated_engagement_graph",
            "evidence_sha256": finding_sha,
        }],
        generation_binding={
            "task_id": "task-custody-report",
            "task_payload_sha256": task_payload_sha256(task_payload),
            "authorization_version": 1,
            "authorization_sha256": "e" * 64,
            "flow_id": FLOW,
            "flow_revision": 3,
        },
    )
    archived_attestation = report_attestation._canonical({
        "attestation": report_claim,
        "signature": _signature(report_attestation._canonical(report_claim), reporter),
    })
    manifest = report_attestation._canonical({
        "engagement_id": ENG,
        "report_id": REPORT,
        "hash_algorithm": "sha256",
        "signature_status": "ed25519_signed",
        "artifacts": report_claim["artifacts"],
        "attestation_sha256": _sha(archived_attestation),
    })
    originals = {
        **artifacts,
        "attestation": archived_attestation,
        "manifest": manifest,
    }
    for kind, blob in originals.items():
        (folder / f"{REPORT}.{kind}").write_bytes(blob)
    senior_claim = {
        "schema": "ai-osop-independent-senior-release-v1",
        "senior_key_id": trust.senior_key_id,
        "senior_sub": "senior-fixture-only",
        "report": {
            "engagement_id": ENG,
            "report_id": REPORT,
            "attestation_sha256": _sha(archived_attestation),
            "manifest_sha256": _sha(manifest),
            "report_json_sha256": _sha(artifacts["json"]),
            "generation_task_id": "task-custody-report",
        },
        "scope": {
            "tenant_id": ENG,
            "owner_sub": "senior-fixture-only",
            "flow_id": FLOW,
            "flow_revision": 3,
            "authorization_id": "auth-custody-only",
            "authorization_version": 1,
            "authorization_sha256": "e" * 64,
        },
        "target_owner_receipts": [{
            "finding_id": FINDING,
            "verification_id": "itefv-" + "1" * 32,
            "verdict_sha256": "1" * 64,
            "qualification_id": "teqa-" + "2" * 32,
            "qualification_sha256": "2" * 64,
            "challenge_id": "itefc-" + "3" * 32,
            "target_owner_assertion_id": "tauth-" + "4" * 32,
            "target_owner_assertion_sha256": "4" * 64,
            "nonce_receipt_id": "tauth-" + "5" * 32,
            "nonce_receipt_sha256": "5" * 64,
        }],
        "replica_qualifications": [
            {
                "replica_id": rid,
                "qualification_id": f"qual-{rid}",
                "qualification_sha256": "6" * 64,
                "run_receipt_id": f"run-{rid}",
                "run_receipt_sha256": "7" * 64,
            }
            for rid in ("replica-1", "replica-2")
        ],
        "release_receipt_id": "srelease-" + "9" * 32,
        "release_receipt_sha256": "8" * 64,
        "issued_at": NOW - 5,
        "expires_at": NOW + 120,
    }
    return SimpleNamespace(
        trust=trust, reporter=reporter, senior=senior, host=host,
        owner=owner, provider=provider, evidence=evidence,
        claim=senior_claim, originals=originals, folder=folder,
        db=_ReadOnlyPgDouble(),
        host_client=object.__new__(senior_verifier.PinnedHostCurrentAuthority),
    )


async def _call(
    case: SimpleNamespace,
    *,
    trust: Optional[senior_verifier.PinnedReleaseTrust] = None,
    signed: Optional[bytes] = None,
    evidence: Optional[Mapping[str, Any]] = None,
    db: Optional[_ReadOnlyPgDouble] = None,
    host_client: Any = None,
) -> admission.ReadOnlyReleaseAdmission:
    return await admission.ProductionReleaseAdmission().qualify_read_only(
        db=db if db is not None else case.db,
        trust=trust if trust is not None else case.trust,
        current_authority=host_client if host_client is not None else case.host_client,
        signed_senior_envelope=(
            signed if signed is not None else _signed_claim(case.claim, case.senior)
        ),
        engagement_id=ENG,
        report_id=REPORT,
        evidence_by_finding=evidence if evidence is not None else case.evidence,
    )


@pytest.mark.anyio
async def test_unenrolled_fixture_signed_claim_denied_at_missing_committed_ledger(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A correct Ed25519 math result is not independent enrollment or a release.
    fake_sqlalchemy = types.ModuleType("sqlalchemy")
    fake_sqlalchemy.text = lambda q: q
    monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sqlalchemy)
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case)
    assert len(case.db.calls) == 1
    assert case.db.calls[0][1]["receipt"] == case.claim["release_receipt_id"]


@pytest.mark.anyio
@pytest.mark.parametrize("attack", ["unsigned", "forged_senior", "altered_claim",
                                     "expired", "future", "duplicate_json"])
async def test_forged_expired_or_duplicate_senior_claim_denied_before_sql(
    case: SimpleNamespace, attack: str
) -> None:
    claim = copy.deepcopy(case.claim)
    signed = _signed_claim(claim, case.senior)
    if attack == "unsigned":
        signed = b""
    elif attack == "forged_senior":
        signed = _signed_claim(claim, case.reporter)
    elif attack == "altered_claim":
        forged = json.loads(signed)
        forged["claim"]["scope"]["owner_sub"] = "different-owner"
        signed = senior_verifier._canonical(forged)
    elif attack == "expired":
        claim.update(issued_at=NOW - 400, expires_at=NOW - 200)
        signed = _signed_claim(claim, case.senior)
    elif attack == "future":
        claim.update(issued_at=NOW + 300, expires_at=NOW + 360)
        signed = _signed_claim(claim, case.senior)
    elif attack == "duplicate_json":
        signed = (
            b'{"claim":{},"claim":{},"signature":"'
            + b"A" * 86 + b'"}'
        )
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case, signed=signed)
    assert not case.db.calls


@pytest.mark.anyio
async def test_forged_target_owner_absent_denied_before_disk_and_ledger(
    case: SimpleNamespace
) -> None:
    claim = copy.deepcopy(case.claim)
    claim["target_owner_receipts"] = []
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case, signed=_signed_claim(claim, case.senior))
    assert not case.db.calls


@pytest.mark.anyio
@pytest.mark.parametrize("attack", ["manifest_claim", "manifest_raw", "report_json",
                                     "attestation_raw", "evidence"])
async def test_original_report_bytes_not_caller_reconstructable(
    case: SimpleNamespace, attack: str
) -> None:
    claim = copy.deepcopy(case.claim)
    evidence = case.evidence
    if attack == "manifest_claim":
        claim["report"]["manifest_sha256"] = "0" * 64
    elif attack == "manifest_raw":
        # Parsed JSON is identical; original bytes differ.
        path = case.folder / f"{REPORT}.manifest"
        path.write_bytes(path.read_bytes() + b" ")
    elif attack == "attestation_raw":
        path = case.folder / f"{REPORT}.attestation"
        path.write_bytes(path.read_bytes() + b" ")
    elif attack == "report_json":
        path = case.folder / f"{REPORT}.json"
        path.write_bytes(path.read_bytes() + b" ")
    else:
        evidence = {FINDING: [{"fake": "source proof"}]}
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case, signed=_signed_claim(claim, case.senior), evidence=evidence)
    assert not case.db.calls


@pytest.mark.anyio
async def test_revoked_report_signer_does_not_become_senior_permission(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON", raising=False)
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case)
    assert not case.db.calls


@pytest.mark.anyio
@pytest.mark.parametrize("bad_roots", [
    "same_senior_host", "same_senior_owner", "same_replica_owner", "same_replicas",
])
async def test_signer_reuse_across_independent_roots_denied(
    case: SimpleNamespace, bad_roots: str
) -> None:
    # A forged registry snapshot might mutate AFTER the base class constructor.
    raw = vars(case.trust).copy()
    raw["replica_signer_roots"] = dict(raw["replica_signer_roots"])
    if bad_roots == "same_senior_host":
        raw["host_public_key"] = raw["senior_public_key"]
    elif bad_roots == "same_senior_owner":
        raw["target_owner_keys"] = (raw["senior_public_key"],)
    elif bad_roots == "same_replica_owner":
        raw["replica_signer_roots"]["replica-2"] = raw["target_owner_keys"][0]
    else:
        raw["replica_signer_roots"]["replica-2"] = raw["replica_signer_roots"]["replica-1"]
    # Build without validation to model an externally corrupted registry.
    malformed = object.__new__(senior_verifier.PinnedReleaseTrust)
    for name, value in raw.items():
        object.__setattr__(malformed, name, value)
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case, trust=malformed)
    assert not case.db.calls


@pytest.mark.anyio
@pytest.mark.parametrize("invalid", ["not_pg", "no_tx", "missing_host", "subclass_host"])
async def test_only_current_pg_transaction_and_exact_host_transport(
    case: SimpleNamespace, invalid: str
) -> None:
    db = case.db
    host = case.host_client
    if invalid == "not_pg":
        db.name = "sqlite"
    elif invalid == "no_tx":
        db.active = False
    elif invalid == "missing_host":
        host = object()
    else:
        class ForgedHost(senior_verifier.PinnedHostCurrentAuthority):
            pass
        host = object.__new__(ForgedHost)
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case, db=db, host_client=host)
    assert not db.calls


def _ledger_row(case: SimpleNamespace) -> dict[str, Any]:
    claim = case.claim
    scoped = claim["scope"]
    report = claim["report"]
    return {
        "id": claim["release_receipt_id"],
        "engagement_id": ENG,
        "tenant_id": ENG,
        "report_id": REPORT,
        "receipt_sha256": claim["release_receipt_sha256"],
        "signed_claim_sha256": _sha(
            senior_verifier.RELEASE_DOMAIN + senior_verifier._canonical(claim)
        ),
        "attestation_sha256": report["attestation_sha256"],
        "manifest_sha256": report["manifest_sha256"],
        "authorization_id": scoped["authorization_id"],
        "authorization_version": scoped["authorization_version"],
        "authorization_sha256": scoped["authorization_sha256"],
        "flow_id": FLOW,
        "flow_revision": 3,
        "senior_sub": claim["senior_sub"],
        "senior_key_id": claim["senior_key_id"],
        "status": "admitted",
        "commit_status": "committed",
        "ack_status": "confirmed",
        "revoked_at": None,
        "consumed_at": None,
        "replayed_at": None,
        "rollback_at": None,
        "admission_generation": 5,
        "committed_at": NOW - 2,
    }


@pytest.mark.anyio
@pytest.mark.parametrize("attack", [
    "ack_lost", "rollback", "replayed", "consumed", "revoked",
    "wrong_report", "wrong_owner", "wrong_original", "wrong_generation",
    "uncommitted", "no_generation", "no_committed_time",
])
async def test_lost_ack_replay_and_revoked_commits_are_not_read_permissions(
    case: SimpleNamespace, attack: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # This probes ONLY the row-shape reader, not a successful release flow.
    # No app signature or host approval is forged in these tests.
    fake_sqlalchemy = types.ModuleType("sqlalchemy")
    fake_sqlalchemy.text = lambda q: q
    monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sqlalchemy)
    row = _ledger_row(case)
    if attack == "ack_lost":
        row["ack_status"] = "unknown"
    elif attack == "rollback":
        row["rollback_at"] = NOW
    elif attack == "replayed":
        row["replayed_at"] = NOW
    elif attack == "consumed":
        row["consumed_at"] = NOW
    elif attack == "revoked":
        row["revoked_at"] = NOW
    elif attack == "wrong_report":
        row["report_id"] = "report-other"
    elif attack == "wrong_owner":
        row["senior_sub"] = "someone-else"
    elif attack == "wrong_original":
        row["manifest_sha256"] = "0" * 64
    elif attack == "wrong_generation":
        row["admission_generation"] += 1
    elif attack == "uncommitted":
        row["commit_status"] = "UNKNOWN"
    elif attack == "no_generation":
        row["admission_generation"] = None
    else:
        row["committed_at"] = None
    db = _ReadOnlyPgDouble(row)
    expected = row["signed_claim_sha256"]
    with pytest.raises(admission.ProductionReleaseDenied):
        await admission._one_use_ack_fence(
            db, case.claim, expected,
            previous_generation=5 if attack == "wrong_generation" else None,
        )
    assert len(db.calls) == 1


@pytest.mark.anyio
async def test_stable_read_only_ledger_snapshot_never_consumes_record(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_sqlalchemy = types.ModuleType("sqlalchemy")
    fake_sqlalchemy.text = lambda q: q
    monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sqlalchemy)
    row = _ledger_row(case)
    db = _ReadOnlyPgDouble(row)
    gen = await admission._one_use_ack_fence(
        db, case.claim, row["signed_claim_sha256"]
    )
    assert gen == 5
    assert await admission._one_use_ack_fence(
        db, case.claim, row["signed_claim_sha256"], previous_generation=5
    ) == gen
    assert db.row == row and len(db.calls) == 2
    assert admission.ReadOnlyReleaseAdmission(
        status="current_signed_release_readback_verified_not_executable",
        engagement_id=ENG, report_id=REPORT,
        claim_sha256=row["signed_claim_sha256"],
        attestation_sha256=row["attestation_sha256"],
        manifest_sha256=row["manifest_sha256"],
        release_receipt_id=row["id"], admission_generation=gen,
        independent_effects_checked=1, replica_qualifications_checked=2,
    ).grants_release_execution is False


@pytest.mark.anyio
async def test_missing_replica_and_target_owner_cannot_be_shortcut_by_acked_senior_row(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A syntactically committed release row isn't enough. The actual verifier
    # still needs independently signed 0016/0021/0022 owner and replica truth.
    fake_sqlalchemy = types.ModuleType("sqlalchemy")
    fake_sqlalchemy.text = lambda q: q
    monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sqlalchemy)
    case.db.row = _ledger_row(case)
    calls = []

    async def no_external_qualification(*args: Any, **kwargs: Any) -> Any:
        calls.append(True)
        raise senior_verifier.IndependentReleaseDenied(
            "Unenrolled owner, replica, or current signed host is unavailable"
        )

    monkeypatch.setattr(
        admission, "verify_current_release_ledger_join", no_external_qualification
    )
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case)
    assert len(calls) == 1
    assert len(case.db.calls) == 1  # no claimed success, no replay/consumption


@pytest.mark.anyio
async def test_real_replica_ledger_reader_denies_current_row_unavailable(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_sqlalchemy = types.ModuleType("sqlalchemy")
    fake_sqlalchemy.text = lambda q: q
    monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sqlalchemy)
    db = _ReadOnlyPgDouble()
    with pytest.raises(senior_verifier.IndependentReleaseDenied):
        await senior_verifier._locked_row(
            db,
            "SELECT * FROM independent_release_replica_qualifications "
            "WHERE engagement_id=:eng AND flow_id=:flow FOR SHARE",
            eng=ENG, flow=FLOW,
        )
    assert len(db.calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("after_wait", [
    "ack_lost", "senior_revoked", "manifest_changed", "replica_key_rotated",
    "report_signer_revoked",
])
async def test_postawait_race_cannot_turn_stale_readback_into_permission(
    case: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    after_wait: str,
) -> None:
    """Synthetic downstream readback exists *only* to test denial after await.

    This is deliberately NOT a positive release qualification and supplies no
    independently enrolled host, senior, target owner, or live replica proof.
    """
    fake_sqlalchemy = types.ModuleType("sqlalchemy")
    fake_sqlalchemy.text = lambda q: q
    monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sqlalchemy)
    row = _ledger_row(case)
    case.db.row = row

    async def adversarial_wait(*args: Any, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["db"] is case.db
        if after_wait == "ack_lost":
            row["ack_status"] = "unknown"
        elif after_wait == "senior_revoked":
            row["revoked_at"] = NOW
        elif after_wait == "manifest_changed":
            path = case.folder / f"{REPORT}.manifest"
            path.write_bytes(path.read_bytes() + b" ")
        elif after_wait == "replica_key_rotated":
            roots = case.trust.replica_signer_roots
            roots["replica-2"] = _pub(Ed25519PrivateKey.generate())
        else:
            monkeypatch.delenv("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON", raising=False)
        return {
            "status": "read_only_current_release_ledger_join_verified",
            "claim_sha256": row["signed_claim_sha256"],
            "senior_key_id": case.trust.senior_key_id,
            "release_receipt_id": row["id"],
            "engagement_id": ENG, "report_id": REPORT,
            "production_certificate_issued": False,
            "ledger_effects_checked": 1, "ledger_replicas_checked": 2,
        }

    monkeypatch.setattr(
        admission, "verify_current_release_ledger_join", adversarial_wait
    )
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case)
    assert len(case.db.calls) in (1, 2)


@pytest.mark.anyio
async def test_host_failure_does_not_read_signer_secrets_or_call_providers(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_sqlalchemy = types.ModuleType("sqlalchemy")
    fake_sqlalchemy.text = lambda q: q
    monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sqlalchemy)
    case.db.row = _ledger_row(case)
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Production release preflight attempted private signing-key access")
    monkeypatch.setattr(report_attestation, "load_signer", forbidden)
    monkeypatch.setenv("OSOP_REPORT_SIGNING_KEY_FILE", "DO-NOT-READ-THIS-SECRET.pem")
    monkeypatch.setattr(
        admission, "verify_current_release_ledger_join",
        lambda *a, **k: (_ for _ in ()).throw(
            senior_verifier.IndependentReleaseDenied("Current host unavailable")
        ),
    )
    with pytest.raises(admission.ProductionReleaseDenied):
        await _call(case)
    source = inspect.getsource(admission)
    for secret_api in (
        "load_signer(", "Ed25519PrivateKey", "OSOP_REPORT_SIGNING_KEY_FILE",
        "litellm", "requests.post(", "mcp_client", "subprocess",
    ):
        assert secret_api not in source
