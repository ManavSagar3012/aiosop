"""Current-release negative qualification against actual schema boundaries.

Ephemeral fixture keys are used only to exercise cryptographic inputs. No
external senior, owner, provider, target, replica or host is impersonated in
production; no release is issued. DB doubles never touch the application DB.
"""

import base64
import copy
import hashlib
import json
import sys
import types
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.reporting.attestation import _build_payload, _canonical, hash_evidence_snapshot
from ai_osop.reporting import attestation as report_attestation
from ai_osop.safety import independent_release_authority as release
from ai_osop.safety.approval_binding import task_payload_sha256


NOW = 1_800_000_000
ENG = "eng-release-current-ledger"
FLOW = "flow-release-current-ledger"
REPORT = f"report-{ENG}-v3"
FINDING = "finding-one"


def _public(private):
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _signature(raw, private):
    return base64.urlsafe_b64encode(private.sign(raw)).decode("ascii").rstrip("=")


def _envelope(payload, private, domain):
    return release._canonical({
        "claim": payload,
        "signature": _signature(domain + release._canonical(payload), private),
    })


class _Selection:
    def __init__(self, row):
        self.row = row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row


class _ReadOnlyDatabase:
    def __init__(self, fixtures, *, in_tx=True):
        self.fixtures = fixtures
        self.in_tx = in_tx
        self.queries = []

    def in_transaction(self):
        return self.in_tx

    async def execute(self, statement, params=None):
        sql = str(statement)
        self.queries.append((sql, params))
        assert sql.startswith("SELECT ") and "FOR SHARE" in sql
        assert all(token not in sql.upper() for token in (" INSERT ", " DELETE ", " UPDATE "))
        for table, row in self.fixtures.items():
            if "FROM " + table + " " in sql:
                return _Selection(copy.deepcopy(row))
        return _Selection(None)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def case(monkeypatch):
    # The host's lightweight test Python lacks sqlalchemy and neo4j. These
    # synthetic test boundaries exercise the read-only SQL contract without
    # modifying global dependencies or contacting a database.
    sql = types.ModuleType("sqlalchemy")
    sql.text = lambda statement: statement
    monkeypatch.setitem(sys.modules, "sqlalchemy", sql)
    memory_pkg = types.ModuleType("ai_osop.memory")
    memory_pkg.__path__ = []
    monkeypatch.setitem(sys.modules, "ai_osop.memory", memory_pkg)
    authorization_store = types.ModuleType("ai_osop.memory.authorization_store")
    monkeypatch.setitem(
        sys.modules, "ai_osop.memory.authorization_store", authorization_store
    )
    effect_store = types.ModuleType(
        "ai_osop.memory.independent_target_effect_verifications"
    )
    def reject_effect(*args, **kwargs):
        raise AssertionError("No production witness keys configured in test")
    effect_store._current_witness_trust = reject_effect
    effect_store._row_digest = reject_effect
    monkeypatch.setitem(
        sys.modules, "ai_osop.memory.independent_target_effect_verifications",
        effect_store,
    )
    senior, host, reporter, provider, owner, replica_a, replica_b = [
        Ed25519PrivateKey.generate() for _ in range(7)
    ]
    trust = release.PinnedReleaseTrust(
        senior_key_id="senior-release-external",
        senior_public_key=_public(senior),
        host_public_key=_public(host),
        report_signer_keys=(_public(reporter),),
        provider_signer_keys=(_public(provider),),
        target_owner_keys=(_public(owner),),
        replica_signer_roots={
            "replica-a": _public(replica_a),
            "replica-b": _public(replica_b),
        },
    )
    monkeypatch.setattr(
        report_attestation, "_read_trusted_signers",
        lambda: {"test-archive-reporter": _public(reporter)},
    )
    payload = {
        "_authorization_version": 2,
        "_flow_revision": 5,
        "version": "v3",
        "signer_key_id": "test-archive-reporter",
        "require_attestation": True,
    }
    raw_evidence = [{ "type": "bounded-source", "record": "private" }]
    evidence_by_finding = {FINDING: raw_evidence}
    evidence_hash = hash_evidence_snapshot(raw_evidence)
    report_json = release._canonical({
        "engagement_id": ENG,
        "requires_approval": True,
        "verification_status": "verified_findings_only",
        "findings": [{"id": FINDING, "evidence_hash": evidence_hash}],
    })
    artifacts = {"md": b"# sample", "html": b"<p>sample</p>",
                 "graph.html": b"<div>sample</div>", "json": report_json}
    auth_sha = "a" * 64
    attestation = _build_payload(
        engagement_id=ENG, report_id=REPORT,
        signer_key_id="test-archive-reporter", artifacts=artifacts,
        provenance=[{
            "finding_id": FINDING, "source_type": "validated_engagement_graph",
            "evidence_sha256": evidence_hash,
        }],
        generation_binding={
            "task_id": "task-report-generation",
            "task_payload_sha256": task_payload_sha256(payload),
            "authorization_version": 2,
            "authorization_sha256": auth_sha,
            "flow_id": FLOW, "flow_revision": 5,
        },
    )
    signed_attestation = _canonical({
        "attestation": attestation,
        "signature": _signature(_canonical(attestation), reporter),
    })
    manifest = _canonical({
        "engagement_id": ENG, "report_id": REPORT, "hash_algorithm": "sha256",
        "signature_status": "ed25519_signed",
        "artifacts": attestation["artifacts"],
        "attestation_sha256": _sha(signed_attestation),
    })
    claim = {
        "schema": "ai-osop-independent-senior-release-v1",
        "senior_key_id": "senior-release-external", "senior_sub": "senior-owner",
        "report": {
            "engagement_id": ENG, "report_id": REPORT,
            "attestation_sha256": _sha(signed_attestation),
            "manifest_sha256": _sha(manifest),
            "report_json_sha256": _sha(report_json),
            "generation_task_id": "task-report-generation",
        },
        "scope": {
            "tenant_id": ENG, "owner_sub": "senior-owner",
            "flow_id": FLOW, "flow_revision": 5,
            "authorization_id": "auth-current-release",
            "authorization_version": 2, "authorization_sha256": auth_sha,
        },
        "target_owner_receipts": [{
            "finding_id": FINDING,
            "verification_id": "itefv-" + "1" * 32,
            "verdict_sha256": "b" * 64,
            "qualification_id": "teqa-" + "2" * 32,
            "qualification_sha256": "c" * 64,
            "challenge_id": "itefc-" + "3" * 32,
            "target_owner_assertion_id": "tauth-" + "4" * 32,
            "target_owner_assertion_sha256": "d" * 64,
            "nonce_receipt_id": "tauth-" + "5" * 32,
            "nonce_receipt_sha256": "e" * 64,
        }],
        "replica_qualifications": [{
            "replica_id": rid, "qualification_id": f"qualification-{rid}",
            "qualification_sha256": "f" * 64,
            "run_receipt_id": f"run-{rid}", "run_receipt_sha256": "7" * 64,
        } for rid in ("replica-a", "replica-b")],
        "release_receipt_id": "srelease-" + "6" * 32,
        "release_receipt_sha256": "8" * 64,
        "issued_at": NOW - 5, "expires_at": NOW + 120,
    }
    rows = {
        "session_states": {"session_id": ENG, "created_by": "senior-owner"},
        "execution_flows": {"id": FLOW, "engagement_id": ENG, "revision": 5},
        "tasks": {
            "id": "task-report-generation", "engagement_id": ENG,
            "flow_id": FLOW, "type": "generate_report", "agent_type": "reporting",
            "status": "completed", "approval_required": True,
            "started_at": NOW - 8, "completed_at": NOW - 3,
            "payload": payload, "result": {
                "status": "success", "report_id": REPORT,
                "signature_status": "ed25519_signed",
            },
        },
        "operator_subject_controls": {"actor_id": "senior-owner", "disabled": False},
    }
    async def mock_current_signed(db, eng, *, expected_version, expected_digest):
        assert db.in_transaction() is True
        assert eng == ENG and expected_version == 2 and expected_digest == auth_sha
        return SimpleNamespace(session_id=eng, version=2,
                               policy_sha256=auth_sha,
                               authorization_id="auth-current-release")

    authorization_store.guard_sql = mock_current_signed
    monkeypatch.setattr(release.time, "time", lambda: NOW)
    return SimpleNamespace(
        trust=trust, senior=senior, host=host, reporter=reporter,
        replica_signers={"replica-a": replica_a, "replica-b": replica_b},
        claim=claim, attestation=signed_attestation, manifest=manifest,
        archived=artifacts, evidence=evidence_by_finding, rows=rows,
        current_authority=object.__new__(release.PinnedHostCurrentAuthority),
    )


def _signed(case, claim=None, signer=None):
    return _envelope(claim or case.claim, signer or case.senior, release.RELEASE_DOMAIN)


def _enrolled_keys(case, rows):
    rows["independent_senior_release_key_enrollments"] = {
        "key_id": "senior-release-external",
        "tenant_id": ENG, "senior_sub": "senior-owner",
        "public_key_sha256": _sha(case.trust.senior_public_key),
        "status": "active", "revoked_at": None,
    }
    rows["independent_release_host_key_enrollments"] = {
        "tenant_id": ENG,
        "public_key_sha256": _sha(case.trust.host_public_key),
        "status": "active", "revoked_at": None,
    }
    return rows


async def _verify(case, db, *, claim=None, signer=None, attestation=None,
                  artifacts=None, evidence=None):
    return await release.verify_current_release_ledger_join(
        _signed(case, claim=claim, signer=signer),
        db=db, trust=case.trust, current_authority=case.current_authority,
        expected_engagement_id=ENG, expected_report_id=REPORT,
        original_attestation_bytes=attestation or case.attestation,
        original_manifest_bytes=case.manifest,
        archived_artifacts=artifacts or case.archived,
        evidence_by_finding=evidence or case.evidence,
    )


@pytest.mark.anyio
async def test_open_authoritative_transaction_required_before_read(case):
    db = _ReadOnlyDatabase(case.rows, in_tx=False)
    with pytest.raises(release.IndependentReleaseDenied):
        await _verify(case, db)
    assert db.queries == []


@pytest.mark.anyio
async def test_real_fixture_report_signature_and_archive_join_reach_durable_scope(case):
    db = _ReadOnlyDatabase(case.rows)
    with pytest.raises(release.IndependentReleaseDenied):
        await _verify(case, db)
    assert [sql.split("FROM ")[1].split()[0] for sql, _ in db.queries] == [
        "session_states", "execution_flows", "tasks",
        "operator_subject_controls", "independent_senior_release_key_enrollments",
    ]


@pytest.mark.anyio
async def test_revoked_report_signer_denies_before_any_database_claim(
    case, monkeypatch
):
    monkeypatch.setattr(report_attestation, "_read_trusted_signers", lambda: {})
    db = _ReadOnlyDatabase(case.rows)
    with pytest.raises(release.IndependentReleaseDenied):
        await _verify(case, db)
    assert db.queries == []


@pytest.mark.anyio
@pytest.mark.parametrize("tamper", ["senior", "report_signature", "json", "evidence",
                                      "tenant", "cross_owner", "flow_revision"])
async def test_caller_cannot_forge_original_signer_scope_or_evidence(case, tamper):
    claim = copy.deepcopy(case.claim)
    rows = copy.deepcopy(case.rows)
    attestation = case.attestation
    archived = case.archived
    evidence = case.evidence
    signer = case.senior
    if tamper == "senior":
        signer = case.reporter
    elif tamper == "report_signature":
        attestation = attestation.replace(b"test-archive-reporter", b"test-fake-reporter-xx")
    elif tamper == "json":
        archived = {**archived, "json": b'{"findings":[]}'}
    elif tamper == "evidence":
        evidence = {FINDING: [{"type": "forged"}]}
    elif tamper == "tenant":
        claim["scope"]["tenant_id"] = "eng-other"
    elif tamper == "cross_owner":
        rows["session_states"]["created_by"] = "foreign-owner"
    elif tamper == "flow_revision":
        rows["execution_flows"]["revision"] += 1
    db = _ReadOnlyDatabase(rows)
    with pytest.raises(release.IndependentReleaseDenied):
        await _verify(case, db, claim=claim, signer=signer,
                      attestation=attestation, artifacts=archived, evidence=evidence)
    assert not any("independent_senior_release_receipts" in sql for sql, _ in db.queries)


@pytest.mark.anyio
@pytest.mark.parametrize("disabled", [True, None])
async def test_senior_subject_revoked_or_missing_denies(case, disabled):
    rows = copy.deepcopy(case.rows)
    rows["operator_subject_controls"] = (
        None if disabled is None else {"actor_id": "senior-owner", "disabled": True}
    )
    db = _ReadOnlyDatabase(rows)
    with pytest.raises(release.IndependentReleaseDenied):
        await _verify(case, db)
    assert not any("independent_target_effect_verifications" in sql for sql, _ in db.queries)


@pytest.mark.anyio
async def test_fake_enrollment_wrong_key_or_revoked_fails_closed(case):
    for enrollment in (
        {"senior_sub": "senior-owner", "status": "active", "revoked_at": None,
         "key_id": "senior-release-external", "tenant_id": ENG,
         "public_key_sha256": "0" * 64},
        {"senior_sub": "senior-owner", "status": "revoked", "revoked_at": NOW,
         "key_id": "senior-release-external", "tenant_id": ENG,
         "public_key_sha256": _sha(case.trust.senior_public_key)},
    ):
        rows = copy.deepcopy(case.rows)
        rows["independent_senior_release_key_enrollments"] = enrollment
        with pytest.raises(release.IndependentReleaseDenied):
            await _verify(case, _ReadOnlyDatabase(rows))


@pytest.mark.anyio
async def test_even_synthetic_enrollment_cannot_replace_missing_0022_row(case):
    rows = copy.deepcopy(case.rows)
    _enrolled_keys(case, rows)
    db = _ReadOnlyDatabase(rows)
    with pytest.raises(release.IndependentReleaseDenied):
        await _verify(case, db)
    assert "independent_target_effect_verifications" in db.queries[-1][0]


@pytest.mark.anyio
async def test_host_cannot_approve_missing_original_target_evidence(case, monkeypatch):
    rows = copy.deepcopy(case.rows)
    _enrolled_keys(case, rows)
    hit = []

    async def assert_host_never_called(self, challenge, sha):
        hit.append((challenge, sha))
        raise AssertionError("Host must not bless an absent 0022 admission")

    monkeypatch.setattr(
        release.PinnedHostCurrentAuthority, "__call__", assert_host_never_called
    )
    with pytest.raises(release.IndependentReleaseDenied):
        await _verify(case, _ReadOnlyDatabase(rows))
    assert hit == []


@pytest.mark.anyio
async def test_false_0022_flag_denied_despite_senior_enrollment(case):
    rows = copy.deepcopy(case.rows)
    _enrolled_keys(case, rows)
    receipt = case.claim["target_owner_receipts"][0]
    rows["independent_target_effect_verifications"] = {
        "id": receipt["verification_id"], "engagement_id": ENG, "flow_id": FLOW,
        "finding_id": FINDING, "verdict_sha256": receipt["verdict_sha256"],
        "qualification_id": receipt["qualification_id"],
        "qualification_sha256": receipt["qualification_sha256"],
        "challenge_id": receipt["challenge_id"],
        "authorization_id": "auth-current-release", "authorization_version": 2,
        "authorization_sha256": "a" * 64, "flow_revision": 5,
        "status": "VERIFIED", "independent_effect_verified": False,
        "finding_verified": True, "report_release_approved": False,
        "senior_reviewer_sub": "senior-owner",
    }
    db = _ReadOnlyDatabase(rows)
    with pytest.raises(release.IndependentReleaseDenied):
        await _verify(case, db)
    assert "independent_target_effect_verifications" in db.queries[-1][0]


@pytest.mark.anyio
async def test_revoked_or_missing_host_enrollment_denies_before_effect_join(case):
    for state in ("missing", "revoked", "wrong_root"):
        rows = copy.deepcopy(case.rows)
        _enrolled_keys(case, rows)
        if state == "missing":
            rows["independent_release_host_key_enrollments"] = None
        elif state == "revoked":
            rows["independent_release_host_key_enrollments"].update(
                status="revoked", revoked_at=NOW
            )
        else:
            rows["independent_release_host_key_enrollments"].update(
                public_key_sha256="0" * 64
            )
        db = _ReadOnlyDatabase(rows)
        with pytest.raises(release.IndependentReleaseDenied):
            await _verify(case, db)
        assert "independent_release_host_key_enrollments" in db.queries[-1][0]


def _replica(case, name, *, process="a" * 64, issued=NOW-3, expires=NOW+50):
    signed = {
        "schema": "ai-osop.release-replica-qualification.v1",
        "replica_id": name,
        "qualification_id": f"qualification-{name}",
        "run_receipt_id": f"run-{name}", "run_receipt_sha256": "7" * 64,
        "engagement_id": ENG, "tenant_id": ENG, "owner_sub": "senior-owner",
        "flow_id": FLOW, "flow_revision": 5,
        "authorization_version": 2, "authorization_sha256": "a" * 64,
        "report_attestation_sha256": case.claim["report"]["attestation_sha256"],
        "outcome": "passed", "process_identity_sha256": process,
        "issued_at": issued, "expires_at": expires,
    }
    encoded = release._canonical(signed)
    receipt = copy.deepcopy(next(r for r in case.claim["replica_qualifications"]
                                 if r["replica_id"] == name))
    receipt["qualification_sha256"] = _sha(release.REPLICA_DOMAIN + encoded)
    persisted = {
        "signed_receipt_json": encoded,
        "signature_b64url": _signature(
            release.REPLICA_DOMAIN + encoded, case.replica_signers[name]
        ),
    }
    return receipt, persisted


def test_independent_replica_signatures_bound_to_run_owner_scope_and_time(case):
    receipt, stored = _replica(case, "replica-a")
    release._signed_replica_receipt(
        stored, receipt, case.claim,
        case.trust.replica_signer_roots["replica-a"], NOW,
    )
    for mutated_receipt, mutated_stored, key in (
        ({**receipt, "run_receipt_id": "run-wrong"}, stored,
         case.trust.replica_signer_roots["replica-a"]),
        (receipt, stored, case.trust.replica_signer_roots["replica-b"]),
        (receipt, {**stored, "signature_b64url": "A" * 86},
         case.trust.replica_signer_roots["replica-a"]),
    ):
        with pytest.raises(release.IndependentReleaseDenied):
            release._signed_replica_receipt(
                mutated_stored, mutated_receipt, case.claim, key, NOW,
            )
    for kwargs in (
        {"issued": NOW - 400, "expires": NOW - 2},
        {"issued": NOW - 3, "expires": NOW + 301},
    ):
        bad_receipt, bad_row = _replica(case, "replica-a", **kwargs)
        with pytest.raises(release.IndependentReleaseDenied):
            release._signed_replica_receipt(
                bad_row, bad_receipt, case.claim,
                case.trust.replica_signer_roots["replica-a"], NOW,
            )


def test_real_run_receipt_bytes_must_match_recovery_and_revocation_contract(case):
    receipt, signed = _replica(case, "replica-a", process="4" * 64)
    run = {
        "schema": "ai-osop.independent-release-run-receipt.v1",
        "replica_id": "replica-a",
        "run_receipt_id": "run-replica-a",
        "process_identity_sha256": "4" * 64,
        "engagement_id": ENG, "tenant_id": ENG, "owner_sub": "senior-owner",
        "flow_id": FLOW, "flow_revision": 5,
        "authorization_version": 2,
        "authorization_sha256": "a" * 64,
        "report_attestation_sha256": case.claim["report"]["attestation_sha256"],
        "qualification_status": "passed",
        "qualified_behaviors": {
            "multi_process_independence": True,
            "crash_recovery": True, "ack_loss": True,
            "rollback": True, "live_revocation": True,
        },
    }
    raw = release._canonical(run)
    receipt["run_receipt_sha256"] = _sha(release.RUN_DOMAIN + raw)
    row = {"run_receipt_json": raw}
    release._validated_replica_run(
        row, receipt, case.claim, process_identity_sha256="4" * 64
    )
    for change in (
        {"run_receipt_sha256": "9" * 64},
        {"run_receipt_id": "run-other"},
    ):
        with pytest.raises(release.IndependentReleaseDenied):
            release._validated_replica_run(
                row, {**receipt, **change}, case.claim,
                process_identity_sha256="4" * 64,
            )
    for field in ("ack_loss", "live_revocation", "multi_process_independence"):
        modified = copy.deepcopy(run)
        modified["qualified_behaviors"][field] = False
        with pytest.raises(release.IndependentReleaseDenied):
            release._validated_replica_run(
                {"run_receipt_json": release._canonical(modified)},
                receipt, case.claim, process_identity_sha256="4" * 64,
            )
    with pytest.raises(release.IndependentReleaseDenied):
        release._validated_replica_run(
            row, receipt, case.claim, process_identity_sha256="0" * 64,
        )


def test_replica_roots_must_be_distinct_from_senior_and_each_other(case):
    args = vars(case.trust).copy()
    for keys in (
        {"replica-a": case.trust.senior_public_key, "replica-b": case.trust.host_public_key},
        {"replica-a": case.trust.replica_signer_roots["replica-a"],
         "replica-b": case.trust.replica_signer_roots["replica-a"]},
        {"replica-a": case.trust.replica_signer_roots["replica-a"]},
    ):
        with pytest.raises(release.IndependentReleaseDenied):
            release.PinnedReleaseTrust(**{**args, "replica_signer_roots": keys})
