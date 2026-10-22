"""Fail-closed target effect qualification: SQL mocks, no app DB or targets."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from ai_osop.core.target_authority_proof import _canonical
from ai_osop.memory import target_verified_promotions as promotions
from ai_osop.memory import verified_finding_decisions as decisions
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401
from tests.test_verified_finding_decisions_20261016 import review_case  # noqa: F401


class One:
    def __init__(self, value=None):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def mappings(self):
        return self

    def one_or_none(self):
        return self.value


class IsolatedPg:
    def __init__(self, case, signed_claim):
        self.case = case
        self.received = []
        self.attempts = []
        self.in_tx = True
        self.owner = case.proof.owner
        self.collision = False
        self.insert_error = False
        claims = case.proof.claims
        ownership = {
            **claims,
            "schema": "ai-osop.target-independent-audit.v1",
            "role": "ownership",
            "resource_id": "123",
            "target_proof_sha256": case.proof_sha,
            "source_access_allowed": True,
            "nonce": "1" * 32,
            "issued_at": 12,
            "expires_at": 45,
        }
        access = {
            **ownership,
            "role": "access",
            "nonce": "2" * 32,
        }
        self.target_archive = {
            "engagement_id": claims["engagement_id"],
            "flow_id": claims["flow_id"],
            "proof_sha256": case.proof_sha,
            "audit_corroboration_sha256": case.audit_sha,
            "original_source_task_id": case.proof.original.id,
            "source_task_id": case.proof.source.id,
            "target_task_id": case.proof.target.id,
            "authorization_version": case.proof.signed.version,
            "flow_revision": case.proof.flow.revision,
            "target_claims_json": signed_claim,
            "ownership_audit_json": _canonical(ownership),
            "access_audit_json": _canonical(access),
        }

    def in_transaction(self):
        return self.in_tx

    async def execute(self, stmt, args=None):
        sql = str(stmt).upper().strip()
        self.received.append((sql, args))
        if sql.startswith("INSERT INTO TARGET_EFFECT_QUALIFICATION_ATTEMPTS"):
            assert sql.endswith("ON CONFLICT DO NOTHING RETURNING ID")
            assert all(
                not k.endswith("body") and "token" not in k and not k.endswith("_json")
                for k in args
            )
            if self.insert_error:
                raise RuntimeError("isolated DB fault")
            if self.collision or any(row["revision"] == args["revision"] for row in self.attempts):
                return One(None)
            self.attempts.append(dict(args))
            return One(args["id"])
        assert sql.startswith("SELECT "), sql
        assert sql.endswith(("FOR SHARE", "FOR UPDATE")), sql
        if "FROM SESSION_STATES" in sql:
            return One(self.owner)
        if "FROM VERIFIED_TARGET_FINDING_DECISIONS" in sql:
            return One(self.case.review)
        if "FROM TARGET_EFFECT_QUALIFICATION_ATTEMPTS" in sql:
            return One(self.attempts[-1] if self.attempts else None)
        if "FROM TARGET_AUTHORITY_ASSERTIONS" in sql:
            return One(self.target_archive)
        raise AssertionError("unexpected qualification query: " + sql)


@pytest.fixture
def admission(review_case, proof_case, monkeypatch):
    claims, _ = proof_case.signed_bytes()
    case = SimpleNamespace(
        proof=proof_case,
        proof_sha="a" * 64,
        audit_sha="b" * 64,
        review=None,
        review_case=review_case,
        signed=review_case.signed_guard.return_value,
        trusted_current=AsyncMock(return_value=True),
        trusted_report=AsyncMock(return_value=True),
    )
    case.db = IsolatedPg(case, claims)
    monkeypatch.setattr(promotions, "guard_sql", review_case.signed_guard)
    monkeypatch.setattr(
        promotions.FlowArtifactReviewStore,
        "_reviewer_fence",
        review_case.senior_guard,
    )
    case.read_review = AsyncMock()
    monkeypatch.setattr(promotions, "read_latest_candidate_review", case.read_review)
    case.kwargs = {
        "engagement_id": proof_case.flow.engagement_id,
        "flow_id": proof_case.flow.id,
        "finding_id": "vuln-123",
        "proof_sha256": case.proof_sha,
        "audit_sha256": case.audit_sha,
        "authorization_version": proof_case.signed.version,
        "flow_revision": proof_case.flow.revision,
        "reviewer_sub": proof_case.owner,
        "reviewer_role": "senior_operator",
        "reviewer_token_sha256": "e" * 64,
        "reviewer_expires_at": 2080000000,
        "expected_revision": 0,
        "trusted_current_verifier": case.trusted_current,
        "trusted_report_source_check": case.trusted_report,
    }
    return case


async def start(case):
    result = await decisions.append_candidate_review(case.review_case.db, **case.review_case.kwargs)
    case.review = case.review_case.db.stored[0]
    case.read_review.return_value = result
    case.kwargs["review_decision_id"] = result["decision_id"]
    case.kwargs["review_decision_sha256"] = result["decision_sha256"]
    return result


@pytest.mark.asyncio
async def test_unknown_only_append_with_pg_cas_and_human_signed_current_review(admission):
    case = admission
    await start(case)
    result = await promotions.record_unknown_effect_qualification(case.db, **case.kwargs)
    assert result["status"] == "UNKNOWN"
    assert result["reason_code"] == "independent_target_effect_service_missing"
    assert result["revision"] == 1
    assert result["qualification_id"].startswith("teqa-")
    assert len(case.db.attempts) == 1
    row = case.db.attempts[0]
    assert promotions._integrity(row) is True
    assert row["finding_id"] == case.kwargs["finding_id"]
    assert row["proof_sha256"] == case.proof_sha
    assert row["review_decision_sha256"] == case.review["decision_sha256"]
    assert row["observation_binding_sha256"] == case.review["observation_binding_sha256"]
    assert row["resource_id"] == "123"
    assert row["resource_visibility"] == "private"
    assert row["anonymous_http_status"] == 403
    assert row["previous_attempt_id"] is None
    assert row["previous_attempt_sha256"] is None
    assert all(
        val is False
        for key, val in result.items()
        if key.endswith("_verified") or key.endswith("_approved") or key.endswith("_eligible")
    )
    assert "FOR UPDATE" in case.db.received[0][0]
    assert case.read_review.await_count == 1
    assert case.trusted_current.await_count == 1
    case.trusted_report.assert_awaited_once_with("vuln-123", "f" * 64)
    assert case.review_case.senior_guard.await_count >= 4

    second = await promotions.record_unknown_effect_qualification(
        case.db, **{**case.kwargs, "expected_revision": 1}
    )
    assert second["revision"] == 2
    assert case.db.attempts[1]["previous_attempt_id"] == row["id"]
    assert case.db.attempts[1]["previous_attempt_sha256"] == row["attempt_sha256"]
    with pytest.raises(promotions.TargetEffectQualificationDenied) as exc:
        await promotions.record_unknown_effect_qualification(case.db, **case.kwargs)
    assert exc.value.status == 409
    assert len(case.db.attempts) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    [
        "foreign_owner",
        "no_transaction",
        "senior_revoked",
        "roe_revoked",
        "wrong_review_id",
        "wrong_review_sha",
        "wrong_proof_sha",
        "wrong_audit_sha",
        "review_missing",
        "review_edited",
        "reviewer_foreign",
        "wrong_flow_revision",
        "stale_signed_roe",
        "candidate_untrusted",
        "current_session_revoked",
        "report_source_rotated",
        "refreshed_reviewer_revoked",
        "refreshed_signed_roe_rotated",
        "tampered_signed_claim",
        "public_owner",
        "anonymous_public",
        "foreign_owner_record",
        "wrong_identity_pair",
        "changed_response",
        "target_denied",
        "source_denied",
        "differing_signed_audits",
        "unknown_original_task",
        "wrong_immutable_audit",
    ],
)
async def test_adversarial_candidate_cannot_promote_or_persist(admission, attack):
    case = admission
    await start(case)
    if attack == "foreign_owner":
        case.db.owner = "foreign_owner"
    elif attack == "no_transaction":
        case.db.in_tx = False
    elif attack == "senior_revoked":
        case.review_case.senior_guard.side_effect = RuntimeError("revoked")
    elif attack == "roe_revoked":
        case.review_case.signed_guard.side_effect = RuntimeError("revoked")
    elif attack == "wrong_review_id":
        case.kwargs["review_decision_id"] = "vfdec-" + "b" * 32
    elif attack == "wrong_review_sha":
        case.kwargs["review_decision_sha256"] = "1" * 64
    elif attack == "wrong_proof_sha":
        case.kwargs["proof_sha256"] = "8" * 64
    elif attack == "wrong_audit_sha":
        case.kwargs["audit_sha256"] = "8" * 64
    elif attack == "review_missing":
        case.review = None
    elif attack == "review_edited":
        case.review["source_request_sha256"] = "8" * 64
    elif attack == "reviewer_foreign":
        case.kwargs["reviewer_sub"] = "attacker"
    elif attack == "wrong_flow_revision":
        case.kwargs["flow_revision"] = 9
    elif attack == "stale_signed_roe":
        case.signed.policy_sha256 = "c" * 64
    elif attack == "candidate_untrusted":
        case.read_review.return_value = {"status": "UNKNOWN", "decision_id": None}
    elif attack == "current_session_revoked":
        case.trusted_current.return_value = False
    elif attack == "report_source_rotated":
        case.trusted_report.return_value = False
    elif attack == "refreshed_reviewer_revoked":
        case.review_case.senior_guard.side_effect = [None, RuntimeError("revoked")]
    elif attack == "refreshed_signed_roe_rotated":
        changed = SimpleNamespace(**case.signed.__dict__)
        changed.policy_sha256 = "0" * 64
        case.review_case.signed_guard.side_effect = [case.signed, changed]
    elif attack == "tampered_signed_claim":
        case.db.target_archive["target_claims_json"] += b" "
    elif attack == "public_owner":
        _change_claim(case, "resource_visibility", "public")
    elif attack == "anonymous_public":
        _change_claim(case, "anonymous_http_status", 200)
    elif attack == "foreign_owner_record":
        _change_claim(case, "resource_owner_identity", "another_user")
    elif attack == "wrong_identity_pair":
        _change_claim(case, "target_identity", "account_a")
    elif attack == "changed_response":
        _change_claim(case, "target_response_sha256", "c" * 64)
    elif attack == "target_denied":
        _change_claim(case, "target_http_status", 403)
    elif attack == "source_denied":
        _change_claim(case, "source_http_status", 403)
    elif attack == "differing_signed_audits":
        ownership = promotions._strict_json(
            case.db.target_archive["ownership_audit_json"], max_bytes=4096
        )
        ownership["target_http_status"] = 500
        case.db.target_archive["ownership_audit_json"] = _canonical(ownership)
    elif attack == "unknown_original_task":
        case.db.target_archive["original_source_task_id"] = "task-missing"
    elif attack == "wrong_immutable_audit":
        case.db.target_archive["audit_corroboration_sha256"] = "0" * 64
    try:
        result = await promotions.record_unknown_effect_qualification(case.db, **case.kwargs)
        assert result["status"] == "UNKNOWN"
        assert result["revision"] == 0
    except promotions.TargetEffectQualificationDenied:
        pass
    assert case.db.attempts == [], attack


def _change_claim(case, field, value):
    for name in ("target_claims_json", "ownership_audit_json", "access_audit_json"):
        document = promotions._strict_json(case.db.target_archive[name], max_bytes=4096)
        document[field] = value
        case.db.target_archive[name] = _canonical(document)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "param,invalid",
    [
        ("engagement_id", "eng-foreign"),
        ("flow_id", "../../owned"),
        ("finding_id", "finding/other"),
        ("review_decision_id", "abc"),
        ("review_decision_sha256", "f" * 63),
        ("proof_sha256", "A" * 64),
        ("audit_sha256", 1),
        ("authorization_version", True),
        ("flow_revision", -1),
        ("reviewer_sub", "operator-other"),
        ("reviewer_role", "operator"),
        ("reviewer_token_sha256", "password"),
        ("reviewer_expires_at", "2099"),
        ("expected_revision", True),
    ],
)
async def test_invalid_signature_scope_human_role_cannot_insert(admission, param, invalid):
    case = admission
    await start(case)
    with pytest.raises(promotions.TargetEffectQualificationDenied):
        await promotions.record_unknown_effect_qualification(
            case.db, **{**case.kwargs, param: invalid}
        )
    assert case.db.attempts == []


@pytest.mark.asyncio
async def test_missing_real_production_oracle_is_not_a_promotion_capability(admission):
    case = admission
    await start(case)
    # Caller cannot inject source-independent VERIFIED testimony or status.
    with pytest.raises(TypeError):
        await promotions.record_unknown_effect_qualification(
            case.db,
            **case.kwargs,
            independent_target_effect_verified=True,
        )
    assert case.db.attempts == []
    missing_source = await promotions.record_unknown_effect_qualification(
        case.db,
        **{
            **case.kwargs,
            "trusted_current_verifier": None,
        },
    )
    assert missing_source["status"] == "UNKNOWN"
    assert missing_source["revision"] == 0
    assert missing_source["finding_verified"] is False
    assert case.db.attempts == []


@pytest.mark.asyncio
async def test_broken_db_insert_and_atomic_conflict_require_rollback(admission):
    case = admission
    await start(case)
    case.db.collision = True
    with pytest.raises(promotions.TargetEffectQualificationDenied) as exc:
        await promotions.record_unknown_effect_qualification(case.db, **case.kwargs)
    assert exc.value.status == 409
    case.db.collision = False
    case.db.insert_error = True
    with pytest.raises(promotions.TargetEffectQualificationDenied) as exc:
        await promotions.record_unknown_effect_qualification(case.db, **case.kwargs)
    assert exc.value.status == 503
    assert case.db.attempts == []


@pytest.mark.asyncio
async def test_read_only_revocation_or_tamper_returns_unqualified_unknown(admission):
    case = admission
    await start(case)
    await promotions.record_unknown_effect_qualification(case.db, **case.kwargs)
    read = {
        key: case.kwargs[key]
        for key in (
            "engagement_id",
            "flow_id",
            "finding_id",
            "reviewer_sub",
            "reviewer_role",
            "reviewer_token_sha256",
            "reviewer_expires_at",
            "authorization_version",
            "trusted_current_verifier",
            "trusted_report_source_check",
        )
    }
    observed = await promotions.read_target_effect_qualification(case.db, **read)
    assert observed["revision"] == 1
    assert observed["status"] == "UNKNOWN"
    assert observed["finding_verified"] is False
    case.trusted_current.return_value = False
    assert (await promotions.read_target_effect_qualification(case.db, **read))["revision"] == 0
    case.trusted_current.return_value = True
    case.db.attempts[0]["proof_sha256"] = "c" * 64
    assert (await promotions.read_target_effect_qualification(case.db, **read))["revision"] == 0
    assert len(case.db.attempts) == 1


def test_0021_migration_pg_ddl_only_unknown_and_immutable(monkeypatch):
    migration = Path(__file__).parents[1] / "migrations/versions/0021_target_verified_promotions.py"
    spec = importlib.util.spec_from_file_location("target_promotions_0021", migration)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0021" and module.down_revision == "0020"
    metadata = sa.MetaData()
    for table, column in (
        ("session_states", "session_id"),
        ("execution_flows", "id"),
        ("tasks", "id"),
        ("verified_target_finding_decisions", "id"),
        ("target_authority_assertions", "proof_sha256"),
    ):
        sa.Table(table, metadata, sa.Column(column, sa.String(64), primary_key=True))
    actions = []

    class FakeOp:
        def create_table(self, name, *cols):
            table = sa.Table(name, metadata, *cols)
            ddl = str(sa.schema.CreateTable(table).compile(dialect=postgresql.dialect()))
            actions.append(("table", name, ddl))

        def create_index(self, *args):
            actions.append(("index", args))

        def execute(self, query):
            actions.append(("sql", str(query)))

        def drop_index(self, *args, **kwargs):
            actions.append(("drop_index", args))

        def drop_table(self, name):
            actions.append(("drop", name))

    monkeypatch.setattr(module, "op", FakeOp())
    module.upgrade()
    ddl = next(value for kind, _, value in actions if kind == "table")
    assert "status = 'UNKNOWN'" in ddl
    assert "independent_effect_verified = false" in ddl
    assert "finding_verified = false" in ddl
    assert "report_release_approved = false" in ddl
    assert "verified_target_finding_decisions (id)" in ddl
    assert "target_authority_assertions (proof_sha256)" in ddl
    assert "ON CONFLICT" not in ddl
    assert any(
        "BEFORE UPDATE OR DELETE" in action[1]
        and "reject_target_authority_nonce_mutation" in action[1]
        for action in actions
        if action[0] == "sql"
    )
    module.downgrade()
    assert actions[-1] == ("drop", "target_effect_qualification_attempts")
