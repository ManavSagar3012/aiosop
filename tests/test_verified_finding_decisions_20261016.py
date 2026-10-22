"""Adversarial candidate-review storage, immutable SQL and offline DDL checks."""

import copy
import importlib.util
import pathlib
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from ai_osop.memory import verified_finding_decisions as decisions
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


class Result:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    def scalar_one_or_none(self):
        return self.row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row

    def all(self):
        return self.rows


class FakePG:
    """Query-shape-aware mock: no app DB, HTTP or external provider."""

    def __init__(self, case):
        self.case = case
        self.owner = case.owner
        self.received = []
        self.stored = []
        self.in_tx = True
        self.source = {
            "id": case.source.id,
            "engagement_id": case.flow.engagement_id,
            "flow_id": case.flow.id,
            "type": "navigate",
            "status": "completed",
            "parent_task_id": case.source.parent_task_id,
            "payload": copy.deepcopy(case.source.payload),
            "result": copy.deepcopy(case.source.result),
        }
        self.target = {
            "id": case.target.id,
            "engagement_id": case.flow.engagement_id,
            "flow_id": case.flow.id,
            "type": "navigate",
            "status": "completed",
            "parent_task_id": case.target.parent_task_id,
            "payload": copy.deepcopy(case.target.payload),
            "result": copy.deepcopy(case.target.result),
        }
        for role, row, event in (
            ("source", self.source, "evt-source"),
            ("target", self.target, "evt-target"),
        ):
            row["result"]["provider_evidence"].update(
                {
                    "provider_event_id": event,
                    "provider_receipt_sha256": ("b" if role == "source" else "c") * 64,
                }
            )
        blob, _ = case.signed_bytes()
        self.archive = {
            "target_claims_json": blob,
            "proof_sha256": "a" * 64,
            "audit_corroboration_sha256": "b" * 64,
            "authorization_version": case.signed.version,
            "flow_revision": case.flow.revision,
            "original_source_task_id": case.original.id,
            "source_task_id": case.source.id,
            "target_task_id": case.target.id,
        }

    def in_transaction(self):
        return self.in_tx

    async def execute(self, statement, params=None):
        sql = str(statement).upper()
        self.received.append((sql, params))
        if sql.startswith("INSERT INTO VERIFIED_TARGET_FINDING_DECISIONS"):
            assert "ON CONFLICT DO NOTHING RETURNING ID" in sql
            assert all(not name.endswith("body") for name in params)
            if any(
                row["review_revision"] == params["review_revision"]
                and row["engagement_id"] == params["engagement_id"]
                and row["flow_id"] == params["flow_id"]
                and row["finding_id"] == params["finding_id"]
                for row in self.stored
            ):
                return Result()
            self.stored.append(dict(params))
            return Result(params["id"])
        assert sql.strip().startswith("SELECT "), sql
        assert sql.endswith("FOR UPDATE") or sql.endswith("FOR SHARE")
        if "FROM SESSION_STATES" in sql:
            return Result(self.owner)
        if "FROM VERIFIED_TARGET_FINDING_DECISIONS" in sql:
            return Result(self.stored[-1] if self.stored else None)
        if "FROM TARGET_AUTHORITY_ASSERTIONS" in sql:
            return Result(self.archive)
        if "FROM TASKS" in sql:
            return Result(rows=[self.source, self.target])
        raise AssertionError(f"unexpected SQL: {sql}")


@pytest.fixture
def review_case(proof_case, monkeypatch):
    db = FakePG(proof_case)
    signed = SimpleNamespace(
        session_id=proof_case.flow.engagement_id,
        authorization_id=proof_case.signed.authorization_id,
        version=proof_case.signed.version,
        policy_sha256=proof_case.signed.policy_sha256,
        policy={"created_by": proof_case.owner},
    )
    signed_guard = AsyncMock(return_value=signed)
    senior_guard = AsyncMock(return_value=None)
    candidate = AsyncMock(
        return_value={
            "status": "candidate_only",
            "finding_verified": False,
            "report_release_approved": False,
            "finding_release_eligible": False,
        }
    )
    monkeypatch.setattr(decisions, "guard_sql", signed_guard)
    monkeypatch.setattr(decisions.FlowArtifactReviewStore, "_reviewer_fence", senior_guard)
    monkeypatch.setattr(decisions, "inspect_target_finding_evidence", candidate)
    kwargs = {
        "engagement_id": proof_case.flow.engagement_id,
        "flow_id": proof_case.flow.id,
        "finding_id": "vuln-123",
        "original_source_task_id": proof_case.original.id,
        "source_task_id": proof_case.source.id,
        "target_task_id": proof_case.target.id,
        "proof_sha256": "a" * 64,
        "audit_sha256": "b" * 64,
        "authorization_version": signed.version,
        "flow_revision": proof_case.flow.revision,
        "report_source_evidence_sha256": "f" * 64,
        "reviewer_sub": proof_case.owner,
        "reviewer_role": "senior_operator",
        "reviewer_token_sha256": "e" * 64,
        "reviewer_expires_at": 2080000000,
        "expected_revision": 0,
        "trusted_current_verifier": AsyncMock(return_value=True),
        "trusted_report_source_check": AsyncMock(return_value=True),
    }
    return SimpleNamespace(
        db=db,
        kwargs=kwargs,
        candidate=candidate,
        senior_guard=senior_guard,
        signed_guard=signed_guard,
    )


@pytest.mark.asyncio
async def test_append_only_candidate_with_pg_lock_cas_and_provenance(review_case):
    case = review_case
    first = await decisions.append_candidate_review(case.db, **case.kwargs)
    assert first["status"] == "independent_verification_required"
    assert first["review_revision"] == 1
    assert len(case.db.stored) == 1
    record = case.db.stored[0]
    assert record["original_source_task_id"] == case.kwargs["original_source_task_id"]
    assert record["source_event_id"] == "evt-source"
    assert record["target_event_id"] == "evt-target"
    assert record["source_request_sha256"] == "2" * 64
    assert record["target_request_sha256"] == "4" * 64
    assert record["source_response_sha256"] == record["target_response_sha256"]
    assert record["report_source_evidence_sha256"] == "f" * 64
    assert len(record["observation_binding_sha256"]) == 64
    assert len(record["decision_sha256"]) == 64
    assert record["previous_decision_sha256"] is None
    assert record["previous_decision_id"] is None
    assert all(
        v is False
        for k, v in first.items()
        if k.endswith("_verified") or k.endswith("_approved") or k.endswith("_eligible")
    )
    assert "FOR UPDATE" in case.db.received[0][0]
    assert case.senior_guard.await_count == 2
    assert case.kwargs["trusted_current_verifier"].await_count == 1
    case.kwargs["trusted_report_source_check"].assert_awaited_once_with("vuln-123", "f" * 64)

    again = await decisions.append_candidate_review(
        case.db, **{**case.kwargs, "expected_revision": 1, "decision_status": "UNKNOWN"}
    )
    assert again["status"] == "UNKNOWN"
    assert again["review_revision"] == 2
    assert case.db.stored[1]["previous_decision_id"] == record["id"]
    assert case.db.stored[1]["previous_decision_sha256"] == record["decision_sha256"]
    assert len(case.db.stored) == 2
    with pytest.raises(decisions.FindingDecisionDenied) as exc:
        await decisions.append_candidate_review(case.db, **case.kwargs)
    assert exc.value.status == 409
    assert len(case.db.stored) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("engagement_id", "eng-attacker"),
        ("flow_id", "flow-foreign"),
        ("finding_id", "../secret"),
        ("source_task_id", "task-foreign"),
        ("target_task_id", "task-source"),
        ("proof_sha256", "A" * 64),
        ("audit_sha256", "bad"),
        ("report_source_evidence_sha256", True),
        ("authorization_version", True),
        ("flow_revision", -1),
        ("expected_revision", True),
        ("decision_status", "verified"),
        ("decision_status", "released"),
        ("reviewer_role", "operator"),
        ("reviewer_expires_at", "2080000000"),
        ("reviewer_token_sha256", "bad"),
        ("reviewer_sub", "other-reviewer"),
    ],
)
async def test_invalid_scope_status_or_identity_fails_before_insert(
    review_case,
    field,
    value,
):
    case = review_case
    with pytest.raises(decisions.FindingDecisionDenied):
        await decisions.append_candidate_review(case.db, **{**case.kwargs, field: value})
    assert case.db.stored == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    [
        "missing_tx",
        "different_owner",
        "revoked_reviewer",
        "revoked_roe",
        "candidate_unknown",
        "candidate_promoted",
        "report_unverified",
        "callback_revoked",
        "expired_reviewer_after_check",
        "tampered_request",
        "tampered_response",
        "wrong_target_role",
        "wrong_source_event",
        "repeated_event",
        "repeated_provider_receipt",
        "anonymous_label",
        "denied_response",
        "redirected_response",
        "forged_parent",
        "missing_archive",
        "changed_archive_version",
        "changed_archive_audit",
        "changed_original",
        "changed_flow",
        "missing_source_task",
    ],
)
async def test_adversarial_immutable_review_sources_fail_closed(review_case, monkeypatch, attack):
    case = review_case
    if attack == "missing_tx":
        case.db.in_tx = False
    elif attack == "different_owner":
        case.db.owner = "operator-other"
    elif attack == "revoked_reviewer":
        case.senior_guard.side_effect = RuntimeError("revoked")
    elif attack == "revoked_roe":
        case.signed_guard.side_effect = RuntimeError("revoked")
    elif attack == "candidate_unknown":
        case.candidate.return_value["status"] = "UNKNOWN"
    elif attack == "candidate_promoted":
        case.candidate.return_value["finding_verified"] = True
    elif attack == "report_unverified":
        case.kwargs["trusted_report_source_check"].return_value = False
    elif attack == "callback_revoked":
        case.kwargs["trusted_current_verifier"].return_value = False
    elif attack == "expired_reviewer_after_check":
        case.senior_guard.side_effect = [None, RuntimeError("revoked")]
    elif attack == "tampered_request":
        case.db.source["payload"]["_authority_request_sha256"] = "9" * 64
    elif attack == "tampered_response":
        case.db.target["result"]["response_body_sha256"] = "9" * 64
    elif attack == "wrong_target_role":
        case.db.target["payload"]["_comparison_role"] = "source"
    elif attack == "wrong_source_event":
        case.db.source["result"]["provider_evidence"]["provider_event_id"] = "broken"
    elif attack == "repeated_event":
        case.db.target["result"]["provider_evidence"]["provider_event_id"] = "evt-source"
    elif attack == "repeated_provider_receipt":
        case.db.target["result"]["provider_evidence"]["provider_receipt_sha256"] = "b" * 64
    elif attack == "anonymous_label":
        case.db.target["payload"]["user_label"] = "anonymous"
    elif attack == "denied_response":
        case.db.target["result"]["http_status_code"] = 403
    elif attack == "redirected_response":
        case.db.target["result"]["redirected"] = True
    elif attack == "forged_parent":
        case.db.target["parent_task_id"] = "task-other"
    elif attack == "missing_archive":
        case.db.archive = None
    elif attack == "changed_archive_version":
        case.db.archive["authorization_version"] += 1
    elif attack == "changed_archive_audit":
        case.db.archive["audit_corroboration_sha256"] = "9" * 64
    elif attack == "changed_original":
        case.db.archive["original_source_task_id"] = "task-other"
    elif attack == "changed_flow":
        case.db.target["flow_id"] = "flow-other"
    elif attack == "missing_source_task":
        case.db.source = dict(case.db.target)
    with pytest.raises((decisions.FindingDecisionDenied, AttributeError, TypeError)):
        await decisions.append_candidate_review(case.db, **case.kwargs)
    assert case.db.stored == [], attack


@pytest.mark.asyncio
async def test_current_read_reverifies_and_does_not_release(review_case):
    case = review_case
    await decisions.append_candidate_review(case.db, **case.kwargs)
    inputs = {
        k: case.kwargs[k]
        for k in (
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
    result = await decisions.read_latest_candidate_review(case.db, **inputs)
    assert result["status"] == "independent_verification_required"
    assert result["finding_verified"] is False
    assert result["report_release_approved"] is False
    case.candidate.return_value["status"] = "UNKNOWN"
    revoked = await decisions.read_latest_candidate_review(case.db, **inputs)
    assert revoked["status"] == "UNKNOWN"
    assert revoked["review_revision"] == 0
    assert len(case.db.stored) == 1


@pytest.mark.asyncio
async def test_existing_row_corruption_and_concurrent_cas_refused(review_case):
    case = review_case
    await decisions.append_candidate_review(case.db, **case.kwargs)
    case.db.stored[0]["decision_sha256"] = "tampered"
    with pytest.raises(decisions.FindingDecisionDenied):
        await decisions.append_candidate_review(case.db, **{**case.kwargs, "expected_revision": 1})
    assert len(case.db.stored) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "changed_decision_digest",
        "changed_report_evidence",
        "revoked_reviewer",
        "revoked_report_source",
        "changed_observation",
    ],
)
async def test_read_revalidates_immutable_row_and_current_authority(review_case, change):
    case = review_case
    await decisions.append_candidate_review(case.db, **case.kwargs)
    args = {
        k: case.kwargs[k]
        for k in (
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
    if change == "changed_decision_digest":
        case.db.stored[0]["decision_sha256"] = "0" * 64
    elif change == "changed_report_evidence":
        case.db.stored[0]["report_source_evidence_sha256"] = "0" * 64
    elif change == "revoked_reviewer":
        case.senior_guard.side_effect = RuntimeError("revoked")
    elif change == "revoked_report_source":
        args["trusted_report_source_check"].return_value = False
    elif change == "changed_observation":
        case.db.target["result"]["provider_evidence"]["provider_event_id"] = "evt-rotated"
    row = await decisions.read_latest_candidate_review(case.db, **args)
    assert row["status"] == "UNKNOWN"
    assert row["finding_verified"] is False
    assert row["report_release_approved"] is False
    assert len(case.db.stored) == 1


def test_0020_pg_ddl_offline_preserves_0019_and_append_only_constraint(monkeypatch):
    migration = (
        pathlib.Path(__file__).parents[1] / "migrations/versions/0020_verified_target_findings.py"
    )
    spec = importlib.util.spec_from_file_location("verified_target_migration_0020", migration)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "0020"
    assert mod.down_revision == "0019"
    operations = []
    metadata = sa.MetaData()
    # Offline predecessor schemas give the PostgreSQL DDL compiler concrete
    # referenced column names; no database is touched or provisioned.
    sa.Table("session_states", metadata, sa.Column("session_id", sa.String(64), primary_key=True))
    sa.Table("execution_flows", metadata, sa.Column("id", sa.String(64), primary_key=True))
    sa.Table("tasks", metadata, sa.Column("id", sa.String(64), primary_key=True))
    sa.Table(
        "target_authority_assertions",
        metadata,
        sa.Column("proof_sha256", sa.String(64), primary_key=True),
    )

    class FakeOperations:
        def create_table(self, name, *columns, **kwargs):
            table = sa.Table(name, metadata, *columns, **kwargs)
            ddl = str(sa.schema.CreateTable(table).compile(dialect=postgresql.dialect()))
            operations.append(("create_table", name, ddl, table))

        def create_index(self, *args, **kwargs):
            operations.append(("create_index", args, kwargs))

        def drop_index(self, *args, **kwargs):
            operations.append(("drop_index", args, kwargs))

        def execute(self, statement):
            operations.append(("execute", str(statement)))

        def drop_table(self, table):
            operations.append(("drop_table", table))

    monkeypatch.setattr(mod, "op", FakeOperations())
    mod.upgrade()
    table_ddl = next(x[2] for x in operations if x[0] == "create_table")
    for fragment in (
        "FOREIGN KEY(proof_sha256) REFERENCES target_authority_assertions (proof_sha256)",
        "UNIQUE (engagement_id, flow_id, finding_id, review_revision)",
        "independent_verification_required",
        "candidate_only",
        "UNKNOWN",
        "previous_decision_sha256",
        "source_request_sha256",
        "source_response_sha256",
        "observation_binding_sha256",
        "report_source_evidence_sha256",
    ):
        assert fragment in table_ddl
    assert "verified" not in table_ddl.split("decision_status IN", 1)[-1].split(")", 1)[0].lower()
    assert any(
        "BEFORE UPDATE OR DELETE" in entry[1]
        and "reject_target_authority_nonce_mutation" in entry[1]
        for entry in operations
        if entry[0] == "execute"
    )
    mod.downgrade()
    assert operations[-1] == ("drop_table", "verified_target_finding_decisions")
