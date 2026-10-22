"""FastAPI senior-only candidate reviews and signed-source lookup, no external IO."""

import copy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.deps import state
from ai_osop.api.routers import verified_finding_reviews as reviews
from ai_osop.core.models import Task
from ai_osop.orchestrator.context_compaction import task_assignment_sha256
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401

ENG = "eng-tenant"
FLOW = "flow-owned"
FINDING = "vuln-123"
REPORT = f"report-{ENG}-v1"
SHA = "a" * 64


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

    def scalars(self):
        return self

    def all(self):
        return self.rows


class Db:
    def __init__(self, owner, tasks):
        self.owner = owner
        self.tasks = tasks
        self.flow = SimpleNamespace(
            engagement_id=ENG,
            status="running",
            revision=3,
        )
        self.archive = None
        self.fail = False
        self.queries = []
        self.begins = 0
        self.ended = 0

    async def __aenter__(self):
        self.begins += 1
        return self

    async def __aexit__(self, *_):
        self.ended += 1
        return False

    def begin(self):
        return self

    async def execute(self, statement, params=None):
        sql = str(statement)
        self.queries.append((sql, params))
        if self.fail:
            raise RuntimeError("unavailable")
        if "FROM session_states" in sql:
            assert "FOR SHARE" in sql or "FOR UPDATE" in sql
            return Result(self.owner)
        if "FROM verified_target_finding_decisions" in sql:
            assert "FOR SHARE" in sql
            return Result(self.archive)
        if "FROM execution_flows" in sql:
            return Result(self.flow)
        if "FROM user_sessions" in sql:
            return Result(SimpleNamespace(pk="trusted-session"))
        if "FROM tasks" in sql:
            if " IN " in sql.upper():
                return Result(rows=self.tasks)
            return Result(self.tasks[0] if self.tasks else None)
        raise AssertionError(f"Unexpected route SQL: {sql}")


class Memory:
    def __init__(self, db):
        self._async_session = lambda: db
        self.verify_signed_graph_action = AsyncMock(return_value=True)


@pytest.fixture
def candidate_api(monkeypatch, proof_case):
    db = Db(proof_case.owner, [proof_case.source, proof_case.target])
    memory = Memory(db)
    session_store = SimpleNamespace(
        sm=memory,
        _encryption=object(),
        _orm_to_dto=lambda *args: object(),
    )
    orch = SimpleNamespace(
        session_memory=memory, session_store=session_store, graph_memory=SimpleNamespace()
    )
    monkeypatch.setitem(state, "orchestrator", orch)
    monkeypatch.setattr(reviews, "SessionMemory", Memory)
    monkeypatch.setattr(reviews, "assert_engagement_access", AsyncMock(return_value=True))
    signed = SimpleNamespace(
        session_id=ENG,
        version=proof_case.signed.version,
        authorization_id=proof_case.signed.authorization_id,
        policy_sha256=proof_case.signed.policy_sha256,
    )
    signed_check = AsyncMock(return_value=signed)
    senior_check = AsyncMock(return_value=None)
    source_check = AsyncMock(return_value=True)
    dispatch_check = AsyncMock(return_value=True)
    fingerprints = MagicMock(return_value=None)
    monkeypatch.setattr(reviews, "guard_sql", signed_check)
    monkeypatch.setattr(reviews.FlowArtifactReviewStore, "_reviewer_fence", senior_check)
    monkeypatch.setattr(reviews, "_independent_report_source_check", source_check)
    monkeypatch.setattr(reviews, "_verify_signed_replay_dispatches", dispatch_check)
    monkeypatch.setattr(reviews, "reverify_replay_fingerprints", fingerprints)
    reviewer = {
        "sub": proof_case.owner,
        "role": "senior_operator",
        "_reviewer_token_sha256": "f" * 64,
        "_reviewer_expires_at": 2080000000,
    }
    calls = []

    async def append(db_arg, **kwargs):
        assert db_arg is db
        calls.append(("write", kwargs))
        assert await kwargs["trusted_current_verifier"]() is True
        assert (
            await kwargs["trusted_report_source_check"](
                kwargs["finding_id"], kwargs["report_source_evidence_sha256"]
            )
            is True
        )
        return {
            "status": "candidate_only",
            "review_revision": 1,
            "decision_id": "vfdec-" + "1" * 32,
            "finding_verified": False,
            "report_release_approved": False,
            "finding_release_eligible": False,
        }

    async def read(db_arg, **kwargs):
        assert db_arg is db
        calls.append(("read", kwargs))
        assert await kwargs["trusted_current_verifier"]() is True
        assert await kwargs["trusted_report_source_check"](FINDING, SHA) is True
        return {
            "status": "independent_verification_required",
            "review_revision": 1,
            "decision_id": "vfdec-" + "1" * 32,
            "finding_verified": False,
            "report_release_approved": False,
            "finding_release_eligible": False,
        }

    monkeypatch.setattr(reviews, "append_candidate_review", append)
    monkeypatch.setattr(reviews, "read_latest_candidate_review", read)
    app = FastAPI()
    app.include_router(reviews.router)
    app.dependency_overrides[reviews._senior_reviewer] = lambda: reviewer
    client = TestClient(app)
    body = {
        "finding_id": FINDING,
        "report_id": REPORT,
        "original_source_task_id": proof_case.original.id,
        "source_task_id": proof_case.source.id,
        "target_task_id": proof_case.target.id,
        "proof_sha256": SHA,
        "audit_sha256": "b" * 64,
        "report_source_evidence_sha256": SHA,
        "expected_authorization_version": signed.version,
        "expected_flow_revision": proof_case.flow.revision,
        "expected_review_revision": 0,
        "decision_status": "candidate_only",
    }
    root = f"/engagements/{ENG}/flows/{FLOW}/target-authority/finding-candidate-reviews"
    db.archive = {
        "original_source_task_id": body["original_source_task_id"],
        "source_task_id": body["source_task_id"],
        "target_task_id": body["target_task_id"],
        "proof_sha256": body["proof_sha256"],
        "audit_corroboration_sha256": body["audit_sha256"],
        "flow_revision": body["expected_flow_revision"],
        "report_source_evidence_sha256": SHA,
    }
    return SimpleNamespace(
        client=client,
        app=app,
        db=db,
        memory=memory,
        reviewer=reviewer,
        signed_check=signed_check,
        senior_check=senior_check,
        source_check=source_check,
        dispatch_check=dispatch_check,
        fingerprints=fingerprints,
        body=body,
        root=root,
        calls=calls,
    )


def test_create_and_read_are_signed_candidate_only_and_nocache(candidate_api):
    env = candidate_api
    created = env.client.post(env.root, json=env.body)
    assert created.status_code == 200, created.text
    assert created.json()["status"] == "candidate_only"
    assert created.json()["finding_verified"] is False
    assert created.json()["report_release_approved"] is False
    assert created.headers["cache-control"] == "private, no-store"
    assert created.headers["x-content-type-options"] == "nosniff"
    assert env.calls[0][0] == "write"
    assert env.calls[0][1]["trusted_report_source_check"] is not None
    assert "FOR UPDATE" in env.db.queries[0][0]
    assert env.fingerprints.call_count >= 2
    assert env.dispatch_check.await_count >= 1
    assert env.senior_check.await_count >= 2
    env.fingerprints.reset_mock()
    read = env.client.get(
        env.root + "/" + FINDING,
        params={"report_id": REPORT, "expected_authorization_version": 5},
    )
    assert read.status_code == 200, read.text
    assert read.json()["status"] == "independent_verification_required"
    assert read.json()["finding_verified"] is False
    assert read.json()["report_release_approved"] is False
    assert read.headers["cache-control"] == "private, no-store"
    assert env.calls[-1][0] == "read"
    assert any("FOR SHARE" in sql for sql, _ in env.db.queries)
    assert env.fingerprints.call_count >= 2
    assert env.db.begins == env.db.ended
    assert not any(
        q[0].strip().upper().startswith(("INSERT", "UPDATE", "DELETE")) for q in env.db.queries
    )


@pytest.mark.parametrize(
    "changed,expected",
    [
        ("missing_owner", 403),
        ("not_a_senior", 403),
        ("expired_senior", 403),
        ("invalid_reviewer_digest", 403),
        ("revoked_senior", 403),
        ("different_signed_version", 409),
        ("no_report_source", 409),
        ("bad_report_id", 422),
        ("bad_signed_sha", 422),
        ("invalid_role_payload", 422),
        ("duplicate_source_task", 422),
        ("unknown_flow", 422),
        ("db_offline", 503),
        ("dispatch_missing", 409),
        ("rotated_session", 409),
    ],
)
def test_adversarial_create_denied_before_append(candidate_api, changed, expected):
    env = candidate_api
    body = copy.deepcopy(env.body)
    url = env.root
    if changed == "missing_owner":
        env.db.owner = "attacker"
    elif changed == "not_a_senior":
        env.reviewer["role"] = "operator"
    elif changed == "expired_senior":
        env.reviewer["_reviewer_expires_at"] = 1
    elif changed == "invalid_reviewer_digest":
        env.reviewer["_reviewer_token_sha256"] = "garbage"
    elif changed == "revoked_senior":
        env.senior_check.side_effect = reviews.ArtifactReviewDenied(403, "revoked")
    elif changed == "different_signed_version":
        env.signed_check.return_value.version = 7
    elif changed == "no_report_source":
        env.source_check.return_value = False
    elif changed == "bad_report_id":
        body["report_id"] = "../../private"
    elif changed == "bad_signed_sha":
        body["proof_sha256"] = "not-a-digest"
    elif changed == "invalid_role_payload":
        body["decision_status"] = "verified"
    elif changed == "duplicate_source_task":
        body["source_task_id"] = body["target_task_id"]
    elif changed == "unknown_flow":
        url = env.root.replace(FLOW, "../../unknown")
        expected = 404
    elif changed == "db_offline":
        env.db.fail = True
    elif changed == "dispatch_missing":
        env.dispatch_check.return_value = False
    elif changed == "rotated_session":
        env.fingerprints.side_effect = RuntimeError("rotated")
    response = env.client.post(url, json=body)
    assert response.status_code == expected, (changed, response.status_code, response.text)
    assert not env.calls


def test_get_unknown_when_archive_missing_or_source_invalid(candidate_api):
    env = candidate_api
    env.db.archive = None
    response = env.client.get(
        env.root + "/" + FINDING,
        params={"report_id": REPORT, "expected_authorization_version": 5},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "UNKNOWN"
    assert response.json()["review_revision"] == 0
    assert response.json()["finding_verified"] is False
    assert env.calls == []
    env.db.archive = {
        "original_source_task_id": env.body["original_source_task_id"],
        "source_task_id": env.body["source_task_id"],
        "target_task_id": env.body["target_task_id"],
        "proof_sha256": env.body["proof_sha256"],
        "audit_corroboration_sha256": env.body["audit_sha256"],
        "flow_revision": env.body["expected_flow_revision"],
        "report_source_evidence_sha256": SHA,
    }
    env.source_check.return_value = False
    response = env.client.get(
        env.root + "/" + FINDING,
        params={"report_id": REPORT, "expected_authorization_version": 5},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "UNKNOWN"
    assert env.calls == []


def test_live_senior_dependency_denies_missing_bearer_without_override(candidate_api):
    env = candidate_api
    env.app.dependency_overrides.clear()
    response = env.client.post(env.root, json=env.body)
    assert response.status_code == 401
    assert env.calls == []


@pytest.fixture
def report_source_case(monkeypatch, proof_case):
    original = proof_case.original.model_copy(deep=True)
    original.payload["_authorization_version"] = proof_case.signed.version
    original.result["evidence_sha256"] = SHA
    source_binding = {
        "source_task_id": original.id,
        "source_task_sha256": task_assignment_sha256(original),
        "flow_id": FLOW,
        "flow_revision": proof_case.flow.revision,
        "authorization_version": proof_case.signed.version,
        "authorization_sha256": proof_case.signed.policy_sha256,
        "source_event_id": "evt-source",
        "provider_receipt_sha256": "e" * 64,
    }
    bundle = {
        "attestation": {
            "attestation": {
                "evidence_provenance": [{"finding_id": FINDING, "evidence_sha256": SHA}]
            }
        },
        "artifacts": {
            "json": json.dumps(
                {
                    "findings": [
                        {
                            "id": FINDING,
                            "evidence_hash": SHA,
                            "source_binding": source_binding,
                        }
                    ]
                }
            ).encode(),
        },
    }
    db = Db(proof_case.owner, [original])
    memory = Memory(db)
    signed = SimpleNamespace(
        version=proof_case.signed.version,
        policy_sha256=proof_case.signed.policy_sha256,
    )
    graph_evidence = AsyncMock(return_value={FINDING: {"evidence": 1}})

    async def graph(_, __, ___, *, source_records=None):
        source_records[FINDING] = dict(source_binding)
        return await graph_evidence()

    monkeypatch.setattr(reviews, "load_attested_bundle", lambda *args: bundle)
    monkeypatch.setattr(reviews, "_graph_evidence", graph)
    monkeypatch.setattr(
        reviews,
        "verify_loaded_bundle",
        lambda *args, **kwargs: {"release_status": "generation_binding_pending_verification"},
    )
    monkeypatch.setattr(reviews, "_refuse_unsupported_target_promotion", lambda *a: None)
    generator = AsyncMock(return_value=None)
    monkeypatch.setattr(reviews, "_verify_generation_release", generator)
    env = SimpleNamespace(
        db=db,
        memory=memory,
        orch=SimpleNamespace(graph_memory=object()),
        signed=signed,
        bundle=bundle,
        source=original,
        source_binding=source_binding,
        graph_evidence=graph_evidence,
        generator=generator,
    )
    return env


async def _verify_report(case):
    return await reviews._independent_report_source_check(
        case.db,
        case.orch,
        case.memory,
        engagement_id=ENG,
        flow_id=FLOW,
        flow_revision=3,
        report_id=REPORT,
        signed=case.signed,
        finding_id=FINDING,
        evidence_sha256=SHA,
    )


@pytest.mark.asyncio
async def test_independently_signed_report_source_and_pg_event_required(report_source_case):
    env = report_source_case
    assert await _verify_report(env) is True
    env.memory.verify_signed_graph_action.assert_awaited_once_with(
        ENG, env.source.id, "evt-source", "e" * 64, env.signed.version
    )
    env.generator.assert_awaited_once()
    assert any("FROM tasks" in sql and "FOR UPDATE" in sql for sql, _ in env.db.queries)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    [
        "unbound_report",
        "fake_graph_source",
        "missing_task",
        "unverified_event",
        "report_not_generation_bound",
        "wrong_evidence",
        "wrong_roe",
        "changed_source_evidence",
        "signed_report_tampered",
        "report_generated_from_wrong_finding",
        "wrong_source_flow",
        "stale_source_flow_revision",
        "revoked_source_flow",
    ],
)
async def test_unsigned_stale_or_graph_only_report_source_refused(
    report_source_case,
    monkeypatch,
    attack,
):
    env = report_source_case
    if attack == "unbound_report":
        del json.loads(env.bundle["artifacts"]["json"])["findings"][0]["source_binding"]
        report = json.loads(env.bundle["artifacts"]["json"])
        del report["findings"][0]["source_binding"]
        env.bundle["artifacts"]["json"] = json.dumps(report).encode()
    elif attack == "fake_graph_source":
        env.source_binding["source_event_id"] = "evt-foreign"
    elif attack == "missing_task":
        env.db.tasks = []
    elif attack == "unverified_event":
        env.memory.verify_signed_graph_action.return_value = False
    elif attack == "report_not_generation_bound":
        monkeypatch.setattr(
            reviews,
            "verify_loaded_bundle",
            lambda *a, **k: {"release_status": "draft_snapshot_only"},
        )
    elif attack == "wrong_evidence":
        env.source_binding["provider_receipt_sha256"] = "A" * 64
    elif attack == "wrong_roe":
        env.signed.version += 1
    elif attack == "changed_source_evidence":
        env.source.result["evidence_sha256"] = "d" * 64
    elif attack == "signed_report_tampered":
        report = json.loads(env.bundle["artifacts"]["json"])
        report["findings"][0]["evidence_hash"] = "9" * 64
        env.bundle["artifacts"]["json"] = json.dumps(report).encode()
    elif attack == "report_generated_from_wrong_finding":
        env.bundle["attestation"]["attestation"]["evidence_provenance"][0][
            "finding_id"
        ] = "vuln-other"
    elif attack == "wrong_source_flow":
        env.source_binding["flow_id"] = "flow-foreign"
    elif attack == "stale_source_flow_revision":
        env.source_binding["flow_revision"] = 7
    elif attack == "revoked_source_flow":
        env.db.flow.status = "cancelled"
    assert await _verify_report(env) is False, attack
