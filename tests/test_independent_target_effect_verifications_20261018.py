"""0022 signed independent LIVE owner/access admission and readback regressions.

Deterministic PostgreSQL row-lock/CAS surrogate, with REAL cryptographic
Ed25519 independent LIVE access + separately signed owner-of-record witness
verifier from the production core observer module. Live signing here is a lab
fixture ONLY, never evidence of a real target or deployed witness service.
No application PostgreSQL, external target, paid model or network is accessed.
"""

from __future__ import annotations

import copy
import base64
import hashlib
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core.target_authority_proof import _canonical
from ai_osop.core import independent_target_effect_observer as observer
from ai_osop.memory import independent_target_effect_verifications as ledger
from ai_osop.memory import target_verified_promotions as qualifications
from ai_osop.memory import verified_finding_decisions as reviews
from ai_osop.memory.flow_artifact_reviews import FlowArtifactReviewStore
from ai_osop.safety.approval_binding import pinned_evidence
from tests.test_independent_target_effect_observer_20261018 import (
    witness,  # noqa: F401 (reuses two REAL deterministic independent signer fixtures)
)
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


class _Rows:
    def __init__(self, data=None):
        self.data = data

    def mappings(self):
        return self

    def one_or_none(self):
        return self.data

    def all(self):
        return self.data or []

    def scalar_one_or_none(self):
        return self.data


def _review(case):
    proof = case.proof
    result = {field: "1" * 64 for field in reviews._INSERT_COLUMNS}
    result.update(
        id=case.outer["review_decision_id"],
        engagement_id=proof.flow.engagement_id,
        flow_id=proof.flow.id,
        finding_id=case.outer["finding_id"],
        review_revision=1,
        previous_decision_id=None,
        previous_decision_sha256=None,
        decision_status="candidate_only",
        reviewer_sub=proof.owner,
        original_source_task_id=proof.original.id,
        source_task_id=proof.source.id,
        target_task_id=proof.target.id,
        replay_parent_task_id="task-replay-parent",
        proof_sha256=case.outer["proof_sha256"],
        audit_corroboration_sha256=case.outer["audit_sha256"],
        authorization_id=proof.signed.authorization_id,
        authorization_version=proof.signed.version,
        authorization_sha256=proof.signed.policy_sha256,
        flow_revision=proof.flow.revision,
        source_event_id="evt-source",
        target_event_id="evt-target",
        source_provider_receipt_sha256="2" * 64,
        target_provider_receipt_sha256="3" * 64,
        source_request_sha256=proof.claims["source_request_sha256"],
        target_request_sha256=proof.claims["target_request_sha256"],
        source_session_sha256=proof.claims["source_session_sha256"],
        target_session_sha256=proof.claims["target_session_sha256"],
        source_response_sha256=proof.claims["source_response_sha256"],
        target_response_sha256=proof.claims["target_response_sha256"],
        source_identity_sha256="a" * 64,
        target_identity_sha256="b" * 64,
        observation_binding_sha256="c" * 64,
        report_source_evidence_sha256="d" * 64,
    )
    result["decision_sha256"] = hashlib.sha256(
        reviews._DOMAIN
        + _canonical(
            {
                field: result[field]
                for field in reviews._INSERT_COLUMNS
                if field != "decision_sha256"
            }
        )
    ).hexdigest()
    return result


def _qualification(case, review):
    proof = case.proof
    result = {field: None for field in qualifications._COLUMNS}
    result.update(
        id=case.outer["qualification_id"],
        engagement_id=proof.flow.engagement_id,
        flow_id=proof.flow.id,
        finding_id=case.outer["finding_id"],
        revision=1,
        review_decision_id=review["id"],
        review_decision_sha256=review["decision_sha256"],
        review_revision=review["review_revision"],
        original_source_task_id=proof.original.id,
        source_task_id=proof.source.id,
        target_task_id=proof.target.id,
        proof_sha256=case.outer["proof_sha256"],
        audit_corroboration_sha256=case.outer["audit_sha256"],
        observation_binding_sha256=review["observation_binding_sha256"],
        report_source_evidence_sha256=review["report_source_evidence_sha256"],
        authorization_id=proof.signed.authorization_id,
        authorization_version=proof.signed.version,
        authorization_sha256=proof.signed.policy_sha256,
        flow_revision=proof.flow.revision,
        reviewer_sub=proof.owner,
        resource_id=case.outer["resource_id"],
        resource_owner_identity_sha256=hashlib.sha256(
            (proof.flow.engagement_id + "\x00" + proof.claims["source_identity"]).encode()
        ).hexdigest(),
        resource_visibility="private",
        source_http_status=200,
        target_http_status=200,
        anonymous_http_status=403,
        status="UNKNOWN",
        reason_code="independent_target_effect_service_missing",
        independent_effect_verified=False,
        finding_verified=False,
        report_release_approved=False,
        previous_attempt_id=None,
        previous_attempt_sha256=None,
    )
    result["attempt_sha256"] = qualifications._fingerprint(result)
    return result


class _FakeSql:
    def __init__(self, case):
        self.case = case
        self.review = _review(case)
        self.qualification = _qualification(case, self.review)
        self.challenges = {}
        self.promotions = []
        self.queries = []
        self.in_tx = True
        self.fail_insert = False
        self.anon_approved = True
        self.signed_dispatch_valid = True
        self.signed_dispatch_checks = 0
        self.phase = "active"
        self.token_valid = True
        self.trust_valid = True
        self.read_fail = False
        self.assertion = {
            "engagement_id": case.proof.flow.engagement_id,
            "flow_id": case.proof.flow.id,
            "proof_sha256": self.qualification["proof_sha256"],
            "audit_corroboration_sha256": self.qualification["audit_corroboration_sha256"],
            "original_source_task_id": case.proof.original.id,
            "source_task_id": case.proof.source.id,
            "target_task_id": case.proof.target.id,
            "authorization_version": case.proof.signed.version,
            "flow_revision": case.proof.flow.revision,
            "target_claims_json": _canonical(case.proof.claims),
        }
        for name in ("ownership_audit_json", "access_audit_json"):
            self.assertion[name] = _canonical(
                {**case.proof.claims, "resource_id": case.outer["resource_id"]}
            )
        anonymous = case.outer["observations"]["anonymous"]
        payload = {
            "_authorization_version": case.proof.signed.version,
            "_flow_revision": case.proof.flow.revision,
            "identity": "anonymous",
            "role": "anonymous",
            "method": "GET",
            "url": case.proof.claims["endpoint_url"],
            "approval_id": "apr-anonymous",
        }
        self.anon_row = {
            "id": anonymous["task_id"],
            "engagement_id": case.proof.flow.engagement_id,
            "flow_id": case.proof.flow.id,
            "status": "completed",
            "type": "navigate",
            "approval_required": True,
            "assigned_agent_id": "agent-independent-approved",
            "parent_task_id": case.proof.source.parent_task_id,
            "payload": payload,
            "result": {
                "identity": "anonymous",
                "http_status": anonymous["http_status"],
                "redirected": False,
                "request_sha256": anonymous["request_sha256"],
                "response_sha256": anonymous["response_sha256"],
                "provider_evidence": {
                    "provider_event_id": anonymous["event_id"],
                    "provider_receipt_sha256": "5" * 64,
                    "source_authenticity_verified": False,
                },
            },
        }
        self.anon_approval = {
            "id": payload["approval_id"],
            "status": "approved",
            "evidence": pinned_evidence([], payload),
        }
        # The original three signed tasks are read via the real source shape.
        self.tasks = [
            task.model_dump()
            for task in (case.proof.original, case.proof.source, case.proof.target)
        ]
        self.flow = case.proof.flow.model_dump()

    def in_transaction(self):
        return self.in_tx

    async def execute(self, query, args=None):
        sql = str(query)
        self.queries.append(sql)
        if self.read_fail:
            raise OSError("Controlled PostgreSQL read failure")
        if "FROM session_states" in sql:
            assert "FOR UPDATE" in sql or "FOR SHARE" in sql
            return _Rows(self.case.proof.owner)
        if "FROM verified_target_finding_decisions" in sql:
            return _Rows(self.review)
        if "FROM target_effect_qualification_attempts" in sql:
            return _Rows(self.qualification)
        if "FROM target_authority_assertions" in sql:
            return _Rows(self.assertion)
        if "FROM execution_flows" in sql:
            assert "FOR SHARE" in sql
            return _Rows(self.flow)
        if "FROM tasks" in sql and "IN (" in sql:
            assert "FOR SHARE" in sql
            return _Rows(self.tasks)
        if "FROM tasks" in sql and "id=:anon" in sql:
            return _Rows(self.anon_row)
        if "FROM approval_requests" in sql:
            return _Rows(self.anon_approval if self.anon_approved else None)
        if "INSERT INTO independent_target_effect_challenges" in sql:
            assert self.in_tx
            self.challenges[args["id"]] = {
                "id": args["id"],
                "engagement_id": args["eng"],
                "flow_id": args["flow"],
                "finding_id": args["finding"],
                "qualification_id": args["qual"],
                "qualification_sha256": args["sha"],
                "nonce_sha256": args["nonce"],
                "issued_at": args["issued"],
                "expires_at": args["expires"],
            }
            return _Rows(args["id"])
        if "FROM independent_target_effect_challenges" in sql:
            return _Rows(self.challenges.get(args["challenge"]))
        if "FROM independent_target_effect_verifications" in sql:
            found = next(
                (
                    row
                    for row in self.promotions
                    if (
                        (
                            args.get("eng") == row["engagement_id"]
                            and args.get("flow") == row["flow_id"]
                            and args.get("finding") == row["finding_id"]
                        )
                        if "finding" in args
                        else (
                            args.get("nonce") == row["verifier_nonce_sha256"]
                            or args.get("digest") == row["verdict_sha256"]
                        )
                    )
                ),
                None,
            )
            return _Rows(found if sql.startswith("SELECT *") else (found["id"] if found else None))
        if "INSERT INTO independent_target_effect_verifications" in sql:
            if self.fail_insert:
                raise OSError("PostgreSQL ACK unknown")
            if self.promotions:
                return _Rows(None)  # ON CONFLICT DO NOTHING
            self.promotions.append(dict(args))
            return _Rows(args["id"])
        raise AssertionError(f"Unrecognized SQL query: {sql}")


@pytest.fixture
def ready(witness, monkeypatch):
    case = witness
    # Witness signatures are real, but ROE and PostgreSQL authorities are
    # tightly controlled stand-ins, never live production verification.
    case.proof.signed.policy = {"created_by": case.proof.owner}
    case.proof.signed.session_id = case.proof.flow.engagement_id
    # Deliberately different owners for ALL four source and current witness
    # signers. The upstream reusable fixture shares target and owner test-key
    # bytes, but the 0022 ledger must reject that as NOT independent.
    owner_signer = Ed25519PrivateKey.from_private_bytes(bytes(range(129, 161)))
    access_key = case.observer_signer
    audit_owner = Ed25519PrivateKey.from_private_bytes(bytes(range(65, 97)))
    audit_access = Ed25519PrivateKey.from_private_bytes(bytes(range(97, 129)))

    def pub(signer):
        return base64.b64encode(
            signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")

    case.config["owner_public_key_b64"] = pub(owner_signer)
    case.set_config()
    monkeypatch.setenv(
        "OSOP_TARGET_AUDIT_KEYS_JSON",
        _canonical(
            {
                "version": 1,
                "engagement_id": case.proof.flow.engagement_id,
                "flow_id": case.proof.flow.id,
                "origin": "https://tenant.example.test",
                "keys": {"ownership": pub(audit_owner), "access": pub(audit_access)},
            }
        ).decode("utf-8"),
    )

    def seal_independent_keys():
        raw_owner = _canonical(case.owner)
        case.outer["owner_claims_b64url"] = (
            base64.urlsafe_b64encode(raw_owner).decode("ascii").rstrip("=")
        )
        case.outer["owner_signature_b64url"] = (
            base64.urlsafe_b64encode(owner_signer.sign(observer._OWNER_DOMAIN + raw_owner))
            .decode("ascii")
            .rstrip("=")
        )
        case.outer["owner_record_sha256"] = hashlib.sha256(
            observer._OWNER_DOMAIN + raw_owner
        ).hexdigest()
        raw = _canonical(case.outer)
        signature = (
            base64.urlsafe_b64encode(access_key.sign(observer._EFFECT_DOMAIN + raw))
            .decode("ascii")
            .rstrip("=")
        )
        return raw, signature

    case.seal = seal_independent_keys
    state = _FakeSql(case)

    async def senior_fence(_db, *, reviewer_sub, reviewer_token_sha256, reviewer_expires_at):
        assert _db is state
        if (
            not state.token_valid
            or reviewer_sub != case.proof.owner
            or reviewer_token_sha256 != "6" * 64
            or reviewer_expires_at <= int(time.time())
        ):
            raise PermissionError("senior revoked")

    async def signed_roe(_db, engagement_id, expected_version=None):
        if (
            _db is not state
            or not state.trust_valid
            or engagement_id != case.proof.flow.engagement_id
            or expected_version != case.proof.signed.version
        ):
            raise PermissionError("signed operator ROE revoked")
        return case.proof.signed

    async def read_review(_db, **_args):
        return {
            "decision_id": state.review["id"],
            "decision_sha256": state.review["decision_sha256"],
            "status": "candidate_only",
            "finding_verified": False,
            "report_release_approved": False,
        }

    async def read_qualification(_db, **_args):
        return {
            "status": "UNKNOWN",
            "qualification_id": state.qualification["id"],
            "qualification_sha256": state.qualification["attempt_sha256"],
            "revision": state.qualification["revision"],
            "finding_verified": False,
            "report_release_approved": False,
        }

    async def signed_anonymous_dispatch(
        engagement_id, task_id, event_id, provider_receipt_sha256, authorization_version
    ):
        state.signed_dispatch_checks += 1
        return (
            state.signed_dispatch_valid
            and engagement_id == case.proof.flow.engagement_id
            and task_id == state.anon_row["id"]
            and event_id == case.outer["observations"]["anonymous"]["event_id"]
            and provider_receipt_sha256 == "5" * 64
            and authorization_version == case.proof.signed.version
        )

    monkeypatch.setattr(FlowArtifactReviewStore, "_reviewer_fence", senior_fence)
    monkeypatch.setattr(ledger, "guard_sql", signed_roe)
    monkeypatch.setattr(qualifications, "guard_sql", signed_roe)
    monkeypatch.setattr(ledger, "read_latest_candidate_review", read_review)
    monkeypatch.setattr(ledger, "read_target_effect_qualification", read_qualification)
    inputs = {
        "engagement_id": case.proof.flow.engagement_id,
        "flow_id": case.proof.flow.id,
        "finding_id": case.outer["finding_id"],
        "review_decision_id": case.outer["review_decision_id"],
        "review_decision_sha256": state.review["decision_sha256"],
        "qualification_id": case.outer["qualification_id"],
        "qualification_sha256": state.qualification["attempt_sha256"],
        "expected_qualification_revision": 1,
        "authorization_version": case.proof.signed.version,
        "flow_revision": case.proof.flow.revision,
        "reviewer_sub": case.proof.owner,
        "reviewer_role": "senior_operator",
        "reviewer_token_sha256": "6" * 64,
        "reviewer_expires_at": int(time.time()) + 120,
        "trusted_current_verifier": AsyncMock(return_value=True),
        "trusted_report_source_check": AsyncMock(return_value=True),
        # Deterministic stand-in ONLY; production must wire the existing
        # SessionMemory.verify_signed_graph_action against signed PG records.
        "trusted_anonymous_signed_dispatch_check": signed_anonymous_dispatch,
    }
    case.outer["review_decision_sha256"] = state.review["decision_sha256"]
    case.outer["qualification_sha256"] = state.qualification["attempt_sha256"]
    return SimpleNamespace(case=case, state=state, input=inputs)


async def _challenge(ready):
    issued = await ledger.issue_independent_target_effect_challenge(
        ready.state,
        **{
            key: value
            for key, value in ready.input.items()
            if key != "trusted_anonymous_signed_dispatch_check"
        },
    )
    ready.case.outer["nonce"] = issued["expected_nonce"]
    ready.case.owner["nonce"] = issued["expected_nonce"]
    ready.case.owner["observed_at"] = int(time.time())
    ready.case.outer["issued_at"] = int(time.time())
    ready.case.outer["expires_at"] = ready.case.outer["issued_at"] + 60
    signed_blob, signature = ready.case.seal()
    return {
        "challenge_id": issued["challenge_id"],
        "expected_nonce": issued["expected_nonce"],
        "observer_claims_json": signed_blob,
        "observer_signature_b64url": signature,
    }


@pytest.mark.asyncio
async def test_real_dual_ed25519_immutable_finding_cas_and_current_readback(ready):
    challenge = await _challenge(ready)
    inserted = await ledger.admit_independent_target_effect_verification(
        ready.state, **ready.input, **challenge
    )
    assert inserted["status"] == "VERIFIED"
    assert inserted["finding_verified"] is True
    assert inserted["report_release_approved"] is False
    assert inserted["finding_release_eligible"] is False
    assert ready.state.qualification["status"] == "UNKNOWN"
    assert ready.state.qualification["finding_verified"] is False
    assert len(ready.state.promotions) == 1
    row = ready.state.promotions[0]
    assert row["signed_verdict_json"] == challenge["observer_claims_json"]
    assert row["verdict_signature_b64url"] == challenge["observer_signature_b64url"]
    assert row["challenge_id"] == challenge["challenge_id"]
    assert row["report_release_approved"] is False
    assert ready.state.signed_dispatch_checks >= 2
    assert (
        row["verifier_nonce_sha256"]
        == hashlib.sha256(challenge["expected_nonce"].encode("ascii")).hexdigest()
    )
    assert any("FOR UPDATE" in sql for sql in ready.state.queries)

    readback = await ledger.read_independent_target_effect_verification(
        ready.state,
        engagement_id=ready.input["engagement_id"],
        flow_id=ready.input["flow_id"],
        finding_id=ready.input["finding_id"],
        evidence_sha256=row["verdict_sha256"],
        authorization_version=ready.input["authorization_version"],
        reviewer_sub=ready.input["reviewer_sub"],
        reviewer_role=ready.input["reviewer_role"],
        reviewer_token_sha256=ready.input["reviewer_token_sha256"],
        reviewer_expires_at=ready.input["reviewer_expires_at"],
        trusted_current_verifier=ready.input["trusted_current_verifier"],
        trusted_report_source_check=ready.input["trusted_report_source_check"],
        trusted_anonymous_signed_dispatch_check=ready.input[
            "trusted_anonymous_signed_dispatch_check"
        ],
    )
    assert readback["status"] == "VERIFIED"
    assert readback["report_release_approved"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    [
        "raw_boolean",
        "wrong_finding",
        "wrong_review_sha",
        "wrong_qualification_sha",
        "wrong_revision",
        "wrong_challenge",
        "expired_challenge",
        "tampered_outer_signature",
        "tampered_nested_owner_signature",
        "public_resource",
        "anonymous_public",
        "anonymous_unapproved",
        "anonymous_forged_receipt",
        "anonymous_wrong_event_id",
        "anonymous_missing_provider_receipt",
        "anonymous_no_signed_verifier",
        "revoked_roe",
        "revoked_senior",
        "stale_flow",
        "db_unknown",
    ],
)
async def test_candidate_only_or_untrusted_witness_never_promotes(ready, attack):
    challenge = await _challenge(ready)
    state = ready.state
    kwargs = dict(challenge)
    if attack == "raw_boolean":
        kwargs["observer_claims_json"] = True
    elif attack == "wrong_finding":
        ready.input["finding_id"] = "vuln-foreign"
    elif attack == "wrong_review_sha":
        ready.input["review_decision_sha256"] = "0" * 64
    elif attack == "wrong_qualification_sha":
        ready.input["qualification_sha256"] = "0" * 64
    elif attack == "wrong_revision":
        ready.input["expected_qualification_revision"] = 2
    elif attack == "wrong_challenge":
        kwargs["expected_nonce"] = "f" * 32
    elif attack == "expired_challenge":
        state.challenges[challenge["challenge_id"]]["expires_at"] = 1
    elif attack == "tampered_outer_signature":
        kwargs["observer_signature_b64url"] = "A" * 86
    elif attack in {"tampered_nested_owner_signature", "public_resource", "anonymous_public"}:
        outer = json.loads(kwargs["observer_claims_json"])
        if attack == "tampered_nested_owner_signature":
            outer["owner_signature_b64url"] = "A" * 86
        elif attack == "public_resource":
            owner = json.loads(
                __import__("base64").urlsafe_b64decode(outer["owner_claims_b64url"] + "==")
            )
            owner["visibility"] = "public"
            outer["owner_claims_b64url"] = (
                __import__("base64").urlsafe_b64encode(_canonical(owner)).decode().rstrip("=")
            )
        else:
            outer["observations"]["anonymous"]["http_status"] = 200
        outer_bytes = _canonical(outer)
        kwargs["observer_claims_json"] = outer_bytes
        kwargs["observer_signature_b64url"] = (
            __import__("base64")
            .urlsafe_b64encode(
                ready.case.observer_signer.sign(
                    __import__(
                        "ai_osop.core.independent_target_effect_observer",
                        fromlist=["_EFFECT_DOMAIN"],
                    )._EFFECT_DOMAIN
                    + outer_bytes
                )
            )
            .decode()
            .rstrip("=")
        )
    elif attack == "anonymous_unapproved":
        state.anon_approved = False
    elif attack == "anonymous_forged_receipt":
        state.signed_dispatch_valid = False
    elif attack == "anonymous_wrong_event_id":
        state.anon_row["result"]["provider_evidence"]["provider_event_id"] = "evt-forged"
    elif attack == "anonymous_missing_provider_receipt":
        state.anon_row["result"]["provider_evidence"].pop("provider_receipt_sha256")
    elif attack == "anonymous_no_signed_verifier":
        ready.input["trusted_anonymous_signed_dispatch_check"] = None
    elif attack == "revoked_roe":
        state.trust_valid = False
    elif attack == "revoked_senior":
        state.token_valid = False
    elif attack == "stale_flow":
        state.flow["revision"] += 1
    elif attack == "db_unknown":
        state.fail_insert = True
    with pytest.raises(ledger.IndependentTargetEffectDenied):
        await ledger.admit_independent_target_effect_verification(state, **ready.input, **kwargs)
    assert state.promotions == []
    assert state.qualification["status"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_nonce_replay_and_senior_revocation_fail_closed_on_readback(ready):
    challenge = await _challenge(ready)
    first = await ledger.admit_independent_target_effect_verification(
        ready.state, **ready.input, **challenge
    )
    with pytest.raises(ledger.IndependentTargetEffectDenied):
        await ledger.admit_independent_target_effect_verification(
            ready.state, **ready.input, **challenge
        )
    ready.state.token_valid = False
    second = await ledger.read_independent_target_effect_verification(
        ready.state,
        engagement_id=ready.input["engagement_id"],
        flow_id=ready.input["flow_id"],
        finding_id=ready.input["finding_id"],
        evidence_sha256=first["verification_sha256"],
        authorization_version=ready.input["authorization_version"],
        reviewer_sub=ready.input["reviewer_sub"],
        reviewer_role=ready.input["reviewer_role"],
        reviewer_token_sha256=ready.input["reviewer_token_sha256"],
        reviewer_expires_at=ready.input["reviewer_expires_at"],
        trusted_current_verifier=ready.input["trusted_current_verifier"],
        trusted_report_source_check=ready.input["trusted_report_source_check"],
        trusted_anonymous_signed_dispatch_check=ready.input[
            "trusted_anonymous_signed_dispatch_check"
        ],
    )
    assert second["status"] == "UNKNOWN"
    assert second["report_release_approved"] is False
    assert len(ready.state.promotions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "revocation",
    [
        "observer_key_rotation",
        "revoked_roe",
        "report_source_changed",
        "tampered_signed_observer_bytes",
        "tampered_signed_owner_bytes",
        "tampered_private_object_digest",
        "tampered_anonymous_denial_status",
        "tampered_source_task_lineage",
        "tampered_candidate_revision",
    ],
)
async def test_immutable_verified_row_readback_never_trusts_stale_or_tampered_sources(
    ready, revocation
):
    challenge = await _challenge(ready)
    initial = await ledger.admit_independent_target_effect_verification(
        ready.state, **ready.input, **challenge
    )
    row = ready.state.promotions[0]
    if revocation == "observer_key_rotation":
        ready.case.config["generation"] += 1
        ready.case.set_config()
    elif revocation == "revoked_roe":
        ready.state.trust_valid = False
    elif revocation == "report_source_changed":
        ready.input["trusted_report_source_check"].return_value = False
    elif revocation == "tampered_signed_observer_bytes":
        row["signed_verdict_json"] = row["signed_verdict_json"].replace(
            b"ai-osop.independent-target-effect.v1",
            b"ai-osop.synthetic-target-effect.v1",
        )
    elif revocation == "tampered_signed_owner_bytes":
        raw = json.loads(row["signed_verdict_json"])
        raw["owner_signature_b64url"] = "A" * 86
        row["signed_verdict_json"] = _canonical(raw)
    elif revocation == "tampered_private_object_digest":
        row["private_content_sha256"] = "1" * 64
    elif revocation == "tampered_anonymous_denial_status":
        row["anonymous_http_status"] = 401
    elif revocation == "tampered_source_task_lineage":
        row["source_task_id"] = "task-untrusted"
    elif revocation == "tampered_candidate_revision":
        row["review_revision"] += 1

    again = await ledger.read_independent_target_effect_verification(
        ready.state,
        engagement_id=ready.input["engagement_id"],
        flow_id=ready.input["flow_id"],
        finding_id=ready.input["finding_id"],
        evidence_sha256=initial["verification_sha256"],
        authorization_version=ready.input["authorization_version"],
        reviewer_sub=ready.input["reviewer_sub"],
        reviewer_role=ready.input["reviewer_role"],
        reviewer_token_sha256=ready.input["reviewer_token_sha256"],
        reviewer_expires_at=ready.input["reviewer_expires_at"],
        trusted_current_verifier=ready.input["trusted_current_verifier"],
        trusted_report_source_check=ready.input["trusted_report_source_check"],
        trusted_anonymous_signed_dispatch_check=ready.input[
            "trusted_anonymous_signed_dispatch_check"
        ],
    )
    assert again["status"] == "UNKNOWN"
    assert again["finding_verified"] is False
    assert again["report_release_approved"] is False


def test_migration_0022_unique_cas_immutable_and_never_release():
    from importlib import import_module
    from unittest.mock import Mock

    migration = import_module("migrations.versions.0022_independent_target_effect_verifications")
    op = Mock()
    original_op = migration.op
    migration.op = op
    try:
        migration.upgrade()
        tables = {call.args[0]: call for call in op.create_table.call_args_list}
        assert set(tables) == {
            "independent_target_effect_challenges",
            "independent_target_effect_verifications",
        }
        sql = "\n".join(str(call.args[0]) for call in op.execute.call_args_list)
        assert "trg_independent_target_effect_verifications_immutable" in sql
        assert "trg_independent_target_effect_challenges_immutable" in sql
        assert "0021" == migration.down_revision
        checks = "\n".join(
            str(column.sqltext)
            for column in tables["independent_target_effect_verifications"].args[1:]
            if getattr(column, "sqltext", None) is not None
        )
        assert "report_release_approved = false" in checks
        assert "status = 'VERIFIED'" in checks
    finally:
        migration.op = original_op
