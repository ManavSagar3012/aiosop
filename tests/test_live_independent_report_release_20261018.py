"""Negative release qualification: independently signed LIVE effect is mandatory.

No test here provisions an external owner-of-record or certifies a target.
Original 0022 dual-key cryptographic evidence tests live separately.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.api.routers import report_attestations as report


_ENG = "eng-live-report-test"
_FLOW = "flow-live-report-test"
_FID = "finding-private-1"
_SHA = "b" * 64
_OWNER = "senior-report-owner"


class _Selection:
    def __init__(self, row):
        self.row = row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row


class _Database:
    def __init__(self, row=None):
        self.row = row
        self.queries = []

    def in_transaction(self):
        return True

    async def execute(self, statement, params=None):
        self.queries.append((str(statement), params))
        assert "independent_target_effect_verifications" in str(statement)
        assert "FOR SHARE" in str(statement)
        assert params == {"eng": _ENG, "flow": _FLOW, "finding": _FID}
        return _Selection(self.row)


def _inputs(row=None):
    memory = SimpleNamespace(verify_signed_graph_action=AsyncMock(return_value=True))
    session_store = SimpleNamespace(sm=memory, _orm_to_dto=lambda *_: object())
    return (
        _Database(row),
        SimpleNamespace(session_memory=memory, session_store=session_store),
        dict(
            engagement_id=_ENG,
            report_id=f"report-{_ENG}-v1",
            flow_id=_FLOW,
            flow_revision=5,
            finding_id=_FID,
            evidence_sha256=_SHA,
            signed=SimpleNamespace(
                version=2, policy_sha256="a" * 64, authorization_id="auth-report-test"
            ),
            operator={
                "role": "senior_operator",
                "sub": _OWNER,
                "_reviewer_token_sha256": "f" * 64,
                "_reviewer_expires_at": 2080000000,
            },
        ),
    )


def _row():
    return {
        "engagement_id": _ENG,
        "flow_id": _FLOW,
        "finding_id": _FID,
        "report_source_evidence_sha256": _SHA,
        "authorization_version": 2,
        "authorization_sha256": "a" * 64,
        "authorization_id": "auth-report-test",
        "flow_revision": 5,
        "senior_reviewer_sub": _OWNER,
        "report_release_approved": False,
        "independent_effect_verified": True,
        "finding_verified": True,
        "status": "VERIFIED",
        "verdict_sha256": "c" * 64,
        "source_task_id": "task-src-1234",
        "target_task_id": "task-tgt-1234",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "non_senior",
        "no_token_digest",
        "wrong_token_digest",
        "expired_token",
        "wrong_session_store",
        "wrong_flow",
        "wrong_evidence",
        "no_database_transaction",
    ],
)
async def test_release_cannot_query_verdict_with_unsafe_current_operator_or_source(failure):
    db, orch, data = _inputs(_row())
    if failure == "non_senior":
        data["operator"]["role"] = "operator"
    elif failure == "no_token_digest":
        del data["operator"]["_reviewer_token_sha256"]
    elif failure == "wrong_token_digest":
        data["operator"]["_reviewer_token_sha256"] = "not-sha"
    elif failure == "expired_token":
        data["operator"]["_reviewer_expires_at"] = 1
    elif failure == "wrong_session_store":
        orch.session_store.sm = object()
    elif failure == "wrong_flow":
        data["flow_id"] = "not-a-flow"
    elif failure == "wrong_evidence":
        data["evidence_sha256"] = "attacker-controlled"
    else:
        db.in_transaction = lambda: False
    assert await report._live_independent_target_authority_for_release(db, orch, **data) is False
    assert db.queries == []


@pytest.mark.asyncio
async def test_live_finding_requires_immutable_separately_stored_verdict():
    db, orch, data = _inputs()
    assert await report._live_independent_target_authority_for_release(db, orch, **data) is False
    assert len(db.queries) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("engagement_id", "eng-foreign"),
        ("flow_id", "flow-foreign"),
        ("finding_id", "foreign-finding"),
        ("report_source_evidence_sha256", "c" * 64),
        ("authorization_version", 3),
        ("authorization_sha256", "c" * 64),
        ("authorization_id", "auth-different"),
        ("flow_revision", 6),
        ("senior_reviewer_sub", "other-human"),
        ("report_release_approved", True),
        ("independent_effect_verified", False),
        ("finding_verified", False),
        ("status", "UNKNOWN"),
        ("verdict_sha256", "invalid"),
        ("target_task_id", "task-src-1234"),
    ],
)
async def test_durable_verified_flag_cannot_override_exact_release_source(field, value):
    row = _row()
    row[field] = value
    db, orch, data = _inputs(row)
    assert await report._live_independent_target_authority_for_release(db, orch, **data) is False
    assert len(db.queries) == 1


def test_old_untrusted_graph_mcp_task_proof_guard_is_still_closed():
    assert report._independent_target_authority_available(None, _ENG, None, _FID, _SHA) is False


def test_missing_attested_finding_list_cannot_assert_verified_effects():
    assert report._attested_nonempty_findings({}) is False
    assert report._attested_nonempty_findings({"attestation": {"attestation": {}}}) is False
    assert (
        report._attested_nonempty_findings(
            {"attestation": {"attestation": {"evidence_provenance": []}}}
        )
        is False
    )
