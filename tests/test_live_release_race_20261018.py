"""Regression for revocation while durable LIVE report signoff is being appended.

Use a transactional store double and a source-verification boundary double.
These tests deliberately mint no target-effect certificate and never connect
to an app database, external witness, browser, or provider.
"""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.deps import state
from ai_osop.api.routers import report_attestations as report
from ai_osop.reporting.attested_storage import AttestedStorageUnavailable


_ENG = "eng-release-race-20261018"
_RID = f"report-{_ENG}-v1"
_OWNER = "senior-owner"
_SHA = "a" * 64


class _TransactionalDB:
    def __init__(self):
        self.active = False
        self.commits = 0
        self.rollbacks = 0
        self.pending_event = None
        self.committed_event = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    @asynccontextmanager
    async def begin(self):
        assert not self.active
        self.active = True
        try:
            yield
        except Exception:
            self.rollbacks += 1
            self.pending_event = None
            raise
        else:
            self.commits += 1
            self.committed_event = self.pending_event
        finally:
            self.active = False


def _payload():
    return report.FinalReportSignoff(
        expected_authorization_version=2,
        expected_attestation_sha256=_SHA,
        reason="I reviewed this exact signed report and its independent evidence.",
        approval_statement="I approve releasing this exact signed report snapshot",
    )


@pytest.fixture
def race(monkeypatch):
    """The boundary double behaves as the real fail-closed candidate contract."""
    db = _TransactionalDB()
    trust = SimpleNamespace(
        owner=_OWNER,
        reviewer_active=True,
        signed_source_active=True,
        source_engagement_id=_ENG,
        witness_lease_active=True,
        witness_registry_key="pinned-owner-key",
        authorization_version=2,
        authorization_id="auth-release-20261018",
        policy_sha256="c" * 64,
        attestation_sha256=_SHA,
        signed_finding=True,
    )
    verifier_calls = []
    memory = SimpleNamespace(_async_session=lambda: db)
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=memory))

    async def verify(current_db, _orch, sid, rid, operator, *, require_owner=True):
        assert current_db is db and db.active
        assert sid == _ENG and rid == _RID
        verifier_calls.append((sid, trust.authorization_version, trust.witness_registry_key))
        if operator.get("role") != "senior_operator":
            raise HTTPException(status_code=403, detail="Senior operator required")
        if require_owner and (operator.get("sub") != trust.owner):
            raise HTTPException(status_code=403, detail="Engagement owner required")
        if not all(
            (
                trust.reviewer_active,
                trust.signed_source_active,
                trust.source_engagement_id == sid,
                trust.witness_lease_active,
                trust.witness_registry_key == "pinned-owner-key",
            )
        ):
            raise AttestedStorageUnavailable("Current independently trusted source unavailable")
        provenance = [{"finding_id": "private-finding"}] if trust.signed_finding else []
        loaded = {
            "attestation_sha256": trust.attestation_sha256,
            "attestation": {"attestation": {"evidence_provenance": provenance}},
        }
        signed = SimpleNamespace(
            version=trust.authorization_version,
            authorization_id=trust.authorization_id,
            policy_sha256=trust.policy_sha256,
        )
        return {"release_status": "generation_binding_pending_verification"}, loaded, signed

    candidate = AsyncMock(side_effect=verify)
    monkeypatch.setattr(report, "_verified_final_release_candidate", candidate)
    return SimpleNamespace(db=db, trust=trust, calls=verifier_calls, candidate=candidate)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "revocation",
    [
        "stale_reviewer",
        "source_revoked",
        "cross_tenant_source",
        "witness_lease_expired",
        "signing_key_rotated",
    ],
)
async def test_revocation_during_event_append_rolls_back_release(race, monkeypatch, revocation):
    async def append(_store, db, eng, task, kind, actor, payload, *, idempotency_key):
        assert db is race.db and db.active
        assert eng == _ENG and task is None
        assert actor == _OWNER and kind == "report.human_release_approved"
        assert payload["external_effect_verified"] is True
        assert idempotency_key.startswith("report-release:")
        db.pending_event = dict(payload)
        if revocation == "stale_reviewer":
            race.trust.reviewer_active = False
        elif revocation == "source_revoked":
            race.trust.signed_source_active = False
        elif revocation == "cross_tenant_source":
            race.trust.source_engagement_id = "eng-foreign-tenant"
        elif revocation == "witness_lease_expired":
            race.trust.witness_lease_active = False
        elif revocation == "signing_key_rotated":
            race.trust.witness_registry_key = "revoked-old-key"
        return SimpleNamespace(id="evt-pending-rollback")

    monkeypatch.setattr(report.SupervisionStore, "_append_event", append)
    with pytest.raises(HTTPException) as failure:
        await report.approve_signed_report_release(
            _ENG,
            _RID,
            _payload(),
            Response(),
            operator={"role": "senior_operator", "sub": _OWNER},
        )
    assert failure.value.status_code == 503
    assert race.candidate.await_count == 2
    assert race.db.commits == 0 and race.db.rollbacks == 1
    assert race.db.committed_event is None and race.db.pending_event is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed",
    ["attestation", "authorization_version", "authorization_id", "policy_sha256"],
)
async def test_source_snapshot_changes_during_append_fail_cas(race, monkeypatch, changed):
    async def append(_store, db, *_args, **_kwargs):
        db.pending_event = {"status": "human_release_approved"}
        if changed == "attestation":
            race.trust.attestation_sha256 = "d" * 64
        elif changed == "authorization_version":
            race.trust.authorization_version = 3
        elif changed == "authorization_id":
            race.trust.authorization_id = "auth-rotated"
        elif changed == "policy_sha256":
            race.trust.policy_sha256 = "d" * 64
        return SimpleNamespace(id="evt-stale")

    monkeypatch.setattr(report.SupervisionStore, "_append_event", append)
    with pytest.raises(HTTPException) as failure:
        await report.approve_signed_report_release(
            _ENG,
            _RID,
            _payload(),
            Response(),
            operator={"role": "senior_operator", "sub": _OWNER},
        )
    assert failure.value.status_code == 409
    assert race.candidate.await_count == 2
    assert race.db.rollbacks == 1 and race.db.committed_event is None


@pytest.mark.asyncio
async def test_live_validity_is_rechecked_after_signoff_write(race, monkeypatch):
    async def append(_store, db, *_args, **_kwargs):
        db.pending_event = {"status": "human_release_approved"}
        return SimpleNamespace(id="evt-live")

    monkeypatch.setattr(report.SupervisionStore, "_append_event", append)
    result = await report.approve_signed_report_release(
        _ENG,
        _RID,
        _payload(),
        Response(),
        operator={"role": "senior_operator", "sub": _OWNER},
    )
    assert result["status"] == "human_release_approved"
    assert result["external_effect_verified"] is True
    assert result["report_completeness_certified"] is False
    assert race.candidate.await_count == 2
    assert race.db.commits == 1


@pytest.mark.asyncio
async def test_legacy_false_gate_is_not_promoted_by_event_recheck(race, monkeypatch):
    race.trust.signed_finding = False

    async def append(_store, db, *_args, **_kwargs):
        db.pending_event = {"status": "human_release_approved"}
        return SimpleNamespace(id="evt-no-verified-effects")

    monkeypatch.setattr(report.SupervisionStore, "_append_event", append)
    result = await report.approve_signed_report_release(
        _ENG,
        _RID,
        _payload(),
        Response(),
        operator={"role": "senior_operator", "sub": _OWNER},
    )
    assert result["external_effect_verified"] is False
    assert report._independent_target_authority_available(None, _ENG, None, "f", _SHA) is False
    assert race.candidate.await_count == 1


@pytest.mark.asyncio
async def test_signed_release_get_denies_stale_witness_even_if_event_was_committed(
    race, monkeypatch
):
    async def append(_store, db, *_args, **_kwargs):
        db.pending_event = {"status": "human_release_approved"}
        return SimpleNamespace(id="evt-approved-before-rotation")

    monkeypatch.setattr(report.SupervisionStore, "_append_event", append)
    await report.approve_signed_report_release(
        _ENG,
        _RID,
        _payload(),
        Response(),
        operator={"role": "senior_operator", "sub": _OWNER},
    )
    assert race.db.committed_event is not None
    race.trust.witness_registry_key = "rotated-after-approval"
    with pytest.raises(HTTPException) as failure:
        await report.get_signed_report_release_status(
            _ENG,
            _RID,
            Response(),
            operator={"role": "senior_operator", "sub": _OWNER},
        )
    assert failure.value.status_code == 503
    assert race.candidate.await_count == 3
