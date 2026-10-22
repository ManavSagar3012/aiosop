"""Human final release is a separately authenticated, transactional decision."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.deps import state
from ai_osop.api.routers import report_attestations as report
from ai_osop.memory.supervision_store import SupervisionConflict

_SID = "eng-report-owner"
_RID = f"report-{_SID}-v1"
_DIGEST = "a" * 64
_VERSION = 5


class _Database:
    def __init__(self):
        self.committed = 0
        self.rolled_back = 0
        self.active = False
        self.event = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        self.active = True
        try:
            yield
            self.committed += 1
        except Exception:
            self.rolled_back += 1
            raise
        finally:
            self.active = False


@pytest.fixture
def release_harness(monkeypatch):
    db = _Database()
    memory = SimpleNamespace(_async_session=lambda: db)
    monkeypatch.setitem(
        state,
        "orchestrator",
        SimpleNamespace(session_memory=memory, graph_memory=SimpleNamespace()),
    )
    identity = {"sub": "owner", "role": "senior_operator"}

    async def candidate(_db, _orch, _sid, _rid, actor):
        assert _db.active
        assert actor["sub"] == "owner"
        return (
            {"release_status": "generation_binding_pending_verification"},
            {"attestation_sha256": _DIGEST},
            SimpleNamespace(version=_VERSION),
        )

    validation = AsyncMock(side_effect=candidate)
    monkeypatch.setattr(report, "_verified_final_release_candidate", validation)

    async def record(
        store, connection, engagement_id, task_id, kind, actor, payload, *, idempotency_key
    ):
        assert connection.active
        assert engagement_id == _SID
        assert task_id is None
        assert kind == "report.human_release_approved"
        assert actor == "owner"
        assert len(idempotency_key) < 128
        if db.event is not None:
            if db.event["actor"] != actor or db.event["payload"] != payload:
                raise SupervisionConflict("Conflicting human signoff")
            return SimpleNamespace(id="evt-report-signoff")
        db.event = {"actor": actor, "payload": payload, "key": idempotency_key}
        return SimpleNamespace(id="evt-report-signoff")

    monkeypatch.setattr(report.SupervisionStore, "_append_event", record)
    app = FastAPI()
    app.include_router(report.router)
    app.dependency_overrides[report._report_operator] = lambda: identity
    return TestClient(app), app, db, identity, validation


def _path():
    return f"/engagements/{_SID}/attestations/{_RID}/release"


def _body(**overrides):
    return {
        "expected_authorization_version": _VERSION,
        "expected_attestation_sha256": _DIGEST,
        "reason": "I verified this exact release snapshot and its source records.",
        "approval_statement": "I approve releasing this exact signed report snapshot",
        **overrides,
    }


def test_release_requires_senior_owner_and_explicit_human_statement(release_harness):
    client, app, db, identity, verify = release_harness
    identity["role"] = "operator"
    assert client.post(_path(), json=_body()).status_code == 403
    verify.assert_not_awaited()
    identity["role"] = "senior_operator"
    for mutation in (
        {"approval_statement": "I approve automatically"},
        {"reason": "okay"},
        {"expected_authorization_version": True},
        {"expected_attestation_sha256": "b" * 63},
        {"unexpected": "unsafe"},
    ):
        assert client.post(_path(), json=_body(**mutation)).status_code == 422
    assert db.event is None


def test_release_persists_once_in_same_tx_and_returns_no_false_certification(release_harness):
    client, app, db, identity, verify = release_harness
    result = client.post(_path(), json=_body())
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["status"] == "human_release_approved"
    assert data["attestation_sha256"] == _DIGEST
    assert data["authorization_version"] == _VERSION
    assert data["release_event_id"] == "evt-report-signoff"
    assert data["operator_approval_recorded"] is True
    assert data["external_effect_verified"] is False
    assert data["report_completeness_certified"] is False
    assert data["report_id"] == _RID
    assert db.committed == 1
    assert db.event["payload"]["status"] == "human_release_approved"
    assert "Bearer" not in str(db.event)
    again = client.post(_path(), json=_body())
    assert again.status_code == 200
    assert again.json()["release_event_id"] == data["release_event_id"]
    assert db.committed == 2
    assert verify.await_count == 2


def test_report_digest_and_policy_compare_and_swap_fail_without_audit_commit(release_harness):
    client, app, db, identity, verify = release_harness
    for invalid in (
        {"expected_attestation_sha256": "b" * 64},
        {"expected_authorization_version": 4},
    ):
        response = client.post(_path(), json=_body(**invalid))
        assert response.status_code == 409
    assert db.committed == 0
    assert db.rolled_back == 2
    assert db.event is None


def test_failed_storage_cannot_ack_human_release(release_harness, monkeypatch):
    client, app, db, identity, verify = release_harness

    async def fail(*args, **kwargs):
        raise OSError("DB password=SECRET-MUST-NOT-LEAK")

    monkeypatch.setattr(report.SupervisionStore, "_append_event", fail)
    response = client.post(_path(), json=_body())
    assert response.status_code == 503
    assert "SECRET" not in response.text
    assert db.committed == 0
    assert db.rolled_back == 1


def test_signoff_concurrent_actor_conflict_never_fabricates_success(release_harness):
    client, app, db, identity, verify = release_harness
    assert client.post(_path(), json=_body()).status_code == 200
    db.event["actor"] = "other-owner"
    response = client.post(_path(), json=_body())
    assert response.status_code == 409
    assert db.rolled_back == 1


@pytest.mark.asyncio
async def test_candidate_rechecks_owner_signed_roe_report_and_terminal_receipt(monkeypatch):
    durable = SimpleNamespace(
        mappings=lambda: SimpleNamespace(
            one_or_none=lambda: {"session_id": _SID, "created_by": "owner"}
        )
    )
    db = SimpleNamespace(execute=AsyncMock(return_value=durable))
    auth = SimpleNamespace(session_id=_SID, version=_VERSION,
                           authorization_id="roe-owned", policy_sha256="a" * 64)
    guard = AsyncMock(return_value=auth)
    loader = lambda *_: {
        "attestation_sha256": _DIGEST,
        "attestation": {"attestation": {"evidence_provenance": []}},
        "artifacts": {
            "json": b'{"findings":[],"verification_status":"no_verified_findings"}',
            "md": b"# Evidence-only report draft",
            "html": b"<h1>Evidence-only report draft</h1>",
        },
    }
    graph = AsyncMock(return_value={})
    verifier = lambda *_args, **_kwargs: {
        "release_status": "generation_binding_pending_verification"
    }
    terminal = AsyncMock()
    monkeypatch.setattr(report, "guard_sql", guard)
    monkeypatch.setattr(report, "load_attested_bundle", loader)
    monkeypatch.setattr(report, "_graph_evidence", graph)
    monkeypatch.setattr(report, "verify_loaded_bundle", verifier)
    monkeypatch.setattr(report, "_verify_generation_release", terminal)
    operator = {"role": "senior_operator", "sub": "owner"}
    orch = SimpleNamespace(graph_memory=SimpleNamespace())
    result = await report._verified_final_release_candidate(db, orch, _SID, _RID, operator)
    assert result[1]["attestation_sha256"] == _DIGEST
    assert guard.await_count == 2
    guard.assert_any_await(db, _SID)
    guard.assert_any_await(db, _SID, expected_version=_VERSION)
    graph.assert_awaited_once()
    terminal.assert_awaited_once()
    other = {"role": "senior_operator", "sub": "foreign"}
    with pytest.raises(Exception) as exc:
        await report._verified_final_release_candidate(db, orch, _SID, _RID, other)
    assert getattr(exc.value, "status_code", None) == 403
    assert terminal.await_count == 1
    # Independent authenticated senior may verify the existing decision,
    # but cannot submit the owner's human approval mutation.
    reviewed = await report._verified_final_release_candidate(
        db,
        orch,
        _SID,
        _RID,
        other,
        require_owner=False,
    )
    assert reviewed[1]["attestation_sha256"] == _DIGEST
    assert terminal.await_count == 2
