"""Stored signed-authority review reads exact immutable source, never replays."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.routers import target_authority as authority


class _Rows:
    def __init__(self, record):
        self.record = record

    def scalar_one_or_none(self):
        return self.record

    def mappings(self):
        return self

    def one_or_none(self):
        return self.record


class _Database:
    def __init__(self, owner="reviewer", record=None):
        self.owner = owner
        self.record = record
        self.statements = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def begin(self):
        return self

    async def execute(self, statement, params):
        sql = str(statement).upper()
        assert sql.startswith("SELECT") and "FOR SHARE" in sql
        self.statements.append((sql, params))
        return _Rows(self.owner if "FROM SESSION_STATES" in sql else self.record)


def _record():
    return {
        "original_source_task_id": "task-original",
        "source_task_id": "task-source",
        "target_task_id": "task-target",
        "target_claims_json": b"{}",
        "target_signature_b64url": "A" * 86,
        "ownership_audit_json": None,
        "ownership_audit_signature": None,
        "access_audit_json": None,
        "access_audit_signature": None,
    }


@pytest.mark.asyncio
async def test_stored_get_reuses_current_signed_verifier_without_replaying(monkeypatch):
    db = _Database(record=_record())

    class Memory:
        def __init__(self):
            self._async_session = lambda: db

    monkeypatch.setattr(authority, "SessionMemory", Memory)
    monkeypatch.setitem(authority.state, "orchestrator", SimpleNamespace(session_memory=Memory()))
    check_access = AsyncMock()
    check_existing = AsyncMock(
        return_value={"status": "target_assertion_reverified_candidate_only"}
    )
    monkeypatch.setattr(authority, "assert_engagement_access", check_access)
    monkeypatch.setattr(authority, "_process_target_authority_assertion", check_existing)
    result = await authority.reverify_stored_target_authority_assertion(
        "eng-scope", "flow-scope", "a" * 64, Response(), {"sub": "reviewer"}
    )
    assert result["status"] == "target_assertion_reverified_candidate_only"
    check_access.assert_awaited_once()
    assert check_existing.await_args.kwargs == {"existing_proof_sha256": "a" * 64}
    submitted = check_existing.await_args.args[2]
    assert isinstance(submitted, authority.TargetAssertionSubmission)
    assert submitted.source_task_id == "task-source"
    assert len(db.statements) == 2
    assert all("INSERT" not in sql and "UPDATE" not in sql for sql, _ in db.statements)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "owner,record,status",
    [
        ("another-tenant", _record(), 403),
        ("reviewer", None, 404),
        ("reviewer", {**_record(), "target_claims_json": None}, 409),
    ],
)
async def test_stored_get_denies_wrong_owner_or_missing_exact_source(
    monkeypatch, owner, record, status
):
    db = _Database(owner=owner, record=record)

    class Memory:
        def __init__(self):
            self._async_session = lambda: db

    monkeypatch.setattr(authority, "SessionMemory", Memory)
    monkeypatch.setitem(authority.state, "orchestrator", SimpleNamespace(session_memory=Memory()))
    monkeypatch.setattr(authority, "assert_engagement_access", AsyncMock())
    never = AsyncMock()
    monkeypatch.setattr(authority, "_process_target_authority_assertion", never)
    with pytest.raises(HTTPException) as err:
        await authority.reverify_stored_target_authority_assertion(
            "eng-scope", "flow-scope", "a" * 64, Response(), {"sub": "reviewer"}
        )
    assert err.value.status_code == status
    never.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_proof_never_reads_database(monkeypatch):
    forbid = AsyncMock()
    monkeypatch.setattr(authority, "assert_engagement_access", forbid)
    with pytest.raises(HTTPException) as err:
        await authority.reverify_stored_target_authority_assertion(
            "eng-scope", "flow-scope", "not-a-sha", Response(), {"sub": "reviewer"}
        )
    assert err.value.status_code == 422
    forbid.assert_not_awaited()
