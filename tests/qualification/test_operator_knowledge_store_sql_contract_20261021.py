"""Actual operator-knowledge store SQL-branch tests with a recording SQL fake.

This executes OperatorKnowledgeStore and FlowArtifactStore._fence rather than
asserting only strings in source. It is NOT PostgreSQL concurrency or signed
cryptography verification; the adjacent opt-in disposable 0019/0038 tests own
real-schema verification. All SQL is inspected before returning test rows.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory import flow_artifacts as artifact_module
from ai_osop.memory import operator_knowledge as knowledge_module
from ai_osop.memory.operator_knowledge import KnowledgeDenied, OperatorKnowledgeStore


FID = "flow-primary"
SID = "eng-primary"
OWNER = "operator-primary"
DOC = "knowledge-" + "f" * 32
AUTH = "a" * 64
NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


def row(**changes: Any) -> dict[str, Any]:
    content = "Verified inert body"
    result: dict[str, Any] = {
        "id": DOC,
        "engagement_id": SID,
        "flow_id": FID,
        "owner_id": OWNER,
        "title": "Study guide",
        "doc_type": "guide",
        "content": content,
        "content_bytes": len(content.encode()),
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
        "revision": 1,
        "source_flow_revision": 3,
        "authorization_version": 7,
        "authorization_sha256": AUTH,
        "created_at": NOW,
        "updated_at": NOW,
        "deleted_at": None,
    }
    result.update(changes)
    return result


class Result:
    def __init__(self, value: Any) -> None:
        self.value = value

    def mappings(self) -> "Result":
        return self

    def one_or_none(self) -> Any:
        return self.value

    def one(self) -> Any:
        assert self.value is not None
        return self.value

    def all(self) -> list[Any]:
        assert isinstance(self.value, list)
        return self.value

    def scalar_one(self) -> Any:
        assert self.value is not None
        return self.value


class RecordingSession:
    def __init__(self, answers: list[Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.transactions = 0

    async def __aenter__(self) -> "RecordingSession":
        return self

    async def __aexit__(self, *_args: Any) -> bool:
        return False

    def begin(self) -> "RecordingSession":
        self.transactions += 1
        return self

    async def execute(self, statement: Any, args: Any = None) -> Result:
        sql = str(statement)
        self.calls.append((sql, dict(args or {})))
        assert self.answers, "Unexpected database operation: " + sql
        candidate = self.answers.pop(0)
        if isinstance(candidate, Exception):
            raise candidate
        return Result(candidate)


def store(db: RecordingSession) -> OperatorKnowledgeStore:
    return OperatorKnowledgeStore(SimpleNamespace(_async_session=lambda: db))


@pytest.fixture
def admitted(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    async def fence(
        _db: Any, fid: str, owner: str, rev: int, version: int, *, writing: bool = False
    ) -> tuple[str, str]:
        calls.append((fid, owner, rev, version, writing))
        assert (fid, owner, rev, version) == (FID, OWNER, 3, 7)
        return SID, AUTH

    monkeypatch.setattr(OperatorKnowledgeStore, "_fence", staticmethod(fence))
    return calls


@pytest.mark.asyncio
async def test_original_flow_fence_checks_real_durable_owner_before_signed_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession(
        [
            {"engagement_id": SID},
            {"created_by": OWNER, "phase": "reconnaissance"},
        ]
    )
    signer = AsyncMock()
    monkeypatch.setattr(artifact_module, "guard_sql", signer)
    with pytest.raises(artifact_module.ArtifactDenied) as denied:
        await artifact_module.FlowArtifactStore._fence(session, FID, "foreign-owner", 3, 7)
    assert denied.value.status == 403
    signer.assert_not_awaited()
    assert len(session.calls) == 2
    assert "FOR SHARE" in session.calls[1][0]
    assert not session.answers


@pytest.mark.asyncio
async def test_original_flow_fence_denies_revoked_authority_before_document_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession(
        [
            {"engagement_id": SID},
            {"created_by": OWNER, "phase": "reconnaissance"},
        ]
    )
    signer = AsyncMock(side_effect=artifact_module.AuthorizationDenied("revoked"))
    monkeypatch.setattr(artifact_module, "guard_sql", signer)
    kb = store(session)
    with pytest.raises(KnowledgeDenied) as denied:
        await kb.get(FID, OWNER, 3, 7, DOC)
    assert denied.value.status == 403
    signer.assert_awaited_once_with(session, SID, expected_version=7)
    assert all("operator_knowledge_documents" not in sql for sql, _ in session.calls)
    assert not session.answers


@pytest.mark.asyncio
async def test_flow_revision_and_status_are_exactly_checked_after_signed_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for locked, expected_status in (
        ({"id": FID, "engagement_id": SID, "revision": 4, "status": "running"}, 409),
        ({"id": FID, "engagement_id": SID, "revision": 3, "status": "completed"}, 409),
    ):
        session = RecordingSession(
            [
                {"engagement_id": SID},
                {"created_by": OWNER, "phase": "reconnaissance"},
                locked,
            ]
        )
        guard = AsyncMock(return_value=SimpleNamespace(policy_sha256=AUTH))
        monkeypatch.setattr(artifact_module, "guard_sql", guard)
        with pytest.raises(artifact_module.ArtifactDenied) as denied:
            await artifact_module.FlowArtifactStore._fence(session, FID, OWNER, 3, 7, writing=True)
        assert denied.value.status == expected_status
        assert "FOR UPDATE" in session.calls[2][0]
        guard.assert_awaited_once_with(session, SID, expected_version=7)


@pytest.mark.asyncio
async def test_create_binds_real_issuer_owner_digest_and_document_bounds(
    admitted: list[tuple[Any, ...]],
) -> None:
    db = RecordingSession([0, row()])
    output = await store(db).create(
        FID, OWNER, 3, 7, title="Study guide", doc_type="guide", content="Verified inert body"
    )
    assert output["approved_for_agent_context"] is False
    assert "content" not in output
    assert admitted == [(FID, OWNER, 3, 7, True)]
    assert db.transactions == 1
    count, insert = db.calls
    assert all(
        s in count[0]
        for s in ("engagement_id=:sid", "flow_id=:fid", "owner_id=:owner", "deleted_at IS NULL")
    )
    assert "RETURNING id,engagement_id,flow_id,owner_id" in insert[0]
    assert insert[1]["sid"] == SID and insert[1]["owner"] == OWNER
    assert insert[1]["version"] == 7 and insert[1]["auth_sha"] == AUTH
    assert insert[1]["flow_revision"] == 3
    assert insert[1]["sha"] == hashlib.sha256(b"Verified inert body").hexdigest()


@pytest.mark.asyncio
async def test_mutation_cas_and_tombstone_sql_branches(admitted: list[tuple[Any, ...]]) -> None:
    second = row(
        revision=2,
        content="New text",
        content_bytes=8,
        sha256=hashlib.sha256(b"New text").hexdigest(),
    )
    db = RecordingSession([row(), second])
    updated = await store(db).update(
        FID,
        OWNER,
        3,
        7,
        DOC,
        expected_revision=1,
        title="Edited",
        doc_type="answer",
        content="New text",
    )
    assert updated["revision"] == 2
    assert admitted[-1] == (FID, OWNER, 3, 7, True)
    selected, changed = db.calls
    assert "FOR UPDATE" in selected[0]
    for clause in (
        "engagement_id=:sid",
        "flow_id=:fid",
        "owner_id=:owner",
        "authorization_version=:version",
        "authorization_sha256=:auth_sha",
        "revision=:expected",
        "deleted_at IS NULL",
    ):
        assert clause in changed[0]
    assert changed[1]["expected"] == 1
    assert changed[1]["sha"] == hashlib.sha256(b"New text").hexdigest()

    db = RecordingSession([row(revision=2), None])
    with pytest.raises(KnowledgeDenied) as denied:
        await store(db).update(
            FID,
            OWNER,
            3,
            7,
            DOC,
            expected_revision=2,
            title="Edited",
            doc_type="answer",
            content="New text",
        )
    assert denied.value.status == 409
    assert "UPDATE" in db.calls[-1][0]

    db = RecordingSession([row(revision=2), {"id": DOC, "revision": 3, "deleted_at": NOW}])
    deleted = await store(db).delete(FID, OWNER, 3, 7, DOC, expected_revision=2)
    assert deleted == {"id": DOC, "revision": 3, "deleted": True, "deleted_at": NOW.isoformat()}
    assert "SET deleted_at=now()" in db.calls[-1][0]
    assert db.calls[-1][1]["expected"] == 2
    assert "deleted_at IS NULL" in db.calls[-1][0]


@pytest.mark.asyncio
async def test_stale_foreign_or_corrupt_rows_never_return_contents(
    admitted: list[tuple[Any, ...]],
) -> None:
    for foreign in (
        row(owner_id="another-owner"),
        row(engagement_id="eng-another"),
        row(authorization_sha256="b" * 64),
    ):
        db = RecordingSession([foreign])
        with pytest.raises(KnowledgeDenied) as denied:
            await store(db).get(FID, OWNER, 3, 7, DOC)
        assert denied.value.status == 409
        assert db.calls[0][1] == {"sid": SID, "fid": FID, "owner": OWNER, "id": DOC}
    db = RecordingSession([row(content="altered")])
    with pytest.raises(KnowledgeDenied) as denied:
        await store(db).get(FID, OWNER, 3, 7, DOC)
    assert denied.value.status == 503
    assert len(db.calls) == 1


@pytest.mark.asyncio
async def test_search_paginates_literal_needle_without_exposing_content(
    admitted: list[tuple[Any, ...]],
) -> None:
    db = RecordingSession([[row()]])
    found = await store(db).search(
        FID, OWNER, 3, 7, query="%_' OR 1=1 --", doc_type="guide", limit=2, offset=4
    )
    assert len(found["items"]) == 1
    assert "content" not in found["items"][0]
    sql, params = db.calls[0]
    assert "strpos(lower(content),lower(:needle))>0" in sql
    assert "%_' OR 1=1 --" not in sql
    assert params["needle"] == "%_' OR 1=1 --"
    assert params["limit"] == 3 and params["offset"] == 4
    assert params["version"] == 7 and params["auth_sha"] == AUTH

    with pytest.raises(KnowledgeDenied) as denied:
        await store(RecordingSession([])).list(FID, OWNER, 3, 7, limit=51)
    assert denied.value.status == 422
