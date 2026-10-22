"""Production engine-to-SessionMemory evidence artifact admission contract.

Runs the real engine/ORM-query code against deterministic transaction and
signed-source fixtures. It deliberately does not contact any app DB, target,
provider or production signer. 0024 PG trigger qualification lives separately.
"""

import hashlib
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
from ai_osop.core.exceptions import MemoryException, WorkflowException
from ai_osop.core.models import EvidenceArtifact, ScopeDefinition
from ai_osop.memory import authorization_store
from ai_osop.memory.session_memory import (
    EvidenceArtifactORM,
    SessionMemory,
    evidence_artifact_leaf_sha256,
)
from ai_osop.memory.supervision_store import SupervisionStore
from ai_osop.safety.approval_binding import pinned_evidence


URL = "https://authorized.example.test/private?access_token=actual-secret"
SOURCE_ID = "task-artifact-source"
TENANT_ID = "eng-artifact-owner"


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def scalar_one_or_none(self):
        return self.rows

    def scalar_one(self):
        return self.rows

    def scalars(self):
        return self

    def all(self):
        return self.rows if isinstance(self.rows, list) else [self.rows]


class _Db:
    def __init__(self):
        self.task = SimpleNamespace(
            id=SOURCE_ID,
            engagement_id=TENANT_ID,
            status="running",
            approval_required=True,
            payload={
                "url": URL,
                "method": "GET",
                "_authorization_version": 2,
                "approval_id": "apr-artifact-reviewed",
                "operator_approved": True,
                "_flow_revision": 3,
            },
            flow_id="flow-artifact-owner",
            subtask_id="subtask-artifact-owner",
            parent_task_id="task-original-artifact-owner",
        )
        self.flow = SimpleNamespace(
            id=self.task.flow_id,
            engagement_id=TENANT_ID,
            status="running",
            revision=3,
        )
        self.step = SimpleNamespace(
            id=self.task.subtask_id,
            flow_id=self.task.flow_id,
            execution_task_id=SOURCE_ID,
            task_id=self.task.parent_task_id,
            status="running",
        )
        self.approval = SimpleNamespace(
            id=self.task.payload["approval_id"],
            task_id=SOURCE_ID,
            engagement_id=TENANT_ID,
            status="approved",
            operator_id="real-human-record",
            responded_at=datetime.utcnow(),
            evidence=pinned_evidence([], self.task.payload),
        )
        self.stored = {}
        self.staged = None
        self.active = False
        self.commits = 0
        self.read_queries = []
        self.fail_commit = False
        self.read_corrupt = False
        self.read_missing = False
        self.migration_ready = True

    async def __aenter__(self):
        self.active = True
        return self

    async def __aexit__(self, exc_type, *_):
        if exc_type is None and self.staged is not None:
            if self.fail_commit:
                raise OSError("commit acknowledgement UNKNOWN")
            self.stored[self.staged.id] = self.staged
            self.commits += 1
        self.staged = None
        self.active = False

    def begin(self):
        return self

    def add(self, row):
        assert self.active and isinstance(row, EvidenceArtifactORM)
        self.staged = row

    async def execute(self, statement):
        assert self.active
        sql = str(statement)
        if "FROM pg_trigger" in sql:
            result = self.migration_ready
        elif "FROM tasks" in sql:
            result = self.task
        elif "FROM execution_flows" in sql:
            result = self.flow
        elif "FROM execution_subtasks" in sql:
            result = self.step
        elif "FROM approval_requests" in sql:
            result = self.approval
        elif "FROM evidence_artifacts" in sql:
            assert "evidence_artifacts.engagement_id" in sql
            assert "evidence_artifacts.id" in sql or "evidence_artifacts.finding_id" in sql
            self.read_queries.append(sql)
            if "evidence_artifacts.id" in sql:
                result = None if self.read_missing else next(iter(self.stored.values()), None)
                if self.read_corrupt and result is not None:
                    result = SimpleNamespace(
                        **{key: getattr(result, key) for key in EvidenceArtifact.model_fields}
                    )
                    result.request_body_sha256 = "a" * 64
            else:
                result = list(self.stored.values())
        else:
            raise AssertionError(f"Unexpected DB statement: {sql}")
        return _Rows(result)


def _system(monkeypatch):
    db = _Db()
    memory = SessionMemory.__new__(SessionMemory)
    memory._async_session = lambda: db
    engine = DifferentialAuthEngine(memory)

    scope = ScopeDefinition(
        engagement_id=TENANT_ID,
        domains=["authorized.example.test"],
        authorization_ref="fixture-signed-ROE-handle-not-target-proof",
    )

    async def current_engagement(session, engagement_id, *, require_window=False):
        assert db.active and session is db and engagement_id == TENANT_ID
        assert require_window is True
        return SimpleNamespace(scope=scope.model_dump(mode="json")), None

    async def current_signer(session, engagement_id, expected_version=None):
        assert db.active and session is db and engagement_id == TENANT_ID
        return SimpleNamespace(version=2)

    monkeypatch.setattr(SupervisionStore, "_guard", staticmethod(current_engagement))
    monkeypatch.setattr(authorization_store, "guard_sql", current_signer)
    return engine, memory, db


async def _create(engine, **overrides):
    fields = dict(
        finding_id="finding-artifact-candidate",
        engagement_id=TENANT_ID,
        source_task_id=SOURCE_ID,
        target_url=URL,
        http_method="GET",
        request_headers={
            "Authorization": "Bearer raw-secret-access-token",
            "Cookie": "session=raw-session-secret",
            "Accept": "application/json",
        },
        request_body={"password": "not-for-ledger", "token": "secrets-in-request"},
        response_status=200,
        response_headers={"Set-Cookie": "secret-reply"},
        response_body={"private": "untrusted-target-body"},
        approval_id="apr-artifact-reviewed",
        replay_recipe={
            "method": "GET",
            "url": URL,
            "headers": {"Authorization": "Bearer evil-replay-bearer"},
            "body": "supersecret-replay-body",
            "finding_verified": True,
        },
    )
    fields.update(overrides)
    return await engine.create_and_persist_evidence_artifact(**fields)


@pytest.mark.asyncio
async def test_actual_engine_store_and_tenant_fenced_readback_redacts_sensitive_replay(monkeypatch):
    engine, memory, db = _system(monkeypatch)
    artifact = await _create(engine)
    assert db.commits == 1
    assert artifact.id in db.stored
    assert artifact.replay_recipe["replayable"] is False
    assert artifact.replay_recipe["finding_verified"] is False
    assert artifact.replay_recipe["target_effect_verified"] is False
    assert artifact.replay_recipe["method"] == "GET"
    assert "access_token=REDACTED" in artifact.target_url
    assert artifact.merkle_leaf_hash == evidence_artifact_leaf_sha256(artifact)
    assert (
        artifact.request_body_sha256
        == hashlib.sha256(
            b'{"password": "not-for-ledger", "token": "secrets-in-request"}'
        ).hexdigest()
    )
    serialized = str(db.stored[artifact.id].__dict__)
    for secret in (
        "raw-secret-access-token",
        "raw-session-secret",
        "actual-secret",
        "not-for-ledger",
        "secrets-in-request",
        "evil-replay-bearer",
        "supersecret-replay-body",
        "untrusted-target-body",
        "secret-reply",
    ):
        assert secret not in serialized
    assert "authorization" not in artifact.replay_recipe["request_header_names"]
    assert "cookie" not in artifact.replay_recipe["request_header_names"]
    assert db.read_queries and all("evidence_artifacts.engagement_id" in q for q in db.read_queries)
    fetched = await memory.get_evidence_artifact(artifact.id, engagement_id=TENANT_ID)
    assert fetched == artifact


@pytest.mark.asyncio
async def test_without_postgres_engine_never_signals_artifact_success(monkeypatch):
    engine, memory, _ = _system(monkeypatch)
    memory._async_session = None
    with pytest.raises(MemoryException):
        await _create(engine)


@pytest.mark.asyncio
async def test_legacy_0023_without_0024_write_once_trigger_is_not_durable_evidence(monkeypatch):
    engine, _, db = _system(monkeypatch)
    db.migration_ready = False
    with pytest.raises(MemoryException, match="0024"):
        await _create(engine)
    assert not db.stored and db.commits == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "stale_source",
        "tenant",
        "stale_version",
        "url_mismatch",
        "flow_closed",
        "flow_revision",
        "wrong_subtask",
        "approval_revoked",
        "approval_unpinned",
        "not_authorized",
        "bad_status",
        "no_owner",
    ],
)
async def test_production_source_owner_and_approval_fail_closed(monkeypatch, mutation):
    engine, memory, db = _system(monkeypatch)
    if mutation == "stale_source":
        db.task.status = "dispatch_unknown"
    elif mutation == "tenant":
        db.task.engagement_id = "eng-another-tenant"
    elif mutation == "stale_version":
        db.task.payload["_authorization_version"] = 1
    elif mutation == "url_mismatch":
        db.task.payload["url"] = "https://authorized.example.test/different"
    elif mutation == "flow_closed":
        db.flow.status = "paused"
    elif mutation == "flow_revision":
        db.flow.revision = 4
    elif mutation == "wrong_subtask":
        db.step.execution_task_id = "task-foreign"
    elif mutation == "approval_revoked":
        db.approval = None
    elif mutation == "approval_unpinned":
        db.approval.evidence = []
    elif mutation == "not_authorized":

        async def revoked(*_a, **_kw):
            raise PermissionError("Signer was revoked")

        monkeypatch.setattr(authorization_store, "guard_sql", revoked)
    elif mutation == "bad_status":
        db.task.status = "pending"
    elif mutation == "no_owner":
        db.approval.operator_id = None
    with pytest.raises((MemoryException, PermissionError)):
        await _create(engine)
    assert not db.stored


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["no_task_id", "oversized_url", "wrong_recipe_url", "wrong_recipe_method"]
)
async def test_untrusted_or_unbound_artifact_inputs_never_reach_db(monkeypatch, change):
    engine, _, db = _system(monkeypatch)
    fields = {
        "no_task_id": {"source_task_id": None},
        "oversized_url": {"target_url": "https://authorized.example.test/" + "x" * 2200},
        "wrong_recipe_url": {
            "replay_recipe": {"url": "https://attacker.example/", "method": "GET"}
        },
        "wrong_recipe_method": {"replay_recipe": {"url": URL, "method": "DELETE"}},
    }[change]
    with pytest.raises(WorkflowException):
        await _create(engine, **fields)
    assert db.commits == 0 and not db.stored


@pytest.mark.asyncio
async def test_committed_artifact_digest_mismatch_refuses_success_and_readback(monkeypatch):
    engine, memory, db = _system(monkeypatch)
    db.read_corrupt = True
    with pytest.raises(MemoryException):
        await _create(engine)
    assert db.commits == 1
    with pytest.raises(MemoryException):
        await memory.get_evidence_artifact(next(iter(db.stored)), engagement_id=TENANT_ID)


@pytest.mark.asyncio
async def test_missing_durable_readback_after_commit_is_unknown(monkeypatch):
    engine, _, db = _system(monkeypatch)
    db.read_missing = True
    with pytest.raises(MemoryException, match="readback is UNKNOWN"):
        await _create(engine)
    assert db.commits == 1


@pytest.mark.asyncio
async def test_exact_tenant_readback_and_listing_refuse_foreign_rows(monkeypatch):
    engine, memory, db = _system(monkeypatch)
    artifact = await _create(engine)
    assert await memory.list_finding_evidence(TENANT_ID, artifact.finding_id) == [artifact]
    db.stored[artifact.id].engagement_id = "eng-foreign-tenant"
    with pytest.raises(MemoryException, match="tenant readback"):
        await memory.get_evidence_artifact(artifact.id, engagement_id=TENANT_ID)
    with pytest.raises(MemoryException, match="foreign tenant"):
        await memory.list_finding_evidence(TENANT_ID, artifact.finding_id)


@pytest.mark.asyncio
async def test_commit_acknowledgement_unknown_refuses_success(monkeypatch):
    engine, _, db = _system(monkeypatch)
    db.fail_commit = True
    with pytest.raises(OSError, match="commit acknowledgement UNKNOWN"):
        await _create(engine)
    assert db.commits == 0
