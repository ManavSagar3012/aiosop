"""Real signed Flow resource-folder store/router over deterministic PG transactions.

No app database/containers/targets; emulates PostgreSQL SQL rows/transactions
while running actual source SHA/manifest, existing Flow review fences, router,
and real mutation/CAS/event method. Live PostgreSQL migration qualification is
NOT claimed by these mocks.
"""

import copy
import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.routers import flow_resource_folders as api
from ai_osop.memory import flow_artifacts, flow_artifact_reviews
from ai_osop.memory.flow_artifacts import FlowArtifactStore
from ai_osop.memory.flow_resource_folders import FolderDenied
from ai_osop.core.config import settings
from tests.test_flow_resource_aliases_20261019 import (
    _LiveDB,
    _Result,
    FID,
    SID,
    OWNER,
    SHA,
)


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


AUTH = "auth-resource-folders"
PARAMS = {
    "expected_engagement_id": SID,
    "expected_revision": 7,
    "expected_authorization_version": 5,
    "expected_authorization_id": AUTH,
    "expected_authorization_sha256": SHA,
}


class _DB(_LiveDB):
    def __init__(self):
        super().__init__()
        self.catalog = None
        self.folders = {}
        self.assignments = {}
        self.events = []
        self.in_transaction = False
        self._depth = 0
        self.backup = None
        self.on_locked_snapshot = None
        self.on_postcommit_manifest = None
        self.preflight_snapshots = 0
        self.within_snapshot_count = 0
        self.committed = 0
        self.inject_commit_error = False
        self.active_review = True
        self.token_revoked = False
        self.reviewer_disabled = False

    def begin(self):
        # Production SQLAlchemy begin() is nested inside the async session;
        # return a separate context to model atomic commit and rollback.
        class _Transaction:
            async def __aenter__(_self):
                self.in_transaction = True
                self.backup = copy.deepcopy(
                    (self.catalog, self.folders, self.assignments, self.events)
                )
                return self

            async def __aexit__(_self, error_type, *_):
                if error_type is not None or self.inject_commit_error:
                    self.catalog, self.folders, self.assignments, self.events = self.backup
                else:
                    self.committed += 1
                self.in_transaction = False
                if error_type is None and self.inject_commit_error:
                    raise OSError("ambiguous COMMIT")

        return _Transaction()

    async def execute(self, statement, params):
        s = str(statement)
        self.query_log.append((s, dict(params)))
        p = params
        if "SELECT created_by,phase FROM session_states" in s:
            assert "FOR SHARE" in s
            return _Result(value={"created_by": self.owner, "phase": self.session_phase})
        if "SELECT id,engagement_id,revision,status FROM execution_flows" in s:
            assert "FOR SHARE" in s or "FOR UPDATE" in s
            return _Result(
                value={
                    "id": FID,
                    "engagement_id": SID,
                    "revision": self.flow_revision,
                    "status": self.flow_status,
                }
            )
        if "SELECT id,flow_id,engagement_id,owner_id,name,size_bytes,sha256,flow_revision," in s:
            assert self.in_transaction and "LIMIT :limit" in s
            self.within_snapshot_count += 1
            if self.on_locked_snapshot:
                self.on_locked_snapshot()
            return _Result(
                rows=[
                    {**row, "engagement_id": SID, "owner_id": OWNER}
                    for row in self.rows[: p["limit"]]
                ]
            )
        if "INSERT INTO flow_resource_folder_catalogs" in s:
            assert self.in_transaction and "ON CONFLICT (flow_id) DO NOTHING" in s
            if self.catalog is None:
                self.catalog = {
                    "flow_id": p["fid"],
                    "engagement_id": p["sid"],
                    "owner_sub": p["owner"],
                    "revision": 0,
                    "flow_revision": p["flow_rev"],
                    "authorization_version": p["version"],
                    "authorization_id": p["auth_id"],
                    "authorization_sha256": p["auth_sha"],
                    "manifest_sha256": p["manifest"],
                }
            return _Result()
        if "FROM flow_resource_folder_catalogs WHERE flow_id=" in s:
            assert "FOR UPDATE" in s and self.in_transaction
            return _Result(value=self.catalog)
        if "FROM flow_resource_virtual_folders" in s and s.lstrip().startswith("SELECT"):
            return _Result(rows=sorted(self.folders.values(), key=lambda x: (x["name"], x["id"])))
        if "FROM flow_resource_folder_assignments" in s and s.lstrip().startswith("SELECT"):
            return _Result(rows=sorted(self.assignments.values(), key=lambda x: x["artifact_id"]))
        if s.startswith("INSERT INTO flow_resource_virtual_folders"):
            self.folders[p["folder"]] = {
                "id": p["folder"],
                "engagement_id": p["sid"],
                "flow_id": p["fid"],
                "name": p["name"],
            }
            return _Result()
        if s.startswith("UPDATE flow_resource_virtual_folders"):
            self.folders[p["folder"]]["name"] = p["name"]
            return _Result()
        if s.startswith("DELETE FROM flow_resource_virtual_folders"):
            self.folders.pop(p["folder"], None)
            return _Result()
        if s.startswith("INSERT INTO flow_resource_folder_assignments"):
            self.assignments[p["artifact"]] = {
                "flow_id": p["fid"],
                "engagement_id": p["sid"],
                "artifact_id": p["artifact"],
                "artifact_sha256": p["sha"],
                "folder_id": p["folder"],
            }
            return _Result()
        if s.startswith("DELETE FROM flow_resource_folder_assignments"):
            self.assignments.pop(p["artifact"], None)
            return _Result()
        if s.startswith("UPDATE flow_resource_folder_catalogs"):
            assert self.in_transaction and "RETURNING revision" in s
            if not self.catalog or self.catalog["revision"] != p["expected"]:
                return _ScalarResult(None)
            self.catalog["revision"] += 1
            return _ScalarResult(self.catalog["revision"])
        if s.startswith("INSERT INTO flow_resource_folder_events"):
            self.events.append(dict(p))
            return _Result()
        if "FROM flow_artifact_reviews r" in s:
            assert self.in_transaction and "FOR SHARE" in s
            if not self.active_review:
                return _Result(value=None)
            return _Result(
                value={
                    "artifact_id": p["artifact"],
                    "engagement_id": SID,
                    "flow_id": FID,
                    "uploader_sub": OWNER,
                    "reviewer_sub": "senior-different-human",
                    "reviewer_role": "senior_operator",
                    "decision": "approve",
                    "artifact_sha256": self.rows[0]["sha256"],
                    "flow_revision": 7,
                    "authorization_id": AUTH,
                    "authorization_version": 5,
                    "authorization_sha256": SHA,
                }
            )
        if "FROM operator_subject_controls" in s:
            return _ScalarResult(
                self.reviewer_disabled if p["actor"] == "senior-different-human" else None
            )
        if "FROM operator_token_revocations" in s:
            assert self.in_transaction and "FOR SHARE" in s
            return _ScalarResult("revoked-token-digest" if self.token_revoked else None)
        # Existing production FlowArtifactStore's signed snapshot path.
        self.query_log.pop()
        if "FROM flow_artifacts" in s and "LIMIT :limit" in s:
            self.preflight_snapshots += 1
            if self.on_postcommit_manifest and self.committed > 0:
                self.on_postcommit_manifest()
        return await super().execute(statement, p)


@pytest.fixture
def env(monkeypatch):
    db = _DB()
    signed = AsyncMock(
        return_value=SimpleNamespace(
            session_id=SID,
            authorization_id=AUTH,
            version=5,
            policy={"created_by": OWNER},
            policy_sha256=SHA,
        )
    )
    monkeypatch.setattr(flow_artifacts, "guard_sql", signed)
    monkeypatch.setattr(flow_artifact_reviews, "guard_sql", signed)
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    memory = SimpleNamespace(_async_session=db)
    monkeypatch.setattr(api, "_service", lambda: api.FlowResourceFolders(FlowArtifactStore(memory)))

    async def verified(credentials, token):
        assert token is None
        if credentials.credentials == "invalid-token":
            return {"sub": "anonymous", "role": "dev_api_token", "claims": {}}
        if credentials.credentials == "other-owner":
            return {"sub": "foreign-owner", "role": "operator", "claims": {"exp": 2_000_000_000}}
        return {"sub": OWNER, "role": "operator", "claims": {"exp": 2_000_000_000}}

    monkeypatch.setattr(api, "verify_token", verified)
    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)
    headers = {"Authorization": "Bearer signed-owner"}
    return SimpleNamespace(db=db, signed=signed, client=client, headers=headers)


def _query(env):
    # Use the real source manifest path, not fabricated metadata.
    from ai_osop.memory.flow_resource_exports import make_manifest

    m = make_manifest(
        FID,
        7,
        5,
        [
            (
                {
                    "id": row["id"],
                    "flow_id": row["flow_id"],
                    "name": row["name"],
                    "size_bytes": row["size_bytes"],
                    "sha256": row["sha256"],
                    "flow_revision": row["flow_revision"],
                    "authorization_version": row["authorization_version"],
                },
                row["content"],
            )
            for row in env.db.rows
        ],
    )
    return {**PARAMS, "expected_manifest_sha256": m["manifest_sha256"]}


def _get(env, query=None, headers=None):
    return env.client.get(
        f"/flows/{FID}/resource-folders",
        params=query or _query(env),
        headers=headers or env.headers,
    )


def _post(env, operation, revision, query=None, headers=None, **kwargs):
    body = {
        "operation": operation,
        "expected_catalog_revision": revision,
        "explicit_human_confirmation": True,
        **kwargs,
    }
    return env.client.post(
        f"/flows/{FID}/resource-folders",
        params=query or _query(env),
        headers=headers or env.headers,
        json=body,
    )


def test_get_empty_durable_catalog_uses_live_signed_manifest_no_mutation(env):
    response = _get(env)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["catalog_revision"] == 0
    assert data["folders"] == [] and len(data["unassigned"]) == 2
    assert data["metadata_only"] is True
    assert data["host_files_created"] is False
    assert data["worker_sync_performed"] is False
    assert env.db.catalog is None
    assert env.db.preflight_snapshots >= 2 and env.db.within_snapshot_count == 1
    assert response.headers["Cache-Control"] == "private, no-store"


def test_mutable_metadata_crud_persists_catalog_cas_and_append_only_events(env):
    q = _query(env)
    created = _post(env, "create", 0, query=q, name="research_notes")
    assert created.status_code == 201, created.text
    folder = created.json()["folders"][0]
    folder_id = folder["folder_id"]
    assert folder["name"] == "research_notes"
    assert created.json()["catalog_revision"] == 1
    assert created.json()["event_id"].startswith("evt-")
    assert _get(env, q).json()["catalog_revision"] == 1
    rename = _post(env, "rename", 1, query=q, folder_id=folder_id, name="code_reviews")
    assert rename.status_code == 200, rename.text
    assert rename.json()["folders"][0]["name"] == "code_reviews"
    artifact = env.db.rows[0]
    assigned = _post(
        env,
        "assign",
        2,
        query=q,
        folder_id=folder_id,
        artifact_id=artifact["id"],
        artifact_sha256=artifact["sha256"],
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["catalog_revision"] == 3
    assert len(assigned.json()["folders"][0]["items"]) == 1
    assert assigned.json()["folders"][0]["items"][0]["artifact_sha256"] == artifact["sha256"]
    assert _post(env, "delete", 3, query=q, folder_id=folder_id).status_code == 409
    removed = _post(
        env, "unassign", 3, query=q, artifact_id=artifact["id"], artifact_sha256=artifact["sha256"]
    )
    assert removed.status_code == 200, removed.text
    deleted = _post(env, "delete", 4, query=q, folder_id=folder_id)
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["catalog_revision"] == 5
    assert deleted.json()["folders"] == []
    assert len(env.db.events) == 5
    assert [event["catalog"] for event in env.db.events] == [1, 2, 3, 4, 5]
    assert all(event["manifest"] == q["expected_manifest_sha256"] for event in env.db.events)
    assert all(event["owner"] == OWNER for event in env.db.events)
    assert all("bytes" not in e and "content" not in e for e in env.db.events)
    assert env.db.rows[0]["content"] == b"Safe, untrusted notes\n"
    assert not any(
        "UPDATE flow_artifacts" in sql or "DELETE FROM flow_artifacts" in sql
        for sql, _ in env.db.query_log
    )


@pytest.mark.parametrize(
    "invalid", ["../secret", "foo/bar", "C:\\windows", ".hidden", "CamelCase", "a b", "", "x" * 49]
)
def test_unsafe_names_are_rejected_without_catalog_mutation(env, invalid):
    response = _post(env, "create", 0, name=invalid)
    assert response.status_code == 422
    assert env.db.catalog is None and not env.db.events


@pytest.mark.parametrize(
    "field",
    ["missing_confirmation", "wrong_confirmation", "extra", "bool_revision", "wrong_fields"],
)
def test_strict_confirmation_body_denied_without_db_writes(env, field):
    body = {
        "operation": "create",
        "expected_catalog_revision": 0,
        "explicit_human_confirmation": True,
        "name": "notes",
    }
    if field == "missing_confirmation":
        body.pop("explicit_human_confirmation")
    elif field == "wrong_confirmation":
        body["explicit_human_confirmation"] = False
    elif field == "extra":
        body["host_path"] = "C:\\Users\\unsafe"
    elif field == "bool_revision":
        body["expected_catalog_revision"] = True
    elif field == "wrong_fields":
        body["artifact_id"] = "artifact-" + "a" * 32
    response = env.client.post(
        f"/flows/{FID}/resource-folders", params=_query(env), headers=env.headers, json=body
    )
    assert response.status_code == 422, response.text
    assert env.db.catalog is None and env.db.events == []


def test_stale_cas_duplicate_name_double_assign_and_nonempty_delete_fail_closed(env):
    first = _post(env, "create", 0, name="notes")
    assert first.status_code == 201
    folder = first.json()["folders"][0]["folder_id"]
    assert _post(env, "create", 0, name="other").status_code == 409
    assert _post(env, "create", 1, name="notes").status_code == 409
    assert _post(env, "rename", 1, folder_id=folder, name="notes").status_code == 409
    a = env.db.rows[0]
    assert (
        _post(
            env, "assign", 1, folder_id=folder, artifact_id=a["id"], artifact_sha256=a["sha256"]
        ).status_code
        == 200
    )
    assert (
        _post(
            env, "assign", 2, folder_id=folder, artifact_id=a["id"], artifact_sha256=a["sha256"]
        ).status_code
        == 409
    )
    assert _post(env, "delete", 2, folder_id=folder).status_code == 409
    assert _get(env).json()["catalog_revision"] == 2
    assert len(env.db.events) == 2


@pytest.mark.parametrize(
    "change, status",
    [
        ("foreign_owner", 403),
        ("foreign_tenant", 403),
        ("old_flow_rev", 409),
        ("old_authorization_id", 409),
        ("old_authorization_sha", 409),
        ("expired", 409),
        ("unsigned", 403),
        ("missing_bearer", 401),
        ("revoked", 403),
        ("bad_manifest", 409),
    ],
)
def test_signed_owner_flow_policy_revocation_and_manifest_are_fenced(env, change, status):
    p = _query(env)
    headers = env.headers
    if change == "foreign_owner":
        headers = {"Authorization": "Bearer other-owner"}
    elif change == "foreign_tenant":
        p["expected_engagement_id"] = "eng-foreign"
    elif change == "old_flow_rev":
        p["expected_revision"] = 8
    elif change == "old_authorization_id":
        p["expected_authorization_id"] = "auth-other"
    elif change == "old_authorization_sha":
        p["expected_authorization_sha256"] = "f" * 64
    elif change == "expired":
        env.db.session_phase = "completed"
    elif change == "unsigned":
        headers = {"Authorization": "Bearer invalid-token"}
    elif change == "missing_bearer":
        headers = {}
    elif change == "revoked":
        from ai_osop.memory.authorization_store import AuthorizationDenied

        env.signed.side_effect = AuthorizationDenied("signed ROE revoked")
    elif change == "bad_manifest":
        p["expected_manifest_sha256"] = "f" * 64
    response = env.client.post(
        f"/flows/{FID}/resource-folders",
        params=p,
        headers=headers,
        json={
            "operation": "create",
            "expected_catalog_revision": 0,
            "explicit_human_confirmation": True,
            "name": "safe",
        },
    )
    assert response.status_code == status, (change, response.status_code, response.text)
    assert env.db.catalog is None and env.db.events == []


def test_unreviewed_incorrect_and_foreign_artifact_assignment_fails_closed(env):
    create = _post(env, "create", 0, name="notes")
    folder = create.json()["folders"][0]["folder_id"]
    a = env.db.rows[0]
    env.db.active_review = False
    assert (
        _post(
            env, "assign", 1, folder_id=folder, artifact_id=a["id"], artifact_sha256=a["sha256"]
        ).status_code
        == 403
    )
    env.db.active_review = True
    assert (
        _post(
            env, "assign", 1, folder_id=folder, artifact_id=a["id"], artifact_sha256="a" * 64
        ).status_code
        == 409
    )
    assert (
        _post(
            env,
            "assign",
            1,
            folder_id=folder,
            artifact_id="artifact-" + "f" * 32,
            artifact_sha256="b" * 64,
        ).status_code
        == 404
    )
    assert _get(env).json()["catalog_revision"] == 1


def test_same_transaction_sha_manifest_recheck_denies_late_upload_with_rollback(env):
    original = _query(env)

    def flip():
        env.db.rows[0]["content"] = b"modified after the first snapshot"

    env.db.on_locked_snapshot = flip
    response = _post(env, "create", 0, query=original, name="notes")
    assert response.status_code in {409, 503}
    assert env.db.catalog is None and env.db.events == []


def test_same_transaction_manifest_recheck_rejects_late_upload_without_rollback_confusion(env):
    from tests.test_flow_resource_aliases_20261019 import resource

    initial = _query(env)

    def upload_at_transaction_start():
        if len(env.db.rows) == 2:
            env.db.rows.append(resource("later.md", b"A new persisted artifact\n", n=3))

    env.db.on_locked_snapshot = upload_at_transaction_start
    result = _post(env, "create", 0, query=initial, name="notes")
    assert result.status_code == 409
    assert env.db.catalog is None and env.db.events == []
    assert len(env.db.rows) == 3  # Existing append-only source is not rolled back by this fixture.


def test_token_and_independent_reviewer_revocation_prevent_metadata_assignment(env, monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    env.db.token_revoked = True
    assert _post(env, "create", 0, name="notes").status_code == 401
    assert env.db.catalog is None
    env.db.token_revoked = False
    created = _post(env, "create", 0, name="notes")
    assert created.status_code == 201, created.text
    folder = created.json()["folders"][0]["folder_id"]
    env.db.reviewer_disabled = True
    artifact = env.db.rows[0]
    response = _post(
        env,
        "assign",
        1,
        folder_id=folder,
        artifact_id=artifact["id"],
        artifact_sha256=artifact["sha256"],
    )
    assert response.status_code == 403
    assert env.db.catalog["revision"] == 1
    assert len(env.db.events) == 1


def test_ambiguous_commit_unknown_does_not_announce_success(env):
    env.db.inject_commit_error = True
    response = _post(env, "create", 0, name="notes")
    assert response.status_code == 503
    assert env.db.catalog is None and env.db.events == []


def test_postcommit_signed_manifest_recheck_reports_unknown_not_false_success(env):
    original = _query(env)

    def alter_after_commit():
        env.db.rows[0]["content"] = b"changed after metadata committed"

    env.db.on_postcommit_manifest = alter_after_commit
    response = _post(env, "create", 0, query=original, name="notes")
    assert response.status_code == 503
    assert env.db.catalog is not None and env.db.catalog["revision"] == 1
    assert len(env.db.events) == 1  # commit happened; never imply rollback


def test_no_database_no_metadata_success(env):
    # Route must fail closed even when signed snapshots could otherwise be cached.
    from ai_osop.memory.flow_resource_folders import FlowResourceFolders

    def unavailable():
        return FlowResourceFolders(FlowArtifactStore(SimpleNamespace(_async_session=None)))

    from pytest import MonkeyPatch

    with MonkeyPatch.context() as m:
        m.setattr(api, "_service", unavailable)
        response = _get(env)
        assert response.status_code == 503


def test_real_0026_migration_declares_append_only_trigger_and_parent():
    import importlib.util
    from pathlib import Path

    file = Path(__file__).resolve().parents[1] / "migrations/versions/0026_flow_resource_folders.py"
    spec = importlib.util.spec_from_file_location("new_flow_resource_0026", file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0026" and module.down_revision == "0025"
    # Migration will run in a fresh isolated DB separately; tests never apply
    # its DDL to an application database.
    from inspect import getsource

    source = getsource(module.upgrade)
    assert "trg_flow_resource_folder_events_immutable" in source
    assert "reject_target_authority_nonce_mutation" in source
