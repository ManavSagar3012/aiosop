"""Real FlowArtifactStore, manifest, Task resource gate and FastAPI routes.

Deterministic SQL/revocation fixtures, no application DB, targets, containers,
host artifacts, fake synchronization, extraction or side-effect execution.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.routers import flow_artifacts as artifact_api
from ai_osop.api.routers import flow_resource_aliases as alias_api
from ai_osop.memory import authoritative_task_resources, flow_artifacts
from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore
from ai_osop.memory.flow_resource_aliases import FlowResourceAliases
from ai_osop.safety.approval_binding import pinned_evidence
from tests.test_flow_resource_exports import (
    _DB as _ArtifactDB,
    _Result,
    FID,
    OWNER,
    PARAMS,
    SHA,
    SID,
    resource,
)


class _LiveDB(_ArtifactDB):
    """Emulate SQL sources consumed by production signed Task verifier."""

    def __init__(self):
        super().__init__()
        self.rows = [
            resource("notes.txt", b"Safe, untrusted notes\n"),
            resource("readme.py", b"print('not executed')\n", n=2),
        ]
        self.task_state = "running"
        self.step_state = "running"
        self.lease_state = "dispatched"
        self.lease_expires = datetime.utcnow() + timedelta(minutes=5)
        self.approval_state = "approved"
        self.pinned = True
        self.signed_version = 5
        self.owner = OWNER
        self.on_task_read = None
        self.on_artifact_read = None
        self.on_listing = None
        self.task_id = "task-resources-approved"
        self.resource = self.rows[0]
        self.payload = {
            "url": "https://authorized.example.test/controlled",
            "_authorization_version": 5,
            "_flow_revision": 7,
            "resource_artifact_id": self.resource["id"],
            "resource_artifact_sha256": self.resource["sha256"],
            "resource_authorization_sha256": SHA,
            "resource_command_sha256": "c" * 64,
            "operator_approved": True,
            "approval_id": "apr-resource-approved",
        }
        self.scope = {
            "engagement_id": SID,
            "domains": ["authorized.example.test"],
            "authorization_ref": "signed-synthetic-reference-not-authorization",
        }

    async def execute(self, stmt, params):
        statement = str(stmt)
        self.query_log.append((statement, dict(params)))
        if "SELECT created_by, phase, scope FROM session_states" in statement:
            assert "FOR SHARE" in statement
            return _Result(
                value={
                    "created_by": self.owner,
                    "phase": self.session_phase,
                    "scope": self.scope,
                }
            )
        if (
            "SELECT id, engagement_id, revision, status FROM execution_flows" in statement
            and "id=:flow" in statement
        ):
            assert "FOR SHARE" in statement
            return _Result(
                value={
                    "id": FID,
                    "engagement_id": SID,
                    "revision": self.flow_revision,
                    "status": self.flow_status,
                }
            )
        if "FROM tasks WHERE id=:task" in statement:
            assert "FOR SHARE" in statement
            if self.on_task_read:
                self.on_task_read()
            return _Result(
                value={
                    "id": self.task_id,
                    "engagement_id": SID,
                    "flow_id": FID,
                    "subtask_id": "subtask-resource-approved",
                    "parent_task_id": "task-resource-parent",
                    "type": "navigate",
                    "status": self.task_state,
                    "scope_check": True,
                    "approval_required": True,
                    "assigned_agent_id": "agent-resource-worker",
                    "started_at": datetime.utcnow() - timedelta(seconds=5),
                    "completed_at": None,
                    "payload": self.payload,
                }
            )
        if "FROM approval_requests" in statement:
            assert "FOR SHARE" in statement
            return _Result(
                value={
                    "id": "apr-resource-approved",
                    "task_id": self.task_id,
                    "engagement_id": SID,
                    "action_type": "navigate",
                    "target": self.payload["url"],
                    "status": self.approval_state,
                    "operator_id": "senior-owner",
                    "responded_at": datetime.utcnow(),
                    "evidence": pinned_evidence([], self.payload) if self.pinned else [],
                }
            )
        if "FROM execution_subtasks" in statement:
            assert "FOR SHARE" in statement
            return _Result(
                value={
                    "id": "subtask-resource-approved",
                    "engagement_id": SID,
                    "flow_id": FID,
                    "execution_task_id": self.task_id,
                    "status": self.step_state,
                }
            )
        if "FROM supervision_execution_leases" in statement:
            assert "FOR SHARE" in statement
            return _Result(
                value={
                    "engagement_id": SID,
                    "task_id": self.task_id,
                    "lease_id": "lease-current-authorized-resource",
                    "owner_id": "claimed-dispatch-owner",
                    "state": self.lease_state,
                    "expires_at": self.lease_expires,
                }
            )
        if "FROM flow_artifacts" in statement and "AND id=:id" in statement:
            assert "owner_id=:owner" in statement and "engagement_id=:sid" in statement
            if self.on_artifact_read:
                self.on_artifact_read()
            match = next((row for row in self.rows if row["id"] == params["id"]), None)
            return _Result(value=match)
        if "FROM flow_artifacts" in statement and "LIMIT :limit" in statement:
            if self.on_listing:
                self.on_listing()
        # Reuse the existing Flow artifact SQL fixture for real owner, signed
        # revision, SHA, source snapshot and manifest production code.
        self.query_log.pop()
        return await super().execute(stmt, params)


@pytest.fixture
def api(monkeypatch):
    db = _LiveDB()
    store = FlowArtifactStore(SimpleNamespace(_async_session=db))
    signed = AsyncMock(
        return_value=SimpleNamespace(
            session_id=SID,
            policy={"created_by": OWNER},
            policy_sha256=SHA,
            version=5,
        )
    )
    monkeypatch.setattr(flow_artifacts, "guard_sql", signed)
    monkeypatch.setattr(authoritative_task_resources, "guard_sql", signed)

    async def operator(credentials, token):
        assert token is None and credentials.credentials == "verified-owner-jwt"
        return {"sub": OWNER, "role": "operator", "claims": {"exp": 2_000_000_000}}

    monkeypatch.setattr(artifact_api, "verify_token", operator)
    monkeypatch.setattr(alias_api, "_store", lambda: store)
    app = FastAPI()
    # Mirror the prime's intended coexistence with already-mounted Flow
    # artifact endpoints and prove the two routers do not shadow each other.
    app.include_router(artifact_api.router)
    app.include_router(alias_api.router)
    client = TestClient(app)
    header = {"Authorization": "Bearer verified-owner-jwt"}
    return SimpleNamespace(db=db, store=store, signed=signed, client=client, header=header)


def _params(**overrides):
    return {**PARAMS, **overrides}


def _request(api, **overrides):
    entry = api.db.resource
    return {
        "engagement_id": SID,
        "task_id": api.db.task_id,
        "artifact_id": entry["id"],
        "artifact_sha256": entry["sha256"],
        "authorization_sha256": SHA,
        "expected_manifest_sha256": api.client.get(
            f"/flows/{FID}/resource-aliases",
            params=PARAMS,
            headers=api.header,
        ).json()["source_manifest_sha256"],
        **overrides,
    }


def test_read_only_virtual_folder_catalog_is_real_signed_sha_checked_pg_snapshot(api):
    response = api.client.get(
        f"/flows/{FID}/resource-aliases",
        params=PARAMS,
        headers=api.header,
    )
    assert response.status_code == 200, response.text
    info = response.json()
    assert info["format"] == "ai-osop-derived-flow-resource-aliases-v1"
    assert info["count"] == 2
    assert info["folders"] == [
        {"path": "virtual/text", "count": 1},
        {"path": "virtual/source", "count": 1},
    ]
    for entry in info["items"]:
        assert entry["alias_path"].startswith("virtual/")
        assert entry["artifact_id"] in [r["id"] for r in api.db.rows]
        assert entry["approved_for_task"] is False
        assert entry["approved_for_agent_instructions"] is False
        assert entry["sha256"] == next(
            r["sha256"] for r in api.db.rows if r["id"] == entry["artifact_id"]
        )
    assert info["virtual_folders_persisted"] is False
    assert info["aliases_persisted"] is False
    assert info["host_files_created"] is False
    assert info["container_resource_sync_performed"] is False
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["x-resource-manifest-sha256"] == info["source_manifest_sha256"]
    assert api.signed.await_count >= 1
    assert any("FOR SHARE" in sql for sql, _ in api.db.query_log)
    assert not any(
        "INSERT" in sql or "UPDATE" in sql or "DELETE" in sql for sql, _ in api.db.query_log
    )


def test_metadata_preview_requires_manifest_compare_and_return_no_bytes(api):
    source = _request(api)
    ok = api.client.get(
        f"/flows/{FID}/resource-aliases/{source['artifact_id']}/preview",
        params={**PARAMS, "expected_manifest_sha256": source["expected_manifest_sha256"]},
        headers=api.header,
    )
    assert ok.status_code == 200
    value = ok.json()
    assert value["preview_contains_artifact_bytes"] is False
    assert value["replayable_or_executable"] is False
    assert "content" not in value and "bytes" not in value
    assert (
        api.client.get(
            f"/flows/{FID}/resource-aliases/{source['artifact_id']}/preview",
            params={**PARAMS, "expected_manifest_sha256": "e" * 64},
            headers=api.header,
        ).status_code
        == 409
    )
    assert (
        api.client.get(
            f"/flows/{FID}/resource-aliases/artifact-{'f' * 32}/preview",
            params={**PARAMS, "expected_manifest_sha256": source["expected_manifest_sha256"]},
            headers=api.header,
        ).status_code
        == 404
    )


def test_task_preflight_uses_real_approved_pg_task_lease_and_content_hash(api):
    body = _request(api)
    response = api.client.post(
        f"/flows/{FID}/resource-aliases/task-preview",
        params=PARAMS,
        headers=api.header,
        json=body,
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["signed_task_currently_approved"] is True
    assert data["approved_command_sha256"] == "c" * 64
    assert data["sha256"] == hashlib.sha256(api.db.rows[0]["content"]).hexdigest()
    assert data["approved_for_agent_instructions"] is False
    assert data["preview_contains_artifact_bytes"] is False
    assert data["resource_transferred_to_worker"] is False
    assert data["execution_started_by_preview"] is False
    assert data["container_resource_sync_performed"] is False
    assert "content" not in data
    # Original approved command is also pinned before the double-checking
    # reader, then compared to the final refreshed approval/lease readback.
    assert sum("FROM supervision_execution_leases" in sql for sql, _ in api.db.query_log) == 4


@pytest.mark.parametrize(
    "change, expected",
    [
        ("paused", 403),
        ("wrong_revision", 409),
        ("wrong_owner", 403),
        ("signed_revoked", 503),
        ("bad_content_digest", 503),
        ("bad_signed_manifest", 409),
        ("bad_task_digest", 409),
        ("bad_authorization_digest", 403),
        ("wrong_engagement", 403),
        ("unapproved", 403),
        ("lease_unknown", 403),
        ("lease_expired", 403),
        ("task_not_running", 403),
        ("task_unpinned", 403),
    ],
)
def test_denies_stale_revoked_foreign_and_unapproved_artifact_previews(api, change, expected):
    body = _request(api)
    if change == "paused":
        api.db.flow_status = "paused"
    elif change == "wrong_revision":
        api.db.flow_revision = 8
    elif change == "wrong_owner":
        api.db.owner = "different-user"
    elif change == "signed_revoked":
        api.signed.side_effect = PermissionError("Signed ROE revoked")
    elif change == "bad_content_digest":
        api.db.rows[0]["content"] = b"content changed after commit"
    elif change == "bad_signed_manifest":
        body["expected_manifest_sha256"] = "e" * 64
    elif change == "bad_task_digest":
        body["artifact_sha256"] = "f" * 64
    elif change == "bad_authorization_digest":
        body["authorization_sha256"] = "f" * 64
    elif change == "wrong_engagement":
        body["engagement_id"] = "eng-different-tenant"
    elif change == "unapproved":
        api.db.approval_state = "pending"
    elif change == "lease_unknown":
        api.db.lease_state = "unknown"
    elif change == "lease_expired":
        api.db.lease_expires = datetime.utcnow() - timedelta(seconds=2)
    elif change == "task_not_running":
        api.db.task_state = "dispatch_unknown"
    elif change == "task_unpinned":
        api.db.payload["resource_artifact_sha256"] = "f" * 64
    result = api.client.post(
        f"/flows/{FID}/resource-aliases/task-preview",
        params=PARAMS,
        headers=api.header,
        json=body,
    )
    assert result.status_code == expected, (change, result.status_code, result.text)
    assert "content" not in result.text


def test_denies_missing_credentials_query_token_and_malformed_inputs_without_db(api):
    bare = api.client.get(f"/flows/{FID}/resource-aliases", params=PARAMS)
    assert bare.status_code == 401
    query = api.client.get(
        f"/flows/{FID}/resource-aliases",
        params={**PARAMS, "token": "forbidden-query-token"},
        headers=api.header,
    )
    assert query.status_code == 401
    assert (
        api.client.get(
            f"/flows/{FID}/resource-aliases",
            params={"expected_revision": -1, "expected_authorization_version": 5},
            headers=api.header,
        ).status_code
        == 422
    )
    assert (
        api.client.get(
            f"/flows/{FID}/resource-aliases",
            params={"expected_revision": 7, "expected_authorization_version": 0},
            headers=api.header,
        ).status_code
        == 422
    )
    malformed = api.client.post(
        f"/flows/{FID}/resource-aliases/task-preview",
        params=PARAMS,
        headers=api.header,
        json={
            "engagement_id": SID,
            "task_id": "task-identity",
            "artifact_id": "../../pass",
            "authorization_sha256": SHA,
        },
    )
    assert malformed.status_code == 422
    assert not any("DELETE" in sql or "INSERT" in sql for sql, _ in api.db.query_log)


def test_catalog_rejects_binary_html_traversal_without_metadata_leaks(api):
    api.db.rows.append(resource("evil.sh", b"#!/bin/sh\necho run\n", n=3))
    result = api.client.get(f"/flows/{FID}/resource-aliases", params=PARAMS, headers=api.header)
    assert result.status_code == 415
    api.db.rows[-1] = resource("bad.txt", b"<script>alert('x')</script>", n=3)
    result = api.client.get(f"/flows/{FID}/resource-aliases", params=PARAMS, headers=api.header)
    assert result.status_code == 415
    api.db.rows[-1] = resource("../bad.txt", b"unsafe path", n=3)
    result = api.client.get(f"/flows/{FID}/resource-aliases", params=PARAMS, headers=api.header)
    assert result.status_code == 422


def test_catalog_denies_on_concurrent_revision_change_after_first_snapshot(api):
    body = _request(api)
    reads = 0

    def on_listing():
        nonlocal reads
        reads += 1
        if reads == 1:
            api.db.flow_revision = 8

    api.db.on_listing = on_listing
    result = api.client.get(
        f"/flows/{FID}/resource-aliases/{body['artifact_id']}/preview",
        params={**PARAMS, "expected_manifest_sha256": body["expected_manifest_sha256"]},
        headers=api.header,
    )
    assert result.status_code == 409


def test_task_preview_denies_revoked_lease_after_resource_byte_read(api):
    body = _request(api)

    def revoke_after_read():
        api.db.lease_state = "revoked"

    api.db.on_artifact_read = revoke_after_read
    result = api.client.post(
        f"/flows/{FID}/resource-aliases/task-preview",
        params=PARAMS,
        headers=api.header,
        json=body,
    )
    assert result.status_code == 403
    assert "content" not in result.text


def test_task_preview_denies_new_command_digest_at_final_signed_readback(api):
    body = _request(api)
    observed = 0

    def rotate_command():
        nonlocal observed
        observed += 1
        if observed == 4:
            # Simulate replacement in the final synchronous PG read, after
            # both original task+resource checks and final manifest re-read.
            # Even a newly pinned grant is not the SAME reviewed command.
            api.db.payload["resource_command_sha256"] = "d" * 64

    api.db.on_task_read = rotate_command
    result = api.client.post(
        f"/flows/{FID}/resource-aliases/task-preview",
        params=PARAMS,
        headers=api.header,
        json=body,
    )
    assert observed == 4
    assert result.status_code == 403
    assert "content" not in result.text


def test_unavailable_pg_artifact_store_fails_closed(api):
    api.store.session_memory._async_session = None
    result = api.client.get(f"/flows/{FID}/resource-aliases", params=PARAMS, headers=api.header)
    assert result.status_code == 503
