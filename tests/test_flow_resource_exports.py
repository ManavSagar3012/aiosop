"""Flow resource exports: signed PG-read emulation, inert bytes, no host mirror.

All SQL and JWT verification are synthetic; this never contacts app Postgres,
executes artifact contents, uses an execution sandbox, or extracts an archive.
"""

import asyncio
import hashlib
import io
import os
import zipfile
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.routers import flow_artifacts as artifact_api
from ai_osop.memory import flow_artifacts
from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore
from ai_osop.memory.flow_resource_exports import (
    FlowResourceExports,
    MAX_EXPORT_FILES,
    MAX_EXPORT_TOTAL_BYTES,
    _canonical,
    make_bundle,
    make_manifest,
)

FID = "flow-resources"
SID = "eng-resources"
OWNER = "owned-operator"
SHA = "a" * 64
HEADERS = {"Authorization": "Bearer signed-unit-jwt"}
PARAMS = {"expected_revision": 7, "expected_authorization_version": 5}


def resource(name="notes.txt", blob=b"Hello\n", *, n=1, **overrides):
    entry = {
        "id": "artifact-" + f"{n:032x}",
        "flow_id": FID,
        "name": name,
        "size_bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "flow_revision": 7,
        "authorization_version": 5,
        "authorization_sha256": SHA,
        "created_at": datetime(2026, 10, 14, 12, 0, n % 60),
        "content": blob,
    }
    entry.update(overrides)
    return entry


class _Result:
    def __init__(self, *, value=None, rows=None):
        self.value = value
        self.rows = rows

    def mappings(self):
        return self

    def one_or_none(self):
        return self.value

    def all(self):
        return self.rows


class _DB:
    def __init__(self):
        self.rows = [resource()]
        self.flow_revision = 7
        self.owner = OWNER
        self.flow_status = "running"
        self.session_phase = "reconnaissance"
        self.query_log = []
        self.read_attempted = False
        self.on_read = None

    def __call__(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def begin(self):
        return self

    async def execute(self, stmt, params):
        statement = str(stmt)
        self.query_log.append((statement, dict(params)))
        if "SELECT engagement_id FROM execution_flows" in statement:
            return _Result(value={"engagement_id": SID})
        if "SELECT created_by, phase FROM session_states" in statement:
            assert "FOR SHARE" in statement
            return _Result(value={"created_by": self.owner, "phase": self.session_phase})
        if "SELECT id, engagement_id, revision, status FROM execution_flows" in statement:
            assert "FOR SHARE" in statement
            return _Result(
                value={
                    "id": FID,
                    "engagement_id": SID,
                    "revision": self.flow_revision,
                    "status": self.flow_status,
                }
            )
        if "SELECT id,flow_id,name,size_bytes,sha256,flow_revision" in statement:
            assert params == {"sid": SID, "fid": FID, "owner": OWNER, "limit": MAX_EXPORT_FILES + 1}
            self.read_attempted = True
            if self.on_read is not None:
                self.on_read()
            return _Result(rows=self.rows[: params["limit"]])
        raise AssertionError("Unexpected SQL during Flow resource readback")


@pytest.fixture
def harness(monkeypatch):
    db = _DB()
    memory = SimpleNamespace(_async_session=db)
    store = FlowArtifactStore(memory)
    signed = AsyncMock(
        return_value=SimpleNamespace(
            policy_sha256=SHA,
            version=5,
        )
    )
    monkeypatch.setattr(flow_artifacts, "guard_sql", signed)

    async def token(credentials, token):
        assert token is None
        assert credentials.credentials == "signed-unit-jwt"
        return {
            "sub": OWNER,
            "role": "operator",
            "claims": {"exp": 2_000_000_000},
        }

    monkeypatch.setattr(artifact_api, "verify_token", token)
    monkeypatch.setattr(artifact_api, "_store", lambda: store)
    app = FastAPI()
    app.include_router(artifact_api.router)
    return SimpleNamespace(
        db=db,
        store=store,
        signed=signed,
        app=app,
        client=TestClient(app),
    )


@pytest.mark.asyncio
async def test_single_snapshot_uses_signed_owner_fence_and_independent_digest(harness):
    manifest, snapshot = await FlowResourceExports(harness.store).prepare(
        FID,
        OWNER,
        7,
        5,
    )
    assert manifest["count"] == 1
    assert manifest["total_size_bytes"] == 6
    assert manifest["items"][0]["resource_path"] == "resources/notes.txt"
    assert manifest["items"][0]["sha256"] == hashlib.sha256(b"Hello\n").hexdigest()
    assert manifest["read_only"] is True
    assert manifest["content_executed"] is False
    assert manifest["host_files_created"] is False
    assert manifest["artifact_bytes_untrusted"] is True
    assert (
        manifest["manifest_sha256"]
        == hashlib.sha256(
            _canonical({k: v for k, v in manifest.items() if k != "manifest_sha256"})
        ).hexdigest()
    )
    assert snapshot[0][1] == b"Hello\n"
    harness.signed.assert_awaited_once()
    assert harness.signed.await_args.kwargs == {"expected_version": 5}
    assert harness.db.read_attempted
    assert (
        len(
            [
                sql
                for sql, _ in harness.db.query_log
                if "SELECT id,flow_id,name,size_bytes,sha256" in sql
            ]
        )
        == 1
    )


def test_api_manifest_and_bundle_are_read_only_inert_and_not_inline(harness):
    harness.db.rows = [
        resource("source.py", b"print('text only')\n"),
        resource("notes.txt", b"# offline workflow input\n", n=2),
        resource("data.json", b'{"read_only": true}\n', n=3),
    ]
    manifest_reply = harness.client.get(
        f"/flows/{FID}/artifacts/resource-manifest",
        params=PARAMS,
        headers=HEADERS,
    )
    assert manifest_reply.status_code == 200
    manifest = manifest_reply.json()
    assert manifest["count"] == 3
    assert manifest_reply.headers["cache-control"] == "private, no-store"
    assert manifest_reply.headers["x-content-type-options"] == "nosniff"
    assert manifest_reply.headers["x-resource-manifest-sha256"] == manifest["manifest_sha256"]
    bundle_reply = harness.client.get(
        f"/flows/{FID}/artifacts/resource-bundle",
        params=PARAMS,
        headers=HEADERS,
    )
    assert bundle_reply.status_code == 200
    assert bundle_reply.headers["content-type"] == "application/zip"
    assert bundle_reply.headers["cache-control"] == "private, no-store"
    assert bundle_reply.headers["x-content-type-options"] == "nosniff"
    assert "attachment;" in bundle_reply.headers["content-disposition"]
    assert bundle_reply.headers["x-resource-manifest-sha256"] == manifest["manifest_sha256"]
    assert (
        bundle_reply.headers["x-resource-archive-sha256"]
        == hashlib.sha256(bundle_reply.content).hexdigest()
    )
    with zipfile.ZipFile(io.BytesIO(bundle_reply.content)) as archive:
        assert archive.namelist() == [
            "resources/data.json",
            "resources/notes.txt",
            "resources/source.py",
            "resource-manifest.json",
        ]
        for part in archive.infolist():
            assert part.compress_type == zipfile.ZIP_STORED
            assert part.file_size <= MAX_EXPORT_TOTAL_BYTES
            assert ".." not in part.filename
            assert part.filename == "resource-manifest.json" or part.filename.startswith(
                "resources/"
            )
            assert part.external_attr >> 16 & 0o777 == 0o400 or (
                part.filename == "resource-manifest.json"
            )
        assert archive.read("resources/source.py") == b"print('text only')\n"
        assert archive.read("resources/notes.txt") == b"# offline workflow input\n"
        assert archive.read("resource-manifest.json") == _canonical(manifest)
    assert len(harness.db.rows) == 3  # No SQL writes or local filesystem stage.
    assert not any("INSERT" in sql or "UPDATE" in sql for sql, _ in harness.db.query_log)


@pytest.mark.parametrize(
    "name, blob",
    [
        ("../outside.txt", b"plain text"),
        ("outside\\file.txt", b"plain text"),
        ("sneaky/evil.py", b"print('hello')"),
        ("CON.txt", b"plain text"),
        ("notes.html", b"<html>not safe</html>"),
        ("index.htm", b"plain text"),
        ("file.svg", b"<svg/>"),
        ("file.exe", b"MZdata"),
        ("archive.zip", b"PK\x03\x04rest"),
        ("archive.tar", b"not an archive"),
        ("shell.sh", b"echo harmless"),
        ("run.ps1", b"Write-Host foo"),
        ("frame.md", b"<iframe src='https://untrusted.example'></iframe>"),
        ("frame.txt", b"<p onclick='evil()'>hello</p>"),
        ("frame.md", b"<img onerror='evil()' src=x>"),
        ("document.txt", b"<!DOCTYPE html><html>payload</html>"),
        ("document.txt", b"\xef\xbb\xbf<script>alert(1)</script>"),
        ("document.txt", b"<!-- hidden content -->"),
        ("script.py", b"#!/usr/bin/env python3\nprint('x')"),
        ("file.txt", b"\x00inject"),
        ("file.txt", b"\xff\xfebinary"),
        ("file.txt", "fake\u202eexe.txt".encode("utf-8")),
        ("file.txt", b"\x1b[31mcontrol"),
        ("file.py", b"\x7fELF\x00stuff"),
    ],
)
def test_untrusted_executable_markup_archive_binary_or_traversal_rejected(
    harness,
    name,
    blob,
):
    harness.db.rows = [resource(name, blob)]
    for path in ("resource-manifest", "resource-bundle"):
        result = harness.client.get(
            f"/flows/{FID}/artifacts/{path}",
            params=PARAMS,
            headers=HEADERS,
        )
        assert result.status_code in {415, 422}
        assert not result.content.startswith(b"PK")


@pytest.mark.parametrize(
    "poison",
    [
        {"sha256": "0" * 64},
        {"sha256": "BAD"},
        {"size_bytes": 100},
        {"content": "string-not-bytea"},
        {"flow_id": "flow-foreign"},
        {"flow_revision": 6},
        {"authorization_version": 4},
        {"authorization_sha256": "c" * 64},
        {"name": "../secret"},
    ],
)
def test_poisoned_db_row_or_signature_fails_before_any_manifest(harness, poison):
    harness.db.rows = [resource(**poison)]
    response = harness.client.get(
        f"/flows/{FID}/artifacts/resource-manifest",
        params=PARAMS,
        headers=HEADERS,
    )
    assert response.status_code in {409, 422, 503}
    assert "items" not in response.json()


def test_duplicate_name_and_duplicate_snapshot_no_partial_return(harness):
    harness.db.rows = [
        resource("notes.txt", b"first"),
        resource(
            "notes.txt",
            b"second",
            n=2,
        ),
    ]
    response = harness.client.get(
        f"/flows/{FID}/artifacts/resource-bundle",
        params=PARAMS,
        headers=HEADERS,
    )
    assert response.status_code == 503
    assert "items" not in response.json()


def test_max_count_and_max_total_size_maintained_before_response(harness):
    harness.db.rows = [
        resource(f"item-{i}.txt", b"x", n=i + 1) for i in range(MAX_EXPORT_FILES + 1)
    ]
    response = harness.client.get(
        f"/flows/{FID}/artifacts/resource-manifest",
        params=PARAMS,
        headers=HEADERS,
    )
    assert response.status_code == 413
    harness.db.rows = [
        resource(f"item-{i}.txt", b"x" * (2 * 1024 * 1024), n=i + 1) for i in range(3)
    ]
    response = harness.client.get(
        f"/flows/{FID}/artifacts/resource-bundle",
        params=PARAMS,
        headers=HEADERS,
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    "alter",
    [
        {"owner": "someone-else", "status": 403},
        {"revision": 8, "status": 409},
        {"version": 6, "status": 403},
    ],
)
def test_current_signed_roe_revision_and_durable_owner(harness, alter):
    if "owner" in alter:
        harness.db.owner = alter["owner"]
    if "revision" in alter:
        harness.db.flow_revision = alter["revision"]
    if "version" in alter:
        harness.signed.side_effect = flow_artifacts.AuthorizationDenied("revoked policy")
    for path in ("resource-manifest", "resource-bundle"):
        result = harness.client.get(
            f"/flows/{FID}/artifacts/{path}",
            params=PARAMS,
            headers=HEADERS,
        )
        assert result.status_code == alter["status"]
        assert result.headers.get("content-type") != "application/zip"


def test_api_role_and_bearer_scope_not_weakened(harness, monkeypatch):
    path = f"/flows/{FID}/artifacts/resource-manifest"
    assert harness.client.get(path, params=PARAMS).status_code == 401

    async def viewer(*args, **kwargs):
        return {"sub": OWNER, "role": "viewer", "claims": {"exp": 2_000_000_000}}

    monkeypatch.setattr(artifact_api, "verify_token", viewer)
    assert harness.client.get(path, params=PARAMS, headers=HEADERS).status_code == 403
    assert not harness.db.read_attempted


def test_invalid_query_fences_do_not_touch_database(harness):
    response = harness.client.get(
        f"/flows/{FID}/artifacts/resource-manifest",
        params={"expected_revision": -1, "expected_authorization_version": 0},
        headers=HEADERS,
    )
    assert response.status_code == 422
    assert not harness.db.read_attempted


def test_zero_resources_has_signed_empty_manifest_and_inert_archive(harness):
    harness.db.rows = []
    response = harness.client.get(
        f"/flows/{FID}/artifacts/resource-manifest",
        params=PARAMS,
        headers=HEADERS,
    )
    assert response.status_code == 200
    assert response.json()["count"] == 0
    bundle = harness.client.get(
        f"/flows/{FID}/artifacts/resource-bundle",
        params=PARAMS,
        headers=HEADERS,
    )
    assert bundle.status_code == 200
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as archive:
        assert archive.namelist() == ["resource-manifest.json"]


def test_independent_zip_readback_rejects_midbundle_tampering(harness):
    harness.db.rows = [resource("notes.txt", b"trusted")]
    manifest, snapshot = asyncio.run(FlowResourceExports(harness.store).prepare(FID, OWNER, 7, 5))
    snapshot[0] = (snapshot[0][0], b"malicious")
    with pytest.raises(ArtifactDenied, match="SHA readback"):
        make_bundle(snapshot, manifest)


@pytest.mark.parametrize(
    "tamper",
    [
        {"manifest_sha256": "0" * 64},
        {
            "items": [
                {
                    "name": "../wrong.txt",
                    "resource_path": "resources/../wrong.txt",
                    "size_bytes": 7,
                    "sha256": "f" * 64,
                }
            ]
        },
    ],
)
def test_bundle_rejects_manifest_integrity_or_path_tampering(harness, tamper):
    harness.db.rows = [resource("notes.txt", b"trusted")]
    manifest, snapshot = asyncio.run(FlowResourceExports(harness.store).prepare(FID, OWNER, 7, 5))
    altered = {**manifest, **tamper}
    if "items" in tamper:
        altered["manifest_sha256"] = hashlib.sha256(
            _canonical({key: value for key, value in altered.items() if key != "manifest_sha256"})
        ).hexdigest()
    with pytest.raises(ArtifactDenied):
        make_bundle(snapshot, altered)


def test_failed_packaging_leaves_no_tempfiles_or_workdir(harness, tmp_path, monkeypatch):
    harness.db.rows = [resource("safe.txt", b"only offline data")]
    monkeypatch.chdir(tmp_path)
    before = list(tmp_path.iterdir())

    def crash(*args, **kwargs):
        raise OSError("simulated interrupted exporter")

    monkeypatch.setattr(zipfile.ZipFile, "writestr", crash)
    response = harness.client.get(
        f"/flows/{FID}/artifacts/resource-bundle",
        params=PARAMS,
        headers=HEADERS,
    )
    assert response.status_code == 503
    assert list(tmp_path.iterdir()) == before == []


@pytest.mark.asyncio
async def test_fence_stale_or_corrupt_snapshot_never_turns_into_fallback_download(harness):
    def mutate_during_read():
        harness.db.rows[0]["sha256"] = "f" * 64

    harness.db.on_read = mutate_during_read
    with pytest.raises(ArtifactDenied, match="integrity"):
        await FlowResourceExports(harness.store).prepare(FID, OWNER, 7, 5)
    # No retry against a weaker unsigned source is present.
    assert sum("SELECT id,flow_id,name,size_bytes" in sql for sql, _ in harness.db.query_log) == 1
