"""Flow artifacts: real disposable PostgreSQL, signed ROE, JWT, CAS and events.

Opt in only with OSOP_FLOW_ARTIFACT_TEST_PG_URI pointing to an isolated local
database named flow_artifacts_qualification_* on a nonstandard port. Without
an explicit disposable DB, unit validation runs and integration tests skip.
"""

import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from jose import jwt
from sqlalchemy import select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import router
from ai_osop.core.config import settings
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.flow_artifacts import ArtifactDenied, MAX_BYTES, _identity, safe_filename
from ai_osop.memory.session_memory import ExecutionFlowORM, SessionMemory
from tests.test_authorization_store import make_signed_session


@pytest.mark.parametrize("name", [
    "../secret", "x/y", "x\\y", ".hidden", "file.", "CON.txt",
    "LPT1", "note\nheader", " space", "évidence.txt", "a" * 129,
])
def test_invalid_filename_rejected_without_disk_access(name):
    with pytest.raises(ArtifactDenied) as exc:
        safe_filename(name)
    assert exc.value.status == 422


@pytest.mark.parametrize("name", ["report.txt", "evidence-1.json", "a_b.txt"])
def test_valid_filename_is_not_rewritten(name):
    assert safe_filename(name) == name


def test_signed_owner_email_subject_does_not_require_filesystem_safe_chars():
    # JWT subjects may be email addresses or opaque identifiers; they are
    # bound as database parameters, never interpreted as filenames/paths.
    _identity("flow-safe", "operator@example.test", 7, 1)


def _db_uri():
    import os
    raw = os.environ.get("OSOP_FLOW_ARTIFACT_TEST_PG_URI")
    if not raw:
        pytest.skip("Disposable Flow artifact PostgreSQL not configured")
    parsed = make_url(raw)
    if (
        parsed.drivername != "postgresql+asyncpg"
        or parsed.host not in {"localhost", "127.0.0.1"}
        or parsed.port in {None, 5432, 5433}
        or not (parsed.database or "").startswith("flow_artifacts_qualification_")
    ):
        pytest.fail("Refusing application or non-disposable PostgreSQL")
    return raw


def _upgrade(connection):
    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, "head")


@pytest.fixture
async def api(monkeypatch):
    engine = create_async_engine(_db_uri(), pool_size=5)
    try:
        async with engine.begin() as db:
            await db.run_sync(_upgrade)
        memory = SessionMemory.__new__(SessionMemory)
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        suffix = uuid.uuid4().hex[:12]
        eid, fid = "eng-artifacts-" + suffix, "flow-artifacts-" + suffix
        owner = "artifact-owner-" + suffix
        session, verified, _, _ = make_signed_session(
            monkeypatch, session_id=eid, owner=owner,
            authorization_id="auth-artifact-" + suffix,
        )
        await AuthorizationStore(memory).create_authorized_session(session, verified, owner)
        now = datetime.utcnow()
        async with memory._async_session() as db:
            async with db.begin():
                db.add(ExecutionFlowORM(
                    id=fid, engagement_id=eid, status="running", revision=7,
                    objective="Synthetic safe file handoff", created_at=now,
                    updated_at=now,
                ))
        monkeypatch.setattr(settings, "environment", "production")
        monkeypatch.setattr(settings, "jwt_secret", "flow-artifact-qualification-secret")
        monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
        monkeypatch.setattr(settings, "jwt_audience", None)
        monkeypatch.setattr(settings, "jwt_issuer", None)
        monkeypatch.setitem(state, "orchestrator", type("Orch", (), {"session_memory": memory})())
        app = FastAPI()
        app.include_router(router)

        def header(sub=owner, role="operator"):
            token = jwt.encode({
                "sub": sub, "role": role,
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            }, settings.jwt_secret, algorithm="HS256")
            return {"Authorization": "Bearer " + token}

        async def request(method, path=None, *, body=None, sub=owner, role="operator",
                          revision=7, version=1, name="artifact.txt", headers=None):
            url = path or f"/flows/{fid}/artifacts"
            params = {"expected_revision": revision, "expected_authorization_version": version}
            if method == "POST":
                params["name"] = name
            request_headers = {**header(sub, role), **(headers or {})}
            if method == "POST" and "Content-Type" not in request_headers:
                request_headers["Content-Type"] = "application/octet-stream"
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://qualification",
            ) as client:
                return await client.request(
                    method, url, params=params, content=body, headers=request_headers,
                )

        yield SimpleNamespace(memory=memory, engine=engine, app=app, flow=fid,
                              engagement=eid, owner=owner, request=request)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_real_upload_list_read_event_and_outbox_atomic(api):
    body = b"\x00test-binary<do-not-render>\xff"
    added = await api.request("POST", body=body)
    assert added.status_code == 201, added.text
    meta = added.json()
    assert meta["sha256"] == hashlib.sha256(body).hexdigest()
    assert meta["size_bytes"] == len(body)
    assert meta["flow_revision"] == 7
    assert meta["authorization_version"] == 1
    assert "content" not in meta and "engagement_id" not in meta
    listed = await api.request("GET")
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1
    assert listed.json()["items"] == [meta]
    assert listed.headers["cache-control"] == "private, no-store"
    fetched = await api.request("GET", f"/flows/{api.flow}/artifacts/{meta['id']}")
    assert fetched.status_code == 200, fetched.text
    assert fetched.content == body
    assert fetched.headers["content-type"] == "application/octet-stream"
    assert fetched.headers["content-disposition"] == 'attachment; filename="artifact.txt"'
    assert fetched.headers["x-content-type-options"] == "nosniff"
    assert fetched.headers["cache-control"] == "private, no-store"
    async with api.memory._async_session() as db:
        events = (await db.execute(text(
            "SELECT id, payload FROM supervision_events WHERE engagement_id=:sid "
            "AND kind='flow.artifact_uploaded'"
        ), {"sid": api.engagement})).mappings().all()
        outbox = (await db.execute(text(
            "SELECT event_id,payload FROM supervision_outbox "
            "WHERE engagement_id=:sid AND topic='flow.artifact_uploaded'"
        ), {"sid": api.engagement})).mappings().all()
    assert len(events) == len(outbox) == 1
    assert events[0]["id"] == outbox[0]["event_id"]
    assert events[0]["payload"]["sha256"] == meta["sha256"]
    assert body not in str(events + outbox).encode()


@pytest.mark.asyncio
async def test_authenticated_owner_only_and_missing_identity(api):
    created = await api.request("POST", body=b"hi")
    assert created.status_code == 201
    aid = created.json()["id"]
    for method, url, kwargs in (
        ("GET", None, {"sub": "different-tenant"}),
        ("POST", None, {"sub": "different-tenant", "body": b"bad", "name": "other.txt"}),
        ("GET", f"/flows/{api.flow}/artifacts/{aid}", {"sub": "different-tenant"}),
        ("GET", None, {"sub": "different-senior", "role": "senior_operator"}),
    ):
        assert (await api.request(method, url, **kwargs)).status_code == 403
    direct = await api.request("GET", headers={"Authorization": "Bearer fake-shared"})
    assert direct.status_code == 401


@pytest.mark.asyncio
async def test_explicit_revision_and_roe_version_fences_and_closed_flow(api):
    assert (await api.request("POST", body=b"safe", revision=8)).status_code == 409
    assert (await api.request("GET", revision=8)).status_code == 409
    assert (await api.request("GET", version=2)).status_code == 403
    assert (await api.request("POST", body=b"safe", version=2)).status_code == 403
    created = await api.request("POST", body=b"safe")
    assert created.status_code == 201
    async with api.memory._async_session() as db:
        async with db.begin():
            await db.execute(update(ExecutionFlowORM).where(
                ExecutionFlowORM.id == api.flow,
            ).values(revision=8, status="paused"))
    assert (await api.request("GET", revision=7)).status_code == 409
    assert (await api.request("POST", body=b"no", revision=8, name="paused.txt")).status_code == 409
    assert (await api.request("GET", revision=8)).status_code == 409


@pytest.mark.asyncio
async def test_duplicate_and_oversized_requests_leave_no_metadata_or_event(api):
    first = await api.request("POST", body=b"legit")
    assert first.status_code == 201
    conflict = await api.request("POST", body=b"overwrite")
    assert conflict.status_code == 409
    oversize = await api.request("POST", body=b"x" * (MAX_BYTES + 1), name="oversize.txt")
    assert oversize.status_code == 413
    empty = await api.request("POST", body=b"", name="empty.txt")
    assert empty.status_code == 413
    assert (await api.request("GET")).json()["total"] == 1
    async with api.memory._async_session() as db:
        count = (await db.execute(text(
            "SELECT count(*) FROM supervision_events WHERE engagement_id=:sid "
            "AND kind='flow.artifact_uploaded'"
        ), {"sid": api.engagement})).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_chunked_stream_without_content_length_enforces_limit(api):
    async def over_limit_chunks():
        yield b"x" * (MAX_BYTES - 1)
        yield b"yz"

    result = await api.request("POST", body=over_limit_chunks(), name="chunked.dat")
    assert result.status_code == 413
    assert (await api.request("GET")).json()["total"] == 0


@pytest.mark.asyncio
async def test_atomic_upload_rolls_back_content_if_event_insert_fails(api):
    # Disposable DB fixture only; fail the audit append deliberately after
    # PostgreSQL has received the artifact INSERT in the same transaction.
    async with api.memory._async_session() as db:
        async with db.begin():
            await db.execute(text("""
                CREATE FUNCTION reject_artifact_qualification_event() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.kind='flow.artifact_uploaded' THEN
                        RAISE EXCEPTION 'qualification audit append denied';
                    END IF;
                    RETURN NEW;
                END; $$
            """))
            await db.execute(text("""
                CREATE TRIGGER trg_reject_artifact_qualification_event
                BEFORE INSERT ON supervision_events FOR EACH ROW
                EXECUTE FUNCTION reject_artifact_qualification_event()
            """))
    try:
        failure = await api.request("POST", body=b"not-committed", name="rollback.dat")
        assert failure.status_code == 503
        async with api.memory._async_session() as db:
            count = (await db.execute(text(
                "SELECT COUNT(*) FROM flow_artifacts WHERE flow_id=:fid"
            ), {"fid": api.flow})).scalar_one()
        assert count == 0
    finally:
        async with api.memory._async_session() as db:
            async with db.begin():
                await db.execute(text(
                    "DROP TRIGGER trg_reject_artifact_qualification_event ON supervision_events"
                ))
                await db.execute(text("DROP FUNCTION reject_artifact_qualification_event()"))


@pytest.mark.asyncio
async def test_concurrent_same_name_has_one_winner(api):
    outcomes = await asyncio.gather(
        api.request("POST", body=b"first"),
        api.request("POST", body=b"second"),
    )
    assert sorted(r.status_code for r in outcomes) == [201, 409]
    assert (await api.request("GET")).json()["total"] == 1


@pytest.mark.asyncio
async def test_immutable_database_row_rejects_content_and_digest_mutation(api):
    created = await api.request("POST", body=b"trusted")
    artifact_id = created.json()["id"]
    with pytest.raises(DBAPIError, match="immutable"):
        async with api.memory._async_session() as db:
            async with db.begin():
                await db.execute(text(
                    "UPDATE flow_artifacts SET content=:altered, sha256=:digest WHERE id=:id"
                ), {"id": artifact_id, "altered": b"changed", "digest": "0" * 64})
    result = await api.request("GET", f"/flows/{api.flow}/artifacts/{artifact_id}")
    assert result.status_code == 200
    assert result.content == b"trusted"


@pytest.mark.asyncio
async def test_fail_closed_on_revoked_signed_roe(api):
    created = await api.request("POST", body=b"trusted")
    assert created.status_code == 201
    assert await AuthorizationStore(api.memory).revoke(
        api.engagement, api.owner, 1, "Artifact qualification test revoked policy",
    )
    assert (await api.request("GET")).status_code == 403
    assert (await api.request("POST", body=b"nope", name="later.txt")).status_code == 403
    assert (await api.request("GET", f"/flows/{api.flow}/artifacts/{created.json()['id']}")).status_code == 403
