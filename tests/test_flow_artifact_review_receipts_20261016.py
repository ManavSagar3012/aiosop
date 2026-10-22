"""Deterministic transaction/HTTP regression tests without an application DB."""

import asyncio
import copy
import hashlib
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import httpx
import pytest
from fastapi import FastAPI
from jose import jwt

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import router as owner_artifact_router
from ai_osop.api.routers.flow_artifact_reviews import router
from ai_osop.core.config import settings
from ai_osop.memory.flow_artifact_reviews import (
    ArtifactReviewDenied,
    FlowArtifactReviewStore,
)

SHA = hashlib.sha256(b"Reviewed inert notes").hexdigest()
AUTH_SHA = "a" * 64
ARTIFACT_ID = "artifact-" + "b" * 32
FLOW_ID = "flow-review"
SID = "eng-review"
OWNER = "uploader@example.test"
REVIEWER = "senior@example.test"
AUTH_ID = "auth-review"


class Rows:
    def __init__(self, value: Any):
        self.value = value

    def mappings(self) -> "Rows":
        return self

    def one_or_none(self) -> Any:
        return self.value

    def one(self) -> Any:
        assert self.value is not None
        return self.value

    def scalar_one_or_none(self) -> Any:
        return self.value

    def all(self) -> Any:
        return self.value


class FakeDatabase:
    """One deterministic serialized transaction; rolls back on outbox failure."""

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.owner = OWNER
        self.phase = "reconnaissance"
        self.revision = 7
        self.flow_status = "running"
        self.sha = SHA
        self.auth_sha = AUTH_SHA
        self.auth_id = AUTH_ID
        self.version = 3
        self.blob = b"Reviewed inert notes"
        self.artifact_owner = OWNER
        self.review: Optional[Dict[str, Any]] = None
        self.events = []
        self.outbox = []
        self.fail_outbox = False
        self.simulate_last_page = False
        self.queries = []
        self.transaction_count = 0

    def __call__(self) -> "Transaction":
        return Transaction(self)


class Transaction:
    def __init__(self, original: FakeDatabase):
        self.original = original
        self.state: Dict[str, Any] = {}

    async def __aenter__(self) -> "Transaction":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def begin(self) -> "Atomic":
        return Atomic(self)

    async def execute(self, statement: Any, args: Optional[Dict[str, Any]] = None) -> Rows:
        sql = str(statement)
        args = args or {}
        self.original.queries.append((sql, args))
        db = self.original
        if "SELECT engagement_id FROM execution_flows" in sql:
            return Rows({"engagement_id": SID} if args["fid"] == FLOW_ID else None)
        if "SELECT created_by,phase FROM session_states" in sql:
            return Rows({"created_by": db.owner, "phase": db.phase} if args["sid"] == SID else None)
        if "SELECT id,engagement_id,revision,status FROM execution_flows" in sql:
            return Rows(
                {
                    "id": FLOW_ID,
                    "engagement_id": SID,
                    "revision": db.revision,
                    "status": db.flow_status,
                }
            )
        if "LEFT JOIN flow_artifact_reviews AS r" in sql:
            if args["sid"] != SID or args["fid"] != FLOW_ID or args["owner"] != db.owner:
                return Rows([])
            if args["offset"] > 0 and not (db.simulate_last_page and args["offset"] == 64):
                return Rows([])
            return Rows(
                [
                    {
                        "id": ARTIFACT_ID,
                        "flow_id": FLOW_ID,
                        "engagement_id": SID,
                        "owner_id": db.artifact_owner,
                        "name": "notes.txt",
                        "sha256": db.sha,
                        "size_bytes": len(db.blob),
                        "flow_revision": 7,
                        "authorization_version": 3,
                        "authorization_sha256": db.auth_sha,
                        "content": db.blob,
                        "review_decision": (
                            self.state["review"]["decision"] if self.state["review"] else None
                        ),
                        **(
                            {
                                f"review_{field}": self.state["review"][field]
                                for field in (
                                    "uploader_sub",
                                    "reviewer_sub",
                                    "reviewer_role",
                                    "artifact_sha256",
                                    "flow_revision",
                                    "authorization_id",
                                    "authorization_version",
                                    "authorization_sha256",
                                    "flow_id",
                                    "engagement_id",
                                )
                            }
                            if self.state["review"]
                            else {}
                        ),
                    }
                ]
            )
        if "FROM flow_artifacts WHERE" in sql:
            return Rows(
                {
                    "id": ARTIFACT_ID,
                    "flow_id": FLOW_ID,
                    "engagement_id": SID,
                    "owner_id": db.artifact_owner,
                    "name": "notes.txt",
                    "sha256": db.sha,
                    "size_bytes": len(db.blob),
                    "flow_revision": 7,
                    "authorization_version": 3,
                    "authorization_sha256": db.auth_sha,
                    "content": db.blob,
                }
                if args["id"] == ARTIFACT_ID
                else None
            )
        if "SELECT id FROM flow_artifact_reviews" in sql:
            return Rows(self.state["review"]["id"] if self.state["review"] else None)
        if "SELECT id,artifact_id,flow_id,engagement_id" in sql:
            return Rows(self.state["review"])
        if "INSERT INTO flow_artifact_reviews" in sql:
            assert self.state["review"] is None
            self.state["review"] = {
                "id": args["id"],
                "artifact_id": args["artifact"],
                "flow_id": args["fid"],
                "engagement_id": args["sid"],
                "uploader_sub": args["uploader"],
                "reviewer_sub": args["reviewer"],
                "reviewer_role": "senior_operator",
                "decision": args["decision"],
                "artifact_sha256": args["sha"],
                "flow_revision": args["revision"],
                "authorization_id": args["auth_id"],
                "authorization_version": args["version"],
                "authorization_sha256": args["auth_sha"],
                "created_at": datetime.now(timezone.utc),
            }
            return Rows(self.state["review"])
        if "INSERT INTO supervision_events" in sql:
            self.state["events"].append(args)
            return Rows(None)
        if "INSERT INTO supervision_outbox" in sql:
            if db.fail_outbox:
                raise RuntimeError("outbox insert failed")
            self.state["outbox"].append(args)
            return Rows(None)
        raise AssertionError(f"Unexpected query {sql[:80]}")


class Atomic:
    def __init__(self, tx: Transaction):
        self.tx = tx

    async def __aenter__(self) -> Transaction:
        await self.tx.original.lock.acquire()
        db = self.tx.original
        self.tx.state = {
            "review": copy.deepcopy(db.review),
            "events": copy.deepcopy(db.events),
            "outbox": copy.deepcopy(db.outbox),
        }
        return self.tx

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        db = self.tx.original
        if exc_type is None:
            db.review = self.tx.state["review"]
            db.events = self.tx.state["events"]
            db.outbox = self.tx.state["outbox"]
            db.transaction_count += 1
        db.lock.release()


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> Any:
    from ai_osop.memory import flow_artifact_reviews as module

    db = FakeDatabase()

    async def fake_guard(session: Any, sid: str, expected_version: int) -> Any:
        assert sid == SID
        if expected_version != db.version:
            raise module.AuthorizationDenied("revoked")
        return SimpleNamespace(
            version=db.version,
            authorization_id=db.auth_id,
            policy_sha256=db.auth_sha,
            policy={"created_by": db.owner},
        )

    monkeypatch.setattr(module, "guard_sql", fake_guard)
    store = FlowArtifactReviewStore(SimpleNamespace(_async_session=db))
    kwargs = {
        "flow_id": FLOW_ID,
        "artifact_id": ARTIFACT_ID,
        "revision": 7,
        "version": 3,
        "sha256": SHA,
        "authorization_id": AUTH_ID,
        "authorization_sha256": AUTH_SHA,
    }
    return SimpleNamespace(db=db, store=store, kwargs=kwargs, guard=fake_guard)


async def decide(harness: Any, **changes: Any) -> Dict[str, Any]:
    return await harness.store.decide(
        **{
            **harness.kwargs,
            "reviewer_sub": REVIEWER,
            "reviewer_role": "senior_operator",
            "decision": "approve",
            "reason": "Reviewed exact bytes and scoped tenant source",
            **changes,
        }
    )


@pytest.mark.asyncio
async def test_exact_byte_review_and_atomic_event_outbox(harness: Any) -> None:
    assert (await harness.store.read_verified(**harness.kwargs))["decision"] == "UNKNOWN"
    receipt = await decide(harness)
    assert receipt["approved"] is True
    assert receipt["verified_review"] is True
    assert receipt["reviewer_role"] == "senior_operator"
    assert receipt["uploader_sub"] != receipt["reviewer_sub"]
    assert receipt["artifact_sha256"] == SHA
    assert receipt["authorization_sha256"] == AUTH_SHA
    assert len(harness.db.events) == len(harness.db.outbox) == 1
    event = harness.db.events[0]
    outbox = harness.db.outbox[0]
    assert event["event"] == outbox["event"]
    assert event["sid"] == SID
    assert event["actor"] == REVIEWER
    assert event["dedupe"] == "review:" + ARTIFACT_ID
    assert "Reviewed inert notes" not in str(event)
    assert "Reviewed exact bytes" not in str(event)
    assert (await harness.store.read_verified(**harness.kwargs))["approved"] is True
    assert (await harness.store.read_verified_approval(**harness.kwargs)) == receipt
    approved_text = await harness.store.read_approved_inert_text(**harness.kwargs)
    assert approved_text["untrusted_reviewed_text"] == "Reviewed inert notes"
    assert approved_text["text_trust_boundary"] == "inert_reviewed_data_only"
    assert approved_text["security_evidence_verified"] is False
    assert any("FOR UPDATE" in sql for sql, _ in harness.db.queries)
    assert any("FOR SHARE" in sql for sql, _ in harness.db.queries)


@pytest.mark.asyncio
async def test_reject_receipt_is_immutable_not_approved(harness: Any) -> None:
    rejected = await decide(harness, decision="reject")
    assert rejected["decision"] == "reject"
    assert rejected["approved"] is False
    assert await harness.store.read_verified_approval(**harness.kwargs) is None
    assert await harness.store.read_approved_inert_text(**harness.kwargs) is None
    with pytest.raises(ArtifactReviewDenied) as err:
        await decide(harness, decision="approve")
    assert err.value.status == 409
    assert len(harness.db.events) == 1


@pytest.mark.asyncio
async def test_concurrent_decisions_choose_exactly_one_transaction(harness: Any) -> None:
    approvals = await asyncio.gather(
        decide(harness), decide(harness, decision="reject"), return_exceptions=True
    )
    assert len([x for x in approvals if isinstance(x, dict)]) == 1
    assert len([x for x in approvals if isinstance(x, ArtifactReviewDenied)]) == 1
    assert len(harness.db.events) == len(harness.db.outbox) == 1


@pytest.mark.asyncio
async def test_outbox_failure_rolls_back_receipt_and_supervision_event(harness: Any) -> None:
    harness.db.fail_outbox = True
    with pytest.raises(ArtifactReviewDenied) as err:
        await decide(harness)
    assert err.value.status == 503
    assert harness.db.review is None
    assert harness.db.events == []
    assert harness.db.outbox == []
    harness.db.fail_outbox = False
    assert (await decide(harness))["approved"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"sha256": "0" * 64},
        {"revision": 8},
        {"version": 4},
        {"authorization_id": "auth-other"},
        {"authorization_sha256": "c" * 64},
        {"reviewer_sub": OWNER},
        {"reviewer_role": "operator"},
        {"reviewer_role": "senior_operator", "reason": ""},
        {"decision": "maybe"},
        {"artifact_id": "artifact-" + "0" * 32},
    ],
)
async def test_bad_fence_or_reviewer_never_creates_receipt(
    harness: Any, change: Dict[str, Any]
) -> None:
    with pytest.raises(ArtifactReviewDenied):
        await decide(harness, **change)
    assert harness.db.review is None
    assert harness.db.events == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        lambda db: setattr(db, "blob", b"corrupted"),
        lambda db: setattr(db, "sha", "0" * 64),
        lambda db: setattr(db, "owner", "other-tenant"),
        lambda db: setattr(db, "artifact_owner", "other-tenant"),
        lambda db: setattr(db, "flow_status", "paused"),
        lambda db: setattr(db, "phase", "halted"),
        lambda db: setattr(db, "auth_id", "auth-rotated"),
        lambda db: setattr(db, "auth_sha", "f" * 64),
        lambda db: setattr(db, "revision", 8),
        lambda db: setattr(db, "version", 4),
    ],
)
async def test_stale_owner_roe_flow_or_bytes_fail_closed(harness: Any, mutation: Any) -> None:
    mutation(harness.db)
    with pytest.raises(ArtifactReviewDenied):
        await decide(harness)
    assert harness.db.review is None


@pytest.mark.asyncio
async def test_read_revalidates_current_authority_and_bytes(harness: Any) -> None:
    await decide(harness)
    harness.db.blob = b"changed by corrupt storage"
    with pytest.raises(ArtifactReviewDenied):
        await harness.store.read_verified_approval(**harness.kwargs)
    harness.db.blob = b"Reviewed inert notes"
    harness.db.revision = 8
    with pytest.raises(ArtifactReviewDenied):
        await harness.store.read_verified_approval(**harness.kwargs)


@pytest.mark.asyncio
async def test_review_does_not_expose_binary_or_large_text_to_agent(harness: Any) -> None:
    harness.db.blob = b"\x00\x01"
    harness.db.sha = hashlib.sha256(harness.db.blob).hexdigest()
    harness.kwargs["sha256"] = harness.db.sha
    await decide(harness)
    assert await harness.store.read_approved_inert_text(**harness.kwargs) is None
    assert (await harness.store.read_verified_approval(**harness.kwargs))["approved"] is True


@pytest.mark.asyncio
async def test_approved_text_byte_budget_remains_fail_closed(harness: Any) -> None:
    harness.db.blob = b"a" * 4097
    harness.db.sha = hashlib.sha256(harness.db.blob).hexdigest()
    harness.kwargs["sha256"] = harness.db.sha
    await decide(harness)
    assert await harness.store.read_approved_inert_text(**harness.kwargs) is None
    assert (await harness.store.read_verified_approval(**harness.kwargs))["approved"] is True


@pytest.mark.asyncio
async def test_forged_receipt_reviewer_role_rejected_on_read(harness: Any) -> None:
    await decide(harness)
    harness.db.review["reviewer_role"] = "operator"
    with pytest.raises(ArtifactReviewDenied):
        await harness.store.read_verified_approval(**harness.kwargs)


@pytest.mark.asyncio
async def test_signed_roe_colon_at_and_128_char_id_preserved(harness: Any) -> None:
    auth_id = "auth:senior@example.test:" + "x" * 100
    assert len(auth_id) <= 128
    harness.db.auth_id = auth_id
    harness.kwargs["authorization_id"] = auth_id
    receipt = await decide(harness)
    assert receipt["authorization_id"] == auth_id
    assert (await harness.store.read_verified_approval(**harness.kwargs)) is not None


@pytest.mark.asyncio
async def test_independent_senior_inventory_and_verified_original_bytes(harness: Any) -> None:
    candidate_args = {
        "flow_id": FLOW_ID,
        "engagement_id": SID,
        "revision": 7,
        "version": 3,
        "authorization_id": AUTH_ID,
        "authorization_sha256": AUTH_SHA,
        "reviewer_sub": REVIEWER,
        "reviewer_role": "senior_operator",
    }
    inventory = await harness.store.list_review_candidates(**candidate_args)
    assert inventory["flow_id"] == FLOW_ID
    assert inventory["items"][0]["artifact_id"] == ARTIFACT_ID
    assert inventory["items"][0]["sha256"] == SHA
    assert inventory["items"][0]["verified_bytes"] is True
    assert inventory["items"][0]["approved"] is False
    assert inventory["items"][0]["review_decision"] == "UNKNOWN"
    info, content = await harness.store.read_review_source(
        **candidate_args, artifact_id=ARTIFACT_ID, sha256=SHA
    )
    assert content == b"Reviewed inert notes"
    assert info["sha256"] == hashlib.sha256(content).hexdigest()
    assert info["approved"] is False
    await decide(harness, decision="reject")
    inventory = await harness.store.list_review_candidates(**candidate_args)
    assert inventory["items"][0]["review_decision"] == "reject"
    assert inventory["items"][0]["approved"] is False


@pytest.mark.asyncio
async def test_review_inventory_never_offers_out_of_bounds_next_cursor(harness: Any) -> None:
    harness.db.simulate_last_page = True
    result = await harness.store.list_review_candidates(
        flow_id=FLOW_ID,
        engagement_id=SID,
        revision=7,
        version=3,
        authorization_id=AUTH_ID,
        authorization_sha256=AUTH_SHA,
        reviewer_sub=REVIEWER,
        reviewer_role="senior_operator",
        limit=1,
        offset=64,
    )
    assert len(result["items"]) == 1
    assert result["next_offset"] is None


@pytest.mark.asyncio
async def test_independent_source_denies_uploader_wrong_tenant_corruption_and_roe(
    harness: Any,
) -> None:
    args = {
        "flow_id": FLOW_ID,
        "engagement_id": SID,
        "revision": 7,
        "version": 3,
        "authorization_id": AUTH_ID,
        "authorization_sha256": AUTH_SHA,
        "reviewer_sub": REVIEWER,
        "reviewer_role": "senior_operator",
    }
    for changes in (
        {"reviewer_sub": OWNER},
        {"engagement_id": "eng-other"},
        {"reviewer_role": "operator"},
        {"authorization_sha256": "0" * 64},
        {"revision": 8},
    ):
        with pytest.raises(ArtifactReviewDenied):
            await harness.store.list_review_candidates(**{**args, **changes})
        with pytest.raises(ArtifactReviewDenied):
            await harness.store.read_review_source(
                **{**args, **changes}, artifact_id=ARTIFACT_ID, sha256=SHA
            )
    harness.db.blob = b"tampered"
    with pytest.raises(ArtifactReviewDenied):
        await harness.store.list_review_candidates(**args)
    with pytest.raises(ArtifactReviewDenied):
        await harness.store.read_review_source(**args, artifact_id=ARTIFACT_ID, sha256=SHA)


def test_migration_enforces_unique_once_only_receipt_and_immutable_trigger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "0015_flow_artifact_reviews.py"
    )
    spec = importlib.util.spec_from_file_location("review_schema_0015", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0015"
    assert module.down_revision == "0014"
    created = []
    executed = []
    indexed = []
    monkeypatch.setattr(module.op, "create_table", lambda *a, **kw: created.append(a))
    monkeypatch.setattr(module.op, "create_index", lambda *a, **kw: indexed.append(a))
    monkeypatch.setattr(module.op, "execute", lambda statement: executed.append(str(statement)))
    module.upgrade()
    assert len(created) == 1
    assert created[0][0] == "flow_artifact_reviews"
    constraint_names = {getattr(item, "name", None) for item in created[0][1:]}
    assert "uq_flow_artifact_single_review" in constraint_names
    assert "ck_flow_artifact_independent_reviewer" in constraint_names
    assert "ck_flow_artifact_senior_role" in constraint_names
    assert "ck_flow_artifact_review_hashes" in constraint_names
    assert len(indexed) == 1
    assert "BEFORE UPDATE OR DELETE" in "\n".join(executed)
    assert "RAISE EXCEPTION" in "\n".join(executed)


@pytest.mark.asyncio
async def test_api_signed_senior_bearer_and_independent_upload_identity(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "jwt_secret", "flow-review-qualification-secret")
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    monkeypatch.setitem(
        state,
        "orchestrator",
        SimpleNamespace(session_memory=SimpleNamespace(_async_session=harness.db)),
    )
    app = FastAPI()
    app.include_router(owner_artifact_router)  # production router order
    app.include_router(router)

    def header(sub: str, role: str, *, expired: bool = False) -> Dict[str, str]:
        seconds = -5 if expired else 300
        token = jwt.encode(
            {
                "sub": sub,
                "role": role,
                "exp": int((datetime.now(timezone.utc) + timedelta(seconds=seconds)).timestamp()),
            },
            settings.jwt_secret,
            algorithm="HS256",
        )
        return {"Authorization": "Bearer " + token}

    body = {
        "decision": "approve",
        "expected_sha256": SHA,
        "expected_revision": 7,
        "expected_authorization_version": 3,
        "expected_authorization_id": AUTH_ID,
        "expected_authorization_sha256": AUTH_SHA,
        "reason": "Reviewed source",
    }
    path = f"/flows/{FLOW_ID}/artifacts/{ARTIFACT_ID}/review"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://review.local"
    ) as client:
        for headers, expected_status in (
            ({}, 401),
            (header(REVIEWER, "operator"), 403),
            (header(REVIEWER, "senior_operator", expired=True), 401),
            (header(OWNER, "senior_operator"), 403),
        ):
            response = await client.post(path, headers=headers, json=body)
            assert response.status_code == expected_status, response.text
        assert harness.db.review is None
        approved = await client.post(path, headers=header(REVIEWER, "senior_operator"), json=body)
        assert approved.status_code == 201, approved.text
        assert approved.json()["approved"] is True
        assert approved.headers["cache-control"] == "private, no-store"
        params = {
            "expected_sha256": SHA,
            "expected_revision": 7,
            "expected_authorization_version": 3,
            "expected_authorization_id": AUTH_ID,
            "expected_authorization_sha256": AUTH_SHA,
        }
        inspect_params = {**params, "expected_engagement_id": SID}
        candidate_path = f"/flows/{FLOW_ID}/artifact-reviews/candidates"
        source_path = f"/flows/{FLOW_ID}/artifact-reviews/{ARTIFACT_ID}/content"
        for pathname in (candidate_path, source_path):
            missing = await client.get(pathname, params=inspect_params)
            assert missing.status_code == 401, missing.text
            uploader = await client.get(
                pathname, headers=header(OWNER, "senior_operator"), params=inspect_params
            )
            assert uploader.status_code == 403, uploader.text
            cross_tenant = await client.get(
                pathname,
                headers=header(REVIEWER, "senior_operator"),
                params={**inspect_params, "expected_engagement_id": "eng-another"},
            )
            assert cross_tenant.status_code == 403, cross_tenant.text
        candidate = await client.get(
            candidate_path, params=inspect_params, headers=header(REVIEWER, "senior_operator")
        )
        assert candidate.status_code == 200, candidate.text
        assert candidate.json()["items"][0]["sha256"] == SHA
        assert candidate.json()["items"][0]["verified_bytes"] is True
        assert candidate.headers["cache-control"] == "private, no-store"
        download = await client.get(
            source_path, params=inspect_params, headers=header(REVIEWER, "senior_operator")
        )
        assert download.status_code == 200, download.text
        assert download.content == b"Reviewed inert notes"
        assert download.headers["content-type"] == "application/octet-stream"
        assert download.headers["x-artifact-sha256"] == SHA
        assert download.headers["cache-control"] == "private, no-store"
        assert download.headers["x-content-type-options"] == "nosniff"
        assert download.headers["content-disposition"] == 'attachment; filename="review-source.bin"'
        read = await client.get(path, headers=header(REVIEWER, "senior_operator"), params=params)
        assert read.status_code == 200, read.text
        assert read.json()["review_id"] == approved.json()["review_id"]
        again = await client.post(path, headers=header(REVIEWER, "senior_operator"), json=body)
        assert again.status_code == 409
        assert len(harness.db.events) == 1
