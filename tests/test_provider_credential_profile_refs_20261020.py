"""Adversarial SQL lifecycle and FastAPI qualification for NONSECRET profile refs."""

from __future__ import annotations

import copy
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.core.config import AgentType, settings
from ai_osop.memory.flow_artifact_reviews import FlowArtifactReviewStore
from ai_osop.memory.provider_route_policy_reviews import canonical_policy
from ai_osop.memory.provider_credential_profile_refs import (
    CredentialProfileDenied,
    ProviderCredentialProfileRefStore,
    _digest,
)
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.api.routers import provider_credential_profile_refs as api

SHA = "a" * 64
REVIEW = "provider-review-" + "1" * 32
OP1 = "pcop-" + "2" * 32
OP2 = "pcop-" + "3" * 32
OP3 = "pcop-" + "4" * 32
OP4 = "pcop-" + "5" * 32


def policy() -> dict:
    return {
        "provider": "openai",
        "model": "openai/gpt-4o",
        "operations": ["completion"],
        "allowed_roles": [next(iter(AgentType)).value],
        "capabilities": ["text_completion"],
        "max_output_tokens": 500,
        "budget_source": "signed_postgres_roe",
    }


def signer() -> dict:
    return {
        "flow_id": "flow-owned",
        "engagement_id": "eng-owned",
        "flow_revision": 3,
        "version": 2,
        "authorization_id": "auth-current",
        "authorization_sha256": SHA,
    }


def subject(*, senior=False) -> dict:
    return {
        "actor": "human-senior" if senior else "owner-1",
        "role": "senior_operator" if senior else "operator",
        "delegated_tenants": ["eng-owned"] if senior else [],
        "token_sha256": "b" * 64,
        "token_expires_at": int(datetime.now(timezone.utc).timestamp()) + 300,
    }


class Result:
    def __init__(self, one=None, rows=None):
        self.one = one
        self.rows = rows or []

    def mappings(self):
        return self

    def one_or_none(self):
        return copy.deepcopy(self.one)

    def one(self):
        assert self.one is not None
        return copy.deepcopy(self.one)

    def all(self):
        return copy.deepcopy(self.rows)

    def scalar_one(self):
        return self.one

    def scalar_one_or_none(self):
        return self.one


class Database:
    """Emulate atomic source rows/CAS with immutable idempotency audit."""

    def __init__(self):
        self.references = {}
        self.events = {}
        self.queries = []
        self.fail_ack_once = False
        self.force_cas_conflict = False
        self.reviewer_enabled = {"owner-1": False, "human-senior": False, "policy-senior": False}
        self.policy, self.policy_sha = canonical_policy(policy())
        self.policy_status = "approved"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        yield self
        if self.fail_ack_once:
            self.fail_ack_once = False
            raise RuntimeError("ACK lost: secret://should-never-leak")

    async def execute(self, sql, args=None):
        q = str(sql)
        p = args or {}
        self.queries.append((q, copy.deepcopy(p)))
        if q.startswith("SELECT disabled FROM operator_subject_controls"):
            return Result(self.reviewer_enabled.get(p["actor"]))
        if q.startswith("SELECT id,engagement_id,flow_id,creator_sub,policy,policy_sha256"):
            if p["id"] != REVIEW or p["eng"] != "eng-owned" or p["flow"] != "flow-owned":
                return Result()
            return Result(
                {
                    "id": REVIEW,
                    "engagement_id": "eng-owned",
                    "flow_id": "flow-owned",
                    "creator_sub": "owner-1",
                    "policy": copy.deepcopy(self.policy),
                    "policy_sha256": self.policy_sha,
                    "status": self.policy_status,
                    "senior_sub": "policy-senior",
                    "flow_revision": 3,
                    "authorization_version": 2,
                    "authorization_id": "auth-current",
                    "authorization_sha256": SHA,
                }
            )
        if q.startswith("SELECT operation_id,ref_id,engagement_id"):
            return Result(self.events.get(p["op"]))
        if q.startswith("SELECT count(*) FROM provider_credential_profile_refs"):
            return Result(len(self.references))
        if q.startswith("SELECT id,engagement_id,flow_id,owner_sub"):
            if "WHERE id=:id" in q:
                row = self.references.get(p["id"])
                if row and row["engagement_id"] == p["eng"] and row["flow_id"] == p["flow"]:
                    return Result(row)
                return Result()
            rows = [
                r
                for r in self.references.values()
                if r["engagement_id"] == p["eng"] and r["flow_id"] == p["flow"]
            ]
            return Result(rows=rows[p["offset"] : p["offset"] + p["limit"]])
        if q.startswith("INSERT INTO provider_credential_profile_refs"):
            assert p["id"] not in self.references
            assert not any(
                r["provider"] == p["provider"] and r["slot"] == p["slot"]
                for r in self.references.values()
            ), "UNIQUE per Flow/provider/slot"
            now = datetime.utcnow()
            row = {
                "id": p["id"],
                "engagement_id": p["eng"],
                "flow_id": p["flow"],
                "owner_sub": p["owner"],
                "provider": p["provider"],
                "slot": p["slot"],
                "policy_review_id": p["review"],
                "policy_sha256": p["policy_sha"],
                "reference_sha256": p["reference_sha"],
                "reference_revision": 1,
                "generation": 1,
                "status": "pending",
                "senior_sub": None,
                "flow_revision": p["revision"],
                "authorization_version": p["version"],
                "authorization_id": p["auth_id"],
                "authorization_sha256": p["auth_sha"],
                "created_at": now,
                "updated_at": now,
            }
            self.references[p["id"]] = row
            return Result(row)
        if q.startswith("UPDATE provider_credential_profile_refs"):
            row = self.references[p["id"]]
            if (
                self.force_cas_conflict
                or row["reference_revision"] != p["expected"]
                or row["status"] != p["prior"]
            ):
                return Result()
            row.update(
                {
                    "status": p["status"],
                    "senior_sub": p["senior"],
                    "generation": p["generation"],
                    "reference_sha256": p["sha"],
                    "reference_revision": row["reference_revision"] + 1,
                    "updated_at": datetime.utcnow(),
                }
            )
            return Result(row)
        if q.startswith("INSERT INTO provider_credential_profile_ref_events"):
            assert p["op"] not in self.events
            assert not any(
                e["ref_id"] == p["ref"] and e["reference_revision"] == p["revision"]
                for e in self.events.values()
            )
            self.events[p["op"]] = {
                "operation_id": p["op"],
                "ref_id": p["ref"],
                "engagement_id": p["eng"],
                "flow_id": p["flow"],
                "actor_sub": p["actor"],
                "operation": p["operation"],
                "reference_revision": p["revision"],
                "generation": p["generation"],
                "status": p["status"],
                "request_sha256": p["request_sha"],
            }
            return Result()
        raise AssertionError("Unexpected SQL " + q[:145])


class Harness:
    def __init__(self, monkeypatch):
        self.db = Database()
        self.store = ProviderCredentialProfileRefStore(SessionMemory())
        self.store._sessions = lambda: lambda: self.db

        async def trusted(db, **kwargs):
            if kwargs["expected_engagement_id"] != "eng-owned":
                raise RuntimeError("Signed tenant mismatch")
            if kwargs["revision"] != 3 or kwargs["version"] != 2:
                raise RuntimeError("Signed revision mismatch")
            if (
                kwargs["authorization_id"] != "auth-current"
                or kwargs["authorization_sha256"] != SHA
            ):
                raise RuntimeError("Signed digest mismatch")
            return {"owner": "owner-1", "sid": "eng-owned"}

        monkeypatch.setattr(FlowArtifactReviewStore, "_fence", trusted)
        monkeypatch.setattr(FlowArtifactReviewStore, "_reviewer_fence", AsyncMock())

    async def perform(self, op, *, senior=False, **kw):
        return await self.store.perform(
            operation=op, **{**signer(), **subject(senior=senior), **kw}
        )

    async def register(self, op_id=OP1):
        return await self.perform(
            "register",
            operation_id=op_id,
            provider="openai",
            slot="primary",
            policy_review_id=REVIEW,
            policy_sha256=self.db.policy_sha,
        )

    async def approve(self, ref_id, rev, operation_id=OP2):
        return await self.perform(
            "approve",
            senior=True,
            operation_id=operation_id,
            ref_id=ref_id,
            expected_ref_revision=rev,
            reason="Independent senior review accepted",
        )


@pytest.mark.asyncio
async def test_registration_is_inert_durable_and_senior_approval_separate(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()
    assert created["reference_revision"] == 1 and created["generation"] == 1
    assert created["status"] == "pending" and created["senior_reviewed"] is False
    assert created["credentials_stored"] is False
    assert created["credential_rotated"] is False
    assert created["credential_available_verified"] is False
    assert created["execution_enabled"] is False
    assert created["provider_contacted"] is False
    assert created["route_activated"] is False
    assert all("api_key" not in str(p) for _, p in h.db.queries)
    with pytest.raises(CredentialProfileDenied) as err:
        await h.perform(
            "approve",
            operation_id=OP2,
            ref_id=created["ref_id"],
            expected_ref_revision=1,
            reason="Independent senior review accepted",
        )
    assert err.value.status == 403
    approved = await h.approve(created["ref_id"], 1)
    assert approved["reference_revision"] == 2
    assert approved["generation"] == 1 and approved["status"] == "approved"
    assert approved["senior_reviewed"] is True
    assert len(h.db.events) == 2


@pytest.mark.asyncio
async def test_rotation_is_only_a_new_pending_symbolic_generation(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()
    approved = await h.approve(created["ref_id"], 1)
    rotated = await h.perform(
        "rotate",
        operation_id=OP3,
        ref_id=created["ref_id"],
        expected_ref_revision=2,
        provider="openai",
        slot="primary",
        policy_review_id=REVIEW,
        policy_sha256=h.db.policy_sha,
    )
    assert rotated["status"] == "pending"
    assert rotated["generation"] == 2 and rotated["reference_revision"] == 3
    assert rotated["senior_reviewed"] is False and rotated["credential_rotated"] is False
    with pytest.raises(CredentialProfileDenied):
        await h.perform(
            "rotate",
            operation_id=OP4,
            ref_id=created["ref_id"],
            expected_ref_revision=3,
            provider="openai",
            slot="primary",
            policy_review_id=REVIEW,
            policy_sha256=h.db.policy_sha,
        )
    after = await h.approve(created["ref_id"], 3, operation_id=OP4)
    assert after["generation"] == 2 and after["status"] == "approved"


@pytest.mark.asyncio
async def test_senior_revocation_and_tenant_scoped_reads(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()
    revoked = await h.perform(
        "revoke",
        senior=True,
        operation_id=OP2,
        ref_id=created["ref_id"],
        expected_ref_revision=1,
        reason="Revoke pending symbolic provider ref",
    )
    assert revoked["status"] == "revoked" and revoked["reference_revision"] == 2
    assert revoked["generation"] == 1
    listed = await h.perform("list")
    assert listed["items"][0]["ref_id"] == created["ref_id"]
    assert listed["has_more"] is False
    detail = await h.perform("detail", ref_id=created["ref_id"])
    assert detail["status"] == "revoked"
    with pytest.raises(CredentialProfileDenied):
        await h.perform(
            "approve",
            senior=True,
            operation_id=OP3,
            ref_id=created["ref_id"],
            expected_ref_revision=2,
            reason="Independent senior review accepted",
        )


@pytest.mark.asyncio
async def test_same_operation_id_committed_replay_no_double_write(monkeypatch):
    h = Harness(monkeypatch)
    first = await h.register()
    queries = len(h.db.events)
    recovered = await h.register()
    assert recovered["idempotent_replay"] is True
    assert recovered["replayed_event_status"] == "pending"
    assert len(h.db.references) == 1 and len(h.db.events) == queries
    approved = await h.approve(first["ref_id"], 1)
    observed = await h.register()
    assert observed["idempotent_replay"] is True
    assert observed["current_state_may_have_advanced"] is True
    assert observed["status"] == "approved"
    assert observed["replayed_event_revision"] == 1
    assert observed["replayed_event_status"] == "pending"
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.perform(
            "revoke",
            senior=True,
            operation_id=OP1,
            ref_id=first["ref_id"],
            expected_ref_revision=2,
            reason="Independent senior revoke decision",
        )
    assert denied.value.status == 409


@pytest.mark.asyncio
async def test_lost_post_commit_ack_stays_unknown_readback_required(monkeypatch):
    h = Harness(monkeypatch)
    h.db.fail_ack_once = True
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.register()
    assert denied.value.status == 503 and "UNKNOWN" in str(denied.value)
    assert "secret" not in str(denied.value)
    assert len(h.db.references) == 1 and len(h.db.events) == 1
    assert (await h.register())["idempotent_replay"] is True
    assert len(h.db.references) == 1 and len(h.db.events) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "candidate",
    [
        {"provider": "not-a-provider"},
        {"provider": "https://evil.example/key"},
        {"slot": "AWS_SECRET_ACCESS_KEY"},
        {"slot": "/tmp/key"},
        {"slot": "primary?secret=s"},
        {"policy_sha256": "sk-live-secret"},
        {"policy_review_id": "provider-review-../../wrong"},
        {"operation_id": "pcop-invalid"},
    ],
)
async def test_secret_key_path_and_untrusted_alias_inputs_denied(monkeypatch, candidate):
    h = Harness(monkeypatch)
    body = dict(
        operation_id=OP1,
        provider="openai",
        slot="primary",
        policy_review_id=REVIEW,
        policy_sha256=h.db.policy_sha,
    )
    body.update(candidate)
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.perform("register", **body)
    assert denied.value.status == 422
    assert not h.db.references and not h.db.events


@pytest.mark.asyncio
async def test_policy_senior_and_source_digest_must_remain_signed(monkeypatch):
    h = Harness(monkeypatch)
    h.db.policy["model"] = "openai/changed"
    with pytest.raises(CredentialProfileDenied):
        await h.register()
    h.db.policy, h.db.policy_sha = canonical_policy(policy())
    h.db.policy_sha = "f" * 64
    with pytest.raises(CredentialProfileDenied):
        await h.register()
    assert not h.db.events


@pytest.mark.asyncio
async def test_policy_original_senior_current_subject_revocation_fails(monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    h = Harness(monkeypatch)
    h.db.reviewer_enabled["policy-senior"] = True
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.register()
    assert denied.value.status == 403
    h.db.reviewer_enabled.pop("policy-senior")
    with pytest.raises(CredentialProfileDenied):
        await h.register()
    h.db.reviewer_enabled["policy-senior"] = False
    assert (await h.register())["status"] == "pending"


@pytest.mark.asyncio
async def test_signed_owner_senior_delegation_and_revocation_guard(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()
    with pytest.raises(CredentialProfileDenied):
        await h.perform(
            "approve",
            senior=True,
            operation_id=OP2,
            ref_id=created["ref_id"],
            expected_ref_revision=1,
            delegated_tenants=[],
            reason="Independent senior review accepted",
        )
    with pytest.raises(CredentialProfileDenied):
        await h.perform(
            "approve",
            operation_id=OP2,
            ref_id=created["ref_id"],
            expected_ref_revision=1,
            reason="Independent senior review accepted",
        )
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    h.db.reviewer_enabled["human-senior"] = True
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.approve(created["ref_id"], 1)
    assert denied.value.status == 403
    h.db.reviewer_enabled["human-senior"] = False
    assert (await h.approve(created["ref_id"], 1))["status"] == "approved"


@pytest.mark.asyncio
async def test_cas_conflicts_terminal_state_and_cross_flow_fail_closed(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()
    h.db.force_cas_conflict = True
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.approve(created["ref_id"], 1)
    assert denied.value.status == 409
    h.db.force_cas_conflict = False
    with pytest.raises(CredentialProfileDenied):
        await h.approve(created["ref_id"], 2)
    h.db.references[created["ref_id"]]["flow_revision"] = 99
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.approve(created["ref_id"], 1)
    assert denied.value.status == 409


@pytest.mark.asyncio
async def test_missing_senior_reason_unsafe_reason_denied(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()
    for reason in (
        None,
        "brief",
        "sk_live secret credential",
        "http://example.com/password",
        "bearer token abc",
        "new\nsecret\nvalue",
    ):
        with pytest.raises(CredentialProfileDenied) as denied:
            await h.perform(
                "approve",
                senior=True,
                operation_id=OP2,
                ref_id=created["ref_id"],
                expected_ref_revision=1,
                reason=reason,
            )
        assert denied.value.status == 422


@pytest.mark.asyncio
async def test_exact_delegated_senior_can_read_without_owner_write(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()
    listed = await h.perform("list", senior=True)
    assert listed["items"][0]["ref_id"] == created["ref_id"]
    detail = await h.perform("detail", senior=True, ref_id=created["ref_id"])
    assert detail["ref_id"] == created["ref_id"]
    assert detail["policy_current_approval_verified"] is False
    assert detail["status_is_historical_review_only"] is True
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.perform("list", senior=True, delegated_tenants=[])
    assert denied.value.status == 403
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.perform(
            "detail", senior=True, ref_id=created["ref_id"], delegated_tenants=["eng-other"]
        )
    assert denied.value.status == 403
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.perform(
            "rotate",
            senior=True,
            operation_id=OP3,
            ref_id=created["ref_id"],
            expected_ref_revision=1,
            provider="openai",
            slot="primary",
            policy_review_id=REVIEW,
            policy_sha256=h.db.policy_sha,
        )
    assert denied.value.status == 403


@pytest.mark.asyncio
async def test_policy_revoke_after_reference_approval_remains_inert_historical(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()
    approved = await h.approve(created["ref_id"], 1)
    assert approved["status"] == "approved"
    h.db.policy_status = "revoked"
    observed = await h.perform("detail", ref_id=created["ref_id"])
    assert observed["status"] == "approved"  # historical reference decision only
    for safety_flag in (
        "credentials_stored",
        "credential_available_verified",
        "credential_rotated",
        "execution_enabled",
        "provider_contacted",
        "route_activated",
        "policy_current_approval_verified",
    ):
        assert observed[safety_flag] is False
    with pytest.raises(CredentialProfileDenied) as denied:
        await h.perform(
            "rotate",
            operation_id=OP3,
            ref_id=created["ref_id"],
            expected_ref_revision=2,
            provider="openai",
            slot="primary",
            policy_review_id=REVIEW,
            policy_sha256=h.db.policy_sha,
        )
    assert denied.value.status == 403
    # Emergency separate-senior revocation remains possible even after 0025 is revoked.
    revoked = await h.perform(
        "revoke",
        senior=True,
        operation_id=OP4,
        ref_id=created["ref_id"],
        expected_ref_revision=2,
        reason="Independent senior revoke decision",
    )
    assert revoked["status"] == "revoked"


@pytest.mark.asyncio
async def test_roe_revocation_fails_read_and_write_without_stale_approval(monkeypatch):
    h = Harness(monkeypatch)
    created = await h.register()

    async def denied_authorization(*args, **kwargs):
        raise RuntimeError("Revoked signed authorization with private details")

    monkeypatch.setattr(FlowArtifactReviewStore, "_fence", denied_authorization)
    with pytest.raises(CredentialProfileDenied) as read:
        await h.perform("detail", ref_id=created["ref_id"])
    assert read.value.status == 503 and "private details" not in str(read.value)
    with pytest.raises(CredentialProfileDenied) as approval:
        await h.approve(created["ref_id"], 1)
    assert approval.value.status == 503
    assert len(h.db.events) == 1


def api_client(monkeypatch, h):
    app = FastAPI()
    app.include_router(api.router)

    async def principal():
        return {
            "sub": "owner-1",
            "role": "operator",
            "claims": {
                "exp": int(datetime.now(timezone.utc).timestamp()) + 300,
                "provider_review_engagement_ids": [],
            },
            "_reviewer_token_sha256": "b" * 64,
        }

    app.dependency_overrides[api._operator_principal] = principal
    monkeypatch.setattr(api, "_store", lambda: h.store)
    return TestClient(app)


def url():
    return (
        "/flows/flow-owned/provider-credential-profile-refs?"
        "expected_engagement_id=eng-owned&expected_revision=3&"
        "expected_authorization_version=2&expected_authorization_id=auth-current&"
        f"expected_authorization_sha256={SHA}"
    )


def register_body(h):
    return {
        "operation": "register",
        "operation_id": OP1,
        "provider": "openai",
        "slot": "primary",
        "policy_review_id": REVIEW,
        "policy_sha256": h.db.policy_sha,
    }


def test_fastapi_register_get_list_detail_and_headers(monkeypatch):
    h = Harness(monkeypatch)
    client = api_client(monkeypatch, h)
    created = client.post(url(), json=register_body(h))
    assert created.status_code == 201, created.text
    data = created.json()
    assert data["status"] == "pending"
    assert created.headers["cache-control"] == "private, no-store"
    assert client.post(url(), json=register_body(h)).status_code == 200
    listed = client.get(url())
    assert listed.status_code == 200
    assert listed.json()["items"][0]["ref_id"] == data["ref_id"]
    readback = client.get(url().replace("?", "/" + data["ref_id"] + "?"))
    assert readback.status_code == 200 and readback.json()["ref_id"] == data["ref_id"]


def test_fastapi_rejects_duplicate_keys_extra_secret_fields_and_oversize(monkeypatch):
    h = Harness(monkeypatch)
    client = api_client(monkeypatch, h)
    valid = register_body(h)
    for extra in (
        {"api_key": "sk-live-secret"},
        {"env": "OPENAI_API_KEY"},
        {"url": "https://test.invalid"},
        {"secret_bytes": "secret"},
    ):
        response = client.post(url(), json={**valid, **extra})
        assert response.status_code == 422 and "sk-live" not in response.text
    raw = json.dumps(valid).replace(
        '"provider": "openai"', '"provider": "openai", "provider": "anthropic"'
    )
    response = client.post(url(), content=raw, headers={"content-type": "application/json"})
    assert response.status_code == 422
    oversized = client.post(
        url(),
        content=json.dumps({**valid, "note": "a" * 5000}),
        headers={"content-type": "application/json"},
    )
    assert oversized.status_code == 413
    assert (
        client.post(url(), content="{}", headers={"content-type": "text/plain"}).status_code == 415
    )
    assert not h.db.references


def test_fastapi_requires_exact_signed_query_fence(monkeypatch):
    h = Harness(monkeypatch)
    client = api_client(monkeypatch, h)
    assert client.get("/flows/flow-owned/provider-credential-profile-refs").status_code == 422
    assert (
        client.post(url().replace("auth-current", "auth-other"), json=register_body(h)).status_code
        == 503
    )
    assert not h.db.references
