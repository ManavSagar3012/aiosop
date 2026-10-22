"""FastAPI+PostgreSQL-transaction-surrogate provider policy lifecycle tests.

No app database, container, provider API, credentials or live model is touched.
Fake database enforces CAS and row/tenant filters; production guard calls must
occur inside the same transaction (only their external ROE DB is stubbed).
"""

import hashlib
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.deps import state
from ai_osop.api.routers import provider_route_policy_reviews as api
from ai_osop.core.provider_routing import configured_routes
from ai_osop.memory.flow_artifact_reviews import (
    ArtifactReviewDenied,
    FlowArtifactReviewStore,
)
from ai_osop.memory.provider_route_policy_reviews import (
    ProviderPolicyDenied,
    canonical_policy,
)
from ai_osop.memory.session_memory import SessionMemory

SID = "eng-provider-intent-test"
FLOW = "flow-provider-intent-test"
OWNER = "owner-human-1"
SENIOR = "senior-human-2"
VERSION = 3
REVISION = 5
AUTH_ID = "auth-provider-intent"
AUTH_SHA = "e" * 64
NOW = datetime.utcnow()
POLICY = {
    "provider": "openai",
    "model": "openai/gpt-4o",
    "operations": ["completion"],
    "allowed_roles": ["recon"],
    "capabilities": ["text_completion", "json_mode"],
    "max_output_tokens": 1000,
    "budget_source": "signed_postgres_roe",
}


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def mappings(self):
        return self

    def one(self):
        assert self.value is not None
        return self.value

    def one_or_none(self):
        return self.value

    def all(self):
        return self.value


class _Database:
    def __init__(self):
        self.rows = {}
        self.events = []
        self.active = False
        self.guards = []
        self.fail = False
        self.flow_revision = REVISION
        self.flow_active = True

    def __call__(self):
        return self

    async def __aenter__(self):
        assert not self.active
        self.active = True
        return self

    async def __aexit__(self, *_):
        self.active = False

    def begin(self):
        return _Transaction(self)

    async def execute(self, stmt, args):
        assert self.active, "Every query must remain inside the signed Flow transaction"
        if self.fail:
            raise OSError("PostgreSQL lost")
        sql = str(stmt)
        assert "provider_route_policy_review" in sql
        if "SELECT count(*)" in sql:
            return _Result(len(self.rows))
        if "INSERT INTO provider_route_policy_reviews" in sql:
            row = {
                "id": args["id"],
                "engagement_id": args["sid"],
                "flow_id": args["fid"],
                "creator_sub": args["actor"],
                "policy": __import__("json").loads(args["policy"]),
                "policy_sha256": args["sha"],
                "policy_revision": 1,
                "status": "pending",
                "senior_sub": None,
                "decision_reason": None,
                "flow_revision": args["flow_revision"],
                "authorization_version": args["version"],
                "authorization_id": args["authorization_id"],
                "authorization_sha256": args["authorization_sha256"],
                "created_at": NOW,
                "updated_at": NOW,
            }
            assert row["id"] not in self.rows
            self.rows[row["id"]] = row
            return _Result(deepcopy(row))
        if "INSERT INTO provider_route_policy_review_events" in sql:
            assert not any(
                event["review_id"] == args["review_id"] and event["revision"] == args["revision"]
                for event in self.events
            )
            self.events.append(dict(args))
            return _Result(None)
        if "SELECT" in sql and "ORDER BY created_at DESC" in sql:
            result = [
                deepcopy(row)
                for row in self.rows.values()
                if row["engagement_id"] == args["sid"] and row["flow_id"] == args["fid"]
            ]
            return _Result(result[args["offset"] : args["offset"] + args["limit"]])
        if "SELECT" in sql:
            row = self.rows.get(args["id"])
            if row is not None and (
                row["engagement_id"] != args["sid"] or row["flow_id"] != args["fid"]
            ):
                row = None
            return _Result(deepcopy(row))
        if "UPDATE" in sql:
            row = self.rows.get(args["id"])
            if (
                row is None
                or row["engagement_id"] != args["sid"]
                or row["flow_id"] != args["fid"]
                or row["policy_revision"] != args["revision"]
            ):
                return _Result(None)
            if "policy=CAST" in sql:
                if row["status"] != "pending":
                    return _Result(None)
                row["policy"] = __import__("json").loads(args["policy"])
                row["policy_sha256"] = args["sha"]
            else:
                if row["status"] != args["prior"]:
                    return _Result(None)
                row["status"] = args["decision"]
                row["senior_sub"] = args["senior"]
                row["decision_reason"] = args["reason"]
            row["policy_revision"] += 1
            row["updated_at"] = datetime.utcnow()
            return _Result(deepcopy(row))
        raise AssertionError(sql)


class _Transaction:
    def __init__(self, db):
        self.db = db

    async def __aenter__(self):
        assert self.db.active
        return self.db

    async def __aexit__(self, *_):
        return False


@pytest.fixture
def harness(monkeypatch):
    db = _Database()
    memory = SessionMemory.__new__(SessionMemory)
    memory._async_session = db
    app = FastAPI()
    app.include_router(api.router)
    principal = {
        "sub": OWNER,
        "role": "operator",
        "claims": {
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        },
    }

    async def operator():
        return principal

    async def senior():
        return principal

    app.dependency_overrides[api._operator_principal] = operator
    app.dependency_overrides[api._senior_reviewer] = senior

    async def fenced(
        locked_db,
        *,
        flow_id,
        revision,
        version,
        authorization_id,
        authorization_sha256,
        writing,
        expected_engagement_id,
    ):
        assert locked_db is db and db.active and writing
        db.guards.append((flow_id, revision, version, expected_engagement_id))
        if expected_engagement_id != SID:
            raise ArtifactReviewDenied(403, "Foreign tenant")
        if (
            flow_id != FLOW
            or revision != db.flow_revision
            or version != VERSION
            or authorization_id != AUTH_ID
            or authorization_sha256 != AUTH_SHA
            or not db.flow_active
        ):
            raise ArtifactReviewDenied(409, "Current signed Flow or ROE changed")
        return {"sid": SID, "owner": OWNER}

    async def reviewer_fence(
        locked_db, *, reviewer_sub, reviewer_token_sha256, reviewer_expires_at
    ):
        assert locked_db is db and db.active
        if reviewer_sub != SENIOR or reviewer_expires_at <= 0:
            raise ArtifactReviewDenied(403, "No trusted senior signer")

    monkeypatch.setattr(FlowArtifactReviewStore, "_fence", staticmethod(fenced))
    monkeypatch.setattr(FlowArtifactReviewStore, "_reviewer_fence", staticmethod(reviewer_fence))
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=memory))
    query = {
        "expected_engagement_id": SID,
        "expected_revision": REVISION,
        "expected_authorization_version": VERSION,
        "expected_authorization_id": AUTH_ID,
        "expected_authorization_sha256": AUTH_SHA,
    }
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, db=db, principal=principal, query=query)


def _base():
    return f"/flows/{FLOW}/provider-route-policy-reviews"


def _create(harness):
    response = harness.client.post(_base(), params=harness.query, json=POLICY)
    assert response.status_code == 201, response.text
    return response.json()


def _senior(harness):
    harness.principal.update(
        {
            "sub": SENIOR,
            "role": "senior_operator",
            "claims": {
                "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
                "provider_review_engagement_ids": [SID],
            },
            "_reviewer_token_sha256": hashlib.sha256(b"fake-expiring-signed-bearer").hexdigest(),
        }
    )


def test_crud_cas_independent_senior_approve_revoke_and_audit(harness, monkeypatch):
    monkeypatch.delenv("OSOP_VERIFIED_PROVIDER_ROUTES_JSON", raising=False)
    original_env = configured_routes()
    created = _create(harness)
    rid = created["review_id"]
    assert created["status"] == "pending"
    assert created["policy"] == canonical_policy(POLICY)[0]
    assert created["policy_sha256"] == canonical_policy(POLICY)[1]
    assert created["provider_served_model_verified"] is False
    assert created["callable_remotely"] is False
    assert created["execution_enabled"] is False
    assert created["credentials_stored"] is False
    assert created["budget_reserved"] is False
    listed = harness.client.get(_base(), params=harness.query)
    assert listed.status_code == 200 and len(listed.json()["items"]) == 1
    assert listed.headers["cache-control"] == "private, no-store"
    details = harness.client.get(f"{_base()}/{rid}", params=harness.query)
    assert details.status_code == 200 and details.json() == created
    updated = {**POLICY, "max_output_tokens": 2048, "expected_policy_revision": 1}
    response = harness.client.put(f"{_base()}/{rid}", params=harness.query, json=updated)
    assert response.status_code == 200, response.text
    assert response.json()["policy_revision"] == 2
    assert response.json()["status"] == "pending"
    stale = harness.client.put(f"{_base()}/{rid}", params=harness.query, json=updated)
    assert stale.status_code == 409
    _senior(harness)
    approval = harness.client.post(
        f"{_base()}/{rid}/decision",
        params=harness.query,
        json={
            "expected_policy_revision": 2,
            "decision": "approve",
            "reason": "I approve this inert proposal only",
        },
    )
    assert approval.status_code == 200, approval.text
    assert approval.json()["status"] == "approved"
    assert approval.json()["policy_revision"] == 3
    assert approval.json()["callable_remotely"] is False
    assert harness.client.get(_base(), params=harness.query).status_code == 200
    again = harness.client.post(
        f"{_base()}/{rid}/decision",
        params=harness.query,
        json={
            "expected_policy_revision": 3,
            "decision": "approve",
            "reason": "Duplicate approval should never work",
        },
    )
    assert again.status_code == 409
    revoke = harness.client.post(
        f"{_base()}/{rid}/decision",
        params=harness.query,
        json={
            "expected_policy_revision": 3,
            "decision": "revoke",
            "reason": "I withdraw this approval permanently",
        },
    )
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["status"] == "revoked"
    assert revoke.json()["policy_revision"] == 4
    assert [evt["event"] for evt in harness.db.events] == [
        "created",
        "updated",
        "approved",
        "revoked",
    ]
    assert len({evt["revision"] for evt in harness.db.events}) == 4
    assert configured_routes() == original_env  # inert: no dispatch configuration
    assert not harness.db.active


@pytest.mark.parametrize(
    "poison",
    [
        {"credential_env": "OPENAI_API_KEY"},
        {"api_base": "https://evil.test"},
        {"api_key": "private-secret"},
        {"provider": "unlisted"},
        {"model": "anthropic/other"},
        {"operations": ["embedding"]},
        {"capabilities": ["embeddings"]},
        {"allowed_roles": ["root_admin"]},
        {"max_output_tokens": True},
        {"max_output_tokens": 16385},
        {"budget_source": "unverified_runtime"},
        {"model": "openai/sk-live-not-a-model"},
    ],
)
def test_malicious_or_secret_provider_policy_is_rejected(harness, poison):
    response = harness.client.post(_base(), params=harness.query, json={**POLICY, **poison})
    assert response.status_code == 422, response.text
    assert not harness.db.rows and not harness.db.events


def test_owner_cannot_approve_and_senior_needs_explicit_tenant_delegation(harness):
    rid = _create(harness)["review_id"]
    decision = {
        "decision": "approve",
        "expected_policy_revision": 1,
        "reason": "Independent human review recorded",
    }
    owner = harness.client.post(f"{_base()}/{rid}/decision", params=harness.query, json=decision)
    assert owner.status_code == 403
    harness.principal["sub"] = SENIOR
    harness.principal["role"] = "senior_operator"
    missing_scope = harness.client.post(
        f"{_base()}/{rid}/decision", params=harness.query, json=decision
    )
    assert missing_scope.status_code == 403
    _senior(harness)
    harness.principal["claims"]["provider_review_engagement_ids"] = ["eng-other"]
    foreign_scope = harness.client.post(
        f"{_base()}/{rid}/decision", params=harness.query, json=decision
    )
    assert foreign_scope.status_code == 403
    assert harness.db.rows[rid]["status"] == "pending"


def test_wrong_flow_version_cross_tenant_revocation_and_pg_partition_fail_closed(harness):
    created = _create(harness)
    rid = created["review_id"]
    foreign = harness.client.get(
        f"{_base()}/{rid}", params={**harness.query, "expected_engagement_id": "eng-other"}
    )
    assert foreign.status_code == 403
    wrong_revision = harness.client.get(
        f"{_base()}/{rid}", params={**harness.query, "expected_revision": REVISION + 1}
    )
    assert wrong_revision.status_code == 409
    harness.db.flow_active = False
    assert harness.client.get(f"{_base()}/{rid}", params=harness.query).status_code == 409
    harness.db.flow_active = True
    harness.db.fail = True
    denied = harness.client.get(f"{_base()}/{rid}", params=harness.query)
    assert denied.status_code == 503 and rid not in denied.text
    assert harness.db.rows[rid]["policy_revision"] == 1


def test_duplicate_and_malformed_review_identity_fail_without_mutation(harness):
    created = _create(harness)
    assert (
        harness.client.get(f"{_base()}/provider-review-{'0'*32}", params=harness.query).status_code
        == 404
    )
    assert harness.client.get(f"{_base()}/secret", params=harness.query).status_code == 422
    assert harness.client.get(_base(), params={**harness.query, "limit": 999}).status_code == 422
    assert (
        harness.client.put(
            f"{_base()}/{created['review_id']}",
            params=harness.query,
            json={**POLICY, "expected_policy_revision": 1},
        ).status_code
        == 409
    )
    assert len(harness.db.events) == 1


def test_ambiguous_json_oversized_body_and_embedded_secret_reason_are_denied(harness):
    import json

    raw = json.dumps(POLICY)[:-1] + ',"provider":"anthropic"}'
    duplicate = harness.client.post(
        _base(),
        params=harness.query,
        content=raw,
        headers={"content-type": "application/json"},
    )
    assert duplicate.status_code == 422
    too_big = harness.client.post(
        _base(),
        params=harness.query,
        content=json.dumps(POLICY)[:-1] + ', "padding":"' + "x" * 6000 + '"}',
        headers={"content-type": "application/json"},
    )
    assert too_big.status_code == 413
    assert not harness.db.rows
    rid = _create(harness)["review_id"]
    _senior(harness)
    bad = harness.client.post(
        f"{_base()}/{rid}/decision",
        params=harness.query,
        json={
            "expected_policy_revision": 1,
            "decision": "approve",
            "reason": "Store secret bearer token in logs",
        },
    )
    assert bad.status_code == 422
    assert harness.db.rows[rid]["status"] == "pending"


def test_canonicalization_equal_under_permutation_and_strict_no_secrets():
    original, digest = canonical_policy(POLICY)
    reordered = {
        **POLICY,
        "capabilities": list(reversed(POLICY["capabilities"])),
    }
    assert canonical_policy(reordered) == (original, digest)
    for unsafe in (
        {**POLICY, "credential_env": "OPENAI_API_KEY"},
        {**POLICY, "api_base": "https://untrusted.test"},
        {**POLICY, "operations": ["completion", "completion"]},
        {**POLICY, "model": "../evil"},
    ):
        with pytest.raises(ProviderPolicyDenied):
            canonical_policy(unsafe)
